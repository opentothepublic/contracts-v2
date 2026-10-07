// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import { SignatureChecker } from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

import { IOTTPRegistry } from "./IOTTPRegistry.sol";
import { IOTTPRegistryAuthority } from "./IOTTPRegistryAuthority.sol";

/// @title OTTPRegistry
/// @notice Issues sequential, permanent OTTP IDs (like Farcaster FIDs). One ID per wallet. An ID moves only with
///         the receiving wallet's own consent (two-step transfer or guardian recovery); the owner may grant
///         attest-only delegates.
/// @dev Immutable by design: no admin, no proxy, no pause, no owner. The deployer has no special powers.
///      Implements OTTP v2 Smart Contract Specification v1.2 plus the authority addendum
///      (`specs/ottp-contracts-addendum-authority-PROPOSED.md`, PROPOSED — pending ratification).
///      Upgrades are generational: a future registry proves records on this one through the public getters.
contract OTTPRegistry is IOTTPRegistryAuthority, EIP712 {
    /// @notice Next ID to issue. Starts at 1; 0 is reserved for "no ID".
    uint256 public nextId = 1;
    /// @notice Current wallet per ID (zero address = nonexistent).
    mapping(uint256 id => address wallet) public idToWallet;
    /// @notice ID per wallet (0 = none).
    mapping(address wallet => uint256 id) public walletToId;
    /// @notice EIP-712 nonces, one shared counter per signer. Every signature path consumes exactly one nonce of
    ///         its signer (via _useNonce); register() consumes one too (spec v1.2 D6).
    mapping(address wallet => uint256 nonce) public nonces;
    /// @notice Ownership epoch per ID. Increments on every ownership change; all granted authority is active only
    ///         in the epoch it was granted in (authority addendum B0, PROPOSED).
    mapping(uint256 id => uint96 epoch) public ownerEpoch;

    /// @dev keccak256("Register(address wallet,uint256 nonce,uint256 deadline)")
    bytes32 public constant REGISTER_TYPEHASH = keccak256("Register(address wallet,uint256 nonce,uint256 deadline)");

    /// @notice Registration target is the zero address.
    error OTTPRegistry__ZeroAddress();
    /// @notice The wallet already holds an OTTP ID (one ID per wallet).
    error OTTPRegistry__WalletAlreadyRegistered(address wallet, uint256 existingId);
    /// @notice msg.sender is not the current wallet of the ID (or the ID is unissued).
    error OTTPRegistry__NotOwner(uint256 id, address caller);
    /// @notice The receiving wallet already holds an OTTP ID (no consolidation, by design).
    error OTTPRegistry__TargetAlreadyRegistered(address target, uint256 existingId);
    /// @notice Signature deadline has passed.
    error OTTPRegistry__SignatureExpired(uint256 deadline, uint256 blockTimestamp);
    /// @notice Signature did not verify for `wallet` (ECDSA or ERC-1271) at its current nonce (and the ID's epoch).
    error OTTPRegistry__InvalidSignature(address wallet);
    /// @notice An owner-signed action names an ID that has not been issued.
    error OTTPRegistry__IdNotRegistered(uint256 id);

    /// @notice A new ID was claimed (both registration paths).
    event Registered(uint256 indexed id, address indexed wallet);
    /// @notice An ID moved to a new wallet. Emitted on every ownership-change path; all granted authority is now void.
    event Transferred(uint256 indexed id, address indexed oldWallet, address indexed newWallet);

    // ─── B1: two-step transfer (PROPOSED) ──────────────────────────────────────────────────────────────────

    struct PendingTransfer {
        address newWallet;
        uint96 epoch;
    }

    /// @dev Owner-proposed transfer per ID; live only while `epoch == ownerEpoch[id]`.
    mapping(uint256 id => PendingTransfer) internal _pendingTransfer;

    /// @dev keccak256("AcceptId(uint256 id,address wallet,uint256 epoch,uint256 nonce,uint256 deadline)")
    bytes32 public constant ACCEPT_ID_TYPEHASH =
        keccak256("AcceptId(uint256 id,address wallet,uint256 epoch,uint256 nonce,uint256 deadline)");

    /// @notice cancelTransfer: there is no live pending transfer for the ID.
    error OTTPRegistry__NoPendingTransfer(uint256 id);
    /// @notice accept: there is no live pending move of the ID to `wallet`.
    error OTTPRegistry__NoPendingMove(uint256 id, address wallet);

    /// @notice The owner proposed moving `id` to `newWallet`; nothing moves until `newWallet` accepts.
    event TransferProposed(uint256 indexed id, address indexed owner, address indexed newWallet, uint256 epoch);
    /// @notice The owner withdrew the pending transfer.
    event TransferCancelled(uint256 indexed id, address indexed newWallet);

    // ─── B2: delegates (PROPOSED) ──────────────────────────────────────────────────────────────────────────

    struct Delegation {
        uint64 expiry;
        uint96 epoch;
    }

    /// @dev Attest-only delegates per (ID, account); active only while `epoch == ownerEpoch[id]` and before expiry.
    mapping(uint256 id => mapping(address account => Delegation)) internal _delegations;

    /// @dev keccak256("SetDelegate(uint256 id,address delegate,uint64 expiry,uint256 epoch,uint256 nonce,uint256 deadline)")
    bytes32 public constant SET_DELEGATE_TYPEHASH = keccak256(
        "SetDelegate(uint256 id,address delegate,uint64 expiry,uint256 epoch,uint256 nonce,uint256 deadline)"
    );

    /// @notice The delegate is the zero address or the ID's owner.
    error OTTPRegistry__InvalidDelegate(address delegate);
    /// @notice A non-zero delegate expiry is not in the future.
    error OTTPRegistry__InvalidExpiry(uint64 expiry);

    /// @notice The owner granted (`expiry > now`) or revoked (`expiry == 0`) attest-only authority for `delegate`.
    event DelegateSet(uint256 indexed id, address indexed delegate, uint64 expiry, uint256 epoch);

    // ─── B3: guardian recovery (PROPOSED) ──────────────────────────────────────────────────────────────────

    struct Guardian {
        address guardian;
        uint96 epoch;
    }

    struct PendingRecovery {
        address newWallet;
        uint96 epoch;
        uint64 readyAt;
    }

    /// @notice How long a guardian-initiated recovery waits before the new wallet can accept.
    /// @dev PROPOSED — decision for Nate.
    uint256 public constant RECOVERY_DELAY = 7 days;

    /// @dev Guardian per ID; active only while `epoch == ownerEpoch[id]`.
    mapping(uint256 id => Guardian) internal _guardians;
    /// @dev Pending recovery per ID; live only while `epoch == ownerEpoch[id]`.
    mapping(uint256 id => PendingRecovery) internal _pendingRecovery;

    /// @dev keccak256("SetGuardian(uint256 id,address guardian,uint256 epoch,uint256 nonce,uint256 deadline)")
    bytes32 public constant SET_GUARDIAN_TYPEHASH =
        keccak256("SetGuardian(uint256 id,address guardian,uint256 epoch,uint256 nonce,uint256 deadline)");

    /// @notice The guardian is the ID's owner.
    error OTTPRegistry__InvalidGuardian(address guardian);
    /// @notice msg.sender is not the ID's active guardian.
    error OTTPRegistry__NotGuardian(uint256 id, address caller);
    /// @notice msg.sender is neither the ID's owner nor its active guardian.
    error OTTPRegistry__NotOwnerOrGuardian(uint256 id, address caller);
    /// @notice There is no live pending recovery for the ID.
    error OTTPRegistry__NoPendingRecovery(uint256 id);
    /// @notice accept: the recovery to this wallet has not matured yet.
    error OTTPRegistry__RecoveryNotReady(uint256 id, uint256 readyAt);

    /// @notice The owner set (or cleared, `guardian == 0`) the ID's guardian.
    event GuardianSet(uint256 indexed id, address indexed guardian, uint256 epoch);
    /// @notice The guardian started a recovery to `newWallet`, acceptable by `newWallet` from `readyAt`.
    event RecoveryInitiated(uint256 indexed id, address indexed guardian, address indexed newWallet, uint256 readyAt);
    /// @notice A pending recovery was cancelled by the owner or the guardian.
    event RecoveryCancelled(uint256 indexed id, address indexed by);
    /// @notice A recovery completed (emitted alongside Transferred).
    event RecoveryFinalized(uint256 indexed id, address indexed oldWallet, address indexed newWallet);

    /// @dev EIP-712 domain: name "OTTPRegistry", version "2", chainId = block.chainid, verifyingContract = this.
    ///      Exposed via ERC-5267 `eip712Domain()` (inherited from OpenZeppelin EIP712).
    constructor() EIP712("OTTPRegistry", "2") { }

    /// @notice Claim the next available OTTP ID for the caller.
    /// @return id The newly issued ID.
    function register() external returns (uint256 id) {
        _useNonce(msg.sender);
        return _register(msg.sender);
    }

    /// @notice Claim an OTTP ID for `wallet`, authorized by its EIP-712 signature.
    /// @dev Sponsored (gasless) registration: any relayer may submit and pays gas. The relayer never receives
    ///      an ID as a side effect — the only outcome any submitter can produce is `wallet` getting registered.
    ///      Supports EOAs (ECDSA) and smart-contract wallets (ERC-1271) via OpenZeppelin SignatureChecker.
    ///      Replay protection: per-wallet nonce (consumed by EVERY registration, either path — spec v1.2 D6),
    ///      deadline, and the chain/contract-bound domain.
    /// @param wallet The wallet to register (the EIP-712 signer).
    /// @param deadline Unix timestamp after which the signature is no longer valid.
    /// @param signature EIP-712 signature over Register(wallet, nonces[wallet], deadline).
    /// @return id The newly issued ID.
    function registerFor(address wallet, uint256 deadline, bytes calldata signature) external returns (uint256 id) {
        _checkDeadline(deadline);
        _checkSignature(wallet, keccak256(abi.encode(REGISTER_TYPEHASH, wallet, nonces[wallet], deadline)), signature);
        _useNonce(wallet);
        return _register(wallet);
    }

    // ─── B1: two-step transfer (PROPOSED) ──────────────────────────────────────────────────────────────────

    /// @notice Propose moving your ID to `newWallet` (key rotation / wallet migration). Nothing moves until
    ///         `newWallet` accepts with its own call or signature.
    /// @dev Owner only. `newWallet` must be non-zero and ID-free, now and at acceptance. Overwrites any earlier
    ///      proposal. The owner pays gas directly; there is no signature variant of proposing.
    function proposeTransfer(uint256 id, address newWallet) external {
        _checkOwner(id);
        _checkReceivable(newWallet);
        uint96 epoch = ownerEpoch[id];
        _pendingTransfer[id] = PendingTransfer({ newWallet: newWallet, epoch: epoch });
        emit TransferProposed(id, msg.sender, newWallet, epoch);
    }

    /// @notice Withdraw your pending transfer proposal.
    function cancelTransfer(uint256 id) external {
        _checkOwner(id);
        address target = pendingTransferOf(id);
        if (target == address(0)) revert OTTPRegistry__NoPendingTransfer(id);
        delete _pendingTransfer[id];
        emit TransferCancelled(id, target);
    }

    /// @notice Accept ID `id` into msg.sender: completes a pending transfer, or a matured recovery, to msg.sender.
    function acceptId(uint256 id) external {
        _accept(id, msg.sender);
    }

    /// @notice Gasless acceptId: `wallet` signs AcceptId(id, wallet, ownerEpoch[id], nonces[wallet], deadline).
    /// @dev Any relayer may submit; the only possible outcome is `id` moving into `wallet` on terms it signed.
    function acceptIdBySig(uint256 id, address wallet, uint256 deadline, bytes calldata signature) external {
        _checkDeadline(deadline);
        _checkSignature(
            wallet,
            keccak256(abi.encode(ACCEPT_ID_TYPEHASH, id, wallet, ownerEpoch[id], nonces[wallet], deadline)),
            signature
        );
        _useNonce(wallet);
        _accept(id, wallet);
    }

    // ─── B2: delegates (PROPOSED) ──────────────────────────────────────────────────────────────────────────

    /// @notice Grant (`expiry > now`), change, or revoke (`expiry == 0`) attest-only authority for `delegate`.
    /// @dev Owner only. `type(uint64).max` means no expiry. A delegate can only attest Objects for this ID (via
    ///      canAttest in the Object resolver); it cannot transfer, accept, set delegates or touch recovery.
    function setDelegate(uint256 id, address delegate, uint64 expiry) external {
        _checkOwner(id);
        _setDelegate(id, msg.sender, delegate, expiry);
    }

    /// @notice Gasless setDelegate, signed by the ID's current owner over
    ///         SetDelegate(id, delegate, expiry, ownerEpoch[id], nonces[owner], deadline).
    /// @dev Consumes exactly one nonce of the owner, after verification. The epoch in the digest is the current
    ///      one, so signatures from an earlier ownership epoch are dead.
    function setDelegateBySig(uint256 id, address delegate, uint64 expiry, uint256 deadline, bytes calldata signature)
        external
    {
        _checkDeadline(deadline);
        address owner = _existingOwner(id);
        _checkSignature(
            owner,
            keccak256(abi.encode(SET_DELEGATE_TYPEHASH, id, delegate, expiry, ownerEpoch[id], nonces[owner], deadline)),
            signature
        );
        _useNonce(owner);
        _setDelegate(id, owner, delegate, expiry);
    }

    // ─── B3: guardian recovery (PROPOSED) ──────────────────────────────────────────────────────────────────

    /// @notice Set (or clear, `guardian == 0`) the account that may initiate recovery of your ID.
    /// @dev Owner only; the guardian must not be the owner. Any call also cancels a live pending recovery. The
    ///      guardian can only initiate and cancel recovery; it cannot attest or do anything else.
    function setGuardian(uint256 id, address guardian) external {
        _checkOwner(id);
        _setGuardian(id, msg.sender, guardian);
    }

    /// @notice Gasless setGuardian, signed by the ID's current owner over
    ///         SetGuardian(id, guardian, ownerEpoch[id], nonces[owner], deadline).
    /// @dev Consumes exactly one nonce of the owner, after verification.
    function setGuardianBySig(uint256 id, address guardian, uint256 deadline, bytes calldata signature) external {
        _checkDeadline(deadline);
        address owner = _existingOwner(id);
        _checkSignature(
            owner,
            keccak256(abi.encode(SET_GUARDIAN_TYPEHASH, id, guardian, ownerEpoch[id], nonces[owner], deadline)),
            signature
        );
        _useNonce(owner);
        _setGuardian(id, owner, guardian);
    }

    /// @notice Active guardian only: start moving `id` to `newWallet`, which may accept from now + RECOVERY_DELAY.
    /// @dev `newWallet` must be non-zero and ID-free. Re-initiating overwrites and restarts the clock. The owner
    ///      (or the guardian) can cancel at any time before acceptance.
    function initiateRecovery(uint256 id, address newWallet) external {
        if (msg.sender == address(0) || guardianOf(id) != msg.sender) revert OTTPRegistry__NotGuardian(id, msg.sender);
        _checkReceivable(newWallet);
        // forge-lint: disable-next-line(unsafe-typecast)
        uint64 readyAt = uint64(block.timestamp + RECOVERY_DELAY); // timestamps fit uint64 for ~5.8e11 years
        _pendingRecovery[id] = PendingRecovery({ newWallet: newWallet, epoch: ownerEpoch[id], readyAt: readyAt });
        emit RecoveryInitiated(id, msg.sender, newWallet, readyAt);
    }

    /// @notice Owner or active guardian: cancel the pending recovery.
    function cancelRecovery(uint256 id) external {
        address owner = idToWallet[id];
        bool isOwner = owner != address(0) && owner == msg.sender;
        if (!isOwner && (msg.sender == address(0) || guardianOf(id) != msg.sender)) {
            revert OTTPRegistry__NotOwnerOrGuardian(id, msg.sender);
        }
        (address target,) = pendingRecoveryOf(id);
        if (target == address(0)) revert OTTPRegistry__NoPendingRecovery(id);
        delete _pendingRecovery[id];
        emit RecoveryCancelled(id, msg.sender);
    }

    /// @inheritdoc IOTTPRegistry
    function getId(address wallet) external view returns (uint256) {
        return walletToId[wallet];
    }

    /// @inheritdoc IOTTPRegistry
    function getWallet(uint256 id) external view returns (address) {
        return idToWallet[id];
    }

    /// @inheritdoc IOTTPRegistry
    function totalRegistered() external view returns (uint256) {
        return nextId - 1;
    }

    /// @inheritdoc IOTTPRegistryAuthority
    function isDelegate(uint256 id, address account) public view returns (bool) {
        return delegateExpiry(id, account) != 0;
    }

    /// @inheritdoc IOTTPRegistryAuthority
    function canAttest(uint256 id, address account) external view returns (bool) {
        address owner = idToWallet[id];
        return owner != address(0) && (account == owner || isDelegate(id, account));
    }

    /// @notice Active delegate expiry for (`id`, `account`), or 0 if `account` is not an active delegate.
    function delegateExpiry(uint256 id, address account) public view returns (uint64) {
        Delegation memory d = _delegations[id][account];
        // forge-lint: disable-next-line(block-timestamp)
        if (idToWallet[id] == address(0) || d.epoch != ownerEpoch[id] || block.timestamp >= d.expiry) return 0;
        return d.expiry;
    }

    /// @notice Active guardian for `id`, or address(0).
    function guardianOf(uint256 id) public view returns (address) {
        Guardian memory g = _guardians[id];
        return g.epoch == ownerEpoch[id] ? g.guardian : address(0);
    }

    /// @notice Live pending recovery for `id` as (newWallet, readyAt), or zeros.
    function pendingRecoveryOf(uint256 id) public view returns (address newWallet, uint256 readyAt) {
        PendingRecovery memory r = _pendingRecovery[id];
        if (r.epoch != ownerEpoch[id]) return (address(0), 0);
        return (r.newWallet, r.readyAt);
    }

    /// @notice Live pending-transfer target for `id`, or address(0).
    function pendingTransferOf(uint256 id) public view returns (address) {
        PendingTransfer memory p = _pendingTransfer[id];
        return p.epoch == ownerEpoch[id] ? p.newWallet : address(0);
    }

    /// @dev Shared issuance path for register() and registerFor(). Both callers consume the wallet's nonce first
    ///      (spec v1.2 D6), so any registerFor signature issued before a registration is dead after it.
    function _register(address wallet) internal returns (uint256 id) {
        if (wallet == address(0)) revert OTTPRegistry__ZeroAddress();
        uint256 existing = walletToId[wallet];
        if (existing != 0) revert OTTPRegistry__WalletAlreadyRegistered(wallet, existing);

        id = nextId;
        nextId = id + 1;
        idToWallet[id] = wallet;
        walletToId[wallet] = id;

        emit Registered(id, wallet);
    }

    /// @dev The single ownership-change path: updates both mappings, bumps the epoch (voiding every granted
    ///      authority), deletes pending moves, and emits Transferred.
    function _move(uint256 id, address newWallet) internal returns (address old) {
        old = idToWallet[id];
        walletToId[old] = 0;
        idToWallet[id] = newWallet;
        walletToId[newWallet] = id;
        ownerEpoch[id] += 1;
        delete _pendingTransfer[id];
        delete _pendingRecovery[id];
        emit Transferred(id, old, newWallet);
    }

    /// @dev Accept rules, in order: (1) a live pending transfer to `wallet`, or a live recovery to `wallet` whose
    ///      readyAt has passed (a transfer to `wallet` takes precedence); (2) `wallet` still ID-free; (3) _move, plus
    ///      RecoveryFinalized for a recovery. `wallet == 0` never matches (an empty record reads as target 0).
    function _accept(uint256 id, address wallet) internal {
        bool isRecovery = false;
        if (wallet == address(0) || pendingTransferOf(id) != wallet) {
            (address target, uint256 readyAt) = pendingRecoveryOf(id);
            if (wallet == address(0) || target != wallet) revert OTTPRegistry__NoPendingMove(id, wallet);
            // forge-lint: disable-next-line(block-timestamp)
            if (block.timestamp < readyAt) revert OTTPRegistry__RecoveryNotReady(id, readyAt);
            isRecovery = true;
        }
        uint256 existing = walletToId[wallet];
        if (existing != 0) revert OTTPRegistry__TargetAlreadyRegistered(wallet, existing);
        address old = _move(id, wallet);
        if (isRecovery) emit RecoveryFinalized(id, old, wallet);
    }

    function _setDelegate(uint256 id, address owner, address delegate, uint64 expiry) internal {
        if (delegate == address(0) || delegate == owner) revert OTTPRegistry__InvalidDelegate(delegate);
        uint96 epoch = ownerEpoch[id];
        if (expiry == 0) {
            delete _delegations[id][delegate];
        } else {
            // forge-lint: disable-next-line(block-timestamp)
            if (expiry <= block.timestamp) revert OTTPRegistry__InvalidExpiry(expiry);
            _delegations[id][delegate] = Delegation({ expiry: expiry, epoch: epoch });
        }
        emit DelegateSet(id, delegate, expiry, epoch);
    }

    function _setGuardian(uint256 id, address owner, address guardian) internal {
        if (guardian == owner) revert OTTPRegistry__InvalidGuardian(guardian);
        (address target,) = pendingRecoveryOf(id);
        if (target != address(0)) {
            delete _pendingRecovery[id];
            emit RecoveryCancelled(id, owner);
        }
        uint96 epoch = ownerEpoch[id];
        _guardians[id] = Guardian({ guardian: guardian, epoch: epoch });
        emit GuardianSet(id, guardian, epoch);
    }

    /// @dev Increments `nonces[signer]`; the single place any nonce moves. Signature paths call it AFTER verifying
    ///      a signature made over the current nonce, so an ERC-1271 wallet sees the pre-increment value during
    ///      `isValidSignature` (unchanged from v1.2).
    function _useNonce(address signer) internal {
        nonces[signer] += 1;
    }

    function _checkDeadline(uint256 deadline) internal view {
        // forge-lint: disable-next-line(block-timestamp)
        if (block.timestamp > deadline) revert OTTPRegistry__SignatureExpired(deadline, block.timestamp);
    }

    /// @dev EIP-712 (domain unchanged) + OZ SignatureChecker: EOA ECDSA or ERC-1271.
    function _checkSignature(address signer, bytes32 structHash, bytes calldata signature) internal view {
        if (!SignatureChecker.isValidSignatureNow(signer, _hashTypedDataV4(structHash), signature)) {
            revert OTTPRegistry__InvalidSignature(signer);
        }
    }

    /// @dev msg.sender must be the ID's current, non-zero wallet. Unissued IDs map to address(0); the explicit
    ///      non-zero check keeps this sound even for a hypothetical zero-address sender (spec v1.2 D1).
    function _checkOwner(uint256 id) internal view {
        address owner = idToWallet[id];
        if (owner == address(0) || owner != msg.sender) revert OTTPRegistry__NotOwner(id, msg.sender);
    }

    /// @dev The ID's current wallet, for owner-signed paths; reverts for an unissued ID.
    function _existingOwner(uint256 id) internal view returns (address owner) {
        owner = idToWallet[id];
        if (owner == address(0)) revert OTTPRegistry__IdNotRegistered(id);
    }

    /// @dev A wallet that may receive an ID: non-zero and ID-free (no consolidation, by design).
    function _checkReceivable(address wallet) internal view {
        if (wallet == address(0)) revert OTTPRegistry__ZeroAddress();
        uint256 existing = walletToId[wallet];
        if (existing != 0) revert OTTPRegistry__TargetAlreadyRegistered(wallet, existing);
    }
}
