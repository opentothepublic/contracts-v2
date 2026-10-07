// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import { SignatureChecker } from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

import { IOTTPRegistry } from "./IOTTPRegistry.sol";

/// @title OTTPRegistry
/// @notice Issues sequential, permanent OTTP IDs (like Farcaster FIDs). One ID per wallet. An ID moves only with
///         the receiving wallet's own consent (two-step transfer).
/// @dev Immutable by design: no admin, no proxy, no pause, no owner. The deployer has no special powers.
///      Implements OTTP v2 Smart Contract Specification v1.2 plus the authority addendum
///      (`specs/ottp-contracts-addendum-authority-PROPOSED.md`, PROPOSED — pending ratification).
///      Upgrades are generational: a future registry proves records on this one through the public getters.
contract OTTPRegistry is IOTTPRegistry, EIP712 {
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

    /// @notice Accept ID `id` into msg.sender, completing a pending move to msg.sender.
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
        emit Transferred(id, old, newWallet);
    }

    /// @dev Accept rules, in order: (1) a live pending move of `id` to `wallet`; (2) `wallet` still ID-free;
    ///      (3) _move. `wallet == 0` never matches (an empty record reads as target 0).
    function _accept(uint256 id, address wallet) internal {
        if (wallet == address(0) || pendingTransferOf(id) != wallet) revert OTTPRegistry__NoPendingMove(id, wallet);
        uint256 existing = walletToId[wallet];
        if (existing != 0) revert OTTPRegistry__TargetAlreadyRegistered(wallet, existing);
        _move(id, wallet);
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

    /// @dev A wallet that may receive an ID: non-zero and ID-free (no consolidation, by design).
    function _checkReceivable(address wallet) internal view {
        if (wallet == address(0)) revert OTTPRegistry__ZeroAddress();
        uint256 existing = walletToId[wallet];
        if (existing != 0) revert OTTPRegistry__TargetAlreadyRegistered(wallet, existing);
    }
}
