// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import { SignatureChecker } from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

import { IOTTPRegistry } from "./IOTTPRegistry.sol";

/// @title OTTPRegistry
/// @notice Issues sequential, permanent OTTP IDs (like Farcaster FIDs). One ID per wallet; transferable
///         by the current owner only.
/// @dev Immutable by design: no admin, no proxy, no pause, no owner. The deployer has no special powers.
///      Implements OTTP v2 Smart Contract Specification v1.1 (July 2026).
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
    /// @notice transferId target already holds an OTTP ID (no consolidation, by design).
    error OTTPRegistry__TargetAlreadyRegistered(address target, uint256 existingId);
    /// @notice registerFor deadline has passed.
    error OTTPRegistry__SignatureExpired(uint256 deadline, uint256 blockTimestamp);
    /// @notice registerFor signature did not verify for `wallet` (ECDSA or ERC-1271).
    error OTTPRegistry__InvalidSignature(address wallet);

    /// @notice A new ID was claimed (both registration paths).
    event Registered(uint256 indexed id, address indexed wallet);
    /// @notice An ID moved to a new wallet.
    event Transferred(uint256 indexed id, address indexed oldWallet, address indexed newWallet);

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

    /// @notice Transfer your OTTP ID to a new wallet (key rotation / wallet migration).
    /// @dev Only the current wallet may call. Target must be ID-free (no consolidation, by design).
    ///      No signature variant: transfers are rare and high-stakes; the owner pays gas directly.
    /// @param id The ID to move. Must be owned by msg.sender.
    /// @param newWallet The receiving wallet. Must be non-zero and hold no ID.
    function transferId(uint256 id, address newWallet) external {
        _checkOwner(id);
        _checkReceivable(newWallet);
        _move(id, newWallet);
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
    ///      authority), and emits Transferred.
    function _move(uint256 id, address newWallet) internal returns (address old) {
        old = idToWallet[id];
        walletToId[old] = 0;
        idToWallet[id] = newWallet;
        walletToId[newWallet] = id;
        ownerEpoch[id] += 1;
        emit Transferred(id, old, newWallet);
    }

    /// @dev Increments `nonces[signer]`; the single place any nonce moves. Signature paths call it AFTER verifying
    ///      a signature made over the current nonce, so an ERC-1271 wallet sees the pre-increment value during
    ///      `isValidSignature` (unchanged from v1.2).
    function _useNonce(address signer) internal returns (uint256 current) {
        current = nonces[signer];
        nonces[signer] = current + 1;
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
