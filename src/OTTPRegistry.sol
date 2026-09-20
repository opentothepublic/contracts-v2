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
    /// @notice EIP-712 nonces for registerFor signatures. Consumed by every registration (either path).
    mapping(address wallet => uint256 nonce) public nonces;

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
        // forge-lint: disable-next-line(block-timestamp)
        if (block.timestamp > deadline) revert OTTPRegistry__SignatureExpired(deadline, block.timestamp);

        // Read the nonce BEFORE _register, which is what consumes it.
        bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(REGISTER_TYPEHASH, wallet, nonces[wallet], deadline)));
        if (!SignatureChecker.isValidSignatureNow(wallet, digest, signature)) {
            revert OTTPRegistry__InvalidSignature(wallet);
        }

        return _register(wallet);
    }

    /// @notice Transfer your OTTP ID to a new wallet (key rotation / wallet migration).
    /// @dev Only the current wallet may call. Target must be ID-free (no consolidation, by design).
    ///      No signature variant: transfers are rare and high-stakes; the owner pays gas directly.
    /// @param id The ID to move. Must be owned by msg.sender.
    /// @param newWallet The receiving wallet. Must be non-zero and hold no ID.
    function transferId(uint256 id, address newWallet) external {
        // Unissued IDs map to address(0); the explicit non-zero check keeps this sound even for a hypothetical
        // zero-address sender (spec v1.2 D1: defense-in-depth beyond a single equality check).
        address owner = idToWallet[id];
        if (owner == address(0) || owner != msg.sender) revert OTTPRegistry__NotOwner(id, msg.sender);
        if (newWallet == address(0)) revert OTTPRegistry__ZeroAddress();
        uint256 existing = walletToId[newWallet];
        if (existing != 0) revert OTTPRegistry__TargetAlreadyRegistered(newWallet, existing);

        walletToId[msg.sender] = 0;
        idToWallet[id] = newWallet;
        walletToId[newWallet] = id;

        emit Transferred(id, msg.sender, newWallet);
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

    /// @dev Shared issuance path for register() and registerFor(). Consumes the wallet's nonce on BOTH paths
    ///      (spec v1.2 D6), so any registerFor signature issued before a registration is dead after it.
    function _register(address wallet) internal returns (uint256 id) {
        if (wallet == address(0)) revert OTTPRegistry__ZeroAddress();
        uint256 existing = walletToId[wallet];
        if (existing != 0) revert OTTPRegistry__WalletAlreadyRegistered(wallet, existing);

        id = nextId;
        nextId = id + 1;
        idToWallet[id] = wallet;
        walletToId[wallet] = id;
        nonces[wallet] += 1;

        emit Registered(id, wallet);
    }
}
