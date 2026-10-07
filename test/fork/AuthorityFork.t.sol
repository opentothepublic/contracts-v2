// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import { Test, console2 } from "forge-std/Test.sol";
import {
    IEAS,
    AttestationRequest,
    AttestationRequestData,
    DelegatedAttestationRequest
} from "@ethereum-attestation-service/eas-contracts/contracts/IEAS.sol";
import { ISchemaRegistry } from "@ethereum-attestation-service/eas-contracts/contracts/ISchemaRegistry.sol";
import {
    Attestation,
    Signature,
    EMPTY_UID,
    NO_EXPIRATION_TIME
} from "@ethereum-attestation-service/eas-contracts/contracts/Common.sol";
import { ISchemaResolver } from "@ethereum-attestation-service/eas-contracts/contracts/resolver/ISchemaResolver.sol";

import { OTTPRegistry } from "../../src/OTTPRegistry.sol";
import { OTTPResolver__AttesterNotOwner } from "../../src/OTTPResolverErrors.sol";
import { OTTPSubjectResolver } from "../../src/OTTPSubjectResolver.sol";
import { OTTPObjectResolver } from "../../src/OTTPObjectResolver.sol";
import { OTTPSchemas } from "../../src/Schemas.sol";
import { RegistrySigUtils } from "../utils/RegistrySigUtils.sol";
import { AuthoritySigUtils } from "../utils/AuthoritySigUtils.sol";
import { DelegatedAttestationRequestV101, IEASv101, IEASIntrospect } from "./EASFork.t.sol";

// ─── Safe v1.4.1 (canonical deployments, present on Base mainnet and Base Sepolia) ──────────────────────────────

interface ISafeProxyFactory {
    function createProxyWithNonce(address singleton, bytes memory initializer, uint256 saltNonce)
        external
        returns (address proxy);
}

interface ISafe {
    function setup(
        address[] calldata owners,
        uint256 threshold,
        address to,
        bytes calldata data,
        address fallbackHandler,
        address paymentToken,
        uint256 payment,
        address payable paymentReceiver
    ) external;
    function execTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes memory signatures
    ) external payable returns (bool success);
    function getTransactionHash(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        uint256 _nonce
    ) external view returns (bytes32);
    function nonce() external view returns (uint256);
    function getOwners() external view returns (address[] memory);
    function VERSION() external view returns (string memory);
}

interface ICompatibilityFallbackHandler {
    function getMessageHashForSafe(address safe, bytes memory message) external view returns (bytes32);
}

/// @title AuthorityForkBase
/// @notice Authority addendum (PROPOSED) against the REAL EAS and a REAL Safe v1.4.1 on Base forks.
///         The motivating case: a Safe-owned ID cannot have ERC-1271 attestations relayed on mainnet EAS 1.0.1, so
///         it sets an EOA delegate whose ECDSA-signed Object attestations a relayer submits via attestByDelegation.
///         Enabled with FORK_TESTS=true. Nothing is broadcast.
abstract contract AuthorityForkBase is Test {
    address internal constant SAFE_PROXY_FACTORY = 0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67;
    address internal constant SAFE_SINGLETON_L2 = 0x29fcB43b46531BcA003ddC8FCB67FFE91900C762;
    address internal constant SAFE_FALLBACK_HANDLER = 0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99;

    IEAS internal eas = IEAS(OTTPSchemas.EAS);
    ISchemaRegistry internal schemaRegistry = ISchemaRegistry(OTTPSchemas.SCHEMA_REGISTRY);

    OTTPRegistry internal registry;
    OTTPSubjectResolver internal subjectResolver;
    OTTPObjectResolver internal objectResolver;
    bytes32 internal subjectSchema;
    bytes32 internal objectSchema;

    ISafe internal safe;
    address internal safeOwner;
    uint256 internal safeOwnerPk;
    uint256 internal safeId;

    address internal delegate;
    uint256 internal delegatePk;
    address internal guardian;
    uint256 internal guardianPk;
    address internal relayer = makeAddr("relayer");

    uint64 internal constant FOREVER = type(uint64).max;

    function _rpcEnvVar() internal pure virtual returns (string memory);
    function _defaultRpc() internal pure virtual returns (string memory);
    function _expectedChainId() internal pure virtual returns (uint256);
    function _expectedEasVersion() internal pure virtual returns (string memory);
    function _easRelaysErc1271() internal pure virtual returns (bool);
    /// @dev Build the chain-specific EAS delegated typed-data digest for `attester` (EOA or contract).
    function _easDigest(bytes32 schema, AttestationRequestData memory data, address attester, uint64 deadline)
        internal
        view
        virtual
        returns (bytes32);
    /// @dev Submit a delegated attestation as `relayer` with a pre-built signature.
    function _submitDelegated(
        bytes32 schema,
        AttestationRequestData memory data,
        address attester,
        uint64 deadline,
        bytes memory sig
    ) internal virtual returns (bytes32);

    function setUp() public {
        if (!vm.envOr("FORK_TESTS", false)) {
            vm.skip(true);
            return;
        }
        vm.createSelectFork(vm.envOr(_rpcEnvVar(), _defaultRpc()));
        assertEq(block.chainid, _expectedChainId(), "wrong chain");
        assertEq(IEASIntrospect(address(eas)).version(), _expectedEasVersion(), "unexpected EAS version");
        assertEq(ISafe(SAFE_SINGLETON_L2).VERSION(), "1.4.1", "unexpected Safe singleton");

        (safeOwner, safeOwnerPk) = makeAddrAndKey("safe-owner");
        (delegate, delegatePk) = makeAddrAndKey("delegate");
        (guardian, guardianPk) = makeAddrAndKey("guardian");
        vm.deal(relayer, 1 ether);
        vm.deal(safeOwner, 1 ether);
        vm.deal(delegate, 1 ether);
        vm.deal(guardian, 1 ether);

        registry = new OTTPRegistry();
        subjectResolver = new OTTPSubjectResolver(eas, registry);
        objectResolver = new OTTPObjectResolver(eas, registry);
        subjectSchema = schemaRegistry.register(
            OTTPSchemas.SUBJECT, ISchemaResolver(address(subjectResolver)), OTTPSchemas.REVOCABLE
        );
        objectSchema = schemaRegistry.register(
            OTTPSchemas.OBJECT, ISchemaResolver(address(objectResolver)), OTTPSchemas.REVOCABLE
        );

        safe = _deploySafe(safeOwner, 0);
        // Sponsored registration of the Safe itself, authorized by a real Safe ERC-1271 signature.
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 digest = RegistrySigUtils.digest(address(registry), block.chainid, address(safe), 0, deadline);
        vm.prank(relayer);
        safeId = registry.registerFor(address(safe), deadline, _safeSign(safe, digest));
        assertEq(registry.getWallet(safeId), address(safe));
    }

    // ─── Safe helpers ──────────────────────────────────────────────────────────────────────────────────────

    function _deploySafe(address owner, uint256 salt) internal returns (ISafe) {
        address[] memory owners = new address[](1);
        owners[0] = owner;
        bytes memory init = abi.encodeCall(
            ISafe.setup, (owners, 1, address(0), "", SAFE_FALLBACK_HANDLER, address(0), 0, payable(address(0)))
        );
        return ISafe(ISafeProxyFactory(SAFE_PROXY_FACTORY).createProxyWithNonce(SAFE_SINGLETON_L2, init, salt));
    }

    /// @dev Real Safe ERC-1271: the owner signs the SafeMessage hash of `digest` (Safe's EIP-712 wrapper).
    function _safeSign(ISafe s, bytes32 digest) internal view returns (bytes memory) {
        bytes32 safeMsgHash =
            ICompatibilityFallbackHandler(SAFE_FALLBACK_HANDLER).getMessageHashForSafe(address(s), abi.encode(digest));
        (uint8 v, bytes32 r, bytes32 sg) = vm.sign(safeOwnerPk, safeMsgHash);
        return abi.encodePacked(r, sg, v);
    }

    /// @dev Execute `data` on `to` as a Safe transaction signed by the owner and submitted by the relayer.
    function _safeExec(ISafe s, address to, bytes memory data) internal {
        bytes memory sigs = _safeTxSig(s, to, data);
        vm.prank(relayer);
        bool success = s.execTransaction(to, 0, data, 0, 0, 0, 0, address(0), payable(address(0)), sigs);
        assertTrue(success, "safe tx failed");
    }

    function _safeTxSig(ISafe s, address to, bytes memory data) internal view returns (bytes memory) {
        bytes32 txHash = s.getTransactionHash(to, 0, data, 0, 0, 0, 0, address(0), address(0), s.nonce());
        (uint8 v, bytes32 r, bytes32 sg) = vm.sign(safeOwnerPk, txHash);
        return abi.encodePacked(r, sg, v);
    }

    // ─── EAS helpers ───────────────────────────────────────────────────────────────────────────────────────

    function _data(bytes memory payload) internal pure returns (AttestationRequestData memory) {
        return AttestationRequestData({
            recipient: address(0),
            expirationTime: NO_EXPIRATION_TIME,
            revocable: false,
            refUID: EMPTY_UID,
            data: payload,
            value: 0
        });
    }

    function _object(uint256 creatorId) internal pure returns (bytes memory) {
        return abi.encode(bytes32(0), creatorId, '{"type":"release","title":"via delegate"}');
    }

    function _subject(uint256 id) internal pure returns (bytes memory) {
        return abi.encode(id, "collab-operator", '{"identityType":"org"}');
    }

    /// @dev `signerPk` signs a delegated attestation naming `attester`; the relayer submits it.
    function _relayEoa(bytes32 schema, bytes memory payload, uint256 signerPk, address attester, bytes4 expectedRevert)
        internal
        returns (bytes32 uid)
    {
        AttestationRequestData memory d = _data(payload);
        uint64 deadline = uint64(block.timestamp + 1 hours);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, _easDigest(schema, d, attester, deadline));
        if (expectedRevert != bytes4(0)) vm.expectPartialRevert(expectedRevert);
        return _submitDelegated(schema, d, attester, deadline, abi.encodePacked(r, s, v));
    }

    function _setDelegateViaSafeTx(address d, uint64 expiry) internal {
        _safeExec(safe, address(registry), abi.encodeCall(OTTPRegistry.setDelegate, (safeId, d, expiry)));
    }

    // ─── the motivating case ───────────────────────────────────────────────────────────────────────────────

    /// @notice Safe-owned ID → EOA delegate (set by a real Safe transaction) → delegate signs a delegated Object
    ///         attestation → a separate relayer submits attestByDelegation → accepted, attributed to the Safe's ID.
    function test_SafeOwnedId_EoaDelegate_RelayedObjectAccepted() public {
        _setDelegateViaSafeTx(delegate, FOREVER);
        assertTrue(registry.isDelegate(safeId, delegate));

        bytes32 uid = _relayEoa(objectSchema, _object(safeId), delegatePk, delegate, bytes4(0));
        Attestation memory a = eas.getAttestation(uid);
        assertEq(a.attester, delegate, "EAS records the delegate as attester");
        (, uint256 creatorId,) = abi.decode(a.data, (bytes32, uint256, string));
        assertEq(creatorId, safeId, "attributed to the Safe's id (indexer rule D-1)");
        assertEq(a.schema, objectSchema);
        console2.log("EAS version", _expectedEasVersion(), "- delegate-relayed Object uid:");
        console2.logBytes32(uid);
    }

    /// @notice Same flow, but the delegate is granted gaslessly: the Safe signs SetDelegate via ERC-1271 and a
    ///         relayer submits setDelegateBySig. Works on both chains because the REGISTRY verifies the 1271
    ///         signature (OZ SignatureChecker), not EAS.
    function test_SafeOwnedId_SetDelegateBySig_Erc1271_ThenRelayedObject() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 digest = AuthoritySigUtils.toTypedData(
            address(registry),
            block.chainid,
            AuthoritySigUtils.setDelegateHash(
                safeId, delegate, FOREVER, registry.ownerEpoch(safeId), registry.nonces(address(safe)), deadline
            )
        );
        vm.prank(relayer);
        registry.setDelegateBySig(safeId, delegate, FOREVER, deadline, _safeSign(safe, digest));
        assertTrue(registry.isDelegate(safeId, delegate));
        assertEq(registry.nonces(address(safe)), 2, "registerFor + setDelegateBySig");

        _relayEoa(objectSchema, _object(safeId), delegatePk, delegate, bytes4(0));
    }

    /// @notice Contrast: the Safe's OWN relayed attestation is impossible on EAS 1.0.1 (ECDSA-only), possible on
    ///         1.2.0. This is why delegates exist.
    function test_SafeOwnRelayedAttest_DependsOnEasVersion() public {
        AttestationRequestData memory d = _data(_object(safeId));
        uint64 deadline = uint64(block.timestamp + 1 hours);
        bytes32 digest = _easDigest(objectSchema, d, address(safe), deadline);
        bytes memory sig = _safeSign(safe, digest);
        if (_easRelaysErc1271()) {
            bytes32 uid = _submitDelegated(objectSchema, d, address(safe), deadline, sig);
            assertEq(eas.getAttestation(uid).attester, address(safe));
        } else {
            vm.expectRevert(bytes4(keccak256("InvalidSignature()"))); // EAS 1.0.1: ECDSA.recover ≠ the Safe
            _submitDelegated(objectSchema, d, address(safe), deadline, sig);
        }
    }

    function test_Delegate_SubjectAttestationRejected() public {
        _setDelegateViaSafeTx(delegate, FOREVER);
        _relayEoa(subjectSchema, _subject(safeId), delegatePk, delegate, OTTPResolver__AttesterNotOwner.selector);
        vm.prank(delegate);
        vm.expectPartialRevert(OTTPResolver__AttesterNotOwner.selector);
        eas.attest(AttestationRequest({ schema: subjectSchema, data: _data(_subject(safeId)) }));
    }

    function test_Delegate_ExpiredRejected() public {
        _setDelegateViaSafeTx(delegate, uint64(block.timestamp + 1 days));
        _relayEoa(objectSchema, _object(safeId), delegatePk, delegate, bytes4(0));
        vm.warp(block.timestamp + 1 days);
        _relayEoa(objectSchema, _object(safeId), delegatePk, delegate, OTTPResolver__AttesterNotOwner.selector);
    }

    function test_Delegate_RevokedRejected() public {
        _setDelegateViaSafeTx(delegate, FOREVER);
        _setDelegateViaSafeTx(delegate, 0);
        _relayEoa(objectSchema, _object(safeId), delegatePk, delegate, OTTPResolver__AttesterNotOwner.selector);
        vm.prank(delegate);
        vm.expectPartialRevert(OTTPResolver__AttesterNotOwner.selector);
        eas.attest(AttestationRequest({ schema: objectSchema, data: _data(_object(safeId)) }));
    }

    function test_Delegate_RejectedAfterTransfer() public {
        _setDelegateViaSafeTx(delegate, FOREVER);
        _relayEoa(objectSchema, _object(safeId), delegatePk, delegate, bytes4(0));

        // The Safe moves its id to a new Safe; the new Safe accepts gaslessly with its own ERC-1271 signature.
        ISafe safe2 = _deploySafe(safeOwner, 1);
        _safeExec(safe, address(registry), abi.encodeCall(OTTPRegistry.proposeTransfer, (safeId, address(safe2))));
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 digest = AuthoritySigUtils.toTypedData(
            address(registry),
            block.chainid,
            AuthoritySigUtils.acceptIdHash(safeId, address(safe2), registry.ownerEpoch(safeId), 0, deadline)
        );
        vm.prank(relayer);
        registry.acceptIdBySig(safeId, address(safe2), deadline, _safeSign(safe2, digest));
        assertEq(registry.getWallet(safeId), address(safe2));

        assertFalse(registry.isDelegate(safeId, delegate));
        _relayEoa(objectSchema, _object(safeId), delegatePk, delegate, OTTPResolver__AttesterNotOwner.selector);
    }
}

/// @notice Base mainnet fork — EAS 1.0.1 (the motivating chain).
contract BaseMainnetAuthorityForkTest is AuthorityForkBase {
    function _rpcEnvVar() internal pure override returns (string memory) {
        return "BASE_RPC_URL";
    }

    function _defaultRpc() internal pure override returns (string memory) {
        return "https://mainnet.base.org";
    }

    function _expectedChainId() internal pure override returns (uint256) {
        return OTTPSchemas.BASE_MAINNET;
    }

    function _expectedEasVersion() internal pure override returns (string memory) {
        return "1.0.1";
    }

    function _easRelaysErc1271() internal pure override returns (bool) {
        return false;
    }

    function _easDigest(bytes32 schema, AttestationRequestData memory data, address attester, uint64)
        internal
        view
        override
        returns (bytes32)
    {
        IEASIntrospect e = IEASIntrospect(address(eas));
        bytes32 structHash = keccak256(
            abi.encode(
                e.getAttestTypeHash(),
                schema,
                data.recipient,
                data.expirationTime,
                data.revocable,
                data.refUID,
                keccak256(data.data),
                e.getNonce(attester)
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", e.getDomainSeparator(), structHash));
    }

    function _submitDelegated(
        bytes32 schema,
        AttestationRequestData memory data,
        address attester,
        uint64,
        bytes memory sig
    ) internal override returns (bytes32) {
        (bytes32 r, bytes32 s, uint8 v) = _split(sig);
        vm.prank(relayer);
        return IEASv101(address(eas))
            .attestByDelegation(
                DelegatedAttestationRequestV101({
                schema: schema, data: data, signature: Signature({ v: v, r: r, s: s }), attester: attester
            })
            );
    }

    function _split(bytes memory sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        assembly ("memory-safe") {
            r := mload(add(sig, 0x20))
            s := mload(add(sig, 0x40))
            v := byte(0, mload(add(sig, 0x60)))
        }
    }
}

/// @notice Base Sepolia fork — EAS 1.2.0.
contract BaseSepoliaAuthorityForkTest is AuthorityForkBase {
    function _rpcEnvVar() internal pure override returns (string memory) {
        return "BASE_SEPOLIA_RPC_URL";
    }

    function _defaultRpc() internal pure override returns (string memory) {
        return "https://sepolia.base.org";
    }

    function _expectedChainId() internal pure override returns (uint256) {
        return OTTPSchemas.BASE_SEPOLIA;
    }

    function _expectedEasVersion() internal pure override returns (string memory) {
        return "1.2.0";
    }

    function _easRelaysErc1271() internal pure override returns (bool) {
        return true;
    }

    function _easDigest(bytes32 schema, AttestationRequestData memory data, address attester, uint64 deadline)
        internal
        view
        override
        returns (bytes32)
    {
        IEASIntrospect e = IEASIntrospect(address(eas));
        bytes32 structHash = keccak256(
            bytes.concat(
                abi.encode(
                    e.getAttestTypeHash(), schema, data.recipient, data.expirationTime, data.revocable, data.refUID
                ),
                abi.encode(keccak256(data.data), data.value, e.getNonce(attester), deadline)
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", e.getDomainSeparator(), structHash));
    }

    function _submitDelegated(
        bytes32 schema,
        AttestationRequestData memory data,
        address attester,
        uint64 deadline,
        bytes memory sig
    ) internal override returns (bytes32) {
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly ("memory-safe") {
            r := mload(add(sig, 0x20))
            s := mload(add(sig, 0x40))
            v := byte(0, mload(add(sig, 0x60)))
        }
        vm.prank(relayer);
        return eas.attestByDelegation(
            DelegatedAttestationRequest({
                schema: schema,
                data: data,
                signature: Signature({ v: v, r: r, s: s }),
                attester: attester,
                deadline: deadline
            })
        );
    }
}
