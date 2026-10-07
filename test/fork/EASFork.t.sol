// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import { Test, console2 } from "forge-std/Test.sol";
import {
    IEAS,
    AttestationRequest,
    AttestationRequestData,
    RevocationRequest,
    RevocationRequestData,
    DelegatedAttestationRequest
} from "@ethereum-attestation-service/eas-contracts/contracts/IEAS.sol";
import {
    ISchemaRegistry,
    SchemaRecord
} from "@ethereum-attestation-service/eas-contracts/contracts/ISchemaRegistry.sol";
import {
    Attestation,
    Signature,
    EMPTY_UID,
    NO_EXPIRATION_TIME
} from "@ethereum-attestation-service/eas-contracts/contracts/Common.sol";
import { ISchemaResolver } from "@ethereum-attestation-service/eas-contracts/contracts/resolver/ISchemaResolver.sol";

import { OTTPRegistry } from "../../src/OTTPRegistry.sol";
import {
    OTTPResolver__ZeroId,
    OTTPResolver__IdNotRegistered,
    OTTPResolver__AttesterNotOwner,
    OTTPResolver__ZeroRegistry
} from "../../src/OTTPResolverErrors.sol";
import { OTTPSubjectResolver } from "../../src/OTTPSubjectResolver.sol";
import { OTTPObjectResolver } from "../../src/OTTPObjectResolver.sol";
import { OTTPSchemas } from "../../src/Schemas.sol";
import { RegistrySigUtils } from "../utils/RegistrySigUtils.sol";
import { ERC1271Wallet } from "../mocks/ERC1271Wallet.sol";
import { Deploy } from "../../script/Deploy.s.sol";

/// @dev EAS 1.0.1 (Base mainnet) delegated request: no `deadline` field.
struct DelegatedAttestationRequestV101 {
    bytes32 schema;
    AttestationRequestData data;
    Signature signature;
    address attester;
}

interface IEASv101 {
    function attestByDelegation(DelegatedAttestationRequestV101 calldata request) external payable returns (bytes32);
}

interface IEASIntrospect {
    function version() external view returns (string memory);
    function getDomainSeparator() external view returns (bytes32);
    function getAttestTypeHash() external view returns (bytes32);
    function getNonce(address account) external view returns (uint256);
}

/// @title EASForkBase
/// @notice Runs the whole primitive against the REAL EAS + SchemaRegistry predeploys on a fork.
///         Enabled with FORK_TESTS=true (network access). Chain-specific subclasses supply the RPC and the
///         delegated-attestation encoding, which differs between EAS 1.0.1 (Base mainnet) and 1.2.0 (Base Sepolia).
abstract contract EASForkBase is Test {
    IEAS internal eas = IEAS(OTTPSchemas.EAS);
    ISchemaRegistry internal schemaRegistry = ISchemaRegistry(OTTPSchemas.SCHEMA_REGISTRY);

    OTTPRegistry internal registry;
    OTTPSubjectResolver internal subjectResolver;
    OTTPObjectResolver internal objectResolver;
    bytes32 internal subjectSchema;
    bytes32 internal objectSchema;

    address internal alice;
    uint256 internal alicePk;
    address internal bob;
    uint256 internal bobPk;
    address internal mallory;
    uint256 internal malloryPk;
    address internal relayer = makeAddr("relayer");

    function _rpcEnvVar() internal pure virtual returns (string memory);
    function _defaultRpc() internal pure virtual returns (string memory);
    function _expectedChainId() internal pure virtual returns (uint256);
    function _expectedEasVersion() internal pure virtual returns (string memory);
    /// @dev EAS 1.0.1 verifies delegated signatures with ECDSA.recover (EOA only); 1.2.0+ uses SignatureChecker.
    function _easRelaysErc1271() internal pure virtual returns (bool);
    /// @dev If `expectedRevert` is non-zero, `vm.expectRevert(expectedRevert)` is armed immediately before the
    ///      real `attestByDelegation` call (after the view calls used to build the signature).
    function _attestByDelegation(
        bytes32 schema,
        AttestationRequestData memory data,
        uint256 signerPk,
        address signer,
        bytes4 expectedRevert
    ) internal virtual returns (bytes32);

    function setUp() public {
        if (!vm.envOr("FORK_TESTS", false)) {
            vm.skip(true);
            return;
        }
        vm.createSelectFork(vm.envOr(_rpcEnvVar(), _defaultRpc()));
        assertEq(block.chainid, _expectedChainId(), "wrong chain");
        assertGt(address(eas).code.length, 0, "EAS predeploy missing");
        assertGt(address(schemaRegistry).code.length, 0, "SchemaRegistry predeploy missing");
        assertEq(IEASIntrospect(address(eas)).version(), _expectedEasVersion(), "unexpected EAS version");

        (alice, alicePk) = makeAddrAndKey("alice");
        (bob, bobPk) = makeAddrAndKey("bob");
        (mallory, malloryPk) = makeAddrAndKey("mallory");
        vm.deal(alice, 1 ether);
        vm.deal(bob, 1 ether);
        vm.deal(mallory, 1 ether);
        vm.deal(relayer, 1 ether);

        // Deploy exactly as the deploy script does.
        registry = new OTTPRegistry();
        subjectResolver = new OTTPSubjectResolver(eas, registry);
        objectResolver = new OTTPObjectResolver(eas, registry);
        subjectSchema = schemaRegistry.register(
            OTTPSchemas.SUBJECT, ISchemaResolver(address(subjectResolver)), OTTPSchemas.REVOCABLE
        );
        objectSchema = schemaRegistry.register(
            OTTPSchemas.OBJECT, ISchemaResolver(address(objectResolver)), OTTPSchemas.REVOCABLE
        );

        vm.prank(alice);
        registry.register(); // 1
        vm.prank(bob);
        registry.register(); // 2
    }

    // ─── helpers ───────────────────────────────────────────────────────────────────────────────────────────

    function _data(bytes memory payload, bytes32 refUID) internal pure returns (AttestationRequestData memory) {
        return AttestationRequestData({
            recipient: address(0),
            expirationTime: NO_EXPIRATION_TIME,
            revocable: false,
            refUID: refUID,
            data: payload,
            value: 0
        });
    }

    function _subject(uint256 id) internal pure returns (bytes memory) {
        return abi.encode(id, "alice", '{"identityType":"user"}');
    }

    function _object(bytes32 originUid, uint256 creatorId) internal pure returns (bytes memory) {
        return abi.encode(originUid, creatorId, '{"type":"work","title":"fork test"}');
    }

    // ─── tests ─────────────────────────────────────────────────────────────────────────────────────────────

    function test_SchemasRegisteredNonRevocableWithResolvers() public view {
        SchemaRecord memory s = schemaRegistry.getSchema(subjectSchema);
        assertEq(address(s.resolver), address(subjectResolver));
        assertFalse(s.revocable);
        assertEq(s.schema, OTTPSchemas.SUBJECT);
        SchemaRecord memory o = schemaRegistry.getSchema(objectSchema);
        assertEq(address(o.resolver), address(objectResolver));
        assertFalse(o.revocable);
        assertEq(o.schema, OTTPSchemas.OBJECT);
        // UID derivation matches EAS: keccak256(abi.encodePacked(schema, resolver, revocable))
        assertEq(subjectSchema, keccak256(abi.encodePacked(OTTPSchemas.SUBJECT, address(subjectResolver), false)));
    }

    function test_SubjectAttest_OwnerSucceeds_ImpersonatorRevertsInsideRealEAS() public {
        vm.prank(alice);
        bytes32 uid = eas.attest(AttestationRequest({ schema: subjectSchema, data: _data(_subject(1), EMPTY_UID) }));
        Attestation memory a = eas.getAttestation(uid);
        assertEq(a.attester, alice);
        assertEq(a.schema, subjectSchema);
        assertFalse(a.revocable);
        console2.log("subject attestation uid:");
        console2.logBytes32(uid);

        // bob claims alice's id → reverts inside the real EAS via the resolver
        vm.prank(bob);
        vm.expectPartialRevert(OTTPResolver__AttesterNotOwner.selector);
        eas.attest(AttestationRequest({ schema: subjectSchema, data: _data(_subject(1), EMPTY_UID) }));

        // bob attests his own → fine
        vm.prank(bob);
        eas.attest(AttestationRequest({ schema: subjectSchema, data: _data(_subject(2), EMPTY_UID) }));

        // id 0 and unissued id
        vm.prank(alice);
        vm.expectRevert(OTTPResolver__ZeroId.selector);
        eas.attest(AttestationRequest({ schema: subjectSchema, data: _data(_subject(0), EMPTY_UID) }));
        vm.prank(alice);
        vm.expectPartialRevert(OTTPResolver__IdNotRegistered.selector);
        eas.attest(AttestationRequest({ schema: subjectSchema, data: _data(_subject(3), EMPTY_UID) }));
    }

    function test_ObjectAttest_WithRefUidToSubject() public {
        vm.prank(alice);
        bytes32 subj = eas.attest(AttestationRequest({ schema: subjectSchema, data: _data(_subject(1), EMPTY_UID) }));
        vm.prank(alice);
        bytes32 obj = eas.attest(AttestationRequest({ schema: objectSchema, data: _data(_object(EMPTY_UID, 1), subj) }));
        Attestation memory a = eas.getAttestation(obj);
        assertEq(a.refUID, subj);
        assertEq(a.attester, alice);
        assertEq(a.schema, objectSchema);

        // bob attaches to alice's object (allowed; authority is an indexer concern), but cannot claim her id
        vm.prank(bob);
        eas.attest(AttestationRequest({ schema: objectSchema, data: _data(_object(EMPTY_UID, 2), obj) }));
        vm.prank(bob);
        vm.expectPartialRevert(OTTPResolver__AttesterNotOwner.selector);
        eas.attest(AttestationRequest({ schema: objectSchema, data: _data(_object(EMPTY_UID, 1), obj) }));

        // dangling refUID rejected by EAS core
        vm.prank(alice);
        vm.expectRevert(); // NotFound()
        eas.attest(AttestationRequest({ schema: objectSchema, data: _data(_object(EMPTY_UID, 1), keccak256("nope")) }));
    }

    function test_RevokeRejectedByRealEAS() public {
        vm.prank(alice);
        bytes32 uid = eas.attest(AttestationRequest({ schema: subjectSchema, data: _data(_subject(1), EMPTY_UID) }));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSignature("Irrevocable()"));
        eas.revoke(RevocationRequest({ schema: subjectSchema, data: RevocationRequestData({ uid: uid, value: 0 }) }));
        assertEq(eas.getAttestation(uid).revocationTime, 0);

        // a revocable=true request on the non-revocable schema is rejected up-front
        AttestationRequestData memory d = _data(_subject(1), EMPTY_UID);
        d.revocable = true;
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSignature("Irrevocable()"));
        eas.attest(AttestationRequest({ schema: subjectSchema, data: d }));
    }

    function test_DelegatedAttest_SignerIsAttester() public {
        // relayer submits, alice signed → resolver sees alice as attester and accepts
        bytes32 uid = _attestByDelegation(subjectSchema, _data(_subject(1), EMPTY_UID), alicePk, alice, bytes4(0));
        Attestation memory a = eas.getAttestation(uid);
        assertEq(a.attester, alice, "attester must be the signer, not the relayer");
        assertTrue(a.attester != relayer);
        console2.log("delegated subject attestation uid:");
        console2.logBytes32(uid);

        // delegated Object with refUID to the delegated Subject
        bytes32 obj = _attestByDelegation(objectSchema, _data(_object(EMPTY_UID, 1), uid), alicePk, alice, bytes4(0));
        assertEq(eas.getAttestation(obj).refUID, uid);
    }

    function test_DelegatedAttest_UnregisteredSignerRejected() public {
        _attestByDelegation(
            subjectSchema, _data(_subject(1), EMPTY_UID), malloryPk, mallory, OTTPResolver__AttesterNotOwner.selector
        );
    }

    function test_DelegatedAttest_SignerClaimingOthersIdRejected() public {
        _attestByDelegation(
            objectSchema, _data(_object(EMPTY_UID, 1), EMPTY_UID), bobPk, bob, OTTPResolver__AttesterNotOwner.selector
        );
    }

    function test_DelegatedAttest_ForgedSignatureRejectedByEAS() public {
        // bob signs a request that names alice as attester → EAS's own signature check rejects before our resolver
        _attestByDelegation(
            subjectSchema, _data(_subject(1), EMPTY_UID), bobPk, alice, bytes4(keccak256("InvalidSignature()"))
        );
    }

    function test_SponsoredRegistrationThenDelegatedAttest_EndToEnd() public {
        // full gasless onboarding: registerFor (relayer pays) + attestByDelegation (relayer pays)
        (address newcomer, uint256 newcomerPk) = makeAddrAndKey("newcomer");
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig =
            RegistrySigUtils.sign(vm, newcomerPk, address(registry), block.chainid, newcomer, 0, deadline);
        vm.prank(relayer);
        uint256 id = registry.registerFor(newcomer, deadline, sig);
        assertEq(id, 3);
        assertEq(newcomer.balance, 0, "newcomer never needed ETH");

        bytes32 uid = _attestByDelegation(
            subjectSchema, _data(abi.encode(id, "newcomer", "{}"), EMPTY_UID), newcomerPk, newcomer, ""
        );
        assertEq(eas.getAttestation(uid).attester, newcomer);
    }

    /// @dev Safe-style smart-contract wallet: minimal ERC-1271 wallet whose isValidSignature accepts an ECDSA
    ///      signature from its single owner over the raw hash (Safe's 1-of-1 semantics for EIP-712 hashes without
    ///      the Safe message wrapper). Deploying a real Safe on the fork would need the Safe factory + singleton
    ///      bytecode and Safe's message-hash wrapping in the signer; the resolver/EAS behaviour under test does not
    ///      depend on either.
    function test_SafeStyleWallet_RegisterForThenDirectAttest() public {
        (address owner, uint256 ownerPk) = makeAddrAndKey("safe-owner");
        ERC1271Wallet safe = new ERC1271Wallet(owner);
        vm.deal(address(safe), 1 ether);
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig =
            RegistrySigUtils.sign(vm, ownerPk, address(registry), block.chainid, address(safe), 0, deadline);
        vm.prank(relayer);
        uint256 id = registry.registerFor(address(safe), deadline, sig);
        assertEq(id, 3);
        assertEq(registry.getWallet(3), address(safe));

        // Direct attestation FROM the contract wallet: accepted on every EAS version.
        vm.prank(address(safe));
        bytes32 uid = eas.attest(
            AttestationRequest({ schema: subjectSchema, data: _data(abi.encode(id, "safe", "{}"), EMPTY_UID) })
        );
        assertEq(eas.getAttestation(uid).attester, address(safe));
        vm.prank(address(safe));
        eas.attest(AttestationRequest({ schema: objectSchema, data: _data(_object(EMPTY_UID, id), uid) }));
    }

    /// @dev Relayed (attestByDelegation) attestation where the attester is a contract wallet and the signature is
    ///      the owner's ECDSA signature. EAS 1.0.1 (Base mainnet) recovers the owner, not the wallet → rejects.
    ///      EAS 1.2.0 (Base Sepolia) uses SignatureChecker → accepts via ERC-1271. Locks the divergence in.
    function test_SafeStyleWallet_RelayedAttest_DependsOnEasVersion() public {
        (address owner, uint256 ownerPk) = makeAddrAndKey("safe-owner");
        ERC1271Wallet safe = new ERC1271Wallet(owner);
        uint256 deadline = block.timestamp + 1 hours;
        vm.prank(relayer);
        uint256 id = registry.registerFor(
            address(safe),
            deadline,
            RegistrySigUtils.sign(vm, ownerPk, address(registry), block.chainid, address(safe), 0, deadline)
        );
        AttestationRequestData memory d = _data(abi.encode(id, "safe", "{}"), EMPTY_UID);
        if (_easRelaysErc1271()) {
            bytes32 uid = _attestByDelegation(subjectSchema, d, ownerPk, address(safe), bytes4(0));
            assertEq(eas.getAttestation(uid).attester, address(safe));
        } else {
            _attestByDelegation(subjectSchema, d, ownerPk, address(safe), bytes4(keccak256("InvalidSignature()")));
        }
    }

    /// @dev D5: the deploy script must register exactly keccak256(schemaString ‖ resolver ‖ false) for both
    ///      schemas, with the spec's byte-for-byte strings, against the REAL SchemaRegistry.
    function test_DeployScript_RegistersExactSchemaUids() public {
        vm.setEnv("ALLOW_MAINNET", "true"); // fork only; nothing is broadcast
        Deploy d = new Deploy();
        d.run();
        (address reg, address subj, address obj, bytes32 subjUid, bytes32 objUid) = d.last();
        assertEq(subjUid, keccak256(abi.encodePacked("uint256 ottpId, string name, string metadata", subj, false)));
        assertEq(
            objUid, keccak256(abi.encodePacked("bytes32 originUid, uint256 creatorId, string metadata", obj, false))
        );
        SchemaRecord memory sr = schemaRegistry.getSchema(subjUid);
        SchemaRecord memory orr = schemaRegistry.getSchema(objUid);
        assertEq(sr.schema, "uint256 ottpId, string name, string metadata");
        assertEq(orr.schema, "bytes32 originUid, uint256 creatorId, string metadata");
        assertEq(address(sr.resolver), subj);
        assertEq(address(orr.resolver), obj);
        assertFalse(sr.revocable);
        assertFalse(orr.revocable);
        assertEq(address(OTTPSubjectResolver(payable(subj)).registry()), reg);
        assertEq(address(OTTPObjectResolver(payable(obj)).registry()), reg);
    }

    function test_AfterTransfer_RealEAS() public {
        (address alice2,) = makeAddrAndKey("alice2");
        vm.prank(alice);
        registry.proposeTransfer(1, alice2);
        vm.prank(alice2);
        registry.acceptId(1);
        vm.prank(alice);
        vm.expectPartialRevert(OTTPResolver__AttesterNotOwner.selector);
        eas.attest(AttestationRequest({ schema: subjectSchema, data: _data(_subject(1), EMPTY_UID) }));
        vm.prank(alice2);
        eas.attest(AttestationRequest({ schema: subjectSchema, data: _data(_subject(1), EMPTY_UID) }));
    }

    function test_GasSnapshot_ThroughRealEAS() public {
        vm.prank(alice);
        uint256 g = gasleft();
        bytes32 subj = eas.attest(AttestationRequest({ schema: subjectSchema, data: _data(_subject(1), EMPTY_UID) }));
        console2.log("gas: Subject attest via real EAS", g - gasleft());
        vm.prank(alice);
        g = gasleft();
        eas.attest(AttestationRequest({ schema: objectSchema, data: _data(_object(EMPTY_UID, 1), subj) }));
        console2.log("gas: Object attest via real EAS", g - gasleft());
    }

    function test_GasSnapshot_BaselineNoResolver() public {
        // Identical payloads on resolver-less schemas, to isolate the resolver overhead.
        bytes32 bareSubject = schemaRegistry.register(OTTPSchemas.SUBJECT, ISchemaResolver(address(0)), false);
        bytes32 bareObject = schemaRegistry.register(OTTPSchemas.OBJECT, ISchemaResolver(address(0)), false);
        vm.prank(alice);
        uint256 g = gasleft();
        bytes32 bs = eas.attest(AttestationRequest({ schema: bareSubject, data: _data(_subject(1), EMPTY_UID) }));
        console2.log("gas: Subject attest, NO resolver (baseline)", g - gasleft());
        vm.prank(alice);
        g = gasleft();
        eas.attest(AttestationRequest({ schema: bareObject, data: _data(_object(EMPTY_UID, 1), bs) }));
        console2.log("gas: Object attest, NO resolver (baseline)", g - gasleft());
    }
}

/// @notice Base mainnet fork — EAS 1.0.1. Read-only against the chain; nothing is broadcast.
contract BaseMainnetForkTest is EASForkBase {
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

    /// @dev EAS 1.0.1 typed data:
    ///      Attest(bytes32 schema,address recipient,uint64 expirationTime,bool revocable,bytes32 refUID,bytes data,uint256 nonce)
    function _digestV101(bytes32 schema, AttestationRequestData memory data, address signer)
        internal
        view
        returns (bytes32)
    {
        IEASIntrospect e = IEASIntrospect(address(eas));
        bytes32 typeHash = e.getAttestTypeHash();
        assertEq(
            typeHash,
            keccak256(
                "Attest(bytes32 schema,address recipient,uint64 expirationTime,bool revocable,bytes32 refUID,bytes data,uint256 nonce)"
            )
        );
        bytes32 structHash = keccak256(
            abi.encode(
                typeHash,
                schema,
                data.recipient,
                data.expirationTime,
                data.revocable,
                data.refUID,
                keccak256(data.data),
                e.getNonce(signer)
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", e.getDomainSeparator(), structHash));
    }

    function _attestByDelegation(
        bytes32 schema,
        AttestationRequestData memory data,
        uint256 signerPk,
        address signer,
        bytes4 expectedRevert
    ) internal override returns (bytes32) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, _digestV101(schema, data, signer));
        if (expectedRevert != bytes4(0)) vm.expectPartialRevert(expectedRevert);
        vm.prank(relayer);
        return IEASv101(address(eas))
            .attestByDelegation(
                DelegatedAttestationRequestV101({
                schema: schema, data: data, signature: Signature({ v: v, r: r, s: s }), attester: signer
            })
            );
    }
}

/// @notice Base Sepolia fork — EAS 1.2.0.
contract BaseSepoliaForkTest is EASForkBase {
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

    /// @dev EAS 1.2.0 typed data:
    ///      Attest(bytes32 schema,address recipient,uint64 expirationTime,bool revocable,bytes32 refUID,bytes data,uint256 value,uint256 nonce,uint64 deadline)
    function _digestV120(bytes32 schema, AttestationRequestData memory data, address signer, uint64 deadline)
        internal
        view
        returns (bytes32)
    {
        IEASIntrospect e = IEASIntrospect(address(eas));
        bytes32 typeHash = e.getAttestTypeHash();
        assertEq(
            typeHash,
            keccak256(
                "Attest(bytes32 schema,address recipient,uint64 expirationTime,bool revocable,bytes32 refUID,bytes data,uint256 value,uint256 nonce,uint64 deadline)"
            )
        );
        bytes32 structHash = keccak256(
            bytes.concat(
                abi.encode(typeHash, schema, data.recipient, data.expirationTime, data.revocable, data.refUID),
                abi.encode(keccak256(data.data), data.value, e.getNonce(signer), deadline)
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", e.getDomainSeparator(), structHash));
    }

    function _attestByDelegation(
        bytes32 schema,
        AttestationRequestData memory data,
        uint256 signerPk,
        address signer,
        bytes4 expectedRevert
    ) internal override returns (bytes32) {
        uint64 deadline = uint64(block.timestamp + 1 hours);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, _digestV120(schema, data, signer, deadline));
        if (expectedRevert != bytes4(0)) vm.expectPartialRevert(expectedRevert);
        vm.prank(relayer);
        return eas.attestByDelegation(
            DelegatedAttestationRequest({
                schema: schema,
                data: data,
                signature: Signature({ v: v, r: r, s: s }),
                attester: signer,
                deadline: deadline
            })
        );
    }
}
