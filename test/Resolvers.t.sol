// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import { Test } from "forge-std/Test.sol";
import { IEAS, AttestationRequestData } from "@ethereum-attestation-service/eas-contracts/contracts/IEAS.sol";
import {
    Attestation,
    AccessDenied,
    InvalidEAS,
    EMPTY_UID,
    NO_EXPIRATION_TIME
} from "@ethereum-attestation-service/eas-contracts/contracts/Common.sol";
import { ISchemaResolver } from "@ethereum-attestation-service/eas-contracts/contracts/resolver/ISchemaResolver.sol";
import { SchemaResolver } from "@ethereum-attestation-service/eas-contracts/contracts/resolver/SchemaResolver.sol";

import { OTTPRegistry } from "../src/OTTPRegistry.sol";
import {
    OTTPResolver__ZeroId,
    OTTPResolver__IdNotRegistered,
    OTTPResolver__AttesterNotOwner,
    OTTPResolver__ZeroRegistry
} from "../src/OTTPResolverErrors.sol";
import { IOTTPRegistry } from "../src/IOTTPRegistry.sol";
import { OTTPSubjectResolver } from "../src/OTTPSubjectResolver.sol";
import { OTTPObjectResolver } from "../src/OTTPObjectResolver.sol";
import { OTTPSchemas } from "../src/Schemas.sol";
import { MockEAS } from "./mocks/MockEAS.sol";

contract ResolversTest is Test {
    OTTPRegistry internal registry;
    MockEAS internal eas;
    OTTPSubjectResolver internal subjectResolver;
    OTTPObjectResolver internal objectResolver;
    bytes32 internal subjectSchema;
    bytes32 internal objectSchema;

    address internal alice = makeAddr("alice"); // id 1
    address internal bob = makeAddr("bob"); // id 2
    address internal mallory = makeAddr("mallory"); // unregistered
    address internal relayer = makeAddr("relayer");

    function setUp() public {
        registry = new OTTPRegistry();
        eas = new MockEAS();
        subjectResolver = new OTTPSubjectResolver(IEAS(address(eas)), registry);
        objectResolver = new OTTPObjectResolver(IEAS(address(eas)), registry);
        subjectSchema =
            eas.registerSchema(OTTPSchemas.SUBJECT, ISchemaResolver(address(subjectResolver)), OTTPSchemas.REVOCABLE);
        objectSchema =
            eas.registerSchema(OTTPSchemas.OBJECT, ISchemaResolver(address(objectResolver)), OTTPSchemas.REVOCABLE);

        vm.prank(alice);
        registry.register();
        vm.prank(bob);
        registry.register();
    }

    // ─── helpers ───────────────────────────────────────────────────────────────────────────────────────────

    function _subjectData(uint256 ottpId) internal pure returns (bytes memory) {
        return abi.encode(ottpId, "name", '{"identityType":"user"}');
    }

    function _objectData(bytes32 originUid, uint256 creatorId) internal pure returns (bytes memory) {
        return abi.encode(originUid, creatorId, '{"type":"work"}');
    }

    function _req(bytes memory data, bytes32 refUID) internal pure returns (AttestationRequestData memory) {
        return AttestationRequestData({
            recipient: address(0),
            expirationTime: NO_EXPIRATION_TIME,
            revocable: false,
            refUID: refUID,
            data: data,
            value: 0
        });
    }

    function _attestSubject(address attester, uint256 ottpId) internal returns (bytes32) {
        vm.prank(attester);
        return eas.attest(subjectSchema, _req(_subjectData(ottpId), EMPTY_UID));
    }

    function _attestObject(address attester, uint256 creatorId, bytes32 refUID, bytes32 originUid)
        internal
        returns (bytes32)
    {
        vm.prank(attester);
        return eas.attest(objectSchema, _req(_objectData(originUid, creatorId), refUID));
    }

    // ─── construction ──────────────────────────────────────────────────────────────────────────────────────

    function test_Constructor_State() public view {
        assertEq(address(subjectResolver.registry()), address(registry));
        assertEq(address(objectResolver.registry()), address(registry));
        assertEq(subjectResolver.version(), "1.4.0"); // EAS SchemaResolver base version
        assertFalse(subjectResolver.isPayable());
        assertFalse(objectResolver.isPayable());
    }

    function test_Constructor_ZeroRegistryReverts() public {
        vm.expectRevert(OTTPResolver__ZeroRegistry.selector);
        new OTTPSubjectResolver(IEAS(address(eas)), IOTTPRegistry(address(0)));
        vm.expectRevert(OTTPResolver__ZeroRegistry.selector);
        new OTTPObjectResolver(IEAS(address(eas)), IOTTPRegistry(address(0)));
    }

    function test_Constructor_ZeroEasReverts() public {
        vm.expectRevert(InvalidEAS.selector);
        new OTTPSubjectResolver(IEAS(address(0)), registry);
        vm.expectRevert(InvalidEAS.selector);
        new OTTPObjectResolver(IEAS(address(0)), registry);
    }

    function test_SchemaUidsAreDeterministic() public view {
        assertEq(subjectSchema, keccak256(abi.encodePacked(OTTPSchemas.SUBJECT, address(subjectResolver), false)));
        assertEq(objectSchema, keccak256(abi.encodePacked(OTTPSchemas.OBJECT, address(objectResolver), false)));
    }

    // ─── Subject: accept / reject ──────────────────────────────────────────────────────────────────────────

    function test_Subject_OwnerAccepted() public {
        bytes32 uid = _attestSubject(alice, 1);
        assertTrue(eas.isAttestationValid(uid));
        Attestation memory a = eas.getAttestation(uid);
        assertEq(a.attester, alice);
        assertEq(a.schema, subjectSchema);
        assertFalse(a.revocable);
    }

    function test_Subject_NonOwnerRejected() public {
        vm.prank(bob);
        vm.expectPartialRevert(OTTPResolver__AttesterNotOwner.selector);
        eas.attest(subjectSchema, _req(_subjectData(1), EMPTY_UID));
    }

    function test_Subject_UnregisteredWalletRejected() public {
        vm.prank(mallory);
        vm.expectPartialRevert(OTTPResolver__AttesterNotOwner.selector);
        eas.attest(subjectSchema, _req(_subjectData(1), EMPTY_UID));
    }

    function test_Subject_IdZeroRejected() public {
        vm.prank(alice);
        vm.expectRevert(OTTPResolver__ZeroId.selector);
        eas.attest(subjectSchema, _req(_subjectData(0), EMPTY_UID));
        // …even from an unregistered wallet, and the zero check fires first
        vm.prank(mallory);
        vm.expectRevert(OTTPResolver__ZeroId.selector);
        eas.attest(subjectSchema, _req(_subjectData(0), EMPTY_UID));
    }

    function test_Subject_UnissuedIdRejected() public {
        uint256 next = registry.totalRegistered() + 1;
        vm.prank(alice);
        vm.expectPartialRevert(OTTPResolver__IdNotRegistered.selector);
        eas.attest(subjectSchema, _req(_subjectData(next), EMPTY_UID));
        vm.prank(alice);
        vm.expectPartialRevert(OTTPResolver__IdNotRegistered.selector);
        eas.attest(subjectSchema, _req(_subjectData(type(uint256).max), EMPTY_UID));
    }

    function test_Subject_MalformedDataRejected() public {
        vm.startPrank(alice);
        vm.expectRevert(); // abi.decode reverts on short data
        eas.attest(subjectSchema, _req(hex"", EMPTY_UID));
        vm.expectRevert();
        eas.attest(subjectSchema, _req(abi.encode(uint256(1)), EMPTY_UID));
        vm.expectRevert();
        eas.attest(subjectSchema, _req(abi.encode(uint256(1), "name"), EMPTY_UID));
        // v2.0-draft string-typed layout must not decode as a valid v2.1 Subject
        vm.expectRevert();
        eas.attest(subjectSchema, _req(abi.encode("1", "name", "{}"), EMPTY_UID));
        vm.stopPrank();
    }

    function test_Subject_MetadataNeverInterpreted() public {
        // Arbitrary / hostile metadata and name are accepted verbatim — the resolver checks authenticity only.
        vm.prank(alice);
        eas.attest(subjectSchema, _req(abi.encode(uint256(1), "", ""), EMPTY_UID));
        vm.prank(alice);
        eas.attest(subjectSchema, _req(abi.encode(uint256(1), "x", "not json at all }{"), EMPTY_UID));
        vm.prank(alice);
        eas.attest(subjectSchema, _req(abi.encode(uint256(1), "x", '{"ottpId":"2","creatorId":2}'), EMPTY_UID));
    }

    function test_Subject_ExtraTrailingDataAccepted() public {
        // abi.decode ignores trailing bytes; documenting the behaviour (harmless: ID is still validated).
        vm.prank(alice);
        eas.attest(subjectSchema, _req(bytes.concat(_subjectData(1), hex"deadbeef"), EMPTY_UID));
    }

    function test_Subject_RecipientAndRefUidIgnoredByResolver() public {
        bytes32 first = _attestSubject(alice, 1);
        vm.prank(alice);
        AttestationRequestData memory r = _req(_subjectData(1), first);
        r.recipient = bob;
        eas.attest(subjectSchema, r); // update-style Subject referencing the previous one
    }

    function test_Subject_MultipleAttestationsSameId() public {
        _attestSubject(alice, 1);
        _attestSubject(alice, 1);
        _attestSubject(alice, 1); // profile updates are just newer attestations (indexer S-2)
    }

    // ─── Object: accept / reject ───────────────────────────────────────────────────────────────────────────

    function test_Object_OwnerAccepted() public {
        bytes32 subj = _attestSubject(alice, 1);
        bytes32 uid = _attestObject(alice, 1, subj, EMPTY_UID);
        assertTrue(eas.isAttestationValid(uid));
        assertEq(eas.getAttestation(uid).refUID, subj);
    }

    function test_Object_NonOwnerRejected() public {
        vm.prank(bob);
        vm.expectPartialRevert(OTTPResolver__AttesterNotOwner.selector);
        eas.attest(objectSchema, _req(_objectData(EMPTY_UID, 1), EMPTY_UID));
    }

    function test_Object_UnregisteredWalletRejected() public {
        vm.prank(mallory);
        vm.expectPartialRevert(OTTPResolver__AttesterNotOwner.selector);
        eas.attest(objectSchema, _req(_objectData(EMPTY_UID, 2), EMPTY_UID));
    }

    function test_Object_CreatorIdZeroRejected() public {
        vm.prank(alice);
        vm.expectRevert(OTTPResolver__ZeroId.selector);
        eas.attest(objectSchema, _req(_objectData(EMPTY_UID, 0), EMPTY_UID));
    }

    function test_Object_UnissuedIdRejected() public {
        vm.prank(alice);
        vm.expectPartialRevert(OTTPResolver__IdNotRegistered.selector);
        eas.attest(objectSchema, _req(_objectData(EMPTY_UID, 3), EMPTY_UID));
    }

    function test_Object_MalformedDataRejected() public {
        vm.startPrank(alice);
        vm.expectRevert();
        eas.attest(objectSchema, _req(hex"", EMPTY_UID));
        vm.expectRevert();
        eas.attest(objectSchema, _req(abi.encode(bytes32(0), uint256(1)), EMPTY_UID));
        // a Subject-shaped payload on the Object schema decodes creatorId from the wrong slot → not owned
        vm.expectRevert();
        eas.attest(objectSchema, _req(_subjectData(1), EMPTY_UID));
        vm.stopPrank();
    }

    function test_Object_OriginUidNotValidatedByResolver() public {
        // Spec is silent on originUid; the resolver validates nothing about it (open question for Nate).
        bytes32 subj = _attestSubject(alice, 1);
        _attestObject(alice, 1, EMPTY_UID, EMPTY_UID); // origin
        _attestObject(alice, 1, subj, subj); // originUid == refUID
        _attestObject(alice, 1, subj, keccak256("nonexistent")); // originUid points nowhere
        _attestObject(alice, 1, EMPTY_UID, subj); // originUid without refUID
    }

    function test_Object_RefUidMustExist() public {
        // EAS core enforces refUID existence (indexer rule G-1 relies on it); the resolver does not.
        vm.prank(alice);
        vm.expectRevert(); // NotFound() in the mock, as in EAS
        eas.attest(objectSchema, _req(_objectData(EMPTY_UID, 1), keccak256("nope")));
    }

    function test_Object_CrossOwnerLinkingAllowed() public {
        // bob (id 2) may attach an Object to alice's Object — authority is derived offchain (indexer V-1).
        bytes32 aliceObj = _attestObject(alice, 1, EMPTY_UID, EMPTY_UID);
        bytes32 bobObj = _attestObject(bob, 2, aliceObj, EMPTY_UID);
        assertEq(eas.getAttestation(bobObj).refUID, aliceObj);
        // …but bob cannot claim alice's creatorId while doing so
        vm.prank(bob);
        vm.expectPartialRevert(OTTPResolver__AttesterNotOwner.selector);
        eas.attest(objectSchema, _req(_objectData(EMPTY_UID, 1), aliceObj));
    }

    // ─── transferId interaction ────────────────────────────────────────────────────────────────────────────

    function test_AfterTransfer_OldWalletRejectedNewWalletAccepted() public {
        address alice2 = makeAddr("alice2");
        _attestSubject(alice, 1);
        vm.prank(alice);
        registry.proposeTransfer(1, alice2);
        vm.prank(alice2);
        registry.acceptId(1);

        vm.prank(alice);
        vm.expectPartialRevert(OTTPResolver__AttesterNotOwner.selector);
        eas.attest(subjectSchema, _req(_subjectData(1), EMPTY_UID));
        vm.prank(alice);
        vm.expectPartialRevert(OTTPResolver__AttesterNotOwner.selector);
        eas.attest(objectSchema, _req(_objectData(EMPTY_UID, 1), EMPTY_UID));

        _attestSubject(alice2, 1);
        _attestObject(alice2, 1, EMPTY_UID, EMPTY_UID);
    }

    function test_AfterTransfer_OldWalletReRegistersAndOnlyOwnsNewId() public {
        address alice2 = makeAddr("alice2");
        vm.prank(alice);
        registry.proposeTransfer(1, alice2);
        vm.prank(alice2);
        registry.acceptId(1);
        vm.prank(alice);
        uint256 newId = registry.register(); // 3
        assertEq(newId, 3);
        _attestSubject(alice, 3);
        vm.prank(alice);
        vm.expectPartialRevert(OTTPResolver__AttesterNotOwner.selector);
        eas.attest(subjectSchema, _req(_subjectData(1), EMPTY_UID));
    }

    // ─── delegated attestations ────────────────────────────────────────────────────────────────────────────

    function test_Delegated_SignerIsAttester_Accepted() public {
        vm.prank(relayer);
        bytes32 uid = eas.attestByDelegation(subjectSchema, _req(_subjectData(1), EMPTY_UID), alice);
        assertEq(eas.getAttestation(uid).attester, alice);
        vm.prank(relayer);
        eas.attestByDelegation(objectSchema, _req(_objectData(EMPTY_UID, 1), uid), alice);
    }

    function test_Delegated_RelayerOwnsIdButSignerDoesNot_Rejected() public {
        // msg.sender (relayer) owning the ID must not help: the resolver checks attester (signer) only.
        vm.prank(bob); // bob owns id 2, relays for mallory
        vm.expectPartialRevert(OTTPResolver__AttesterNotOwner.selector);
        eas.attestByDelegation(subjectSchema, _req(_subjectData(2), EMPTY_UID), mallory);
    }

    function test_Delegated_UnregisteredSignerRejected() public {
        vm.prank(relayer);
        vm.expectPartialRevert(OTTPResolver__AttesterNotOwner.selector);
        eas.attestByDelegation(objectSchema, _req(_objectData(EMPTY_UID, 1), EMPTY_UID), mallory);
    }

    // ─── revocation ────────────────────────────────────────────────────────────────────────────────────────

    function test_Revoke_RejectedByCoreBeforeResolver() public {
        bytes32 uid = _attestSubject(alice, 1);
        vm.prank(alice);
        vm.expectRevert(MockEAS.Irrevocable.selector);
        eas.revoke(subjectSchema, uid);
        bytes32 ouid = _attestObject(alice, 1, EMPTY_UID, EMPTY_UID);
        vm.prank(alice);
        vm.expectRevert(MockEAS.Irrevocable.selector);
        eas.revoke(objectSchema, ouid);
    }

    function test_Revoke_ResolverDeniesEvenIfCoreBypassed() public {
        bytes32 uid = _attestSubject(alice, 1);
        vm.expectRevert(MockEAS.InvalidRevocation.selector);
        eas.revokeBypassingCoreCheck(uid);
        bytes32 ouid = _attestObject(alice, 1, EMPTY_UID, EMPTY_UID);
        vm.expectRevert(MockEAS.InvalidRevocation.selector);
        eas.revokeBypassingCoreCheck(ouid);
    }

    function test_OnRevoke_ReturnsFalseForAnyInput() public {
        Attestation memory a = eas.getAttestation(_attestSubject(alice, 1));
        vm.prank(address(eas));
        assertFalse(subjectResolver.revoke(a));
        vm.prank(address(eas));
        assertFalse(objectResolver.revoke(a));
        Attestation[] memory arr = new Attestation[](1);
        arr[0] = a;
        uint256[] memory vals = new uint256[](1);
        vm.prank(address(eas));
        assertFalse(subjectResolver.multiRevoke(arr, vals));
        vm.prank(address(eas));
        assertFalse(objectResolver.multiRevoke(arr, vals));
    }

    function test_RevocableRequestOnNonRevocableSchemaRejected() public {
        AttestationRequestData memory r = _req(_subjectData(1), EMPTY_UID);
        r.revocable = true;
        vm.prank(alice);
        vm.expectRevert(MockEAS.Irrevocable.selector);
        eas.attest(subjectSchema, r);
    }

    // ─── access control & payability ───────────────────────────────────────────────────────────────────────

    function test_OnlyEasMayCallResolver() public {
        Attestation memory a;
        a.attester = alice;
        a.data = _subjectData(1);
        vm.prank(alice);
        vm.expectRevert(AccessDenied.selector);
        subjectResolver.attest(a);
        vm.prank(alice);
        vm.expectRevert(AccessDenied.selector);
        subjectResolver.revoke(a);
        vm.prank(alice);
        vm.expectRevert(AccessDenied.selector);
        objectResolver.attest(a);
        Attestation[] memory arr = new Attestation[](1);
        arr[0] = a;
        uint256[] memory vals = new uint256[](1);
        vm.prank(alice);
        vm.expectRevert(AccessDenied.selector);
        subjectResolver.multiAttest(arr, vals);
        vm.prank(alice);
        vm.expectRevert(AccessDenied.selector);
        objectResolver.multiRevoke(arr, vals);
    }

    function test_ResolversRejectEther() public {
        vm.deal(alice, 1 ether);
        vm.prank(alice);
        (bool ok,) = address(subjectResolver).call{ value: 1 }("");
        assertFalse(ok);
        vm.prank(alice);
        (ok,) = address(objectResolver).call{ value: 1 }("");
        assertFalse(ok);
        assertEq(address(subjectResolver).balance, 0);
        assertEq(address(objectResolver).balance, 0);
    }

    function test_AttestWithValueRejected() public {
        vm.deal(alice, 1 ether);
        AttestationRequestData memory r = _req(_subjectData(1), EMPTY_UID);
        r.value = 1;
        vm.prank(alice);
        vm.expectRevert(MockEAS.NotPayable.selector);
        eas.attest{ value: 1 }(subjectSchema, r);
    }

    function test_MultiAttestPathValidatesEach() public {
        Attestation[] memory arr = new Attestation[](2);
        arr[0].attester = alice;
        arr[0].data = _subjectData(1);
        arr[1].attester = bob;
        arr[1].data = _subjectData(1); // bob claims alice's id
        uint256[] memory vals = new uint256[](2);
        vm.prank(address(eas));
        vm.expectPartialRevert(OTTPResolver__AttesterNotOwner.selector);
        subjectResolver.multiAttest(arr, vals);
        arr[1].data = _subjectData(2);
        vm.prank(address(eas));
        assertTrue(subjectResolver.multiAttest(arr, vals));
    }

    // ─── full accept/reject matrix ─────────────────────────────────────────────────────────────────────────

    /// @dev {owns, doesn't own, id 0, unissued} × {direct, delegated} × {Subject, Object}
    function test_Matrix() public {
        uint256[4] memory ids = [uint256(1), 2, 0, 99];
        bytes4 expectedErr;
        for (uint256 s = 0; s < 2; s++) {
            bool isSubject = s == 0;
            for (uint256 i = 0; i < 4; i++) {
                for (uint256 d = 0; d < 2; d++) {
                    bool delegated = d == 1;
                    uint256 id = ids[i];
                    bool shouldPass = i == 0; // alice attests; only id 1 is hers
                    if (i == 1) expectedErr = OTTPResolver__AttesterNotOwner.selector;
                    if (i == 3) expectedErr = OTTPResolver__IdNotRegistered.selector;
                    if (i == 2) {
                        expectedErr = OTTPResolver__ZeroId.selector;
                    }

                    bytes memory data = isSubject ? _subjectData(id) : _objectData(EMPTY_UID, id);
                    bytes32 schema = isSubject ? subjectSchema : objectSchema;
                    AttestationRequestData memory r = _req(data, EMPTY_UID);

                    if (!shouldPass) vm.expectPartialRevert(expectedErr);
                    if (delegated) {
                        vm.prank(relayer);
                        eas.attestByDelegation(schema, r, alice);
                    } else {
                        vm.prank(alice);
                        eas.attest(schema, r);
                    }
                }
            }
        }
    }

    // ─── fuzz ──────────────────────────────────────────────────────────────────────────────────────────────

    function testFuzz_Subject_AcceptIffAttesterOwnsId(address attester, uint256 id) public {
        bool owns = id != 0 && attester != address(0) && registry.getWallet(id) == attester;
        AttestationRequestData memory r = _req(_subjectData(id), EMPTY_UID);
        if (!owns) vm.expectRevert();
        vm.prank(attester);
        eas.attest(subjectSchema, r);
    }

    function testFuzz_Object_AcceptIffAttesterOwnsId(address attester, uint256 id, bytes32 originUid) public {
        bool owns = id != 0 && attester != address(0) && registry.getWallet(id) == attester;
        AttestationRequestData memory r = _req(_objectData(originUid, id), EMPTY_UID);
        if (!owns) vm.expectRevert();
        vm.prank(attester);
        eas.attest(objectSchema, r);
    }

    function testFuzz_Delegated_AcceptIffSignerOwnsId(address signer, address relayer_, uint256 id) public {
        bool owns = id != 0 && signer != address(0) && registry.getWallet(id) == signer;
        AttestationRequestData memory r = _req(_subjectData(id), EMPTY_UID);
        if (!owns) vm.expectRevert();
        vm.prank(relayer_);
        eas.attestByDelegation(subjectSchema, r, signer);
    }

    function testFuzz_MetadataContentNeverAffectsOutcome(string memory name, string memory metadata) public {
        vm.prank(alice);
        eas.attest(subjectSchema, _req(abi.encode(uint256(1), name, metadata), EMPTY_UID));
        vm.prank(alice);
        eas.attest(objectSchema, _req(abi.encode(bytes32(0), uint256(1), metadata), EMPTY_UID));
    }
}
