// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

// AUDIT ROUND 2 (2026-09-20) — resolvers: abi.decode edge cases, D1/D4 exactness, error propagation through an
// EAS-shaped core, multiAttest, revoke, access control.
//   forge test --match-path 'test/audit2/*'

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

import { IOTTPRegistry } from "../../src/IOTTPRegistry.sol";
import { OTTPRegistry } from "../../src/OTTPRegistry.sol";
import { OTTPSubjectResolver } from "../../src/OTTPSubjectResolver.sol";
import { OTTPObjectResolver } from "../../src/OTTPObjectResolver.sol";
import {
    OTTPResolver__ZeroId,
    OTTPResolver__IdNotRegistered,
    OTTPResolver__AttesterNotOwner,
    OTTPResolver__ZeroRegistry
} from "../../src/OTTPResolverErrors.sol";
import { OTTPSchemas } from "../../src/Schemas.sol";
import { MockEAS } from "../mocks/MockEAS.sol";

contract Audit2ResolversTest is Test {
    OTTPRegistry internal registry;
    MockEAS internal eas;
    OTTPSubjectResolver internal subjectResolver;
    OTTPObjectResolver internal objectResolver;
    bytes32 internal subjectSchema;
    bytes32 internal objectSchema;

    address internal alice = makeAddr("alice"); // id 1
    address internal bob = makeAddr("bob"); // id 2
    address internal mallory = makeAddr("mallory"); // no id

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

    function _req(bytes memory data) internal pure returns (AttestationRequestData memory) {
        return AttestationRequestData({
            recipient: address(0),
            expirationTime: NO_EXPIRATION_TIME,
            revocable: false,
            refUID: EMPTY_UID,
            data: data,
            value: 0
        });
    }

    function _att(address attester, bytes memory data) internal pure returns (Attestation memory a) {
        a.attester = attester;
        a.data = data;
        a.time = 1;
    }

    // ───────────────────────────── D4 exactness (resolvers) ─────────────────────────────

    function test_D4_ExactResolverErrors() public {
        // ZeroId()
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(OTTPResolver__ZeroId.selector));
        eas.attest(subjectSchema, _req(abi.encode(uint256(0), "n", "{}")));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(OTTPResolver__ZeroId.selector));
        eas.attest(objectSchema, _req(abi.encode(bytes32(0), uint256(0), "{}")));

        // IdNotRegistered(id): nextId (just unissued) and max
        uint256 unissued = registry.nextId();
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(OTTPResolver__IdNotRegistered.selector, unissued));
        eas.attest(subjectSchema, _req(abi.encode(unissued, "n", "{}")));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(OTTPResolver__IdNotRegistered.selector, type(uint256).max));
        eas.attest(objectSchema, _req(abi.encode(bytes32(0), type(uint256).max, "{}")));

        // AttesterNotOwner(id, attester, owner)
        vm.prank(mallory);
        vm.expectRevert(abi.encodeWithSelector(OTTPResolver__AttesterNotOwner.selector, 1, mallory, alice));
        eas.attest(subjectSchema, _req(abi.encode(uint256(1), "n", "{}")));
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(OTTPResolver__AttesterNotOwner.selector, 1, bob, alice));
        eas.attest(objectSchema, _req(abi.encode(bytes32(0), uint256(1), "{}")));

        // constructor guards
        vm.expectRevert(abi.encodeWithSelector(OTTPResolver__ZeroRegistry.selector));
        new OTTPSubjectResolver(IEAS(address(eas)), IOTTPRegistry(address(0)));
        vm.expectRevert(abi.encodeWithSelector(OTTPResolver__ZeroRegistry.selector));
        new OTTPObjectResolver(IEAS(address(eas)), IOTTPRegistry(address(0)));
        vm.expectRevert(abi.encodeWithSelector(InvalidEAS.selector));
        new OTTPSubjectResolver(IEAS(address(0)), registry);
    }

    /// The deployed runtime bytecode of both resolvers contains no `Error(string)` selector.
    function test_D4_NoStringRevertSelector() public view {
        bytes4 sel = bytes4(keccak256("Error(string)"));
        assertFalse(_has(address(subjectResolver).code, sel));
        assertFalse(_has(address(objectResolver).code, sel));
    }

    function _has(bytes memory code, bytes4 sel) internal pure returns (bool) {
        for (uint256 i = 0; i + 4 <= code.length; ++i) {
            if (code[i] == sel[0] && code[i + 1] == sel[1] && code[i + 2] == sel[2] && code[i + 3] == sel[3]) {
                return true;
            }
        }
        return false;
    }

    // ───────────────────────────── D1: order of checks, zero attester ─────────────────────────────

    /// For an UNISSUED id the resolver rejects BEFORE comparing attester, so attester == address(0) is never
    /// accepted (independent of whether EAS could ever produce a zero attester).
    function testFuzz_D1_UnissuedIdRejectedForAnyAttester(address attester, uint256 id) public {
        vm.assume(id > 2); // 1, 2 issued
        vm.prank(address(eas));
        vm.expectRevert(abi.encodeWithSelector(OTTPResolver__IdNotRegistered.selector, id));
        subjectResolver.attest(_att(attester, abi.encode(id, "", "")));
        vm.prank(address(eas));
        vm.expectRevert(abi.encodeWithSelector(OTTPResolver__IdNotRegistered.selector, id));
        objectResolver.attest(_att(attester, abi.encode(bytes32(0), id, "")));
    }

    /// For an ISSUED id, exactly one attester is accepted — the current wallet — for every payload tail.
    function testFuzz_D1_IssuedIdAcceptsOnlyOwner(address attester, string memory a, string memory b) public {
        vm.prank(address(eas));
        if (attester == alice) {
            assertTrue(subjectResolver.attest(_att(attester, abi.encode(uint256(1), a, b))));
        } else {
            vm.expectRevert(abi.encodeWithSelector(OTTPResolver__AttesterNotOwner.selector, 1, attester, alice));
            subjectResolver.attest(_att(attester, abi.encode(uint256(1), a, b)));
        }
        vm.prank(address(eas));
        if (attester == bob) {
            assertTrue(objectResolver.attest(_att(attester, abi.encode(bytes32(uint256(7)), uint256(2), a))));
        } else {
            vm.expectRevert(abi.encodeWithSelector(OTTPResolver__AttesterNotOwner.selector, 2, attester, bob));
            objectResolver.attest(_att(attester, abi.encode(bytes32(uint256(7)), uint256(2), a)));
        }
    }

    // ───────────────────────────── abi.decode edge cases ─────────────────────────────

    /// Decision depends ONLY on (attester, head word) — never on tails. Fuzz the whole tail region.
    function testFuzz_Decode_DecisionDependsOnlyOnHeadWord(uint256 w0, bytes32 w1, bytes32 w2, bytes memory tail)
        public
    {
        bytes memory data = bytes.concat(bytes32(w0), w1, w2, tail);
        // Subject: id = w0
        vm.prank(address(eas));
        (bool ok, bytes memory ret) =
            address(subjectResolver).call(abi.encodeWithSelector(ISchemaResolver.attest.selector, _att(alice, data)));
        // NOTE: abi.decode failures surface either as an EMPTY revert or as Panic(0x41) (allocation of an absurd
        //       string length). Both are rejections; SDKs must treat ANY revert as "not accepted".
        bytes4 PANIC = 0x4e487b71;
        if (ok) {
            assertEq(w0, 1, "accepted => head word is alice's id");
        } else if (ret.length >= 4) {
            // forge-lint: disable-next-line(unsafe-typecast)
            bytes4 sel = bytes4(ret);
            if (sel == OTTPResolver__ZeroId.selector) assertEq(w0, 0);
            else if (sel == OTTPResolver__IdNotRegistered.selector) assertTrue(w0 > 2);
            else if (sel == OTTPResolver__AttesterNotOwner.selector) assertEq(w0, 2);
            else if (sel == PANIC) assertEq(abi.decode(_slice(ret), (uint256)), 0x41);
            else fail("unexpected selector");
        } // else: abi.decode failure (empty revert) — never an acceptance
        // Object: id = w1
        vm.prank(address(eas));
        (ok, ret) =
            address(objectResolver).call(abi.encodeWithSelector(ISchemaResolver.attest.selector, _att(bob, data)));
        if (ok) {
            assertEq(uint256(w1), 2, "accepted => word 1 is bob's id");
        } else if (ret.length >= 4) {
            // forge-lint: disable-next-line(unsafe-typecast)
            bytes4 sel = bytes4(ret);
            if (sel == OTTPResolver__ZeroId.selector) assertEq(uint256(w1), 0);
            else if (sel == OTTPResolver__IdNotRegistered.selector) assertTrue(uint256(w1) > 2);
            else if (sel == OTTPResolver__AttesterNotOwner.selector) assertEq(uint256(w1), 1);
            else if (sel == PANIC) assertEq(abi.decode(_slice(ret), (uint256)), 0x41);
            else fail("unexpected selector");
        }
    }

    function _slice(bytes memory ret) internal pure returns (bytes memory out) {
        out = new bytes(ret.length - 4);
        for (uint256 i = 0; i < out.length; ++i) {
            out[i] = ret[i + 4];
        }
    }

    /// Short payloads (< 3 head words) can never be accepted, whatever the bytes.
    function testFuzz_Decode_ShortPayloadNeverAccepted(bytes memory data) public {
        vm.assume(data.length < 96);
        vm.prank(address(eas));
        (bool ok,) =
            address(subjectResolver).call(abi.encodeWithSelector(ISchemaResolver.attest.selector, _att(alice, data)));
        assertFalse(ok);
        vm.prank(address(eas));
        (ok,) = address(objectResolver).call(abi.encodeWithSelector(ISchemaResolver.attest.selector, _att(bob, data)));
        assertFalse(ok);
    }

    /// Non-canonical encodings the Solidity decoder ACCEPTS: aliased string tails, offsets into the head,
    /// unaligned offsets, trailing bytes. All are accepted for the owner and rejected for anyone else —
    /// i.e. the ownership check is unaffected by encoding tricks. Offchain decoders must read the head word.
    function test_Decode_NonCanonicalStillOwnershipChecked() public {
        bytes[] memory payloads = new bytes[](4);
        payloads[0] = bytes.concat(
            // forge-lint: disable-next-line(unsafe-typecast)
            bytes32(uint256(1)),
            bytes32(uint256(0x60)),
            bytes32(uint256(0x60)),
            bytes32(uint256(2)),
            // forge-lint: disable-next-line(unsafe-typecast)
            bytes32("hi")
        );
        payloads[1] = bytes.concat(
            bytes32(uint256(1)),
            bytes32(uint256(0x20)),
            bytes32(uint256(0x60)),
            bytes32(0),
            bytes32(0),
            bytes32(0),
            bytes32(0)
        );
        payloads[2] = bytes.concat(
            bytes32(uint256(1)),
            bytes32(uint256(0x60)),
            bytes32(uint256(0x61)),
            bytes32(0),
            bytes32(0),
            bytes32(0),
            bytes32(0)
        );
        payloads[3] = bytes.concat(abi.encode(uint256(1), "n", "{}"), hex"deadbeef");
        for (uint256 i = 0; i < payloads.length; ++i) {
            vm.prank(alice);
            eas.attest(subjectSchema, _req(payloads[i]));
            vm.prank(bob);
            vm.expectRevert(abi.encodeWithSelector(OTTPResolver__AttesterNotOwner.selector, 1, bob, alice));
            eas.attest(subjectSchema, _req(payloads[i]));
        }
        // Object schema: same with creatorId at word 1
        bytes memory obj = bytes.concat(bytes32(0), bytes32(uint256(2)), bytes32(uint256(0x60)), bytes32(uint256(0)));
        vm.prank(bob);
        eas.attest(objectSchema, _req(obj));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(OTTPResolver__AttesterNotOwner.selector, 2, alice, bob));
        eas.attest(objectSchema, _req(obj));
    }

    /// Cross-schema payload confusion: a Subject-shaped payload on the Object schema is validated on WORD 1
    /// (the Subject's `name` offset, 0x60 = 96) => IdNotRegistered(96); an Object-shaped payload on the
    /// Subject schema is validated on WORD 0 (originUid). No schema decodes another schema's id field.
    function test_Decode_CrossSchemaPayloads() public {
        bytes memory subj = abi.encode(uint256(1), "n", "{}");
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(OTTPResolver__IdNotRegistered.selector, 0x60));
        eas.attest(objectSchema, _req(subj));
        // an attacker who owns id 1 could set originUid = bytes32(1) and get a Subject accepted for id 1 — but
        // that is their own id, so no impersonation is possible.
        bytes memory objAsSubj =
            bytes.concat(bytes32(uint256(1)), bytes32(uint256(0x60)), bytes32(uint256(0x60)), bytes32(0));
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(OTTPResolver__AttesterNotOwner.selector, 1, bob, alice));
        eas.attest(subjectSchema, _req(objAsSubj));
        vm.prank(alice);
        eas.attest(subjectSchema, _req(objAsSubj));
    }

    // ───────────────────────────── error propagation / control flow through core ─────────────────────────────

    /// Resolver reverts bubble through the core unchanged and NO attestation is stored. Returning-false path
    /// (InvalidAttestation) is never used by these resolvers; every rejection is a typed revert.
    function test_Flow_RevertPropagatesAndNothingStored() public {
        vm.prank(mallory);
        (bool ok, bytes memory ret) = address(eas)
            .call(abi.encodeWithSelector(MockEAS.attest.selector, subjectSchema, _req(abi.encode(uint256(1), "", ""))));
        assertFalse(ok);
        // forge-lint: disable-next-line(unsafe-typecast)
        assertEq(bytes4(ret), OTTPResolver__AttesterNotOwner.selector);
        // nothing in the db: a fresh attest from the owner gets the first salt
        vm.prank(alice);
        bytes32 uid = eas.attest(subjectSchema, _req(abi.encode(uint256(1), "", "")));
        assertEq(eas.getAttestation(uid).attester, alice);
    }

    /// multiAttest: every item is validated with ITS attester; one bad item reverts the whole batch
    /// (SchemaResolver.multiAttest short-circuits on first failure and our onAttest reverts, not returns false).
    function test_Flow_MultiAttestOneBadItemRevertsBatch() public {
        Attestation[] memory arr = new Attestation[](3);
        arr[0] = _att(alice, abi.encode(uint256(1), "", ""));
        arr[1] = _att(alice, abi.encode(uint256(2), "", "")); // alice claiming bob's id
        arr[2] = _att(alice, abi.encode(uint256(1), "", ""));
        uint256[] memory vals = new uint256[](3);
        vm.prank(address(eas));
        vm.expectRevert(abi.encodeWithSelector(OTTPResolver__AttesterNotOwner.selector, 2, alice, bob));
        subjectResolver.multiAttest(arr, vals);
        // all-good batch passes
        arr[1] = _att(alice, abi.encode(uint256(1), "", ""));
        vm.prank(address(eas));
        assertTrue(subjectResolver.multiAttest(arr, vals));
        // length mismatch is rejected by the base contract
        vm.prank(address(eas));
        vm.expectRevert(abi.encodeWithSignature("InvalidLength()"));
        subjectResolver.multiAttest(arr, new uint256[](2));
    }

    /// Revocation: rejected in core (Irrevocable) and, if core were bypassed, by the resolver (false).
    /// onRevoke / multiRevoke return false for ANY input, including a would-be-valid owner attestation.
    function test_Flow_RevokeAlwaysDenied() public {
        vm.prank(alice);
        bytes32 uid = eas.attest(subjectSchema, _req(abi.encode(uint256(1), "", "")));
        vm.prank(alice);
        vm.expectRevert(MockEAS.Irrevocable.selector);
        eas.revoke(subjectSchema, uid);
        vm.expectRevert(MockEAS.InvalidRevocation.selector);
        eas.revokeBypassingCoreCheck(uid);
        vm.prank(address(eas));
        assertFalse(subjectResolver.revoke(_att(alice, abi.encode(uint256(1), "", ""))));
        vm.prank(address(eas));
        assertFalse(objectResolver.revoke(_att(bob, abi.encode(bytes32(0), uint256(2), ""))));
        Attestation[] memory arr = new Attestation[](1);
        arr[0] = _att(alice, abi.encode(uint256(1), "", ""));
        vm.prank(address(eas));
        assertFalse(subjectResolver.multiRevoke(arr, new uint256[](1)));
        // revocable=true request on the non-revocable schema is rejected up-front by core
        AttestationRequestData memory r = _req(abi.encode(uint256(1), "", ""));
        r.revocable = true;
        vm.prank(alice);
        vm.expectRevert(MockEAS.Irrevocable.selector);
        eas.attest(subjectSchema, r);
    }

    /// Only EAS may call attest/multiAttest/revoke/multiRevoke; ETH is refused by receive(); isPayable false.
    function test_Flow_AccessControlAndValue() public {
        Attestation memory a = _att(alice, abi.encode(uint256(1), "", ""));
        address[3] memory callers = [alice, address(registry), address(this)];
        for (uint256 i = 0; i < 3; ++i) {
            vm.prank(callers[i]);
            vm.expectRevert(AccessDenied.selector);
            subjectResolver.attest(a);
            vm.prank(callers[i]);
            vm.expectRevert(AccessDenied.selector);
            objectResolver.revoke(a);
        }
        assertFalse(subjectResolver.isPayable());
        assertFalse(objectResolver.isPayable());
        vm.deal(alice, 1 ether);
        vm.prank(alice);
        (bool ok,) = address(subjectResolver).call{ value: 1 }("");
        assertFalse(ok);
        // core refuses value for a non-payable resolver before reaching it
        vm.prank(alice);
        vm.expectRevert(MockEAS.NotPayable.selector);
        eas.attest{ value: 1 }(subjectSchema, _req(abi.encode(uint256(1), "", "")));
    }

    /// After transferId: old wallet rejected with exact params, new wallet accepted; history-only semantics.
    function test_Flow_AfterTransfer() public {
        vm.prank(alice);
        registry.transferId(1, mallory);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(OTTPResolver__AttesterNotOwner.selector, 1, alice, mallory));
        eas.attest(subjectSchema, _req(abi.encode(uint256(1), "", "")));
        vm.prank(mallory);
        eas.attest(subjectSchema, _req(abi.encode(uint256(1), "", "")));
        vm.prank(mallory);
        eas.attest(objectSchema, _req(abi.encode(bytes32(0), uint256(1), "")));
    }

    /// Resolver state: none. Two resolvers deployed against the same registry have identical behaviour and
    /// hold no storage beyond immutables (registry() and version()).
    function test_Stateless() public view {
        assertEq(address(subjectResolver.registry()), address(registry));
        assertEq(address(objectResolver.registry()), address(registry));
        assertEq(subjectResolver.version(), "1.4.0");
        assertEq(objectResolver.version(), "1.4.0");
        // storage slot 0..3 are empty (no state variables)
        for (uint256 s = 0; s < 4; ++s) {
            assertEq(vm.load(address(subjectResolver), bytes32(s)), bytes32(0));
            assertEq(vm.load(address(objectResolver), bytes32(s)), bytes32(0));
        }
    }
}
