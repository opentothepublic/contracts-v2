// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

// AUDIT SCRATCH TESTS (2026-09-20). Not part of the main suite.

import { Test } from "forge-std/Test.sol";
import { IEAS, AttestationRequestData } from "@ethereum-attestation-service/eas-contracts/contracts/IEAS.sol";
import {
    Attestation,
    EMPTY_UID,
    NO_EXPIRATION_TIME
} from "@ethereum-attestation-service/eas-contracts/contracts/Common.sol";
import { ISchemaResolver } from "@ethereum-attestation-service/eas-contracts/contracts/resolver/ISchemaResolver.sol";

import { OTTPRegistry } from "../../src/OTTPRegistry.sol";
import { OTTPSubjectResolver } from "../../src/OTTPSubjectResolver.sol";
import { OTTPObjectResolver } from "../../src/OTTPObjectResolver.sol";
import { OTTPSchemas } from "../../src/Schemas.sol";
import { MockEAS } from "../mocks/MockEAS.sol";

/// @dev Stand-in for EAS's EIP712Proxy / any shared forwarder: it calls eas.attest itself, so EAS records the
///      PROXY as `attester`. Anyone can drive it (the real EIP712Proxy verifies a signature from whatever
///      `attester` the submitter names — i.e. the submitter's own key).
contract ProxyLike {
    MockEAS internal immutable eas;

    constructor(MockEAS e) {
        eas = e;
    }

    function attestVia(bytes32 schema, AttestationRequestData calldata d) external returns (bytes32) {
        return eas.attest(schema, d);
    }

    function transferOut(OTTPRegistry r, uint256 id, address to) external {
        r.transferId(id, to);
    }
}

contract Bomb {
    constructor(address payable to) payable {
        selfdestruct(to);
    }
}

contract AuditResolversTest is Test {
    OTTPRegistry internal registry;
    MockEAS internal eas;
    OTTPSubjectResolver internal subjectResolver;
    OTTPObjectResolver internal objectResolver;
    bytes32 internal subjectSchema;
    bytes32 internal objectSchema;

    address internal alice = makeAddr("alice"); // id 1
    address internal bob = makeAddr("bob"); // id 2
    address internal mallory = makeAddr("mallory");

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
    }

    // ── R1: for the Subject schema the validated ID is ALWAYS calldata word 0; for Object ALWAYS word 1.
    //       No offset trick can make the contract validate a different ID than any head-reading decoder sees.
    function testFuzz_R1_ValidatedIdIsHeadWord(bytes32 w0, bytes32 w1, bytes32 w2, bytes memory tail) public {
        bytes memory data = bytes.concat(w0, w1, w2, tail);
        // Subject: try to decode; if it decodes, the id the resolver checked equals w0.
        vm.prank(address(eas));
        try subjectResolver.attest(_att(alice, data)) returns (bool ok) {
            assertTrue(ok);
            assertEq(uint256(w0), 1, "resolver accepted alice for an id that is not word 0 == 1");
        } catch (bytes memory reason) {
            // Either abi.decode failed, or the id check failed; if the id check failed, w0 must not be 1
            if (
                keccak256(reason)
                    == keccak256(abi.encodeWithSignature("Error(string)", "OTTP: attester does not own this id"))
            ) {
                assertTrue(uint256(w0) != 1);
            } else if (keccak256(reason) == keccak256(abi.encodeWithSignature("Error(string)", "OTTP: id is zero"))) {
                assertEq(uint256(w0), 0);
            }
        }
        // Object: same, for word 1.
        vm.prank(address(eas));
        try objectResolver.attest(_att(alice, data)) returns (bool ok) {
            assertTrue(ok);
            assertEq(uint256(w1), 1);
        } catch (bytes memory reason) {
            if (
                keccak256(reason)
                    == keccak256(abi.encodeWithSignature("Error(string)", "OTTP: attester does not own this id"))
            ) {
                assertTrue(uint256(w1) != 1);
            }
        }
    }

    // ── R2: non-canonical ABI encodings that Solidity's abi.decode ACCEPTS (offchain decoders may be stricter):
    //       aliased offsets, offsets pointing into the head, non-32-aligned offsets, invalid UTF-8, trailing bytes.
    //       These are accepted onchain with the correct ID check; an indexer that treats "strict decode failed"
    //       as "not an OTTP attestation" would DROP an authentic record (INFO for the indexer). ──
    function test_R2_NonCanonicalEncodings_AcceptedOnchain() public {
        // (a) both strings alias the same tail; length 4, "abcd"
        bytes memory aliased = bytes.concat(
            bytes32(uint256(1)), bytes32(uint256(0x60)), bytes32(uint256(0x60)), bytes32(uint256(4)), bytes32("abcd")
        );
        vm.prank(alice);
        eas.attest(subjectSchema, _req(aliased));

        // (b) name offset points at the head itself (offset 0x20 → "length" = 0x60 → reads 0x60 bytes from 0x40)
        bytes memory intoHead = bytes.concat(
            bytes32(uint256(1)),
            bytes32(uint256(0x20)),
            bytes32(uint256(0x60)),
            bytes32(uint256(0)),
            bytes32(0),
            bytes32(0),
            bytes32(0)
        );
        vm.prank(alice);
        eas.attest(subjectSchema, _req(intoHead));

        // (c) non-32-aligned offset (0x61) for metadata, still in bounds
        bytes memory unaligned = bytes.concat(
            bytes32(uint256(1)),
            bytes32(uint256(0x60)),
            bytes32(uint256(0x61)),
            bytes32(uint256(0)),
            bytes32(0),
            bytes32(0),
            bytes32(0)
        );
        vm.prank(alice);
        eas.attest(subjectSchema, _req(unaligned));

        // (d) invalid UTF-8 in `name` — Solidity does not validate strings
        bytes memory raw = hex"fffe80";
        bytes memory badUtf8 = abi.encode(uint256(1), string(raw), "{}");
        vm.prank(alice);
        eas.attest(subjectSchema, _req(badUtf8));

        // (e) trailing garbage
        vm.prank(alice);
        eas.attest(subjectSchema, _req(bytes.concat(abi.encode(uint256(1), "n", "{}"), hex"00")));

        // (f) BUT the id check always ran on word 0: same encodings with bob's id are rejected for alice
        aliased = bytes.concat(
            bytes32(uint256(2)), bytes32(uint256(0x60)), bytes32(uint256(0x60)), bytes32(uint256(4)), bytes32("abcd")
        );
        vm.prank(alice);
        vm.expectRevert("OTTP: attester does not own this id");
        eas.attest(subjectSchema, _req(aliased));

        // (g) out-of-bounds offset reverts (no panic-string, plain revert from abi.decode)
        bytes memory oob = bytes.concat(bytes32(uint256(1)), bytes32(uint256(0x1000)), bytes32(uint256(0x60)));
        vm.prank(alice);
        vm.expectRevert();
        eas.attest(subjectSchema, _req(oob));
    }

    // ── R3: EIP712Proxy-style flows: EAS records the proxy as attester, so a real user is REJECTED through a
    //       proxy; and if an ID is ever moved to a shared proxy, ANYONE can attest as that ID (LOW footgun). ──
    function test_R3_ProxyAttester_RejectedForUser_ImpersonationIfProxyHoldsId() public {
        ProxyLike proxy = new ProxyLike(eas);
        // alice attests via the proxy → attester = proxy → rejected
        vm.prank(alice);
        vm.expectRevert("OTTP: attester does not own this id");
        proxy.attestVia(subjectSchema, _req(abi.encode(uint256(1), "alice", "{}")));

        // alice (mistakenly) parks her ID in the proxy
        vm.prank(alice);
        registry.transferId(1, address(proxy));

        // now mallory attests AS id 1 through the shared proxy
        vm.prank(mallory);
        bytes32 uid = proxy.attestVia(subjectSchema, _req(abi.encode(uint256(1), "mallory-was-here", "{}")));
        assertEq(eas.getAttestation(uid).attester, address(proxy));
        // and mallory can even try to walk the ID out if the proxy exposes any arbitrary-call surface
        vm.prank(mallory);
        proxy.transferOut(registry, 1, mallory);
        assertEq(registry.getWallet(1), mallory, "id stolen through a permissionless proxy holding it");
    }

    // ── R4: ETH can be force-sent to a resolver (selfdestruct) and is then stuck forever; harmless (INFO). ──
    function test_R4_ForceSentEthIsStuckButHarmless() public {
        new Bomb{ value: 1 ether }(payable(address(subjectResolver)));
        assertEq(address(subjectResolver).balance, 1 ether);
        // no effect on validation
        vm.prank(alice);
        eas.attest(subjectSchema, _req(abi.encode(uint256(1), "a", "{}")));
        // no way out: receive() reverts on any inbound value and there is no withdraw function
        (bool ok,) = address(subjectResolver).call{ value: 1 }("");
        assertFalse(ok);
    }

    // ── R5: SchemaResolver.multiAttest is `payable` and only checks values[i] <= msg.value; if the EAS core
    //       ever forwarded ETH despite isPayable()==false, it would be stranded. Real EAS (1.0.1/1.2.0/1.4.0)
    //       reverts NotPayable before reaching here, so this is INFO / defense-in-depth only. ──
    function test_R5_MultiAttestValueBookkeeping_DoesNotProtectAgainstMisbehavingCore() public {
        Attestation[] memory arr = new Attestation[](1);
        arr[0] = _att(alice, abi.encode(uint256(1), "a", "{}"));
        uint256[] memory vals = new uint256[](1);
        vals[0] = 1;
        vm.deal(address(eas), 2);
        vm.prank(address(eas));
        assertTrue(subjectResolver.multiAttest{ value: 1 }(arr, vals));
        assertEq(address(subjectResolver).balance, 1, "stranded");
        // values > msg.value is rejected by the base contract
        vals[0] = 2;
        vm.prank(address(eas));
        vm.expectRevert(abi.encodeWithSignature("InsufficientValue()"));
        subjectResolver.multiAttest{ value: 1 }(arr, vals);
    }

    // ── R6 (finding LOW-1, FIXED 2026-09-20): the resolvers now carry an explicit non-zero owner check, so
    //       attester == address(0) with an unissued id is rejected by the resolver itself, independent of EAS. ──
    function test_R6_ZeroAttester_RejectedForUnissuedId() public {
        vm.prank(address(eas));
        vm.expectRevert("OTTP: id is zero");
        subjectResolver.attest(_att(address(0), abi.encode(uint256(0), "", "")));

        vm.prank(address(eas));
        vm.expectRevert("OTTP: attester does not own this id");
        subjectResolver.attest(_att(address(0), abi.encode(uint256(999), "", "")));
        vm.prank(address(eas));
        vm.expectRevert("OTTP: attester does not own this id");
        objectResolver.attest(_att(address(0), abi.encode(bytes32(0), uint256(type(uint256).max), "")));
    }

    // ── R7: gas is paid by the attester; a 64 KiB metadata blob still validates in bounded gas (no DoS on others). ──
    function test_R7_HugeMetadataCostsOnlyTheAttester() public {
        bytes memory big = new bytes(64 * 1024);
        Attestation memory a = _att(alice, abi.encode(uint256(1), "a", string(big)));
        vm.prank(address(eas));
        uint256 g = gasleft();
        assertTrue(subjectResolver.attest(a));
        uint256 used = g - gasleft();
        assertLt(used, 2_000_000, "resolver gas for 64KiB metadata");
    }
}
