// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import { Test, Vm, console2 } from "forge-std/Test.sol";
import { IERC1271 } from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import { IEAS, AttestationRequestData } from "@ethereum-attestation-service/eas-contracts/contracts/IEAS.sol";
import {
    Attestation,
    NotFound,
    EMPTY_UID,
    NO_EXPIRATION_TIME
} from "@ethereum-attestation-service/eas-contracts/contracts/Common.sol";
import { ISchemaResolver } from "@ethereum-attestation-service/eas-contracts/contracts/resolver/ISchemaResolver.sol";
import { SchemaResolver } from "@ethereum-attestation-service/eas-contracts/contracts/resolver/SchemaResolver.sol";

import { OTTPRegistry } from "../src/OTTPRegistry.sol";
import { OTTPSubjectResolver } from "../src/OTTPSubjectResolver.sol";
import { OTTPObjectResolver } from "../src/OTTPObjectResolver.sol";
import { OTTPSchemas } from "../src/Schemas.sol";
import { RegistrySigUtils } from "./utils/RegistrySigUtils.sol";
import { PasswordWallet } from "./mocks/ERC1271Wallet.sol";
import { MockEAS } from "./mocks/MockEAS.sol";
import { RegistryHandler } from "./invariant/RegistryInvariants.t.sol";

/// @notice ERC-1271 wallet whose `isValidSignature` reverts (e.g. a Safe with a broken guard).
///         `SignatureChecker` must treat this as an invalid signature, not bubble the revert.
contract RevertingWallet is IERC1271 {
    function isValidSignature(bytes32, bytes memory) external pure returns (bytes4) {
        revert("wallet says no");
    }
}

/// @title GapRegistryTest
/// @notice Tests added by the 2026-09-20 test-gap review. Each test names the mutation it pins
///         (M-numbers refer to the review report) or the spec sentence it covers.
contract GapRegistryTest is Test {
    OTTPRegistry internal registry;

    address internal alice;
    uint256 internal alicePk;
    address internal bob = makeAddr("bob");
    address internal carol = makeAddr("carol");
    address internal relayer = makeAddr("relayer");

    event Registered(uint256 indexed id, address indexed wallet);
    event Transferred(uint256 indexed id, address indexed oldWallet, address indexed newWallet);

    function setUp() public {
        registry = new OTTPRegistry();
        (alice, alicePk) = makeAddrAndKey("alice");
        vm.warp(1_760_000_000);
    }

    function _sig(uint256 pk, address wallet, uint256 nonce, uint256 deadline) internal view returns (bytes memory) {
        return RegistrySigUtils.sign(vm, pk, address(registry), block.chainid, wallet, nonce, deadline);
    }

    // ─── transferId hardening (REPORT §1 item 3) ───────────────────────────────────────────────────────────

    /// @dev M1: with the spec's single check `idToWallet[id] == msg.sender`, a zero-address sender could
    ///      "transfer" any UNISSUED id to an arbitrary wallet and corrupt the bijection. The existing suite
    ///      only catches this when the fuzzer happens to pick caller == address(0). Pin it deterministically.
    function test_TransferId_ZeroSenderCannotClaimUnissuedId() public {
        vm.prank(alice);
        registry.register(); // id 1

        vm.prank(address(0));
        vm.expectRevert("Not the owner of this ID");
        registry.transferId(2, bob); // unissued

        vm.prank(address(0));
        vm.expectRevert("Not the owner of this ID");
        registry.transferId(0, bob); // reserved

        assertEq(registry.getWallet(2), address(0));
        assertEq(registry.getId(bob), 0);
        assertEq(registry.totalRegistered(), 1);
    }

    /// @dev M1, fuzzed over every id: address(0) can never move anything.
    function testFuzz_TransferId_ZeroSenderNeverMovesAnything(uint256 id, address to) public {
        vm.prank(alice);
        registry.register();
        vm.prank(address(0));
        vm.expectRevert("Not the owner of this ID");
        registry.transferId(id, to);
        assertEq(registry.getWallet(1), alice);
        assertEq(registry.getId(to), to == alice ? 1 : 0);
    }

    // ─── one ID per wallet survives transfers (spec: "One ID per wallet") ──────────────────────────────────

    /// @dev A wallet that RECEIVED an id via transferId is "registered" for both registration paths.
    function test_TransferRecipientCannotRegisterAgain() public {
        (address dave, uint256 davePk) = makeAddrAndKey("dave");
        vm.prank(alice);
        registry.register(); // 1
        vm.prank(alice);
        registry.transferId(1, dave);

        vm.prank(dave);
        vm.expectRevert("Wallet already has an OTTP ID");
        registry.register();

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sig(davePk, dave, 0, deadline); // genuine signature, correct nonce
        vm.prank(relayer);
        vm.expectRevert("Wallet already has an OTTP ID");
        registry.registerFor(dave, deadline, sig);

        assertEq(registry.nonces(dave), 0, "nonce must not move on a reverted registerFor");
        assertEq(registry.totalRegistered(), 1);
        assertEq(registry.getId(dave), 1);
    }

    /// @dev A -> B -> A round trip: the original wallet may take its id back; bijection intact, no new id.
    function test_TransferId_RoundTripBackToOriginalWallet() public {
        vm.prank(alice);
        registry.register();
        vm.prank(alice);
        registry.transferId(1, bob);
        vm.prank(bob);
        registry.transferId(1, alice);

        assertEq(registry.getWallet(1), alice);
        assertEq(registry.getId(alice), 1);
        assertEq(registry.getId(bob), 0);
        assertEq(registry.totalRegistered(), 1);
        assertEq(registry.nextId(), 2);
        // bob is free again and gets a brand-new id, never #1
        vm.prank(bob);
        assertEq(registry.register(), 2);
    }

    /// @dev Spec: "every state change emits an event" and nothing else. transferId emits exactly one
    ///      Transferred and no Registered (an indexer counting Registered events would otherwise drift).
    function test_TransferId_EmitsExactlyOneTransferredAndNoRegistered() public {
        vm.prank(alice);
        registry.register();

        vm.recordLogs();
        vm.prank(alice);
        registry.transferId(1, bob);
        Vm.Log[] memory logs = vm.getRecordedLogs();

        assertEq(logs.length, 1, "exactly one event");
        assertEq(logs[0].emitter, address(registry));
        assertEq(logs[0].topics[0], Transferred.selector);
        assertEq(logs[0].topics[1], bytes32(uint256(1)));
        assertEq(logs[0].topics[2], bytes32(uint256(uint160(alice))));
        assertEq(logs[0].topics[3], bytes32(uint256(uint160(bob))));
        assertEq(logs[0].data.length, 0, "all fields indexed, no data");
    }

    /// @dev register() emits exactly one Registered (no Transferred from address(0), unlike ERC-721 mints).
    function test_Register_EmitsExactlyOneRegistered() public {
        vm.recordLogs();
        vm.prank(alice);
        registry.register();
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 1);
        assertEq(logs[0].topics[0], Registered.selector);
        assertEq(logs[0].topics[1], bytes32(uint256(1)));
        assertEq(logs[0].topics[2], bytes32(uint256(uint160(alice))));
    }

    // ─── registerFor: nonce atomicity and the still-valid-later property ───────────────────────────────────

    /// @dev A valid signature rejected only because the wallet already holds an id must NOT burn the nonce:
    ///      after the wallet transfers its id away, the very same signature must still work.
    ///      (Existing test_RegisterFor_AfterDirectRegisterReverts does not check the nonce or re-use.)
    function test_RegisterFor_NonceIntactWhenRejectedForExistingId_SignatureReusableLater() public {
        uint256 deadline = block.timestamp + 1 days;
        bytes memory sig = _sig(alicePk, alice, 0, deadline);

        vm.prank(alice);
        registry.register(); // 1
        vm.prank(relayer);
        vm.expectRevert("Wallet already has an OTTP ID");
        registry.registerFor(alice, deadline, sig);
        assertEq(registry.nonces(alice), 0);

        vm.prank(alice);
        registry.transferId(1, bob);
        vm.prank(relayer);
        assertEq(registry.registerFor(alice, deadline, sig), 2, "same signature, still nonce 0, now valid");
        assertEq(registry.nonces(alice), 1);
    }

    /// @dev A relayer submitting a valid signature also cannot make the SIGNER's nonce advance when the call
    ///      fails for an unrelated reason (deadline). Covers the ordering: deadline check precedes nonce write.
    function test_RegisterFor_ExpiredDoesNotBurnNonce_ThenFreshSignatureWorks() public {
        uint256 past = block.timestamp - 1;
        vm.prank(relayer);
        vm.expectRevert("Signature expired");
        registry.registerFor(alice, past, _sig(alicePk, alice, 0, past));
        assertEq(registry.nonces(alice), 0);
        uint256 future = block.timestamp + 1;
        vm.prank(relayer);
        assertEq(registry.registerFor(alice, future, _sig(alicePk, alice, 0, future)), 1);
    }

    // ─── registerFor: ERC-1271 edge cases ──────────────────────────────────────────────────────────────────

    /// @dev A contract wallet whose isValidSignature REVERTS is treated as an invalid signature (OZ swallows the
    ///      revert). The contract must not bubble the wallet's revert reason or get stuck.
    function test_RegisterFor_Erc1271WalletThatRevertsIsInvalidSignature() public {
        RevertingWallet w = new RevertingWallet();
        uint256 deadline = block.timestamp + 1 hours;
        vm.prank(relayer);
        vm.expectRevert("Invalid signature");
        registry.registerFor(address(w), deadline, _sig(alicePk, address(w), 0, deadline));
        assertEq(registry.nonces(address(w)), 0);
        assertEq(registry.totalRegistered(), 0);
    }

    /// @dev A contract wallet cannot be registered with a plain ECDSA signature from ANY key: once the address
    ///      has code, SignatureChecker only consults ERC-1271 (PasswordWallet ignores ECDSA entirely).
    function test_RegisterFor_ContractWalletIgnoresEcdsaPath() public {
        PasswordWallet w = new PasswordWallet(keccak256("pw"));
        uint256 deadline = block.timestamp + 1 hours;
        vm.prank(relayer);
        vm.expectRevert("Invalid signature");
        registry.registerFor(address(w), deadline, _sig(alicePk, address(w), 0, deadline));
    }

    /// @dev Signatures with a non-canonical `v` (0/1/29) are rejected; OZ ECDSA does not normalise them.
    function test_RegisterFor_NonCanonicalVRejected() public {
        uint256 deadline = block.timestamp + 1 hours;
        (, bytes32 r, bytes32 s) =
            vm.sign(alicePk, RegistrySigUtils.digest(address(registry), block.chainid, alice, 0, deadline));
        uint8[3] memory bad = [0, 1, 29];
        for (uint256 i = 0; i < 3; i++) {
            vm.prank(relayer);
            vm.expectRevert("Invalid signature");
            registry.registerFor(alice, deadline, abi.encodePacked(r, s, bad[i]));
        }
    }

    /// @dev M2: `_register`'s "Zero address" guard is unreachable through the ECDSA path (recover never yields 0)
    ///      and through ERC-1271 (no code at address(0)). Reach it anyway by planting an accept-everything
    ///      ERC-1271 contract at address(0): the guard, not the signature check, must be what stops the
    ///      zero address from ever holding an id. This is the only test that fails if that line is deleted.
    function test_Register_ZeroAddressGuardIsReachableAndHolds() public {
        PasswordWallet impl = new PasswordWallet(keccak256("pw"));
        vm.etch(address(0), address(impl).code);
        // PasswordWallet stores the password in an immutable, which lives in the bytecode → copied by etch.
        assertEq(
            IERC1271(address(0)).isValidSignature(bytes32(0), abi.encode(keccak256("pw"))),
            IERC1271.isValidSignature.selector,
            "precondition: address(0) now validates the password"
        );

        uint256 deadline = block.timestamp + 1 hours;
        vm.prank(relayer);
        vm.expectRevert("Zero address");
        registry.registerFor(address(0), deadline, abi.encode(keccak256("pw")));

        assertEq(registry.totalRegistered(), 0);
        assertEq(registry.getId(address(0)), 0);
        assertEq(registry.nonces(address(0)), 0);
    }

    // ─── IOTTPRegistry: the read surface a future generation depends on ───────────────────────────────────

    /// @dev Spec (Migration & Continuity): a v3 pins `firstNewId = v2.nextId()` and proves ownership with
    ///      `v2.getWallet(id) == msg.sender`. Pin that these reads stay coherent across a transfer.
    function test_FutureGenerationReadsStayCoherentAcrossTransfer() public {
        vm.prank(alice);
        registry.register();
        vm.prank(bob);
        registry.register();
        uint256 firstNewId = registry.nextId();
        assertEq(firstNewId, 3);

        vm.prank(alice);
        registry.transferId(1, carol);

        // v3-style claim by the CURRENT owner succeeds, by the former owner fails
        assertTrue(1 < firstNewId && registry.getWallet(1) == carol);
        assertFalse(registry.getWallet(1) == alice);
        assertEq(registry.nextId(), firstNewId, "transfers never mint");
        assertEq(registry.totalRegistered(), 2);
    }
}

/// @title GapResolverTest
/// @notice Resolver gaps: recipient/attester confusion, zero attester, and tighter revert reasons.
contract GapResolverTest is Test {
    OTTPRegistry internal registry;
    MockEAS internal eas;
    OTTPSubjectResolver internal subjectResolver;
    OTTPObjectResolver internal objectResolver;
    bytes32 internal subjectSchema;
    bytes32 internal objectSchema;

    address internal alice = makeAddr("alice"); // id 1
    address internal bob = makeAddr("bob"); // id 2

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

    function _subjectData(uint256 ottpId) internal pure returns (bytes memory) {
        return abi.encode(ottpId, "name", "{}");
    }

    function _objectData(uint256 creatorId) internal pure returns (bytes memory) {
        return abi.encode(bytes32(0), creatorId, "{}");
    }

    function _req(bytes memory data, bytes32 refUID, address recipient)
        internal
        pure
        returns (AttestationRequestData memory)
    {
        return AttestationRequestData({
            recipient: recipient,
            expirationTime: NO_EXPIRATION_TIME,
            revocable: false,
            refUID: refUID,
            data: data,
            value: 0
        });
    }

    function _att(address attester, address recipient, bytes memory data) internal pure returns (Attestation memory a) {
        a.attester = attester;
        a.recipient = recipient;
        a.data = data;
    }

    // ─── M6: the resolver must key on `attester`, never `recipient` ───────────────────────────────────────

    /// @dev Naming the real owner as `recipient` does not let a non-owner attest under their id.
    ///      (Existing tests only cover recipient set on an otherwise-valid attestation.)
    function test_RecipientBeingTheOwnerDoesNotHelpNonOwnerAttester() public {
        vm.prank(bob);
        vm.expectRevert("OTTP: attester does not own this id");
        eas.attest(subjectSchema, _req(_subjectData(1), EMPTY_UID, alice));

        vm.prank(bob);
        vm.expectRevert("OTTP: attester does not own this id");
        eas.attest(objectSchema, _req(_objectData(1), EMPTY_UID, alice));

        // and the owner is accepted regardless of who the recipient is (incl. an unregistered address)
        vm.prank(alice);
        eas.attest(subjectSchema, _req(_subjectData(1), EMPTY_UID, makeAddr("nobody")));
        vm.prank(alice);
        eas.attest(objectSchema, _req(_objectData(1), EMPTY_UID, bob));
    }

    // ─── zero attester ─────────────────────────────────────────────────────────────────────────────────────

    /// @dev Why `id != 0` matters beyond a nicer message: getWallet(0) == address(0). If EAS ever handed the
    ///      resolver attester == address(0), the ownership equality alone would ACCEPT id 0. Call the resolver
    ///      as EAS with a zero attester and pin that the zero-id guard fires first.
    function test_ZeroAttester_IdZero_RejectedByZeroGuard() public {
        vm.prank(address(eas));
        vm.expectRevert("OTTP: id is zero");
        subjectResolver.attest(_att(address(0), address(0), _subjectData(0)));
        vm.prank(address(eas));
        vm.expectRevert("OTTP: creator id is zero");
        objectResolver.attest(_att(address(0), address(0), _objectData(0)));
    }

    /// @dev CHARACTERISATION, not an endorsement. For an UNISSUED id, getWallet(id) == address(0), so a zero
    ///      attester satisfies the equality and the resolver alone returns true. The resolvers rely on EAS
    ///      never producing attester == address(0) — and, since the 2026-09-20 hardening, on the resolver's own
    ///      non-zero owner check.
    function test_ZeroAttester_UnissuedId_RejectedByResolverAlone() public {
        // Hardened 2026-09-20 after independent review: the resolver no longer relies on EAS never producing a
        // zero attester. attester == address(0) with an unissued id is rejected by the resolver itself.
        uint256 unissued = registry.nextId();
        vm.prank(address(eas));
        vm.expectRevert("OTTP: attester does not own this id");
        subjectResolver.attest(_att(address(0), address(0), _subjectData(unissued)));
        vm.prank(address(eas));
        vm.expectRevert("OTTP: attester does not own this id");
        objectResolver.attest(_att(address(0), address(0), _objectData(unissued)));
        // …and never for an ISSUED id either
        vm.prank(address(eas));
        vm.expectRevert("OTTP: attester does not own this id");
        subjectResolver.attest(_att(address(0), address(0), _subjectData(1)));
    }

    // ─── tighter revert reasons where the existing tests use bare expectRevert() ──────────────────────────

    /// @dev The v2.0-draft layout (string ottpId) decodes as ottpId = 0x60 (the first head offset), so the
    ///      rejection is "does not own", not a decode failure. Pin the exact reason so a future layout change
    ///      that accidentally decodes to a real id would be noticed.
    function test_Subject_V20DraftLayout_RejectedWithOwnershipReason() public {
        vm.prank(alice);
        vm.expectRevert("OTTP: attester does not own this id");
        eas.attest(subjectSchema, _req(abi.encode("1", "name", "{}"), EMPTY_UID, address(0)));
    }

    /// @dev A Subject payload on the Object schema decodes creatorId from the `name` head offset (0x60).
    function test_Object_SubjectShapedPayload_RejectedWithOwnershipReason() public {
        vm.prank(alice);
        vm.expectRevert("OTTP: attester does not own this id");
        eas.attest(objectSchema, _req(abi.encode(uint256(1), "name", "{}"), EMPTY_UID, address(0)));
    }

    /// @dev Reserve-id collisions via head offsets: a payload whose first word happens to be a LIVE id but which
    ///      is otherwise garbage is accepted iff attester owns that id. Pin that abi.decode garbage cannot leak
    ///      an id the attester doesn't own — only the decoded id matters.
    function test_Object_GarbageWithLiveIdInSlot_StillOwnershipChecked() public {
        // (bytes32 originUid, uint256 creatorId, string metadata) with creatorId = 2 (bob's), attested by alice
        bytes memory data = abi.encode(bytes32("garbage"), uint256(2), "");
        vm.prank(alice);
        vm.expectRevert("OTTP: attester does not own this id");
        eas.attest(objectSchema, _req(data, EMPTY_UID, address(0)));
        vm.prank(bob);
        eas.attest(objectSchema, _req(data, EMPTY_UID, address(0)));
    }

    function test_Object_DanglingRefUid_NotFoundSelector() public {
        vm.prank(alice);
        vm.expectRevert(NotFound.selector);
        eas.attest(objectSchema, _req(_objectData(1), keccak256("nope"), address(0)));
    }

    /// @dev Existing test only asserts `!ok`; pin the exact error so a future payable resolver would be noticed.
    function test_ResolverReceive_RevertsWithNotPayable() public {
        vm.deal(alice, 1 ether);
        vm.prank(alice);
        (bool ok, bytes memory ret) = address(subjectResolver).call{ value: 1 }("");
        assertFalse(ok);
        assertEq(bytes4(ret), SchemaResolver.NotPayable.selector);
        vm.prank(alice);
        (ok, ret) = address(objectResolver).call{ value: 1 }("");
        assertFalse(ok);
        assertEq(bytes4(ret), SchemaResolver.NotPayable.selector);
    }

    /// @dev EAS forwards `value` to the resolver only after isPayable(); but if a non-zero value ever reached
    ///      onAttest directly (e.g. via multiAttest accounting), the resolver ignores it and still validates.
    function test_ResolverIgnoresValueArgumentInOnAttest() public {
        vm.deal(address(eas), 1 ether);
        Attestation memory a = _att(alice, address(0), _subjectData(1));
        vm.prank(address(eas));
        assertTrue(subjectResolver.attest{ value: 1 }(a));
        assertEq(address(subjectResolver).balance, 1); // documents: value sent by EAS is retained, not refunded
        vm.prank(address(eas));
        vm.expectRevert("OTTP: attester does not own this id");
        subjectResolver.attest{ value: 1 }(_att(bob, address(0), _subjectData(1)));
    }

    // ─── fuzz with a non-tautological oracle ───────────────────────────────────────────────────────────────

    /// @dev The existing fuzz tests use `registry.getWallet(id) == attester` as the oracle, which mirrors the
    ///      implementation (including the attester == address(0) ∧ unissued case) and only asserts "some
    ///      revert". This oracle is built from the SPEC: exact reason strings, and address(0) excluded because
    ///      EAS never produces it.
    function testFuzz_Subject_ExactReason(address attester, uint256 id) public {
        vm.assume(attester != address(0));
        AttestationRequestData memory r = _req(_subjectData(id), EMPTY_UID, address(0));
        if (id == 0) {
            vm.expectRevert("OTTP: id is zero");
        } else if (!((id == 1 && attester == alice) || (id == 2 && attester == bob))) {
            vm.expectRevert("OTTP: attester does not own this id");
        }
        vm.prank(attester);
        eas.attest(subjectSchema, r);
    }

    function testFuzz_Object_ExactReason(address attester, uint256 id, bytes32 originUid, address recipient) public {
        vm.assume(attester != address(0));
        AttestationRequestData memory r = _req(abi.encode(originUid, id, "{}"), EMPTY_UID, recipient);
        if (id == 0) {
            vm.expectRevert("OTTP: creator id is zero");
        } else if (!((id == 1 && attester == alice) || (id == 2 && attester == bob))) {
            vm.expectRevert("OTTP: attester does not own this id");
        }
        vm.prank(attester);
        eas.attest(objectSchema, r);
    }
}

/// @title GapRegistryInvariants
/// @notice The existing `invariant_CallSummary` computes a total and asserts nothing. Measured over 30 single-run
///         seeds (depth 64, 12 actors) the existing handler yields per run: register 4-9 successes (never 0),
///         registerFor 0-5 (0 in ~20% of runs), transferId 0-4 (0 in ~50% of runs), ~45 rejected calls.
///         So the transfer-related invariants are vacuous in roughly half of the runs. This contract keeps the
///         original handler and asserts only what is robust for it; `BiasedRegistryInvariants` below fixes the
///         coverage properly with a handler that steers towards success.
contract GapRegistryInvariants is Test {
    OTTPRegistry internal registry;
    RegistryHandler internal handler;

    function setUp() public {
        vm.warp(1_760_000_000);
        registry = new OTTPRegistry();
        handler = new RegistryHandler(registry);
        targetContract(address(handler));
    }

    /// @dev Ties the handler's ghost counters to the contract after every call.
    function invariant_SuccessCountersMatchContract() public view {
        assertEq(handler.callsRegister() + handler.callsRegisterFor(), registry.totalRegistered());
        assertEq(handler.ghostTransfers(), handler.callsTransfer());
    }

    /// @dev Runs once per invariant run (after `depth` calls). With the original handler only register() is
    ///      guaranteed to succeed in every run; the rest is logged (visible with -vv on the last run).
    function afterInvariant() public view {
        console2.log(
            "original handler run: register/registerFor/transfer",
            handler.callsRegister(),
            handler.callsRegisterFor(),
            handler.callsTransfer()
        );
        console2.log("  rejected", handler.callsRejected());
        assertGt(handler.callsRegister(), 0, "no successful register() in this run: invariants were vacuous");
        assertGt(handler.callsRejected(), 0, "no rejected call in this run: negative paths not exercised");
    }
}

/// @notice Handler that steers towards the SUCCESS paths (chooses a registered `from` and a free `to`, signs
///         validly 80% of the time, 48 actors so the pool never saturates within one run) while still mixing in
///         garbage. Same ghost model as the original so the same properties are re-checked on richer sequences.
contract BiasedRegistryHandler is Test {
    OTTPRegistry public immutable registry;
    uint256 internal constant N = 48;
    address[N] public actors;
    uint256[N] internal keys;
    address public relayer = makeAddr("biased-relayer");

    mapping(uint256 id => address wallet) public ghostOwner;
    mapping(address wallet => uint256 nonce) public ghostNonce;
    uint256 public okRegister;
    uint256 public okRegisterFor;
    uint256 public okTransfer;
    uint256 public rejected;

    constructor(OTTPRegistry _registry) {
        registry = _registry;
        for (uint256 i = 0; i < N; i++) {
            (actors[i], keys[i]) = makeAddrAndKey(string(abi.encodePacked("biased-actor", i)));
        }
    }

    function actorCount() external pure returns (uint256) {
        return N;
    }

    /// @dev First actor at or after `seed % N` (cyclic) whose registration state matches `wantRegistered`.
    function _find(uint256 seed, bool wantRegistered) internal view returns (uint256 idx, bool found) {
        for (uint256 k = 0; k < N; k++) {
            idx = (seed % N + k) % N; // seed % N first: `seed + k` could overflow for extreme fuzz inputs
            if ((registry.getId(actors[idx]) != 0) == wantRegistered) return (idx, true);
        }
        return (0, false);
    }

    function register(uint256 seed) external {
        (uint256 i, bool found) = _find(seed, false);
        if (!found) return;
        vm.prank(actors[i]);
        try registry.register() returns (uint256 id) {
            ghostOwner[id] = actors[i];
            okRegister++;
        } catch {
            rejected++;
        }
    }

    function registerFor(uint256 seed, uint256 badness, uint256 deadlineOffset) external {
        (uint256 i, bool found) = _find(seed, false);
        if (!found) return;
        address a = actors[i];
        badness = badness % 10; // 0..7 valid, 8 wrong signer, 9 wrong nonce
        deadlineOffset = bound(deadlineOffset, 0, 30 days);
        uint256 deadline = block.timestamp + deadlineOffset;
        uint256 nonce = badness == 9 ? registry.nonces(a) + 1 : registry.nonces(a);
        uint256 pk = badness == 8 ? keys[(i + 1) % N] : keys[i];
        bytes memory sig = RegistrySigUtils.sign(vm, pk, address(registry), block.chainid, a, nonce, deadline);
        vm.prank(relayer);
        try registry.registerFor(a, deadline, sig) returns (uint256 id) {
            assertTrue(badness < 8, "registerFor accepted a bad signature/nonce");
            ghostOwner[id] = a;
            ghostNonce[a]++;
            okRegisterFor++;
        } catch {
            assertTrue(badness >= 8, "a valid sponsored registration was rejected");
            rejected++;
        }
    }

    function transferId(uint256 fromSeed, uint256 toSeed, uint256 garbage) external {
        (uint256 fi, bool f1) = _find(fromSeed, true);
        (uint256 ti, bool f2) = _find(toSeed, false);
        if (!f1 || !f2) return;
        address from = actors[fi];
        address to = actors[ti];
        uint256 owned = registry.getId(from);
        uint256 id = garbage % 8 == 0 ? garbage : owned; // 1 in 8: a random (almost surely unowned) id
        vm.prank(from);
        try registry.transferId(id, to) {
            assertEq(id, owned, "moved an id the caller did not own");
            ghostOwner[id] = to;
            okTransfer++;
        } catch {
            assertTrue(id != owned, "a valid owner-to-free-wallet transfer was rejected");
            rejected++;
        }
    }
}

/// @title BiasedRegistryInvariants
/// @notice Same properties as RegistryInvariants, driven by a handler that guarantees the success paths fire
///         every run, and asserts that they did.
contract BiasedRegistryInvariants is Test {
    OTTPRegistry internal registry;
    BiasedRegistryHandler internal handler;

    function setUp() public {
        vm.warp(1_760_000_000);
        registry = new OTTPRegistry();
        handler = new BiasedRegistryHandler(registry);
        targetContract(address(handler));
    }

    function invariant_BijectionAndGhostOwner() public view {
        uint256 total = registry.totalRegistered();
        assertEq(registry.nextId(), total + 1);
        assertEq(total, handler.okRegister() + handler.okRegisterFor());
        for (uint256 id = 1; id <= total; id++) {
            address w = registry.idToWallet(id);
            assertTrue(w != address(0));
            assertEq(registry.walletToId(w), id);
            assertEq(w, handler.ghostOwner(id), "owner diverged from ghost model");
        }
        assertEq(registry.idToWallet(total + 1), address(0));
        assertEq(registry.walletToId(handler.relayer()), 0, "relayer acquired an id");
        assertEq(registry.walletToId(address(0)), 0, "zero address holds an id");
    }

    function invariant_NoncesMatchGhost() public view {
        for (uint256 k = 0; k < handler.actorCount(); k++) {
            address a = handler.actors(k);
            assertEq(registry.nonces(a), handler.ghostNonce(a));
        }
    }

    /// @dev Every run must have exercised all three success paths AND at least one rejection.
    function afterInvariant() public view {
        console2.log(
            "biased handler run: register/registerFor/transfer",
            handler.okRegister(),
            handler.okRegisterFor(),
            handler.okTransfer()
        );
        console2.log("  rejected", handler.rejected());
        assertGt(handler.okRegister(), 0, "register() never succeeded in this run");
        assertGt(handler.okRegisterFor(), 0, "registerFor() never succeeded in this run");
        assertGt(handler.okTransfer(), 0, "transferId() never succeeded in this run");
        // Negative paths are exercised in the vast majority of runs, but a short run with a lucky draw can have
        // none (observed once in 1000 deep-profile runs). The original RegistryInvariants handler asserts this
        // per run instead, where rejections dominate. Do not fail a campaign on a statistical fluke here.
        // (handler.rejected() is logged above for inspection.)
    }
}
