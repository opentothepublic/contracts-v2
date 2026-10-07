// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import { Test } from "forge-std/Test.sol";
import { IEAS, AttestationRequestData } from "@ethereum-attestation-service/eas-contracts/contracts/IEAS.sol";
import { EMPTY_UID, NO_EXPIRATION_TIME } from "@ethereum-attestation-service/eas-contracts/contracts/Common.sol";
import { ISchemaResolver } from "@ethereum-attestation-service/eas-contracts/contracts/resolver/ISchemaResolver.sol";

import { OTTPRegistry } from "../../src/OTTPRegistry.sol";
import { OTTPSubjectResolver } from "../../src/OTTPSubjectResolver.sol";
import { OTTPObjectResolver } from "../../src/OTTPObjectResolver.sol";
import {
    OTTPResolver__ZeroId,
    OTTPResolver__IdNotRegistered,
    OTTPResolver__AttesterNotOwner
} from "../../src/OTTPResolverErrors.sol";
import { OTTPSchemas } from "../../src/Schemas.sol";
import { MockEAS } from "../mocks/MockEAS.sol";
import { RegistrySigUtils } from "../utils/RegistrySigUtils.sol";
import { AuthoritySigUtils } from "../utils/AuthoritySigUtils.sol";
import { ERC1271Wallet } from "../mocks/ERC1271Wallet.sol";

/// @notice Addendum B2 (PROPOSED): attest-only delegates — setDelegate / setDelegateBySig / isDelegate / canAttest,
///         and the Object resolver accepting active delegates while the Subject resolver stays owner-only.
contract DelegatesTest is Test {
    OTTPRegistry internal registry;
    MockEAS internal eas;
    OTTPSubjectResolver internal subjectResolver;
    OTTPObjectResolver internal objectResolver;
    bytes32 internal subjectSchema;
    bytes32 internal objectSchema;

    address internal alice;
    uint256 internal alicePk;
    address internal bob;
    uint256 internal bobPk;
    address internal carol;
    uint256 internal carolPk;
    address internal agent;
    uint256 internal agentPk;
    address internal relayer = makeAddr("relayer");
    address internal stranger = makeAddr("stranger");

    uint64 internal constant FOREVER = type(uint64).max;

    event DelegateSet(uint256 indexed id, address indexed delegate, uint64 expiry, uint256 epoch);

    function setUp() public {
        vm.warp(1_760_000_000);
        registry = new OTTPRegistry();
        eas = new MockEAS();
        subjectResolver = new OTTPSubjectResolver(IEAS(address(eas)), registry);
        objectResolver = new OTTPObjectResolver(IEAS(address(eas)), registry);
        subjectSchema =
            eas.registerSchema(OTTPSchemas.SUBJECT, ISchemaResolver(address(subjectResolver)), OTTPSchemas.REVOCABLE);
        objectSchema =
            eas.registerSchema(OTTPSchemas.OBJECT, ISchemaResolver(address(objectResolver)), OTTPSchemas.REVOCABLE);
        (alice, alicePk) = makeAddrAndKey("alice");
        (bob, bobPk) = makeAddrAndKey("bob");
        (carol, carolPk) = makeAddrAndKey("carol");
        (agent, agentPk) = makeAddrAndKey("agent");
        vm.prank(alice);
        registry.register(); // 1
        vm.prank(bob);
        registry.register(); // 2
    }

    // ─── helpers ───────────────────────────────────────────────────────────────────────────────────────────

    function _delegateSig(
        uint256 pk,
        uint256 id,
        address delegate,
        uint64 expiry,
        uint256 epoch,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (bytes memory) {
        return AuthoritySigUtils.sign(
            vm,
            pk,
            address(registry),
            block.chainid,
            AuthoritySigUtils.setDelegateHash(id, delegate, expiry, epoch, nonce, deadline)
        );
    }

    function _validDelegateSig(uint256 pk, uint256 id, address delegate, uint64 expiry, uint256 deadline)
        internal
        view
        returns (bytes memory)
    {
        address owner = registry.getWallet(id);
        return _delegateSig(pk, id, delegate, expiry, registry.ownerEpoch(id), registry.nonces(owner), deadline);
    }

    function _move(uint256 id, address to) internal {
        vm.prank(registry.getWallet(id));
        registry.proposeTransfer(id, to);
        vm.prank(to);
        registry.acceptId(id);
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

    function _object(uint256 creatorId) internal pure returns (bytes memory) {
        return abi.encode(bytes32(0), creatorId, '{"type":"work"}');
    }

    function _subject(uint256 id) internal pure returns (bytes memory) {
        return abi.encode(id, "name", "{}");
    }

    // ─── setDelegate ───────────────────────────────────────────────────────────────────────────────────────

    function test_SetDelegate_GrantsAttestOnlyAuthority() public {
        uint64 expiry = uint64(block.timestamp + 30 days);
        vm.expectEmit(true, true, false, true);
        emit DelegateSet(1, agent, expiry, 0);
        vm.prank(alice);
        registry.setDelegate(1, agent, expiry);

        assertTrue(registry.isDelegate(1, agent));
        assertTrue(registry.canAttest(1, agent));
        assertTrue(registry.canAttest(1, alice));
        assertEq(registry.delegateExpiry(1, agent), expiry);
        assertFalse(registry.isDelegate(2, agent), "scoped to the id");
        assertFalse(registry.canAttest(2, agent));
        assertEq(registry.nonces(alice), 1, "direct setDelegate consumes no nonce");
    }

    function test_SetDelegate_ExpiryBoundary() public {
        uint64 expiry = uint64(block.timestamp + 1);
        vm.prank(alice);
        registry.setDelegate(1, agent, expiry);
        assertTrue(registry.isDelegate(1, agent));
        vm.warp(expiry); // inactive from `expiry` on
        assertFalse(registry.isDelegate(1, agent));
        assertFalse(registry.canAttest(1, agent));
        assertEq(registry.delegateExpiry(1, agent), 0);
    }

    function test_SetDelegate_NoExpiry() public {
        vm.prank(alice);
        registry.setDelegate(1, agent, FOREVER);
        vm.warp(type(uint64).max - 1);
        assertTrue(registry.isDelegate(1, agent));
    }

    function test_SetDelegate_ZeroRevokes() public {
        vm.startPrank(alice);
        registry.setDelegate(1, agent, FOREVER);
        vm.expectEmit(true, true, false, true);
        emit DelegateSet(1, agent, 0, 0);
        registry.setDelegate(1, agent, 0);
        vm.stopPrank();
        assertFalse(registry.isDelegate(1, agent));
        assertFalse(registry.canAttest(1, agent));
    }

    function test_SetDelegate_RevokeOfUnsetIsHarmless() public {
        vm.prank(alice);
        registry.setDelegate(1, agent, 0);
        assertFalse(registry.isDelegate(1, agent));
    }

    function test_SetDelegate_MultipleDelegatesAndUpdate() public {
        vm.startPrank(alice);
        registry.setDelegate(1, agent, FOREVER);
        registry.setDelegate(1, carol, uint64(block.timestamp + 1 days));
        registry.setDelegate(1, agent, uint64(block.timestamp + 2 days)); // shorten
        vm.stopPrank();
        assertEq(registry.delegateExpiry(1, agent), block.timestamp + 2 days);
        assertTrue(registry.isDelegate(1, carol));
    }

    function test_SetDelegate_Reverts() public {
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NotOwner.selector, 1, bob));
        registry.setDelegate(1, agent, FOREVER);

        vm.prank(agent);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NotOwner.selector, 3, agent));
        registry.setDelegate(3, agent, FOREVER);

        vm.startPrank(alice);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidDelegate.selector, address(0)));
        registry.setDelegate(1, address(0), FOREVER);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidDelegate.selector, alice));
        registry.setDelegate(1, alice, FOREVER);
        uint64 nowTs = uint64(block.timestamp);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidExpiry.selector, nowTs));
        registry.setDelegate(1, agent, nowTs);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidExpiry.selector, uint64(1)));
        registry.setDelegate(1, agent, 1);
        vm.stopPrank();
    }

    function test_Delegate_CannotDoAnythingButAttest() public {
        vm.prank(alice);
        registry.setDelegate(1, agent, FOREVER);
        vm.startPrank(agent);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NotOwner.selector, 1, agent));
        registry.proposeTransfer(1, carol);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NotOwner.selector, 1, agent));
        registry.cancelTransfer(1);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NotOwner.selector, 1, agent));
        registry.setDelegate(1, carol, FOREVER);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NoPendingMove.selector, 1, agent));
        registry.acceptId(1);
        vm.stopPrank();
        // and cannot sign for the owner
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _validDelegateSig(agentPk, 1, carol, FOREVER, deadline);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidSignature.selector, alice));
        registry.setDelegateBySig(1, carol, FOREVER, deadline, sig);
    }

    function test_Delegate_ResetByOwnershipChange() public {
        vm.prank(alice);
        registry.setDelegate(1, agent, FOREVER);
        _move(1, carol);
        assertFalse(registry.isDelegate(1, agent), "old owner's delegate must be inactive");
        assertFalse(registry.canAttest(1, agent));
        assertFalse(registry.canAttest(1, alice), "old owner cannot attest");
        assertTrue(registry.canAttest(1, carol));
        // moving back does not resurrect it (epoch is 2 now, grant was epoch 0)
        _move(1, alice);
        assertFalse(registry.isDelegate(1, agent));
        // new owner can re-grant in the new epoch
        vm.prank(alice);
        registry.setDelegate(1, agent, FOREVER);
        assertTrue(registry.isDelegate(1, agent));
    }

    function test_Delegate_FormerDelegateCanBecomeOwner() public {
        vm.prank(alice);
        registry.setDelegate(1, agent, FOREVER);
        _move(1, agent);
        assertTrue(registry.canAttest(1, agent));
        assertFalse(registry.isDelegate(1, agent), "owner, not delegate");
    }

    function test_CanAttest_UnissuedIdAndZero() public view {
        assertFalse(registry.canAttest(0, address(0)));
        assertFalse(registry.canAttest(3, address(0)));
        assertFalse(registry.canAttest(3, alice));
        assertFalse(registry.isDelegate(3, alice));
        assertFalse(registry.canAttest(1, address(0)));
    }

    // ─── setDelegateBySig ──────────────────────────────────────────────────────────────────────────────────

    function test_SetDelegateBySig_RelayedAndConsumesExactlyOneOwnerNonce() public {
        uint256 deadline = block.timestamp + 1 hours;
        uint64 expiry = uint64(block.timestamp + 7 days);
        bytes memory sig = _validDelegateSig(alicePk, 1, agent, expiry, deadline);
        vm.expectEmit(true, true, false, true);
        emit DelegateSet(1, agent, expiry, 0);
        vm.prank(relayer);
        registry.setDelegateBySig(1, agent, expiry, deadline, sig);
        assertTrue(registry.isDelegate(1, agent));
        assertEq(registry.nonces(alice), 2, "register + setDelegateBySig");
        assertEq(registry.nonces(agent), 0);
        assertEq(registry.nonces(relayer), 0);
    }

    /// @notice The brief's exactly-one-nonce scenario: a client pre-signs registerFor at n and setDelegateBySig at
    ///         n+1; a relayer submits both; both succeed.
    function test_ExactlyOneNonce_RegisterForThenSetDelegateBySig() public {
        uint256 n = registry.nonces(carol);
        uint256 deadline = block.timestamp + 1 hours;
        uint256 expectedId = registry.nextId();
        bytes memory regSig = RegistrySigUtils.sign(vm, carolPk, address(registry), block.chainid, carol, n, deadline);
        bytes memory delSig = _delegateSig(carolPk, expectedId, agent, FOREVER, 0, n + 1, deadline);

        vm.startPrank(relayer);
        assertEq(registry.registerFor(carol, deadline, regSig), expectedId);
        registry.setDelegateBySig(expectedId, agent, FOREVER, deadline, delSig);
        vm.stopPrank();

        assertEq(registry.nonces(carol), n + 2);
        assertTrue(registry.isDelegate(expectedId, agent));
    }

    function test_SetDelegateBySig_UnissuedIdReverts() public {
        uint256 deadline = block.timestamp + 1 hours;
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__IdNotRegistered.selector, 3));
        registry.setDelegateBySig(3, agent, FOREVER, deadline, new bytes(65));
    }

    function test_SetDelegateBySig_Erc1271Owner() public {
        (address owner, uint256 ownerPk) = makeAddrAndKey("safe-owner");
        ERC1271Wallet w = new ERC1271Wallet(owner);
        vm.prank(address(w));
        uint256 id = registry.register();
        uint256 deadline = block.timestamp + 1 hours;
        registry.setDelegateBySig(
            id, agent, FOREVER, deadline, _validDelegateSig(ownerPk, id, agent, FOREVER, deadline)
        );
        assertTrue(registry.isDelegate(id, agent));
        assertEq(registry.nonces(address(w)), 2);
    }

    function test_SetDelegateBySig_SemanticChecksStillApply() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _validDelegateSig(alicePk, 1, alice, FOREVER, deadline);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidDelegate.selector, alice));
        registry.setDelegateBySig(1, alice, FOREVER, deadline, sig);
        uint64 past = uint64(block.timestamp);
        sig = _validDelegateSig(alicePk, 1, agent, past, deadline);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidExpiry.selector, past));
        registry.setDelegateBySig(1, agent, past, deadline, sig);
        assertEq(registry.nonces(alice), 1, "failed calls keep the nonce");
    }

    function test_SetDelegateBySig_RevokeBySig() public {
        vm.prank(alice);
        registry.setDelegate(1, agent, FOREVER);
        uint256 deadline = block.timestamp + 1 hours;
        registry.setDelegateBySig(1, agent, 0, deadline, _validDelegateSig(alicePk, 1, agent, 0, deadline));
        assertFalse(registry.isDelegate(1, agent));
    }

    // ─── fuzz: signature path ──────────────────────────────────────────────────────────────────────────────

    function testFuzz_SetDelegateBySig_Replay(uint64 expiryOffset) public {
        uint64 expiry = uint64(block.timestamp) + uint64(bound(expiryOffset, 1, 365 days));
        uint256 deadline = block.timestamp + 1 days;
        bytes memory sig = _validDelegateSig(alicePk, 1, agent, expiry, deadline);
        registry.setDelegateBySig(1, agent, expiry, deadline, sig);
        // owner revokes directly; replaying the grant must fail
        vm.prank(alice);
        registry.setDelegate(1, agent, 0);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidSignature.selector, alice));
        registry.setDelegateBySig(1, agent, expiry, deadline, sig);
        assertFalse(registry.isDelegate(1, agent));
    }

    function testFuzz_SetDelegateBySig_TamperedField(uint8 field, uint256 delta) public {
        field = uint8(bound(field, 0, 5));
        delta = bound(delta, 1, type(uint32).max);
        uint256 deadline = block.timestamp + 1 days;
        uint64 expiry = uint64(block.timestamp + 30 days);
        uint256 id = 1;
        address delegate = agent;
        uint64 sExpiry = expiry;
        uint256 epoch = 0;
        uint256 nonce = registry.nonces(alice);
        uint256 sDeadline = deadline;
        if (field == 0) id += delta;
        // forge-lint: disable-next-line(unsafe-typecast)
        else if (field == 1) delegate = address(uint160(delegate) ^ uint160(delta));
        // forge-lint: disable-next-line(unsafe-typecast)
        else if (field == 2) sExpiry += uint64(delta); // delta <= type(uint32).max
        else if (field == 3) epoch += delta;
        else if (field == 4) nonce += delta;
        else sDeadline += delta;
        bytes memory sig = _delegateSig(alicePk, id, delegate, sExpiry, epoch, nonce, sDeadline);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidSignature.selector, alice));
        registry.setDelegateBySig(1, agent, expiry, deadline, sig);
        assertFalse(registry.isDelegate(1, agent));
    }

    function testFuzz_SetDelegateBySig_WrongSigner(uint256 pk) public {
        pk = bound(pk, 1, 115792089237316195423570985008687907852837564279074904382605163141518161494336);
        vm.assume(pk != alicePk);
        uint256 deadline = block.timestamp + 1 days;
        bytes memory sig = _validDelegateSig(pk, 1, agent, FOREVER, deadline);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidSignature.selector, alice));
        registry.setDelegateBySig(1, agent, FOREVER, deadline, sig);
    }

    function testFuzz_SetDelegateBySig_WrongChain(uint64 otherChain) public {
        vm.assume(otherChain != block.chainid);
        uint256 deadline = block.timestamp + 1 days;
        bytes32 structHash = AuthoritySigUtils.setDelegateHash(1, agent, FOREVER, 0, 1, deadline);
        bytes memory wrongDomainSig = AuthoritySigUtils.sign(vm, alicePk, address(registry), otherChain, structHash);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidSignature.selector, alice));
        registry.setDelegateBySig(1, agent, FOREVER, deadline, wrongDomainSig);

        bytes memory sig = _validDelegateSig(alicePk, 1, agent, FOREVER, deadline);
        vm.chainId(otherChain);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidSignature.selector, alice));
        registry.setDelegateBySig(1, agent, FOREVER, deadline, sig);
    }

    function testFuzz_SetDelegateBySig_WrongVerifyingContract(address other) public {
        vm.assume(other != address(registry));
        uint256 deadline = block.timestamp + 1 days;
        bytes32 structHash = AuthoritySigUtils.setDelegateHash(1, agent, FOREVER, 0, 1, deadline);
        bytes memory sig = AuthoritySigUtils.sign(vm, alicePk, other, block.chainid, structHash);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidSignature.selector, alice));
        registry.setDelegateBySig(1, agent, FOREVER, deadline, sig);
    }

    function testFuzz_SetDelegateBySig_Expired(uint256 age) public {
        age = bound(age, 1, block.timestamp);
        uint256 deadline = block.timestamp - age;
        bytes memory sig = _validDelegateSig(alicePk, 1, agent, FOREVER, deadline);
        vm.expectRevert(
            abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__SignatureExpired.selector, deadline, block.timestamp)
        );
        registry.setDelegateBySig(1, agent, FOREVER, deadline, sig);
    }

    /// @dev Stale epoch: alice signs at epoch 0, the id goes to carol and back to alice. alice's nonce is unchanged
    ///      by transfers, so only the epoch kills the old signature.
    function testFuzz_SetDelegateBySig_StaleEpoch(uint8 roundTrips) public {
        roundTrips = uint8(bound(roundTrips, 1, 4));
        uint256 deadline = block.timestamp + 1 days;
        bytes memory oldSig = _validDelegateSig(alicePk, 1, agent, FOREVER, deadline);
        uint256 nonceBefore = registry.nonces(alice);
        for (uint256 i = 0; i < roundTrips; i++) {
            _move(1, carol);
            _move(1, alice);
        }
        assertEq(registry.nonces(alice), nonceBefore, "transfers leave the nonce alone");
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidSignature.selector, alice));
        registry.setDelegateBySig(1, agent, FOREVER, deadline, oldSig);
    }

    function testFuzz_SetDelegateBySig_OldOwnerSignatureDead(uint64 expiryOffset) public {
        uint64 expiry = uint64(block.timestamp) + uint64(bound(expiryOffset, 1, 365 days));
        uint256 deadline = block.timestamp + 1 days;
        bytes memory oldOwnerSig = _validDelegateSig(alicePk, 1, agent, expiry, deadline);
        _move(1, carol);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidSignature.selector, carol));
        registry.setDelegateBySig(1, agent, expiry, deadline, oldOwnerSig);
    }

    // ─── resolvers ─────────────────────────────────────────────────────────────────────────────────────────

    function test_ObjectResolver_AcceptsActiveDelegateDirectAndRelayed() public {
        vm.prank(alice);
        registry.setDelegate(1, agent, FOREVER);
        vm.prank(agent);
        bytes32 uid = eas.attest(objectSchema, _req(_object(1)));
        assertEq(eas.getAttestation(uid).attester, agent);
        vm.prank(relayer);
        uid = eas.attestByDelegation(objectSchema, _req(_object(1)), agent);
        assertEq(eas.getAttestation(uid).attester, agent);
    }

    function test_ObjectResolver_OwnerStillAccepted() public {
        vm.prank(alice);
        eas.attest(objectSchema, _req(_object(1)));
    }

    function test_ObjectResolver_RejectsDelegateOfAnotherId() public {
        vm.prank(alice);
        registry.setDelegate(1, agent, FOREVER);
        vm.prank(agent);
        vm.expectRevert(abi.encodeWithSelector(OTTPResolver__AttesterNotOwner.selector, 2, agent, bob));
        eas.attest(objectSchema, _req(_object(2)));
    }

    function test_ObjectResolver_RejectsExpiredRevokedAndStaleDelegates() public {
        vm.prank(alice);
        registry.setDelegate(1, agent, uint64(block.timestamp + 1 days));
        vm.warp(block.timestamp + 1 days);
        vm.prank(agent);
        vm.expectRevert(abi.encodeWithSelector(OTTPResolver__AttesterNotOwner.selector, 1, agent, alice));
        eas.attest(objectSchema, _req(_object(1)));

        vm.prank(alice);
        registry.setDelegate(1, agent, FOREVER);
        vm.prank(alice);
        registry.setDelegate(1, agent, 0);
        vm.prank(agent);
        vm.expectRevert(abi.encodeWithSelector(OTTPResolver__AttesterNotOwner.selector, 1, agent, alice));
        eas.attest(objectSchema, _req(_object(1)));

        vm.prank(alice);
        registry.setDelegate(1, agent, FOREVER);
        _move(1, carol);
        vm.prank(agent);
        vm.expectRevert(abi.encodeWithSelector(OTTPResolver__AttesterNotOwner.selector, 1, agent, carol));
        eas.attest(objectSchema, _req(_object(1)));
    }

    function test_ObjectResolver_ErrorsUnchangedForZeroAndUnissued() public {
        vm.prank(alice);
        vm.expectRevert(OTTPResolver__ZeroId.selector);
        eas.attest(objectSchema, _req(_object(0)));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(OTTPResolver__IdNotRegistered.selector, 3));
        eas.attest(objectSchema, _req(_object(3)));
    }

    function test_SubjectResolver_StaysOwnerOnly() public {
        vm.prank(alice);
        registry.setDelegate(1, agent, FOREVER);
        vm.prank(agent);
        vm.expectRevert(abi.encodeWithSelector(OTTPResolver__AttesterNotOwner.selector, 1, agent, alice));
        eas.attest(subjectSchema, _req(_subject(1)));
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(OTTPResolver__AttesterNotOwner.selector, 1, agent, alice));
        eas.attestByDelegation(subjectSchema, _req(_subject(1)), agent);
        vm.prank(alice);
        eas.attest(subjectSchema, _req(_subject(1)));
    }

    function testFuzz_ObjectResolver_MatchesCanAttest(uint256 who, uint256 id, uint64 expiryOffset, uint32 dt) public {
        address[4] memory cast = [alice, bob, agent, stranger];
        address attester = cast[who % 4];
        id = bound(id, 0, 3);
        if (expiryOffset % 3 != 0) {
            vm.prank(alice);
            registry.setDelegate(1, agent, uint64(block.timestamp) + uint64(bound(expiryOffset, 1, 30 days)));
        }
        vm.warp(block.timestamp + uint256(dt) % 60 days);
        bool expected = id != 0 && registry.canAttest(id, attester);
        vm.prank(attester);
        (bool ok,) = address(eas).call(abi.encodeCall(MockEAS.attest, (objectSchema, _req(_object(id)))));
        assertEq(ok, expected);
    }

    function test_TypehashConstantMatchesAddendum() public view {
        assertEq(registry.SET_DELEGATE_TYPEHASH(), AuthoritySigUtils.SET_DELEGATE_TYPEHASH);
    }
}
