// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import { Test, Vm } from "forge-std/Test.sol";

import { OTTPRegistry } from "../../src/OTTPRegistry.sol";
import { RegistrySigUtils } from "../utils/RegistrySigUtils.sol";
import { AuthoritySigUtils } from "../utils/AuthoritySigUtils.sol";
import { ERC1271Wallet } from "../mocks/ERC1271Wallet.sol";

/// @notice Addendum B3 (PROPOSED): guardian recovery — setGuardian / setGuardianBySig / initiateRecovery /
///         cancelRecovery / completion via acceptId(BySig) after RECOVERY_DELAY.
contract RecoveryTest is Test {
    OTTPRegistry internal registry;

    address internal alice;
    uint256 internal alicePk;
    address internal bob;
    address internal guardian;
    uint256 internal guardianPk;
    address internal fresh;
    uint256 internal freshPk;
    address internal carol;
    address internal relayer = makeAddr("relayer");
    address internal stranger = makeAddr("stranger");

    uint256 internal constant DELAY = 7 days;

    event Transferred(uint256 indexed id, address indexed oldWallet, address indexed newWallet);
    event GuardianSet(uint256 indexed id, address indexed guardian, uint256 epoch);
    event RecoveryInitiated(uint256 indexed id, address indexed guardian, address indexed newWallet, uint256 readyAt);
    event RecoveryCancelled(uint256 indexed id, address indexed by);
    event RecoveryFinalized(uint256 indexed id, address indexed oldWallet, address indexed newWallet);

    function setUp() public {
        vm.warp(1_760_000_000);
        registry = new OTTPRegistry();
        (alice, alicePk) = makeAddrAndKey("alice");
        bob = makeAddr("bob");
        (guardian, guardianPk) = makeAddrAndKey("guardian");
        (fresh, freshPk) = makeAddrAndKey("fresh");
        carol = makeAddr("carol");
        vm.prank(alice);
        registry.register(); // 1
        vm.prank(bob);
        registry.register(); // 2
    }

    // ─── helpers ───────────────────────────────────────────────────────────────────────────────────────────

    function _guardianSig(uint256 pk, uint256 id, address g, uint256 epoch, uint256 nonce, uint256 deadline)
        internal
        view
        returns (bytes memory)
    {
        return AuthoritySigUtils.sign(
            vm, pk, address(registry), block.chainid, AuthoritySigUtils.setGuardianHash(id, g, epoch, nonce, deadline)
        );
    }

    function _validGuardianSig(uint256 pk, uint256 id, address g, uint256 deadline)
        internal
        view
        returns (bytes memory)
    {
        return _guardianSig(pk, id, g, registry.ownerEpoch(id), registry.nonces(registry.getWallet(id)), deadline);
    }

    function _acceptSig(uint256 pk, uint256 id, address wallet, uint256 deadline) internal view returns (bytes memory) {
        return AuthoritySigUtils.sign(
            vm,
            pk,
            address(registry),
            block.chainid,
            AuthoritySigUtils.acceptIdHash(id, wallet, registry.ownerEpoch(id), registry.nonces(wallet), deadline)
        );
    }

    function _setGuardianAndInitiate() internal returns (uint256 readyAt) {
        vm.prank(alice);
        registry.setGuardian(1, guardian);
        vm.prank(guardian);
        registry.initiateRecovery(1, fresh);
        readyAt = block.timestamp + DELAY;
    }

    function _move(uint256 id, address to) internal {
        vm.prank(registry.getWallet(id));
        registry.proposeTransfer(id, to);
        vm.prank(to);
        registry.acceptId(id);
    }

    // ─── setGuardian ───────────────────────────────────────────────────────────────────────────────────────

    function test_SetGuardian_SetsAndClears() public {
        vm.expectEmit(true, true, false, true);
        emit GuardianSet(1, guardian, 0);
        vm.prank(alice);
        registry.setGuardian(1, guardian);
        assertEq(registry.guardianOf(1), guardian);
        assertEq(registry.nonces(alice), 1, "direct setGuardian consumes no nonce");

        vm.prank(alice);
        registry.setGuardian(1, address(0));
        assertEq(registry.guardianOf(1), address(0));
        vm.prank(guardian);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NotGuardian.selector, 1, guardian));
        registry.initiateRecovery(1, fresh);
    }

    function test_SetGuardian_Reverts() public {
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NotOwner.selector, 1, bob));
        registry.setGuardian(1, guardian);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidGuardian.selector, alice));
        registry.setGuardian(1, alice);
        vm.prank(guardian);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NotOwner.selector, 3, guardian));
        registry.setGuardian(3, guardian);
    }

    function test_SetGuardian_AnyCallCancelsPendingRecovery() public {
        _setGuardianAndInitiate();
        vm.expectEmit(true, true, false, false);
        emit RecoveryCancelled(1, alice);
        vm.prank(alice);
        registry.setGuardian(1, guardian); // same guardian, still cancels
        (address target,) = registry.pendingRecoveryOf(1);
        assertEq(target, address(0));
        vm.warp(block.timestamp + DELAY);
        vm.prank(fresh);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NoPendingMove.selector, 1, fresh));
        registry.acceptId(1);
    }

    function test_Guardian_ResetByOwnershipChange() public {
        vm.prank(alice);
        registry.setGuardian(1, guardian);
        _move(1, carol);
        assertEq(registry.guardianOf(1), address(0));
        vm.prank(guardian);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NotGuardian.selector, 1, guardian));
        registry.initiateRecovery(1, fresh);
    }

    function test_Guardian_CannotDoAnythingElse() public {
        vm.prank(alice);
        registry.setGuardian(1, guardian);
        assertFalse(registry.canAttest(1, guardian));
        assertFalse(registry.isDelegate(1, guardian));
        vm.startPrank(guardian);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NotOwner.selector, 1, guardian));
        registry.proposeTransfer(1, fresh);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NotOwner.selector, 1, guardian));
        registry.setDelegate(1, fresh, type(uint64).max);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NotOwner.selector, 1, guardian));
        registry.setGuardian(1, fresh);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NoPendingMove.selector, 1, guardian));
        registry.acceptId(1);
        vm.stopPrank();
    }

    // ─── setGuardianBySig ──────────────────────────────────────────────────────────────────────────────────

    function test_SetGuardianBySig_RelayedConsumesOneNonce() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _validGuardianSig(alicePk, 1, guardian, deadline);
        vm.prank(relayer);
        registry.setGuardianBySig(1, guardian, deadline, sig);
        assertEq(registry.guardianOf(1), guardian);
        assertEq(registry.nonces(alice), 2);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidSignature.selector, alice));
        registry.setGuardianBySig(1, guardian, deadline, sig);
    }

    function test_ExactlyOneNonce_RegisterForThenSetGuardianBySig() public {
        (address user, uint256 userPk) = makeAddrAndKey("user");
        uint256 deadline = block.timestamp + 1 hours;
        uint256 id = registry.nextId();
        bytes memory regSig = RegistrySigUtils.sign(vm, userPk, address(registry), block.chainid, user, 0, deadline);
        bytes memory gSig = _guardianSig(userPk, id, guardian, 0, 1, deadline);
        vm.startPrank(relayer);
        registry.registerFor(user, deadline, regSig);
        registry.setGuardianBySig(id, guardian, deadline, gSig);
        vm.stopPrank();
        assertEq(registry.guardianOf(id), guardian);
        assertEq(registry.nonces(user), 2);
    }

    function test_SetGuardianBySig_UnissuedAndInvalid() public {
        uint256 deadline = block.timestamp + 1 hours;
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__IdNotRegistered.selector, 9));
        registry.setGuardianBySig(9, guardian, deadline, new bytes(65));
        bytes memory sig = _validGuardianSig(alicePk, 1, alice, deadline);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidGuardian.selector, alice));
        registry.setGuardianBySig(1, alice, deadline, sig);
    }

    function test_SetGuardianBySig_Erc1271Owner() public {
        (address owner, uint256 ownerPk) = makeAddrAndKey("safe-owner");
        ERC1271Wallet w = new ERC1271Wallet(owner);
        vm.prank(address(w));
        uint256 id = registry.register();
        uint256 deadline = block.timestamp + 1 hours;
        registry.setGuardianBySig(id, guardian, deadline, _validGuardianSig(ownerPk, id, guardian, deadline));
        assertEq(registry.guardianOf(id), guardian);
    }

    function testFuzz_SetGuardianBySig_TamperedField(uint8 field, uint256 delta) public {
        field = uint8(bound(field, 0, 4));
        delta = bound(delta, 1, type(uint32).max);
        uint256 deadline = block.timestamp + 1 days;
        uint256 id = 1;
        address g = guardian;
        uint256 epoch = 0;
        uint256 nonce = 1;
        uint256 sDeadline = deadline;
        if (field == 0) id += delta;
        // forge-lint: disable-next-line(unsafe-typecast)
        else if (field == 1) g = address(uint160(g) ^ uint160(delta));
        else if (field == 2) epoch += delta;
        else if (field == 3) nonce += delta;
        else sDeadline += delta;
        bytes memory sig = _guardianSig(alicePk, id, g, epoch, nonce, sDeadline);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidSignature.selector, alice));
        registry.setGuardianBySig(1, guardian, deadline, sig);
    }

    function testFuzz_SetGuardianBySig_WrongSigner(uint256 pk) public {
        pk = bound(pk, 1, 115792089237316195423570985008687907852837564279074904382605163141518161494336);
        vm.assume(pk != alicePk);
        uint256 deadline = block.timestamp + 1 days;
        bytes memory sig = _validGuardianSig(pk, 1, guardian, deadline);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidSignature.selector, alice));
        registry.setGuardianBySig(1, guardian, deadline, sig);
    }

    function testFuzz_SetGuardianBySig_WrongChain(uint64 otherChain) public {
        vm.assume(otherChain != block.chainid);
        uint256 deadline = block.timestamp + 1 days;
        bytes memory sig = _validGuardianSig(alicePk, 1, guardian, deadline);
        vm.chainId(otherChain);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidSignature.selector, alice));
        registry.setGuardianBySig(1, guardian, deadline, sig);
    }

    function testFuzz_SetGuardianBySig_WrongDomain(address other) public {
        vm.assume(other != address(registry));
        uint256 deadline = block.timestamp + 1 days;
        bytes memory sig = AuthoritySigUtils.sign(
            vm, alicePk, other, block.chainid, AuthoritySigUtils.setGuardianHash(1, guardian, 0, 1, deadline)
        );
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidSignature.selector, alice));
        registry.setGuardianBySig(1, guardian, deadline, sig);
    }

    function testFuzz_SetGuardianBySig_Expired(uint256 age) public {
        age = bound(age, 1, block.timestamp);
        uint256 deadline = block.timestamp - age;
        bytes memory sig = _validGuardianSig(alicePk, 1, guardian, deadline);
        vm.expectRevert(
            abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__SignatureExpired.selector, deadline, block.timestamp)
        );
        registry.setGuardianBySig(1, guardian, deadline, sig);
    }

    function testFuzz_SetGuardianBySig_StaleEpoch(uint8 roundTrips) public {
        roundTrips = uint8(bound(roundTrips, 1, 4));
        uint256 deadline = block.timestamp + 1 days;
        bytes memory oldSig = _validGuardianSig(alicePk, 1, guardian, deadline);
        for (uint256 i = 0; i < roundTrips; i++) {
            _move(1, carol);
            _move(1, alice);
        }
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidSignature.selector, alice));
        registry.setGuardianBySig(1, guardian, deadline, oldSig);
    }

    // ─── initiate / cancel ─────────────────────────────────────────────────────────────────────────────────

    function test_Initiate_StoresAndEmits() public {
        vm.prank(alice);
        registry.setGuardian(1, guardian);
        vm.expectEmit(true, true, true, true);
        emit RecoveryInitiated(1, guardian, fresh, block.timestamp + DELAY);
        vm.prank(guardian);
        registry.initiateRecovery(1, fresh);
        (address target, uint256 readyAt) = registry.pendingRecoveryOf(1);
        assertEq(target, fresh);
        assertEq(readyAt, block.timestamp + DELAY);
        assertEq(registry.getWallet(1), alice, "nothing moves at initiation");
        assertEq(registry.RECOVERY_DELAY(), DELAY);
    }

    function test_Initiate_Reverts() public {
        vm.prank(guardian);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NotGuardian.selector, 1, guardian));
        registry.initiateRecovery(1, fresh);
        vm.prank(alice);
        registry.setGuardian(1, guardian);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NotGuardian.selector, 1, alice));
        registry.initiateRecovery(1, fresh);
        vm.startPrank(guardian);
        vm.expectRevert(OTTPRegistry.OTTPRegistry__ZeroAddress.selector);
        registry.initiateRecovery(1, address(0));
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__TargetAlreadyRegistered.selector, bob, 2));
        registry.initiateRecovery(1, bob);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NotGuardian.selector, 9, guardian));
        registry.initiateRecovery(9, fresh);
        vm.stopPrank();
        vm.prank(address(0));
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NotGuardian.selector, 9, address(0)));
        registry.initiateRecovery(9, fresh);
    }

    function test_Initiate_ReinitiateOverwritesAndRestartsClock() public {
        _setGuardianAndInitiate();
        vm.warp(block.timestamp + DELAY - 1);
        vm.prank(guardian);
        registry.initiateRecovery(1, carol);
        (address target, uint256 readyAt) = registry.pendingRecoveryOf(1);
        assertEq(target, carol);
        assertEq(readyAt, block.timestamp + DELAY);
        vm.warp(block.timestamp + 1);
        vm.prank(fresh);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NoPendingMove.selector, 1, fresh));
        registry.acceptId(1);
    }

    function test_Cancel_ByOwnerAndByGuardian() public {
        _setGuardianAndInitiate();
        vm.expectEmit(true, true, false, false);
        emit RecoveryCancelled(1, alice);
        vm.prank(alice);
        registry.cancelRecovery(1);
        (address target,) = registry.pendingRecoveryOf(1);
        assertEq(target, address(0));

        vm.prank(guardian);
        registry.initiateRecovery(1, fresh);
        vm.expectEmit(true, true, false, false);
        emit RecoveryCancelled(1, guardian);
        vm.prank(guardian);
        registry.cancelRecovery(1);
        (target,) = registry.pendingRecoveryOf(1);
        assertEq(target, address(0));
    }

    function test_Cancel_Reverts() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NoPendingRecovery.selector, 1));
        registry.cancelRecovery(1);
        _setGuardianAndInitiate();
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NotOwnerOrGuardian.selector, 1, stranger));
        registry.cancelRecovery(1);
        vm.prank(fresh);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NotOwnerOrGuardian.selector, 1, fresh));
        registry.cancelRecovery(1);
        vm.prank(address(0));
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NotOwnerOrGuardian.selector, 7, address(0)));
        registry.cancelRecovery(7);
    }

    // ─── timing & completion ───────────────────────────────────────────────────────────────────────────────

    function test_Recovery_RejectedBeforeReadyAt() public {
        uint256 readyAt = _setGuardianAndInitiate();
        vm.warp(readyAt - 1);
        vm.prank(fresh);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__RecoveryNotReady.selector, 1, readyAt));
        registry.acceptId(1);
    }

    function test_Recovery_AcceptedAtReadyAt() public {
        uint256 readyAt = _setGuardianAndInitiate();
        vm.warp(readyAt);
        vm.expectEmit(true, true, true, true);
        emit Transferred(1, alice, fresh);
        vm.expectEmit(true, true, true, true);
        emit RecoveryFinalized(1, alice, fresh);
        vm.prank(fresh);
        registry.acceptId(1);
        assertEq(registry.getWallet(1), fresh);
        assertEq(registry.getId(alice), 0);
        assertEq(registry.ownerEpoch(1), 1);
        assertEq(registry.guardianOf(1), address(0), "guardian reset by the ownership change");
        (address target,) = registry.pendingRecoveryOf(1);
        assertEq(target, address(0));
    }

    function testFuzz_Recovery_Timing(uint256 dt) public {
        dt = bound(dt, 0, 3 * DELAY);
        uint256 readyAt = _setGuardianAndInitiate();
        vm.warp(block.timestamp + dt);
        vm.prank(fresh);
        // forge-lint: disable-next-line(block-timestamp)
        if (block.timestamp < readyAt) {
            vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__RecoveryNotReady.selector, 1, readyAt));
            registry.acceptId(1);
        } else {
            registry.acceptId(1);
            assertEq(registry.getWallet(1), fresh);
        }
    }

    function test_Recovery_AcceptBySig() public {
        uint256 readyAt = _setGuardianAndInitiate();
        vm.warp(readyAt + 1);
        uint256 deadline = block.timestamp + 1 hours;
        vm.expectEmit(true, true, true, true);
        emit RecoveryFinalized(1, alice, fresh);
        vm.prank(relayer);
        registry.acceptIdBySig(1, fresh, deadline, _acceptSig(freshPk, 1, fresh, deadline));
        assertEq(registry.getWallet(1), fresh);
        assertEq(registry.nonces(fresh), 1);
    }

    function test_Recovery_DeadAfterOwnerCancel() public {
        uint256 readyAt = _setGuardianAndInitiate();
        vm.prank(alice);
        registry.cancelRecovery(1);
        vm.warp(readyAt);
        vm.prank(fresh);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NoPendingMove.selector, 1, fresh));
        registry.acceptId(1);
    }

    function test_Recovery_DeadAfterSetGuardian() public {
        uint256 readyAt = _setGuardianAndInitiate();
        vm.prank(alice);
        registry.setGuardian(1, carol);
        vm.warp(readyAt);
        vm.prank(fresh);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NoPendingMove.selector, 1, fresh));
        registry.acceptId(1);
    }

    function test_Recovery_DeadAfterOwnershipChange() public {
        uint256 readyAt = _setGuardianAndInitiate();
        _move(1, carol);
        _move(1, alice); // even back to the same owner
        vm.warp(readyAt);
        (address target,) = registry.pendingRecoveryOf(1);
        assertEq(target, address(0));
        vm.prank(fresh);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NoPendingMove.selector, 1, fresh));
        registry.acceptId(1);
    }

    function test_Recovery_TargetRegisteredMeanwhile() public {
        uint256 readyAt = _setGuardianAndInitiate();
        vm.prank(fresh);
        uint256 newId = registry.register();
        vm.warp(readyAt);
        vm.prank(fresh);
        vm.expectRevert(
            abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__TargetAlreadyRegistered.selector, fresh, newId)
        );
        registry.acceptId(1);
    }

    function test_TransferTakesPrecedenceOverRecoveryToSameWallet() public {
        _setGuardianAndInitiate();
        vm.prank(alice);
        registry.proposeTransfer(1, fresh);
        // immediately acceptable as a transfer, no RecoveryFinalized
        vm.recordLogs();
        vm.prank(fresh);
        registry.acceptId(1);
        assertEq(registry.getWallet(1), fresh);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 1, "only Transferred");
        assertEq(logs[0].topics[0], keccak256("Transferred(uint256,address,address)"));
    }

    function test_TransferAndRecoveryToDifferentWallets_FirstAcceptWins() public {
        uint256 readyAt = _setGuardianAndInitiate();
        vm.prank(alice);
        registry.proposeTransfer(1, carol);
        vm.warp(readyAt);
        vm.prank(fresh);
        registry.acceptId(1);
        vm.prank(carol);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NoPendingMove.selector, 1, carol));
        registry.acceptId(1);
    }

    function test_DelegatesResetByRecovery() public {
        vm.prank(alice);
        registry.setDelegate(1, carol, type(uint64).max);
        uint256 readyAt = _setGuardianAndInitiate();
        vm.warp(readyAt);
        vm.prank(fresh);
        registry.acceptId(1);
        assertFalse(registry.isDelegate(1, carol));
    }

    // ─── typehash separation across every signed struct ────────────────────────────────────────────────────

    /// @dev For each of the four structs, a valid signature by the right signer is presented to every OTHER
    ///      signature-taking function with matching arguments; every such cross-use must fail InvalidSignature.
    function testFuzz_TypehashSeparation_AllPairs(uint256 deadlineOffset) public {
        deadlineOffset = bound(deadlineOffset, 0, 365 days);
        uint256 deadline = block.timestamp + deadlineOffset;
        uint64 expiry = type(uint64).max;

        // `fresh` is ID-free: give it a pending transfer of id 1 so acceptIdBySig would otherwise pass.
        vm.prank(alice);
        registry.proposeTransfer(1, fresh);

        // Signatures by fresh (for registerFor/acceptIdBySig) and by alice (owner paths), each at the current nonce.
        bytes[4] memory freshSigs = _allTypes(freshPk, fresh, registry.nonces(fresh), deadline);
        bytes[4] memory aliceSigs = _allTypes(alicePk, alice, registry.nonces(alice), deadline);

        for (uint256 t = 0; t < 4; t++) {
            if (t != 0) {
                vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidSignature.selector, fresh));
                registry.registerFor(fresh, deadline, freshSigs[t]);
            }
            if (t != 1) {
                vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidSignature.selector, fresh));
                registry.acceptIdBySig(1, fresh, deadline, freshSigs[t]);
            }
            if (t != 2) {
                vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidSignature.selector, alice));
                registry.setDelegateBySig(1, fresh, expiry, deadline, aliceSigs[t]);
            }
            if (t != 3) {
                vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidSignature.selector, alice));
                registry.setGuardianBySig(1, fresh, deadline, aliceSigs[t]);
            }
        }
        // sanity: the same signatures do work for their own functions
        registry.setDelegateBySig(1, fresh, expiry, deadline, aliceSigs[2]);
        assertTrue(registry.isDelegate(1, fresh));
        registry.acceptIdBySig(1, fresh, deadline, freshSigs[1]);
        assertEq(registry.getWallet(1), fresh);
    }

    /// @dev One signature of each struct type by `pk`, with arguments matching the cross-use calls above:
    ///      Register(signer), AcceptId(1, signer), SetDelegate(1, fresh, max), SetGuardian(1, fresh); epoch 0.
    function _allTypes(uint256 pk, address signer, uint256 nonce, uint256 deadline)
        internal
        view
        returns (bytes[4] memory sigs)
    {
        sigs[0] = RegistrySigUtils.sign(vm, pk, address(registry), block.chainid, signer, nonce, deadline);
        sigs[1] = AuthoritySigUtils.sign(
            vm, pk, address(registry), block.chainid, AuthoritySigUtils.acceptIdHash(1, signer, 0, nonce, deadline)
        );
        sigs[2] = AuthoritySigUtils.sign(
            vm,
            pk,
            address(registry),
            block.chainid,
            AuthoritySigUtils.setDelegateHash(1, fresh, type(uint64).max, 0, nonce, deadline)
        );
        sigs[3] = AuthoritySigUtils.sign(
            vm, pk, address(registry), block.chainid, AuthoritySigUtils.setGuardianHash(1, fresh, 0, nonce, deadline)
        );
    }

    function test_TypehashesDistinctAndMatchAddendum() public view {
        bytes32[4] memory h = [
            registry.REGISTER_TYPEHASH(),
            registry.ACCEPT_ID_TYPEHASH(),
            registry.SET_DELEGATE_TYPEHASH(),
            registry.SET_GUARDIAN_TYPEHASH()
        ];
        for (uint256 i = 0; i < 4; i++) {
            for (uint256 j = i + 1; j < 4; j++) {
                assertTrue(h[i] != h[j]);
            }
        }
        assertEq(h[3], AuthoritySigUtils.SET_GUARDIAN_TYPEHASH);
    }
}
