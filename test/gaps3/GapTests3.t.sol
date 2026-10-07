// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import { Test, Vm } from "forge-std/Test.sol";

import { OTTPRegistry } from "../../src/OTTPRegistry.sol";
import { AuthoritySigUtils } from "../utils/AuthoritySigUtils.sol";

/// @notice Mutation-gap tests for the authority addendum (B0–B3, PROPOSED). Each test names the surviving mutant(s)
///         it kills; all pass on the unmutated code.
contract GapTests3 is Test {
    OTTPRegistry internal registry;

    address internal alice;
    uint256 internal alicePk;
    address internal bob;
    address internal guardian;
    address internal carol;
    uint256 internal carolPk;
    address internal dave;
    uint256 internal davePk;
    address internal delegate = makeAddr("delegate");
    address internal relayer = makeAddr("relayer");

    uint256 internal constant DELAY = 7 days;

    // storage slots (forge inspect OTTPRegistry storageLayout)
    uint256 internal constant SLOT_PENDING_TRANSFER = 7;
    uint256 internal constant SLOT_PENDING_RECOVERY = 10;

    event TransferProposed(uint256 indexed id, address indexed owner, address indexed newWallet, uint256 epoch);
    event DelegateSet(uint256 indexed id, address indexed delegate, uint64 expiry, uint256 epoch);
    event GuardianSet(uint256 indexed id, address indexed guardian, uint256 epoch);
    event RecoveryCancelled(uint256 indexed id, address indexed by);

    function setUp() public {
        vm.warp(1_760_000_000);
        registry = new OTTPRegistry();
        (alice, alicePk) = makeAddrAndKey("alice");
        bob = makeAddr("bob");
        guardian = makeAddr("guardian");
        (carol, carolPk) = makeAddrAndKey("carol");
        (dave, davePk) = makeAddrAndKey("dave");
        vm.prank(alice);
        registry.register(); // 1
        vm.prank(bob);
        registry.register(); // 2
    }

    // ─── helpers ───────────────────────────────────────────────────────────────────────────────────────────

    /// @dev Move ID 1 alice -> carol -> alice so ownerEpoch[1] == 2 and alice owns it again.
    function _bumpEpochTwice() internal {
        vm.prank(alice);
        registry.proposeTransfer(1, carol);
        vm.prank(carol);
        registry.acceptId(1);
        vm.prank(carol);
        registry.proposeTransfer(1, alice);
        vm.prank(alice);
        registry.acceptId(1);
        assertEq(registry.ownerEpoch(1), 2);
        assertEq(registry.getWallet(1), alice);
    }

    function _slot(uint256 id, uint256 base) internal pure returns (bytes32) {
        return keccak256(abi.encode(id, base));
    }

    function _sign(uint256 pk, bytes32 structHash) internal view returns (bytes memory) {
        return AuthoritySigUtils.sign(vm, pk, address(registry), block.chainid, structHash);
    }

    function _countTopic(Vm.Log[] memory logs, bytes32 topic0) internal pure returns (uint256 n) {
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics.length > 0 && logs[i].topics[0] == topic0) n++;
        }
    }

    // ─── event epoch args at epoch > 0 (R12, R89, R99) ─────────────────────────────────────────────────────

    /// @dev Kills: TransferProposed emitted with a constant/zero epoch (existing tests only check at epoch 0).
    function test_TransferProposed_EmitsCurrentNonZeroEpoch() public {
        _bumpEpochTwice();
        vm.expectEmit(true, true, true, true, address(registry));
        emit TransferProposed(1, alice, dave, 2);
        vm.prank(alice);
        registry.proposeTransfer(1, dave);
    }

    /// @dev Kills: DelegateSet emitted with a constant/zero epoch, on the direct and BySig paths and on revoke.
    function test_DelegateSet_EmitsCurrentNonZeroEpoch() public {
        _bumpEpochTwice();
        vm.expectEmit(true, true, true, true, address(registry));
        emit DelegateSet(1, delegate, type(uint64).max, 2);
        vm.prank(alice);
        registry.setDelegate(1, delegate, type(uint64).max);

        vm.expectEmit(true, true, true, true, address(registry));
        emit DelegateSet(1, delegate, 0, 2);
        vm.prank(alice);
        registry.setDelegate(1, delegate, 0);

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig =
            _sign(alicePk, AuthoritySigUtils.setDelegateHash(1, delegate, 5e9, 2, registry.nonces(alice), deadline));
        vm.expectEmit(true, true, true, true, address(registry));
        emit DelegateSet(1, delegate, 5e9, 2);
        vm.prank(relayer);
        registry.setDelegateBySig(1, delegate, 5e9, deadline, sig);
    }

    /// @dev Kills: GuardianSet emitted with a constant/zero epoch, on the direct and BySig paths.
    function test_GuardianSet_EmitsCurrentNonZeroEpoch() public {
        _bumpEpochTwice();
        vm.expectEmit(true, true, true, true, address(registry));
        emit GuardianSet(1, guardian, 2);
        vm.prank(alice);
        registry.setGuardian(1, guardian);

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig =
            _sign(alicePk, AuthoritySigUtils.setGuardianHash(1, address(0), 2, registry.nonces(alice), deadline));
        vm.expectEmit(true, true, true, true, address(registry));
        emit GuardianSet(1, address(0), 2);
        vm.prank(relayer);
        registry.setGuardianBySig(1, address(0), deadline, sig);
    }

    // ─── setGuardian emits RecoveryCancelled only when a live recovery existed (R97) ────────────────────────

    /// @dev Kills: _setGuardian emitting RecoveryCancelled unconditionally. Spec B3: "emitting
    ///      RecoveryCancelled(id, owner) when one existed".
    function test_SetGuardian_NoRecoveryCancelledWithoutLiveRecovery() public {
        bytes32 topic = RecoveryCancelled.selector;

        vm.recordLogs();
        vm.prank(alice);
        registry.setGuardian(1, guardian); // no recovery ever
        assertEq(_countTopic(vm.getRecordedLogs(), topic), 0, "spurious RecoveryCancelled (none pending)");

        // a recovery that was cancelled is gone; a later setGuardian must not report another cancellation
        vm.prank(guardian);
        registry.initiateRecovery(1, dave);
        vm.prank(alice);
        registry.cancelRecovery(1);
        vm.recordLogs();
        vm.prank(alice);
        registry.setGuardian(1, address(0));
        assertEq(_countTopic(vm.getRecordedLogs(), topic), 0, "spurious RecoveryCancelled (after cancel)");

        // with a live recovery: exactly one, by the owner
        vm.prank(alice);
        registry.setGuardian(1, guardian);
        vm.prank(guardian);
        registry.initiateRecovery(1, dave);
        vm.recordLogs();
        vm.prank(alice);
        registry.setGuardian(1, guardian);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(_countTopic(logs, topic), 1, "expected exactly one RecoveryCancelled");
    }

    /// @dev Kills: the BySig path attributing the implicit cancellation to msg.sender (the relayer) instead of the
    ///      owner. Spec B3: RecoveryCancelled(id, owner).
    function test_SetGuardianBySig_ImplicitCancelAttributedToOwnerNotRelayer() public {
        vm.prank(alice);
        registry.setGuardian(1, guardian);
        vm.prank(guardian);
        registry.initiateRecovery(1, dave);

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sign(
            alicePk,
            AuthoritySigUtils.setGuardianHash(1, guardian, registry.ownerEpoch(1), registry.nonces(alice), deadline)
        );
        vm.expectEmit(true, true, true, true, address(registry));
        emit RecoveryCancelled(1, alice);
        vm.prank(relayer);
        registry.setGuardianBySig(1, guardian, deadline, sig);
        (address r,) = registry.pendingRecoveryOf(1);
        assertEq(r, address(0));
    }

    // ─── _move storage hygiene (R70, R71) ──────────────────────────────────────────────────────────────────

    /// @dev Kills: _move not deleting the pending transfer / pending recovery. The epoch check hides stale records
    ///      from every view, so only raw storage shows the difference; spec §2.3 step 3 requires the deletes.
    function test_Move_DeletesPendingTransferAndRecoveryStorage_RecoveryPath() public {
        vm.prank(alice);
        registry.setGuardian(1, guardian);
        vm.prank(alice);
        registry.proposeTransfer(1, carol); // pending transfer to carol stays unaccepted
        vm.prank(guardian);
        registry.initiateRecovery(1, dave);
        vm.warp(block.timestamp + DELAY);
        vm.prank(dave);
        registry.acceptId(1); // recovery path
        assertEq(registry.getWallet(1), dave);

        assertEq(vm.load(address(registry), _slot(1, SLOT_PENDING_TRANSFER)), bytes32(0), "pending transfer kept");
        bytes32 rs = _slot(1, SLOT_PENDING_RECOVERY);
        assertEq(vm.load(address(registry), rs), bytes32(0), "pending recovery kept");
        assertEq(vm.load(address(registry), bytes32(uint256(rs) + 1)), bytes32(0), "recovery readyAt kept");
    }

    function test_Move_DeletesPendingTransferAndRecoveryStorage_TransferPath() public {
        vm.prank(alice);
        registry.setGuardian(1, guardian);
        vm.prank(guardian);
        registry.initiateRecovery(1, dave); // pending recovery to dave stays unaccepted
        vm.prank(alice);
        registry.proposeTransfer(1, carol);
        vm.prank(carol);
        registry.acceptId(1); // transfer path
        assertEq(registry.getWallet(1), carol);

        assertEq(vm.load(address(registry), _slot(1, SLOT_PENDING_TRANSFER)), bytes32(0), "pending transfer kept");
        bytes32 rs = _slot(1, SLOT_PENDING_RECOVERY);
        assertEq(vm.load(address(registry), rs), bytes32(0), "pending recovery kept");
        assertEq(vm.load(address(registry), bytes32(uint256(rs) + 1)), bytes32(0), "recovery readyAt kept");
    }

    // ─── wallet == 0 never matches an empty record (R75, R76) ──────────────────────────────────────────────

    /// @dev Kills: removing either `wallet == address(0)` guard in _accept. With no pending transfer and no pending
    ///      recovery, both empty records read as target 0, so a zero-address sender would move the ID to address(0)
    ///      (spec v1.2 D1 defense in depth; the existing suite tests the other zero-sender guards the same way).
    function test_AcceptId_ZeroSenderNeverMatchesEmptyRecords() public {
        vm.prank(address(0));
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NoPendingMove.selector, 1, address(0)));
        registry.acceptId(1);

        // also with a live transfer to someone else (outer guard bypassed by the transfer mismatch)
        vm.prank(alice);
        registry.proposeTransfer(1, carol);
        vm.prank(address(0));
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NoPendingMove.selector, 1, address(0)));
        registry.acceptId(1);

        // and for an unissued id
        vm.prank(address(0));
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NoPendingMove.selector, 99, address(0)));
        registry.acceptId(99);

        assertEq(registry.getWallet(1), alice);
        assertEq(registry.getId(address(0)), 0);
    }

    // ─── direct calls never touch nonces, spec §2.4 (R125, R127, R128) ─────────────────────────────────────

    function _nonces() internal view returns (uint256[4] memory n) {
        n[0] = registry.nonces(alice);
        n[1] = registry.nonces(guardian);
        n[2] = registry.nonces(carol);
        n[3] = registry.nonces(dave);
    }

    function _assertNoncesUnchanged(uint256[4] memory before, string memory what) internal view {
        uint256[4] memory a = _nonces();
        for (uint256 i = 0; i < 4; i++) {
            assertEq(a[i], before[i], what);
        }
    }

    /// @dev Kills: any direct (non-signature) path consuming a nonce. Covers every direct authority call, by owner,
    ///      guardian and receiver; the invariant handler has no nonce model, so only this pins the rule.
    function test_DirectCalls_NeverTouchNonces() public {
        uint256[4] memory n0 = _nonces();

        vm.prank(alice);
        registry.proposeTransfer(1, carol);
        _assertNoncesUnchanged(n0, "proposeTransfer");
        vm.prank(alice);
        registry.cancelTransfer(1);
        _assertNoncesUnchanged(n0, "cancelTransfer");
        vm.prank(alice);
        registry.setDelegate(1, delegate, type(uint64).max);
        _assertNoncesUnchanged(n0, "setDelegate");
        vm.prank(alice);
        registry.setGuardian(1, guardian);
        _assertNoncesUnchanged(n0, "setGuardian");
        vm.prank(guardian);
        registry.initiateRecovery(1, dave);
        _assertNoncesUnchanged(n0, "initiateRecovery");
        vm.prank(guardian);
        registry.cancelRecovery(1);
        _assertNoncesUnchanged(n0, "cancelRecovery (guardian)");
        vm.prank(guardian);
        registry.initiateRecovery(1, dave);
        vm.prank(alice);
        registry.cancelRecovery(1);
        _assertNoncesUnchanged(n0, "cancelRecovery (owner)");
        vm.prank(guardian);
        registry.initiateRecovery(1, dave);
        vm.warp(block.timestamp + DELAY);
        vm.prank(dave);
        registry.acceptId(1);
        _assertNoncesUnchanged(n0, "acceptId (recovery)");
        vm.prank(dave);
        registry.proposeTransfer(1, carol);
        vm.prank(carol);
        registry.acceptId(1);
        _assertNoncesUnchanged(n0, "acceptId (transfer)");
    }

    // ─── BySig check order, spec §2.6: deadline first (R118, R119, R121) ───────────────────────────────────

    /// @dev Kills: owner-signed BySig paths checking ID existence before the deadline.
    function test_BySig_DeadlineCheckedBeforeExistence() public {
        uint256 deadline = block.timestamp - 1;
        vm.expectRevert(
            abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__SignatureExpired.selector, deadline, block.timestamp)
        );
        registry.setDelegateBySig(99, delegate, type(uint64).max, deadline, hex"");
        vm.expectRevert(
            abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__SignatureExpired.selector, deadline, block.timestamp)
        );
        registry.setGuardianBySig(99, guardian, deadline, hex"");
    }

    /// @dev Kills: acceptIdBySig verifying the signature before the deadline.
    function test_AcceptIdBySig_DeadlineCheckedBeforeSignature() public {
        uint256 deadline = block.timestamp - 1;
        vm.expectRevert(
            abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__SignatureExpired.selector, deadline, block.timestamp)
        );
        registry.acceptIdBySig(1, carol, deadline, hex"");
    }
}
