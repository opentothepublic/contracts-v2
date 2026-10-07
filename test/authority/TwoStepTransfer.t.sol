// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import { Test } from "forge-std/Test.sol";

import { OTTPRegistry } from "../../src/OTTPRegistry.sol";
import { RegistrySigUtils } from "../utils/RegistrySigUtils.sol";
import { AuthoritySigUtils } from "../utils/AuthoritySigUtils.sol";
import { ERC1271Wallet, PasswordWallet, NotAWallet } from "../mocks/ERC1271Wallet.sol";

/// @notice Addendum B1 (PROPOSED): two-step transfer — proposeTransfer / cancelTransfer / acceptId / acceptIdBySig.
contract TwoStepTransferTest is Test {
    OTTPRegistry internal registry;

    address internal alice;
    uint256 internal alicePk;
    address internal bob;
    uint256 internal bobPk;
    address internal carol;
    uint256 internal carolPk;
    address internal dave;
    uint256 internal davePk;
    address internal relayer = makeAddr("relayer");
    address internal stranger = makeAddr("stranger");

    event Transferred(uint256 indexed id, address indexed oldWallet, address indexed newWallet);
    event TransferProposed(uint256 indexed id, address indexed owner, address indexed newWallet, uint256 epoch);
    event TransferCancelled(uint256 indexed id, address indexed newWallet);

    function setUp() public {
        vm.warp(1_760_000_000);
        registry = new OTTPRegistry();
        (alice, alicePk) = makeAddrAndKey("alice");
        (bob, bobPk) = makeAddrAndKey("bob");
        (carol, carolPk) = makeAddrAndKey("carol");
        (dave, davePk) = makeAddrAndKey("dave");
        vm.prank(alice);
        registry.register(); // 1
        vm.prank(bob);
        registry.register(); // 2
    }

    // ─── helpers ───────────────────────────────────────────────────────────────────────────────────────────

    function _acceptSig(uint256 pk, uint256 id, address wallet, uint256 epoch, uint256 nonce, uint256 deadline)
        internal
        view
        returns (bytes memory)
    {
        return AuthoritySigUtils.sign(
            vm, pk, address(registry), block.chainid, AuthoritySigUtils.acceptIdHash(id, wallet, epoch, nonce, deadline)
        );
    }

    function _validAcceptSig(uint256 pk, uint256 id, address wallet, uint256 deadline)
        internal
        view
        returns (bytes memory)
    {
        return _acceptSig(pk, id, wallet, registry.ownerEpoch(id), registry.nonces(wallet), deadline);
    }

    function _move(uint256 id, address to) internal {
        vm.prank(registry.getWallet(id));
        registry.proposeTransfer(id, to);
        vm.prank(to);
        registry.acceptId(id);
    }

    // ─── proposeTransfer ───────────────────────────────────────────────────────────────────────────────────

    function test_Propose_StoresPendingAndMovesNothing() public {
        vm.expectEmit(true, true, true, true);
        emit TransferProposed(1, alice, carol, 0);
        vm.prank(alice);
        registry.proposeTransfer(1, carol);

        assertEq(registry.pendingTransferOf(1), carol);
        assertEq(registry.getWallet(1), alice, "proposal must not move the id");
        assertEq(registry.getId(carol), 0);
        assertEq(registry.ownerEpoch(1), 0);
        assertEq(registry.nonces(alice), 1, "propose consumes no nonce");
        assertEq(registry.nonces(carol), 0);
    }

    function test_Propose_OverwritesEarlierProposal() public {
        vm.startPrank(alice);
        registry.proposeTransfer(1, carol);
        registry.proposeTransfer(1, dave);
        vm.stopPrank();
        assertEq(registry.pendingTransferOf(1), dave);
        vm.prank(carol);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NoPendingMove.selector, 1, carol));
        registry.acceptId(1);
    }

    function test_Propose_RevertsForNonOwner() public {
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NotOwner.selector, 1, bob));
        registry.proposeTransfer(1, carol);
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NotOwner.selector, 1, stranger));
        registry.proposeTransfer(1, carol);
    }

    function test_Propose_RevertsForUnissuedId() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NotOwner.selector, 3, alice));
        registry.proposeTransfer(3, carol);
        vm.prank(address(0));
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NotOwner.selector, 3, address(0)));
        registry.proposeTransfer(3, carol);
    }

    function test_Propose_RevertsForZeroTarget() public {
        vm.prank(alice);
        vm.expectRevert(OTTPRegistry.OTTPRegistry__ZeroAddress.selector);
        registry.proposeTransfer(1, address(0));
    }

    function test_Propose_RevertsForRegisteredTargetIncludingSelf() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__TargetAlreadyRegistered.selector, bob, 2));
        registry.proposeTransfer(1, bob);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__TargetAlreadyRegistered.selector, alice, 1));
        registry.proposeTransfer(1, alice);
    }

    // ─── cancelTransfer ────────────────────────────────────────────────────────────────────────────────────

    function test_Cancel_ClearsPendingAndEmits() public {
        vm.prank(alice);
        registry.proposeTransfer(1, carol);
        vm.expectEmit(true, true, false, false);
        emit TransferCancelled(1, carol);
        vm.prank(alice);
        registry.cancelTransfer(1);
        assertEq(registry.pendingTransferOf(1), address(0));
        vm.prank(carol);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NoPendingMove.selector, 1, carol));
        registry.acceptId(1);
    }

    function test_Cancel_RevertsWithoutPending() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NoPendingTransfer.selector, 1));
        registry.cancelTransfer(1);
    }

    function test_Cancel_RevertsForNonOwner() public {
        vm.prank(alice);
        registry.proposeTransfer(1, carol);
        vm.prank(carol);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NotOwner.selector, 1, carol));
        registry.cancelTransfer(1);
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NotOwner.selector, 1, stranger));
        registry.cancelTransfer(1);
        assertEq(registry.pendingTransferOf(1), carol);
    }

    // ─── acceptId ──────────────────────────────────────────────────────────────────────────────────────────

    function test_Accept_MovesIdBumpsEpochClearsPending() public {
        vm.prank(alice);
        registry.proposeTransfer(1, carol);

        vm.expectEmit(true, true, true, true);
        emit Transferred(1, alice, carol);
        vm.prank(carol);
        registry.acceptId(1);

        assertEq(registry.getWallet(1), carol);
        assertEq(registry.getId(carol), 1);
        assertEq(registry.getId(alice), 0);
        assertEq(registry.ownerEpoch(1), 1);
        assertEq(registry.pendingTransferOf(1), address(0));
        assertEq(registry.nonces(carol), 0, "direct accept consumes no nonce");
        assertEq(registry.nonces(alice), 1);
        assertEq(registry.totalRegistered(), 2);
    }

    function test_Accept_RevertsForWrongWalletOrNoPending() public {
        vm.prank(carol);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NoPendingMove.selector, 1, carol));
        registry.acceptId(1);

        vm.prank(alice);
        registry.proposeTransfer(1, carol);
        vm.prank(dave);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NoPendingMove.selector, 1, dave));
        registry.acceptId(1);
        // the owner cannot accept on the target's behalf
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NoPendingMove.selector, 1, alice));
        registry.acceptId(1);
    }

    function test_Accept_RevertsForUnissuedId() public {
        vm.prank(carol);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NoPendingMove.selector, 99, carol));
        registry.acceptId(99);
        vm.prank(carol);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NoPendingMove.selector, 0, carol));
        registry.acceptId(0);
    }

    function test_Accept_RevertsIfTargetRegisteredInTheMeantime() public {
        vm.prank(alice);
        registry.proposeTransfer(1, carol);
        vm.prank(carol);
        registry.register(); // 3
        vm.prank(carol);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__TargetAlreadyRegistered.selector, carol, 3));
        registry.acceptId(1);
        assertEq(registry.getWallet(1), alice);
    }

    function test_Accept_OnlyOnce() public {
        _move(1, carol);
        vm.prank(carol);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NoPendingMove.selector, 1, carol));
        registry.acceptId(1);
    }

    function test_Accept_OldPendingDeadAfterRoundTrip() public {
        // alice proposes to dave, then moves the id to carol and back; dave's epoch-0 proposal must stay dead.
        vm.prank(alice);
        registry.proposeTransfer(1, dave);
        _move(1, carol); // overwrites dave's proposal, epoch 1
        _move(1, alice); // epoch 2
        assertEq(registry.ownerEpoch(1), 2);
        assertEq(registry.pendingTransferOf(1), address(0));
        vm.prank(dave);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NoPendingMove.selector, 1, dave));
        registry.acceptId(1);
    }

    function test_Accept_OldWalletCanRegisterFreshIdButNeverGetsOldBack() public {
        _move(1, carol);
        vm.prank(alice);
        assertEq(registry.register(), 3);
        assertEq(registry.getWallet(1), carol);
    }

    function test_TransferId_IsGone() public {
        (bool ok,) = address(registry).call(abi.encodeWithSignature("transferId(uint256,address)", 1, carol));
        assertFalse(ok, "one-step transferId must not exist");
        assertEq(registry.getWallet(1), alice);
    }

    function test_NoPush_TargetNeverReceivesWithoutOwnAction() public {
        // proposing to a verified wallet changes nothing for it, however many times; only its own call moves the id
        vm.startPrank(alice);
        registry.proposeTransfer(1, carol);
        registry.proposeTransfer(1, carol);
        vm.stopPrank();
        vm.warp(block.timestamp + 365 days);
        assertEq(registry.getId(carol), 0);
        vm.prank(carol);
        registry.register(); // carol's one-ID slot is still hers to fill
        assertEq(registry.getId(carol), 3);
    }

    // ─── acceptIdBySig ─────────────────────────────────────────────────────────────────────────────────────

    function test_AcceptBySig_RelayedSucceedsAndConsumesExactlyOneNonce() public {
        vm.prank(alice);
        registry.proposeTransfer(1, carol);
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _validAcceptSig(carolPk, 1, carol, deadline);

        vm.expectEmit(true, true, true, true);
        emit Transferred(1, alice, carol);
        vm.prank(relayer);
        registry.acceptIdBySig(1, carol, deadline, sig);

        assertEq(registry.getWallet(1), carol);
        assertEq(registry.nonces(carol), 1, "exactly one nonce");
        assertEq(registry.nonces(relayer), 0);
        assertEq(registry.getId(relayer), 0, "relayer never receives an id");
    }

    function test_AcceptBySig_DeadlineBoundaryInclusive() public {
        vm.prank(alice);
        registry.proposeTransfer(1, carol);
        uint256 deadline = block.timestamp;
        bytes memory sig = _validAcceptSig(carolPk, 1, carol, deadline);
        registry.acceptIdBySig(1, carol, deadline, sig);
        assertEq(registry.getWallet(1), carol);
    }

    function test_AcceptBySig_Erc1271Wallets() public {
        (address owner, uint256 ownerPk) = makeAddrAndKey("safe-owner");
        ERC1271Wallet w = new ERC1271Wallet(owner);
        vm.prank(alice);
        registry.proposeTransfer(1, address(w));
        uint256 deadline = block.timestamp + 1 hours;
        registry.acceptIdBySig(1, address(w), deadline, _validAcceptSig(ownerPk, 1, address(w), deadline));
        assertEq(registry.getWallet(1), address(w));
        assertEq(registry.nonces(address(w)), 1);

        PasswordWallet pw = new PasswordWallet(keccak256("pw"));
        vm.prank(bob);
        registry.proposeTransfer(2, address(pw));
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidSignature.selector, address(pw)));
        registry.acceptIdBySig(2, address(pw), deadline, abi.encode(keccak256("wrong")));
        registry.acceptIdBySig(2, address(pw), deadline, abi.encode(keccak256("pw")));
        assertEq(registry.getWallet(2), address(pw));
    }

    function test_AcceptBySig_NonWalletContractRejected() public {
        NotAWallet nw = new NotAWallet();
        vm.prank(alice);
        registry.proposeTransfer(1, address(nw));
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidSignature.selector, address(nw)));
        registry.acceptIdBySig(1, address(nw), block.timestamp, hex"");
    }

    function test_AcceptBySig_ZeroWalletRejected() public {
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidSignature.selector, address(0)));
        registry.acceptIdBySig(1, address(0), block.timestamp, new bytes(65));
    }

    function test_AcceptBySig_ValidSigButNoPendingMoveRevertsAndKeepsNonce() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _validAcceptSig(carolPk, 1, carol, deadline);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NoPendingMove.selector, 1, carol));
        registry.acceptIdBySig(1, carol, deadline, sig);
        assertEq(registry.nonces(carol), 0, "failed call must not move the nonce");
        // the same signature works once the owner proposes
        vm.prank(alice);
        registry.proposeTransfer(1, carol);
        registry.acceptIdBySig(1, carol, deadline, sig);
        assertEq(registry.getWallet(1), carol);
    }

    function test_AcceptBySig_StaleEpochRejected() public {
        // carol signs at epoch 0 for id 1; the id goes alice → dave → (proposal to carol) at epoch 1.
        uint256 deadline = block.timestamp + 1 days;
        bytes memory oldSig = _acceptSig(carolPk, 1, carol, 0, 0, deadline);
        _move(1, dave);
        vm.prank(dave);
        registry.proposeTransfer(1, carol);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidSignature.selector, carol));
        registry.acceptIdBySig(1, carol, deadline, oldSig);
        // a fresh signature at the current epoch works
        registry.acceptIdBySig(1, carol, deadline, _validAcceptSig(carolPk, 1, carol, deadline));
        assertEq(registry.getWallet(1), carol);
    }

    // ─── fuzz: signature path ──────────────────────────────────────────────────────────────────────────────

    function testFuzz_AcceptBySig_Replay(uint256 deadlineOffset) public {
        deadlineOffset = bound(deadlineOffset, 0, 365 days);
        uint256 deadline = block.timestamp + deadlineOffset;
        vm.prank(alice);
        registry.proposeTransfer(1, carol);
        bytes memory sig = _validAcceptSig(carolPk, 1, carol, deadline);
        registry.acceptIdBySig(1, carol, deadline, sig);

        // carol gives the id back and alice re-proposes: the old signature is dead (nonce and epoch both moved)
        _move(1, alice);
        vm.prank(alice);
        registry.proposeTransfer(1, carol);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidSignature.selector, carol));
        registry.acceptIdBySig(1, carol, deadline, sig);
    }

    /// @dev Each signed field tampered by a non-zero delta → InvalidSignature (or an earlier, field-specific revert).
    function testFuzz_AcceptBySig_TamperedField(uint8 field, uint256 delta) public {
        field = uint8(bound(field, 0, 4));
        delta = bound(delta, 1, type(uint64).max);
        vm.prank(alice);
        registry.proposeTransfer(1, carol);
        uint256 deadline = block.timestamp + 1 days;
        uint256 id = 1;
        address wallet = carol;
        uint256 epoch = 0;
        uint256 nonce = 0;
        uint256 signedDeadline = deadline;
        if (field == 0) id += delta;
        // forge-lint: disable-next-line(unsafe-typecast)
        else if (field == 1) wallet = address(uint160(wallet) ^ uint160(delta));
        else if (field == 2) epoch += delta;
        else if (field == 3) nonce += delta;
        else signedDeadline += delta;
        bytes memory sig = _acceptSig(carolPk, id, wallet, epoch, nonce, signedDeadline);

        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidSignature.selector, carol));
        registry.acceptIdBySig(1, carol, deadline, sig);
        assertEq(registry.getWallet(1), alice);
        assertEq(registry.nonces(carol), 0);
    }

    function testFuzz_AcceptBySig_WrongSigner(uint256 pk) public {
        pk = bound(pk, 1, 115792089237316195423570985008687907852837564279074904382605163141518161494336);
        vm.assume(pk != carolPk);
        vm.prank(alice);
        registry.proposeTransfer(1, carol);
        uint256 deadline = block.timestamp + 1 days;
        bytes memory sig = _validAcceptSig(pk, 1, carol, deadline);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidSignature.selector, carol));
        registry.acceptIdBySig(1, carol, deadline, sig);
    }

    function testFuzz_AcceptBySig_WrongChainOrDomain(uint256 chainId, address verifyingContract, uint8 which) public {
        which = uint8(bound(which, 0, 3));
        vm.prank(alice);
        registry.proposeTransfer(1, carol);
        uint256 deadline = block.timestamp + 1 days;
        bytes32 structHash = AuthoritySigUtils.acceptIdHash(1, carol, 0, 0, deadline);
        bytes32 domain;
        if (which == 0) {
            vm.assume(chainId != block.chainid);
            domain = RegistrySigUtils.domainSeparator(address(registry), chainId);
        } else if (which == 1) {
            vm.assume(verifyingContract != address(registry));
            domain = RegistrySigUtils.domainSeparator(verifyingContract, block.chainid);
        } else {
            domain = keccak256(
                abi.encode(
                    RegistrySigUtils.EIP712_DOMAIN_TYPEHASH,
                    keccak256(which == 2 ? bytes("OTTPRegistryX") : bytes("OTTPRegistry")),
                    keccak256(which == 2 ? bytes("2") : bytes("1")),
                    block.chainid,
                    address(registry)
                )
            );
        }
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(carolPk, keccak256(abi.encodePacked("\x19\x01", domain, structHash)));
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidSignature.selector, carol));
        registry.acceptIdBySig(1, carol, deadline, abi.encodePacked(r, s, v));
    }

    function testFuzz_AcceptBySig_WrongChainAtSubmission(uint64 otherChain) public {
        vm.assume(otherChain != block.chainid);
        vm.prank(alice);
        registry.proposeTransfer(1, carol);
        uint256 deadline = block.timestamp + 1 days;
        bytes memory sig = _validAcceptSig(carolPk, 1, carol, deadline);
        vm.chainId(otherChain); // same signature, replayed on a different chain (domain recomputed)
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidSignature.selector, carol));
        registry.acceptIdBySig(1, carol, deadline, sig);
    }

    function testFuzz_AcceptBySig_Expired(uint256 age) public {
        age = bound(age, 1, block.timestamp);
        uint256 deadline = block.timestamp - age;
        vm.prank(alice);
        registry.proposeTransfer(1, carol);
        bytes memory sig = _validAcceptSig(carolPk, 1, carol, deadline);
        vm.expectRevert(
            abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__SignatureExpired.selector, deadline, block.timestamp)
        );
        registry.acceptIdBySig(1, carol, deadline, sig);
    }

    function testFuzz_AcceptBySig_StaleEpoch(uint8 hops) public {
        hops = uint8(bound(hops, 1, 6));
        uint256 deadline = block.timestamp + 1 days;
        bytes memory oldSig = _acceptSig(carolPk, 1, carol, 0, 0, deadline);
        for (uint256 i = 0; i < hops; i++) {
            _move(1, i % 2 == 0 ? dave : alice);
        }
        address owner = registry.getWallet(1);
        vm.prank(owner);
        registry.proposeTransfer(1, carol);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidSignature.selector, carol));
        registry.acceptIdBySig(1, carol, deadline, oldSig);
    }

    /// @dev Typehash separation: a Register signature with the same signer/nonce/deadline never authorizes an accept,
    ///      and an AcceptId signature never authorizes a registration.
    function testFuzz_AcceptBySig_TypehashSeparationWithRegister(uint256 deadlineOffset) public {
        deadlineOffset = bound(deadlineOffset, 0, 365 days);
        uint256 deadline = block.timestamp + deadlineOffset;
        vm.prank(alice);
        registry.proposeTransfer(1, carol);

        bytes memory registerSig =
            RegistrySigUtils.sign(vm, carolPk, address(registry), block.chainid, carol, 0, deadline);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidSignature.selector, carol));
        registry.acceptIdBySig(1, carol, deadline, registerSig);

        bytes memory acceptSig = _validAcceptSig(carolPk, 1, carol, deadline);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidSignature.selector, carol));
        registry.registerFor(carol, deadline, acceptSig);
    }

    function test_TypehashConstantMatchesAddendum() public view {
        assertEq(registry.ACCEPT_ID_TYPEHASH(), AuthoritySigUtils.ACCEPT_ID_TYPEHASH);
        assertTrue(registry.ACCEPT_ID_TYPEHASH() != registry.REGISTER_TYPEHASH());
    }
}
