// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import { Test } from "forge-std/Test.sol";

import { OTTPRegistry } from "../../src/OTTPRegistry.sol";
import { RegistrySigUtils } from "../utils/RegistrySigUtils.sol";

/// @notice Addendum B0 (PROPOSED): ownership epoch, the single _move path, and the shared nonce counter.
contract EpochTest is Test {
    OTTPRegistry internal registry;
    address internal alice;
    uint256 internal alicePk;
    address internal carol = makeAddr("carol");
    address internal dave = makeAddr("dave");

    event Transferred(uint256 indexed id, address indexed oldWallet, address indexed newWallet);

    function setUp() public {
        vm.warp(1_760_000_000);
        registry = new OTTPRegistry();
        (alice, alicePk) = makeAddrAndKey("alice");
    }

    function _move(uint256 id, address to) internal {
        vm.prank(registry.getWallet(id));
        registry.proposeTransfer(id, to);
        vm.prank(to);
        registry.acceptId(id);
    }

    function test_Epoch_ZeroAtIssuanceBothPaths() public {
        vm.prank(carol);
        uint256 a = registry.register();
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = RegistrySigUtils.sign(vm, alicePk, address(registry), block.chainid, alice, 0, deadline);
        uint256 b = registry.registerFor(alice, deadline, sig);
        assertEq(registry.ownerEpoch(a), 0);
        assertEq(registry.ownerEpoch(b), 0);
        assertEq(registry.ownerEpoch(0), 0);
        assertEq(registry.ownerEpoch(99), 0);
    }

    function test_Epoch_IncrementsByOneOnEveryOwnershipChange() public {
        vm.prank(alice);
        registry.register();
        vm.prank(alice);
        registry.proposeTransfer(1, carol);
        vm.expectEmit(true, true, true, true);
        emit Transferred(1, alice, carol);
        vm.prank(carol);
        registry.acceptId(1);
        assertEq(registry.ownerEpoch(1), 1);
        _move(1, dave);
        assertEq(registry.ownerEpoch(1), 2);
        _move(1, alice);
        assertEq(registry.ownerEpoch(1), 3);
    }

    function test_Epoch_ScopedPerId() public {
        vm.prank(alice);
        registry.register();
        vm.prank(carol);
        registry.register();
        _move(1, dave);
        assertEq(registry.ownerEpoch(1), 1);
        assertEq(registry.ownerEpoch(2), 0);
    }

    function test_Epoch_UnchangedByFailedMove() public {
        vm.prank(alice);
        registry.register();
        vm.prank(carol);
        registry.register();
        vm.prank(alice);
        vm.expectRevert();
        registry.proposeTransfer(1, carol);
        assertEq(registry.ownerEpoch(1), 0);
    }

    function testFuzz_Epoch_CountsMoves(uint8 hops) public {
        hops = uint8(bound(hops, 0, 20));
        vm.prank(alice);
        registry.register();
        for (uint256 i = 0; i < hops; i++) {
            _move(1, i % 2 == 0 ? carol : alice);
        }
        assertEq(registry.ownerEpoch(1), hops);
        assertEq(registry.nonces(alice), 1, "moves never touch nonces");
        assertEq(registry.nonces(carol), 0);
    }
}
