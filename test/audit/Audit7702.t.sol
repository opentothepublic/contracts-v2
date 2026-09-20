// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

// AUDIT SCRATCH TESTS (2026-09-20). Run with:  forge test --match-path 'test/audit/Audit7702*' --evm-version prague
// Base mainnet is post-Pectra (EIP-7702 live), while foundry.toml pins evm_version = cancun for the build.

import { Test } from "forge-std/Test.sol";
import { Vm } from "forge-std/Vm.sol";
import { IERC1271 } from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import { OTTPRegistry } from "../../src/OTTPRegistry.sol";
import { RegistrySigUtils } from "../utils/RegistrySigUtils.sol";

/// @dev 7702 delegate that has NO ERC-1271 (e.g. a batch-executor-only implementation).
contract PlainDelegate {
    function execute(address to, bytes calldata data) external {
        (bool ok,) = to.call(data);
        require(ok);
    }
}

/// @dev 7702 delegate that implements ERC-1271 by checking the account's own EOA key (like OZ SignerEIP7702).
contract Erc1271Delegate is IERC1271 {
    function isValidSignature(bytes32 hash, bytes memory sig) external view returns (bytes4) {
        (address rec, ECDSA.RecoverError err,) = ECDSA.tryRecover(hash, sig);
        return (err == ECDSA.RecoverError.NoError && rec == address(this))
            ? IERC1271.isValidSignature.selector
            : bytes4(0xffffffff);
    }
}

contract Audit7702Test is Test {
    OTTPRegistry internal registry;
    address internal alice;
    uint256 internal alicePk;
    address internal relayer = makeAddr("relayer");

    function setUp() public {
        vm.warp(1_760_000_000);
        registry = new OTTPRegistry();
        (alice, alicePk) = makeAddrAndKey("alice");
    }

    function _sig(uint256 nonce, uint256 deadline) internal view returns (bytes memory) {
        return RegistrySigUtils.sign(vm, alicePk, address(registry), block.chainid, alice, nonce, deadline);
    }

    // 7702-delegated EOA with a delegate lacking ERC-1271: the EOA's own ECDSA signature is REJECTED by
    // SignatureChecker (code.length != 0 → 1271 path only, no ECDSA fallback in OZ 5.6.1).
    function test_7702_DelegateWithout1271_RegisterForFails_RegisterWorks() public {
        PlainDelegate impl = new PlainDelegate();
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sig(0, deadline); // signed while still a plain EOA

        Vm.SignedDelegation memory d = vm.signDelegation(address(impl), alicePk);
        vm.attachDelegation(d);
        assertGt(alice.code.length, 0, "delegation attached");

        vm.prank(relayer);
        vm.expectPartialRevert(OTTPRegistry.OTTPRegistry__InvalidSignature.selector);
        registry.registerFor(alice, deadline, sig);

        // Direct path still works (msg.sender == alice via the delegate or a plain tx from alice)
        vm.prank(alice);
        assertEq(registry.register(), 1);
    }

    // 7702-delegated EOA whose delegate implements ERC-1271 over its own key: sponsored registration works.
    function test_7702_DelegateWith1271_RegisterForWorks() public {
        Erc1271Delegate impl = new Erc1271Delegate();
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sig(0, deadline);

        Vm.SignedDelegation memory d = vm.signDelegation(address(impl), alicePk);
        vm.attachDelegation(d);

        vm.prank(relayer);
        assertEq(registry.registerFor(alice, deadline, sig), 1);
        assertEq(registry.getId(alice), 1);
    }
}
