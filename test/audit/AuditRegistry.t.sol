// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

// AUDIT SCRATCH TESTS (2026-09-20). Not part of the main suite. Each test documents a finding by construction:
// a PASSING test here means the described behaviour is REAL on the current code.

import { Test } from "forge-std/Test.sol";
import { IERC1271 } from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import { IEAS } from "@ethereum-attestation-service/eas-contracts/contracts/IEAS.sol";

import { OTTPRegistry } from "../../src/OTTPRegistry.sol";
import { OTTPSubjectResolver } from "../../src/OTTPSubjectResolver.sol";
import { RegistrySigUtils } from "../utils/RegistrySigUtils.sol";
import { MockEAS } from "../mocks/MockEAS.sol";

/// @dev A contract whose fallback answers the ERC-1271 magic value to ANY call (a buggy / over-permissive wallet).
contract PermissiveWallet {
    fallback(bytes calldata) external returns (bytes memory) {
        return abi.encode(IERC1271.isValidSignature.selector);
    }
}

/// @dev A 1271 wallet whose verifier re-derives the digest from registry.nonces(wallet) (a plausible but wrong
///      wallet implementation) — used to show the nonce-consumed-before-verify ordering is observable by 1271 wallets.
contract NonceReadingWallet is IERC1271 {
    OTTPRegistry public immutable registry;
    uint256 public seenNonce = type(uint256).max;

    constructor(OTTPRegistry r) {
        registry = r;
    }

    function isValidSignature(bytes32, bytes memory) external view returns (bytes4) {
        // Only records what the wallet would observe if it tried to reconstruct the digest itself.
        // (view: we cannot write; return whether nonce is 0 as the "expected first nonce")
        return registry.nonces(address(this)) == 0 ? IERC1271.isValidSignature.selector : bytes4(0xffffffff);
    }
}

contract AuditRegistryTest is Test {
    OTTPRegistry internal registry;
    MockEAS internal eas;
    OTTPSubjectResolver internal subjectResolver;

    address internal alice;
    uint256 internal alicePk;
    address internal alice2 = makeAddr("alice2");
    address internal mallory = makeAddr("mallory");

    function setUp() public {
        vm.warp(1_760_000_000);
        registry = new OTTPRegistry();
        eas = new MockEAS();
        subjectResolver = new OTTPSubjectResolver(IEAS(address(eas)), registry);
        (alice, alicePk) = makeAddrAndKey("alice");
    }

    function _sig(uint256 pk, address wallet, uint256 nonce, uint256 deadline) internal view returns (bytes memory) {
        return RegistrySigUtils.sign(vm, pk, address(registry), block.chainid, wallet, nonce, deadline);
    }

    // ── A1: register() does not consume the EIP-712 nonce → a stale Register signature outlives a direct
    //       registration and a transfer, and lets a third party re-register the old wallet (LOW, griefing). ──
    function test_A1_StaleRegisterSignature_UsableAfterDirectRegisterAndTransfer() public {
        // Alice signs a sponsored-registration message (long deadline, as a relayer UI might request) ...
        uint256 deadline = type(uint256).max;
        bytes memory stale = _sig(alicePk, alice, 0, deadline);

        // ... but the relayer is slow, so she registers herself directly. Nonce stays 0.
        vm.prank(alice);
        uint256 id = registry.register();
        assertEq(id, 1);
        assertEq(registry.nonces(alice), 0, "register() leaves the signature nonce untouched");

        // Later she rotates keys: id 1 moves to alice2. Wallet `alice` is now ID-free again.
        vm.prank(alice);
        registry.transferId(1, alice2);
        assertEq(registry.getId(alice), 0);

        // Anyone holding the stale signature can now register `alice` a second time, against her will.
        vm.prank(mallory);
        uint256 unwanted = registry.registerFor(alice, deadline, stale);
        assertEq(unwanted, 2);
        assertEq(registry.getId(alice), 2, "old wallet re-registered without owner action");

        // Concrete harm: alice2 can no longer move id 1 back to `alice` (target must be ID-free).
        vm.prank(alice2);
        vm.expectRevert("Target wallet already has an OTTP ID");
        registry.transferId(1, alice);
        // Recoverable only by alice spending gas to park id 2 somewhere else first.
    }

    // ── A2: over-permissive ERC-1271 implementation ⇒ anyone can force-register that contract (LOW/INFO). ──
    function test_A2_PermissiveErc1271_CanBeForceRegisteredByAnyone() public {
        PermissiveWallet w = new PermissiveWallet();
        vm.prank(mallory);
        uint256 id = registry.registerFor(address(w), block.timestamp + 1, "");
        assertEq(registry.getId(address(w)), id);
        // Harm is confined to that contract (it now holds an ID it did not ask for); bijection is intact.
        assertEq(registry.getWallet(id), address(w));
    }

    // ── A3: nonce is consumed BEFORE the ERC-1271 call, so a 1271 wallet that reads registry.nonces() during
    //       validation observes nonce+1 (INFO: ordering is atomic and safe, but observable). ──
    function test_A3_NonceIncrementVisibleToErc1271Wallet() public {
        NonceReadingWallet w = new NonceReadingWallet(registry);
        // The wallet accepts only when it observes nonce == 0; the registry has already bumped it to 1.
        vm.prank(mallory);
        vm.expectRevert("Invalid signature");
        registry.registerFor(address(w), block.timestamp + 1, "");
        assertEq(registry.nonces(address(w)), 0, "nonce rolled back with the revert");
    }

    // ── A4: hostile `wallet` values in registerFor are all rejected (registry, resolver, mock EAS, precompiles, 0). ──
    function test_A4_UnusualWalletValues_Rejected() public {
        uint256 deadline = block.timestamp + 1;
        bytes memory junk = new bytes(65);
        address[] memory targets = new address[](5);
        targets[0] = address(registry);
        targets[1] = address(subjectResolver);
        targets[2] = address(eas);
        targets[3] = address(0);
        targets[4] = address(this);
        for (uint256 i = 0; i < targets.length; ++i) {
            vm.prank(mallory);
            vm.expectRevert("Invalid signature");
            registry.registerFor(targets[i], deadline, junk);
        }
        // precompiles 0x01..0x0a: no code → ECDSA path → must recover to the precompile address (infeasible)
        for (uint160 p = 1; p <= 10; ++p) {
            vm.prank(mallory);
            vm.expectRevert("Invalid signature");
            registry.registerFor(address(p), deadline, junk);
            vm.prank(mallory);
            vm.expectRevert("Invalid signature");
            registry.registerFor(address(p), deadline, "");
        }
    }

    // ── A5: an EOA-signed Register is NOT accepted if the wallet has code at submission time (7702 or otherwise)
    //       unless that code implements ERC-1271 for the EOA key. Shown here with raw 0xEF01 delegation bytes on the
    //       cancun EVM (delegation not followed → the code itself is executed → invalid opcode → false). ──
    function test_A5_EoaSignsThenGetsCode_SignatureNoLongerAccepted() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sig(alicePk, alice, 0, deadline);
        // simulate a 7702 delegation designator appearing on alice between signing and relaying
        vm.etch(alice, abi.encodePacked(hex"ef0100", makeAddr("someDelegate")));
        vm.prank(mallory);
        vm.expectRevert("Invalid signature");
        registry.registerFor(alice, deadline, sig);
        // she can still register directly
        vm.etch(alice, "");
        vm.prank(alice);
        assertEq(registry.register(), 1);
    }

    // ── A6: the same registerFor signature is rejected by a second registry deployment (domain binds address). ──
    function test_A6_SignatureNotValidOnSiblingDeployment() public {
        OTTPRegistry other = new OTTPRegistry();
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sig(alicePk, alice, 0, deadline); // bound to `registry`
        vm.prank(mallory);
        vm.expectRevert("Invalid signature");
        other.registerFor(alice, deadline, sig);
        vm.prank(mallory);
        assertEq(registry.registerFor(alice, deadline, sig), 1);
    }

    // ── A7: ERC-2098 compact (64-byte) signatures are NOT accepted (INFO: SDK must always emit 65-byte r||s||v). ──
    function test_A7_CompactSignatureRejected() public {
        uint256 deadline = block.timestamp + 1 hours;
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(alicePk, RegistrySigUtils.digest(address(registry), block.chainid, alice, 0, deadline));
        bytes32 vs = bytes32((uint256(v - 27) << 255) | uint256(s));
        vm.prank(mallory);
        vm.expectRevert("Invalid signature");
        registry.registerFor(alice, deadline, abi.encodePacked(r, vs));
    }

    // ── A8: v ∈ {0,1} (some libraries) is rejected; only 27/28 accepted (INFO). ──
    function test_A8_ZeroOneVRejected() public {
        uint256 deadline = block.timestamp + 1 hours;
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(alicePk, RegistrySigUtils.digest(address(registry), block.chainid, alice, 0, deadline));
        vm.prank(mallory);
        vm.expectRevert("Invalid signature");
        registry.registerFor(alice, deadline, abi.encodePacked(r, s, uint8(v - 27)));
    }

    // ── A9: ID #1 is claimable by anyone the instant the registry exists (deploy script does not reserve it). ──
    function test_A9_FirstIdIsFirstComeFirstServed() public {
        vm.prank(mallory);
        assertEq(registry.register(), 1);
    }
}
