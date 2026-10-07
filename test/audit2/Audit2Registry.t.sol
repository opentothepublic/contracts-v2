// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

// AUDIT ROUND 2 (2026-09-20) — OTTPRegistry, spec v1.2 (D1, D4, D6) and EIP-712 surface.
// Independent of test/audit/* and test/GapTests.t.sol. Every test documents a property BY CONSTRUCTION:
// a PASSING test means the described behaviour is real on HEAD bytecode.
//   forge test --match-path 'test/audit2/*'

import { Test } from "forge-std/Test.sol";
import { IERC1271 } from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import { IERC5267 } from "@openzeppelin/contracts/interfaces/IERC5267.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import { OTTPRegistry } from "../../src/OTTPRegistry.sol";
import { RegistrySigUtils } from "../utils/RegistrySigUtils.sol";

/// @dev A CORRECT ERC-1271 wallet that re-derives the OTTP digest itself from live registry state
///      (eip712Domain() + nonces(this)) and only accepts if the hash it is asked to sign equals that digest,
///      signed by its owner key. This is how a careful smart wallet would validate a Register request.
contract StrictNonceWallet is IERC1271 {
    OTTPRegistry public immutable registry;
    address public immutable owner;

    constructor(OTTPRegistry r, address o) {
        registry = r;
        owner = o;
    }

    function expectedDigest(uint256 deadline) public view returns (bytes32) {
        (, string memory name, string memory version, uint256 chainId, address vc,,) = registry.eip712Domain();
        bytes32 ds = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                chainId,
                vc
            )
        );
        bytes32 sh = keccak256(
            abi.encode(registry.REGISTER_TYPEHASH(), address(this), registry.nonces(address(this)), deadline)
        );
        return keccak256(abi.encodePacked("\x19\x01", ds, sh));
    }

    /// @dev signature = abi.encode(deadline, ecdsaSig)
    function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4) {
        (uint256 deadline, bytes memory sig) = abi.decode(signature, (uint256, bytes));
        if (hash != expectedDigest(deadline)) return 0xffffffff;
        (address rec, ECDSA.RecoverError err,) = ECDSA.tryRecover(hash, sig);
        return
            (err == ECDSA.RecoverError.NoError && rec == owner)
                ? IERC1271.isValidSignature.selector
                : bytes4(0xffffffff);
    }
}

/// @dev ERC-1271 wallet that tries to re-enter the registry during validation.
contract ReentrantWallet is IERC1271 {
    OTTPRegistry public immutable registry;

    constructor(OTTPRegistry r) {
        registry = r;
    }

    function isValidSignature(bytes32, bytes memory) external view returns (bytes4) {
        // isValidSignatureNow uses STATICCALL, so any state change here must revert the validation call.
        // We attempt it through a low-level call so that the revert is observable as `false` (no data).
        (bool ok,) = address(registry).staticcall(abi.encodeWithSelector(OTTPRegistry.register.selector));
        return ok ? IERC1271.isValidSignature.selector : bytes4(0xffffffff);
    }
}

/// @dev ERC-1271 wallet that always says yes.
contract YesWallet is IERC1271 {
    function isValidSignature(bytes32, bytes memory) external pure returns (bytes4) {
        return IERC1271.isValidSignature.selector;
    }
}

contract Audit2RegistryTest is Test {
    OTTPRegistry internal registry;

    address internal alice;
    uint256 internal alicePk;
    address internal bob;
    uint256 internal bobPk;
    address internal carol = makeAddr("carol");
    address internal relayer = makeAddr("relayer");

    event Registered(uint256 indexed id, address indexed wallet);
    event Transferred(uint256 indexed id, address indexed oldWallet, address indexed newWallet);

    function setUp() public {
        vm.warp(1_760_000_000);
        registry = new OTTPRegistry();
        (alice, alicePk) = makeAddrAndKey("alice");
        (bob, bobPk) = makeAddrAndKey("bob");
    }

    function _sig(uint256 pk, address wallet, uint256 nonce, uint256 deadline) internal view returns (bytes memory) {
        return RegistrySigUtils.sign(vm, pk, address(registry), block.chainid, wallet, nonce, deadline);
    }

    function _hasSelector(bytes memory code, bytes4 sel) internal pure returns (bool) {
        if (code.length < 4) return false;
        for (uint256 i = 0; i + 4 <= code.length; ++i) {
            if (code[i] == sel[0] && code[i + 1] == sel[1] && code[i + 2] == sel[2] && code[i + 3] == sel[3]) {
                return true;
            }
        }
        return false;
    }

    // ───────────────────────────── D6: nonce consumed by every registration ─────────────────────────────

    /// D6-1: digest is built from nonces[wallet] BEFORE _register; a fresh wallet signs nonce 0 and it works.
    ///       After registration the nonce is 1 and the same signature is dead (nonce moved).
    function test_D6_1_DigestUsesPreIncrementNonce_ThenSignatureDead() public {
        uint256 deadline = block.timestamp + 1 days;
        bytes memory sig = _sig(alicePk, alice, 0, deadline);
        assertEq(registry.nonces(alice), 0);
        vm.prank(relayer);
        assertEq(registry.registerFor(alice, deadline, sig), 1);
        assertEq(registry.nonces(alice), 1);
        // replay while still registered -> reaches signature check first? No: signature is invalid (nonce 1 != 0)
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidSignature.selector, alice));
        registry.registerFor(alice, deadline, sig);
    }

    /// D6-2: register() + transferId → old signature (nonce 0) is dead; new signature (nonce 1) mints a NEW id.
    function test_D6_2_ReplayAfterDirectRegisterAndTransfer() public {
        uint256 deadline = type(uint256).max;
        bytes memory stale = _sig(alicePk, alice, 0, deadline);
        vm.prank(alice);
        registry.register(); // id 1, nonce 1
        vm.prank(alice);
        registry.proposeTransfer(1, bob);
        vm.prank(bob);
        registry.acceptId(1);
        assertEq(registry.getId(alice), 0);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidSignature.selector, alice));
        registry.registerFor(alice, deadline, stale);
        // a fresh signature at nonce 1 works and yields id 2 (never re-issues id 1)
        vm.prank(relayer);
        assertEq(registry.registerFor(alice, deadline, _sig(alicePk, alice, 1, deadline)), 2);
        assertEq(registry.getWallet(1), bob);
        assertEq(registry.getWallet(2), alice);
        assertEq(registry.nonces(alice), 2);
    }

    /// D6-3: registerFor() + transferId → replay of the consumed signature is dead.
    function test_D6_3_ReplayAfterSponsoredRegisterAndTransfer() public {
        uint256 deadline = type(uint256).max;
        bytes memory sig = _sig(alicePk, alice, 0, deadline);
        vm.prank(relayer);
        registry.registerFor(alice, deadline, sig);
        vm.prank(alice);
        registry.proposeTransfer(1, bob);
        vm.prank(bob);
        registry.acceptId(1);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidSignature.selector, alice));
        registry.registerFor(alice, deadline, sig);
        assertEq(registry.getId(alice), 0, "alice stays id-free");
        assertEq(registry.nextId(), 2, "no id minted");
    }

    /// D6-4: the nonce does not move on ANY revert path.
    function test_D6_4_NonceUnchangedOnEveryRevertPath() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory good = _sig(alicePk, alice, 0, deadline);

        // (a) expired
        bytes memory expiredSig = _sig(alicePk, alice, 0, block.timestamp - 1);
        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                OTTPRegistry.OTTPRegistry__SignatureExpired.selector, block.timestamp - 1, block.timestamp
            )
        );
        registry.registerFor(alice, block.timestamp - 1, expiredSig);
        assertEq(registry.nonces(alice), 0);

        // (b) invalid signature (bob signs for alice)
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidSignature.selector, alice));
        registry.registerFor(alice, deadline, _sig(bobPk, alice, 0, deadline));
        assertEq(registry.nonces(alice), 0);

        // (c) wallet == 0 with garbage
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidSignature.selector, address(0)));
        registry.registerFor(address(0), deadline, new bytes(65));
        assertEq(registry.nonces(address(0)), 0);

        // (d) already registered: valid signature at the CURRENT nonce, but wallet holds an id
        vm.prank(alice);
        registry.register(); // nonce -> 1
        bytes memory atNonce1 = _sig(alicePk, alice, 1, deadline);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__WalletAlreadyRegistered.selector, alice, 1));
        registry.registerFor(alice, deadline, atNonce1);
        assertEq(registry.nonces(alice), 1, "nonce not burned by WalletAlreadyRegistered");
        // ...and that same signature becomes usable if alice transfers away (it was signed at nonce 1)
        vm.prank(alice);
        registry.proposeTransfer(1, bob);
        vm.prank(bob);
        registry.acceptId(1);
        vm.prank(relayer);
        assertEq(registry.registerFor(alice, deadline, atNonce1), 2);

        // (e) transferId reverts never touch nonces
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__ZeroAddress.selector));
        registry.proposeTransfer(2, address(0));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__TargetAlreadyRegistered.selector, bob, 1));
        registry.proposeTransfer(2, bob);
        vm.prank(carol);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NotOwner.selector, 2, carol));
        registry.proposeTransfer(2, carol);
        assertEq(registry.nonces(alice), 2);
        assertEq(registry.nonces(bob), 0, "transfer recipient's nonce untouched");
        (good);
    }

    /// D6-5: invariant — nonces[w] == number of Registered(_, w) events, under a random op sequence.
    ///       Also: bijection holds after every op; transferId never touches nonces.
    function testFuzz_D6_5_NonceEqualsRegistrationCount_AndBijection(uint256 seed) public {
        address[4] memory w = [alice, bob, carol, relayer];
        uint256[4] memory regCount;
        uint256 ops = 24;
        for (uint256 k = 0; k < ops; ++k) {
            uint256 r = uint256(keccak256(abi.encode(seed, k)));
            uint256 who = r % 4;
            uint256 op = (r >> 8) % 3;
            address a = w[who];
            if (op == 0) {
                uint256 cur = registry.getId(a);
                if (cur == 0) {
                    vm.prank(a);
                    registry.register();
                    regCount[who] += 1;
                } else {
                    vm.expectRevert(
                        abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__WalletAlreadyRegistered.selector, a, cur)
                    );
                    vm.prank(a);
                    registry.register();
                }
            } else if (op == 1) {
                // sponsored registration for alice or bob (they have keys)
                uint256 pk = who == 0 ? alicePk : bobPk;
                address s = who == 0 ? alice : bob;
                uint256 sIdx = who == 0 ? 0 : 1;
                uint256 dl = block.timestamp + 1;
                bytes memory sig = _sig(pk, s, registry.nonces(s), dl);
                uint256 cur = registry.getId(s);
                if (cur == 0) {
                    vm.prank(relayer);
                    registry.registerFor(s, dl, sig);
                    regCount[sIdx] += 1;
                } else {
                    vm.expectRevert(
                        abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__WalletAlreadyRegistered.selector, s, cur)
                    );
                    vm.prank(relayer);
                    registry.registerFor(s, dl, sig);
                }
            } else {
                uint256 to = (r >> 16) % 4;
                uint256 id = registry.getId(a);
                uint256 toId = registry.getId(w[to]);
                if (id != 0 && toId == 0) {
                    vm.prank(a);
                    registry.proposeTransfer(id, w[to]);
                    vm.prank(w[to]);
                    registry.acceptId(id);
                } else if (id == 0) {
                    vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NotOwner.selector, 0, a));
                    vm.prank(a);
                    registry.proposeTransfer(0, w[to]);
                } else {
                    vm.expectRevert(
                        abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__TargetAlreadyRegistered.selector, w[to], toId)
                    );
                    vm.prank(a);
                    registry.proposeTransfer(id, w[to]);
                }
            }
            // invariants after every op
            for (uint256 i = 0; i < 4; ++i) {
                assertEq(registry.nonces(w[i]), regCount[i], "nonce == registrations");
                uint256 id = registry.getId(w[i]);
                if (id != 0) assertEq(registry.getWallet(id), w[i], "walletToId -> idToWallet");
            }
            for (uint256 id = 1; id < registry.nextId(); ++id) {
                address o = registry.getWallet(id);
                assertTrue(o != address(0), "issued id has owner");
                assertEq(registry.getId(o), id, "idToWallet -> walletToId");
            }
            assertEq(registry.getWallet(registry.nextId()), address(0));
            assertEq(registry.totalRegistered(), registry.nextId() - 1);
        }
    }

    /// D6-6 (INFO): D6 only kills signatures at the CURRENT nonce. A signature deliberately made at a FUTURE
    ///       nonce (n+1) survives the first registration and becomes live after a transfer-away. Only the
    ///       wallet itself can produce such a signature; clients must always sign nonces(wallet).
    function test_D6_6_FutureNonceSignatureBecomesLiveLater_Info() public {
        uint256 deadline = type(uint256).max;
        bytes memory future = _sig(alicePk, alice, 1, deadline);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidSignature.selector, alice));
        registry.registerFor(alice, deadline, future); // nonce is 0 now
        vm.prank(alice);
        registry.register(); // nonce -> 1
        vm.prank(alice);
        registry.proposeTransfer(1, bob);
        vm.prank(bob);
        registry.acceptId(1);
        vm.prank(relayer);
        assertEq(registry.registerFor(alice, deadline, future), 2, "future-nonce signature is now live");
    }

    /// D6-7: a CORRECT ERC-1271 wallet that recomputes the digest from live nonces()/eip712Domain() during
    ///       validation observes the pre-increment nonce and therefore accepts. (If the nonce were consumed
    ///       before verification, this wallet class would be locked out of registerFor.)
    function test_D6_7_StrictNonceReadingErc1271Wallet_Works() public {
        StrictNonceWallet w = new StrictNonceWallet(registry, alice);
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 digest = RegistrySigUtils.digest(address(registry), block.chainid, address(w), 0, deadline);
        assertEq(digest, w.expectedDigest(deadline), "client digest == wallet digest");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePk, digest);
        bytes memory packed = abi.encode(deadline, abi.encodePacked(r, s, v));
        vm.prank(relayer);
        assertEq(registry.registerFor(address(w), deadline, packed), 1);
        assertEq(registry.nonces(address(w)), 1);
        // replay: the wallet now derives nonce 1 -> hash mismatch -> rejected
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidSignature.selector, address(w)));
        registry.registerFor(address(w), deadline, packed);
    }

    /// D6-8: an ERC-1271 wallet cannot re-enter the registry during validation (STATICCALL), so there is no
    ///       ordering in which a nonce is consumed twice or a registration happens without a nonce bump.
    function test_D6_8_Erc1271ReentrancyIsImpossible() public {
        ReentrantWallet w = new ReentrantWallet(registry);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidSignature.selector, address(w)));
        registry.registerFor(address(w), block.timestamp + 1, "");
        assertEq(registry.nonces(address(w)), 0);
        assertEq(registry.nextId(), 1);
    }

    // ───────────────────────────── D4: custom errors, exact parameters, no strings ─────────────────────────────

    function test_D4_1_ExactErrorsAndParams_AllRegistryPaths() public {
        uint256 deadline = block.timestamp + 1 hours;

        // SignatureExpired(deadline, block.timestamp)
        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                OTTPRegistry.OTTPRegistry__SignatureExpired.selector, deadline - 2 hours, block.timestamp
            )
        );
        registry.registerFor(alice, deadline - 2 hours, "");

        // InvalidSignature(wallet)
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidSignature.selector, alice));
        registry.registerFor(alice, deadline, "");

        // WalletAlreadyRegistered(wallet, existingId) — direct path
        vm.prank(alice);
        registry.register();
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__WalletAlreadyRegistered.selector, alice, 1));
        registry.register();

        // NotOwner(id, caller): unissued id, id 0, foreign id
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NotOwner.selector, 1, bob));
        registry.proposeTransfer(1, carol);
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NotOwner.selector, 0, bob));
        registry.proposeTransfer(0, carol);
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NotOwner.selector, 99, bob));
        registry.proposeTransfer(99, carol);

        // ZeroAddress()
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__ZeroAddress.selector));
        registry.proposeTransfer(1, address(0));

        // TargetAlreadyRegistered(target, existingId) — including self-transfer
        vm.prank(bob);
        registry.register(); // 2
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__TargetAlreadyRegistered.selector, bob, 2));
        registry.proposeTransfer(1, bob);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__TargetAlreadyRegistered.selector, alice, 1));
        registry.proposeTransfer(1, alice);
    }

    /// D4-2: the deployed runtime bytecode contains no `Error(string)` selector, i.e. no string revert survives.
    ///       (Panic(uint256) is present only via the compiler's checked-arithmetic/decoder stubs.)
    function test_D4_2_NoStringRevertSelectorInRuntimeBytecode() public view {
        bytes memory code = address(registry).code;
        assertFalse(_hasSelector(code, bytes4(keccak256("Error(string)"))), "Error(string) selector present");
    }

    /// D4-3: registerFor(address(0), …) can never reach the ZeroAddress branch — the signature check fails first
    ///       (ECDSA never recovers address(0) without an error). Documents the guard as unreachable on that path.
    function testFuzz_D4_3_ZeroWalletAlwaysInvalidSignature(bytes memory sig, uint256 deadline) public {
        deadline = bound(deadline, block.timestamp, type(uint256).max);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidSignature.selector, address(0)));
        registry.registerFor(address(0), deadline, sig);
    }

    // ───────────────────────────── EIP-712 surface ─────────────────────────────

    function test_712_1_TypehashAndDomain() public view {
        assertEq(registry.REGISTER_TYPEHASH(), keccak256("Register(address wallet,uint256 nonce,uint256 deadline)"));
        (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address vc,
            bytes32 salt,
            uint256[] memory ext
        ) = IERC5267(address(registry)).eip712Domain();
        assertEq(fields, hex"0f");
        assertEq(name, "OTTPRegistry");
        assertEq(version, "2");
        assertEq(chainId, block.chainid);
        assertEq(vc, address(registry));
        assertEq(salt, bytes32(0));
        assertEq(ext.length, 0);
    }

    /// Chain binding: a signature made for chain X is rejected on chain Y and vice versa (domain rebuilt on fork).
    function test_712_2_ChainBinding() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory forBase = RegistrySigUtils.sign(vm, alicePk, address(registry), 8453, alice, 0, deadline);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidSignature.selector, alice));
        registry.registerFor(alice, deadline, forBase);
        vm.chainId(8453);
        vm.prank(relayer);
        assertEq(registry.registerFor(alice, deadline, forBase), 1);
    }

    /// Contract binding + tampered fields: any change to wallet/nonce/deadline/verifyingContract invalidates.
    function testFuzz_712_3_TamperRejected(uint256 dNonce, uint256 dDeadline, address otherWallet) public {
        uint256 deadline = block.timestamp + 1 hours;
        dDeadline = bound(dDeadline, 0, 365 days);
        vm.assume(dNonce != 0 || dDeadline != 0 || otherWallet != alice);
        uint256 badDeadline = deadline + dDeadline;
        bytes memory sig =
            RegistrySigUtils.sign(vm, alicePk, address(registry), block.chainid, otherWallet, dNonce, badDeadline);
        // submitted for alice / nonce 0 / deadline
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidSignature.selector, alice));
        registry.registerFor(alice, deadline, sig);
        // sibling deployment
        OTTPRegistry other = new OTTPRegistry();
        bytes memory good = _sig(alicePk, alice, 0, deadline);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidSignature.selector, alice));
        other.registerFor(alice, deadline, good);
    }

    /// Malleability: high-s, v in {0,1}, 64-byte compact, wrong length are all rejected.
    function test_712_4_MalleabilityAndEncodingRejected() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 digest = RegistrySigUtils.digest(address(registry), block.chainid, alice, 0, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePk, digest);
        uint256 N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        bytes32 sHigh = bytes32(N - uint256(s));
        uint8 vFlip = v == 27 ? 28 : 27;
        // sanity: the malleated pair really does recover to alice at the precompile level
        assertEq(ecrecover(digest, vFlip, r, sHigh), alice, "malleated sig recovers at EVM level");
        bytes[] memory bad = new bytes[](5);
        bad[0] = abi.encodePacked(r, sHigh, vFlip);
        bad[1] = abi.encodePacked(r, s, uint8(v - 27));
        bad[2] = abi.encodePacked(r, bytes32((uint256(v - 27) << 255) | uint256(s)));
        bad[3] = abi.encodePacked(r, s, v, uint8(0));
        bad[4] = "";
        for (uint256 i = 0; i < bad.length; ++i) {
            vm.prank(relayer);
            vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidSignature.selector, alice));
            registry.registerFor(alice, deadline, bad[i]);
        }
        vm.prank(relayer);
        assertEq(registry.registerFor(alice, deadline, abi.encodePacked(r, s, v)), 1);
    }

    /// Deadline is inclusive: == now accepted, now+1 after warp rejected with exact params.
    function test_712_5_DeadlineBoundary() public {
        uint256 dl = block.timestamp;
        bytes memory sig = _sig(alicePk, alice, 0, dl);
        vm.warp(dl + 1);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__SignatureExpired.selector, dl, dl + 1));
        registry.registerFor(alice, dl, sig);
        vm.warp(dl);
        vm.prank(relayer);
        assertEq(registry.registerFor(alice, dl, sig), 1);
    }

    /// 7702 (cancun build; delegation designator bytes present): an EOA that gets code between signing and
    /// relaying is routed to the ERC-1271 path; its plain ECDSA signature is no longer accepted unless the
    /// delegate implements ERC-1271 over the EOA key. Direct register() keeps working.
    function test_712_6_CodeAtWalletSwitchesTo1271Path() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sig(alicePk, alice, 0, deadline);
        vm.etch(alice, abi.encodePacked(hex"ef0100", makeAddr("delegate")));
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidSignature.selector, alice));
        registry.registerFor(alice, deadline, sig);
        // a YesWallet delegate would let ANYONE register alice with an empty signature (self-inflicted)
        vm.etch(alice, address(new YesWallet()).code);
        vm.prank(carol);
        assertEq(registry.registerFor(alice, deadline, ""), 1);
    }

    /// Counterfactual wallet (no code yet): registerFor is impossible (ECDSA path must recover to the CREATE2
    /// address); nobody else can register it either. INFO: no ERC-6492 support.
    function test_712_7_CounterfactualWalletCannotRegisterFor() public {
        address cf = vm.computeCreate2Address(bytes32(0), keccak256(type(YesWallet).creationCode), address(this));
        assertEq(cf.code.length, 0);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidSignature.selector, cf));
        registry.registerFor(cf, block.timestamp + 1, _sig(alicePk, cf, 0, block.timestamp + 1));
    }

    // ───────────────────────────── D1 / bijection ─────────────────────────────

    /// D1: zero-sender cannot claim an unissued id via transferId (idToWallet[id] == 0 == msg.sender).
    function testFuzz_D1_ZeroSenderCannotTransferUnissued(uint256 id, address to) public {
        vm.assume(to != address(0));
        vm.prank(address(0));
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__NotOwner.selector, id, address(0)));
        registry.proposeTransfer(id, to);
        assertEq(registry.getWallet(id), address(0));
        assertEq(registry.getId(to), 0);
    }

    /// A transfer to a contract with no way to call back (e.g. the registry itself) is accepted and permanent.
    /// INFO: no two-step / acceptance; a typo in newWallet destroys the identity (design: no admin override).
    /// Addendum B1 (PROPOSED) changes this Info finding: under one-step transferId, sending an id to a dead address
    /// (here the registry itself, which never calls out) destroyed it. Under two-step transfer the dead address can
    /// neither call acceptId nor produce a signature, so the id stays with the owner, who can cancel.
    function test_Info_TransferToDeadAddressIsNowImpossible() public {
        vm.prank(alice);
        registry.register();
        vm.prank(alice);
        registry.proposeTransfer(1, address(registry));
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidSignature.selector, address(registry)));
        registry.acceptIdBySig(1, address(registry), block.timestamp, new bytes(65));
        assertEq(registry.getWallet(1), alice, "id never left the owner");
        vm.prank(alice);
        registry.cancelTransfer(1);
        assertEq(registry.pendingTransferOf(1), address(0));
    }

    /// Events: exactly one Registered per registration, one Transferred per transfer, with the right args.
    function test_Events_Exact() public {
        vm.expectEmit(true, true, true, true, address(registry));
        emit Registered(1, alice);
        vm.prank(alice);
        registry.register();
        vm.prank(alice);
        registry.proposeTransfer(1, bob);
        vm.expectEmit(true, true, true, true, address(registry));
        emit Transferred(1, alice, bob);
        vm.prank(bob);
        registry.acceptId(1);
    }

    /// No ETH accepted anywhere on the registry.
    function test_NoReceive() public {
        vm.deal(relayer, 1 ether);
        vm.prank(relayer);
        (bool ok,) = address(registry).call{ value: 1 }("");
        assertFalse(ok);
        vm.prank(relayer);
        (ok,) = address(registry).call{ value: 1 }(abi.encodeWithSelector(OTTPRegistry.register.selector));
        assertFalse(ok);
    }
}
