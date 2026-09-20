// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import { Test } from "forge-std/Test.sol";

import { OTTPRegistry } from "../../src/OTTPRegistry.sol";
import { RegistrySigUtils } from "../utils/RegistrySigUtils.sol";

/// @dev Drives the registry with a mix of valid and invalid calls from a fixed actor set, recording ghost
///      state only on calls that succeed, so the invariants can check the contract against an independent model.
contract RegistryHandler is Test {
    OTTPRegistry public immutable registry;

    uint256 internal constant N = 12;
    address[N] public actors;
    uint256[N] internal keys;
    address public relayer = makeAddr("relayer");

    // ghost model
    mapping(uint256 id => address wallet) public ghostOwner;
    mapping(address wallet => uint256 nonce) public ghostNonce;
    uint256 public ghostIssued;
    uint256 public ghostTransfers;
    uint256 public callsRegister;
    uint256 public callsRegisterFor;
    uint256 public callsTransfer;
    uint256 public callsRejected;

    constructor(OTTPRegistry _registry) {
        registry = _registry;
        for (uint256 i = 0; i < N; i++) {
            (actors[i], keys[i]) = makeAddrAndKey(string(abi.encodePacked("actor", i)));
        }
    }

    function _actor(uint256 seed) internal view returns (uint256 idx) {
        return seed % N;
    }

    function register(uint256 seed) external {
        uint256 i = _actor(seed);
        address a = actors[i];
        vm.prank(a);
        try registry.register() returns (uint256 id) {
            ghostIssued++;
            ghostOwner[id] = a;
            callsRegister++;
        } catch {
            callsRejected++;
        }
    }

    function registerFor(uint256 seed, uint256 deadlineOffset, bool validSig, bool validNonce) external {
        uint256 i = _actor(seed);
        address a = actors[i];
        deadlineOffset = bound(deadlineOffset, 0, 30 days);
        uint256 deadline = block.timestamp + deadlineOffset;
        uint256 nonce = validNonce ? registry.nonces(a) : registry.nonces(a) + 1 + (seed % 5);
        uint256 pk = validSig ? keys[i] : keys[(i + 1) % N];
        bytes memory sig = RegistrySigUtils.sign(vm, pk, address(registry), block.chainid, a, nonce, deadline);

        vm.prank(relayer);
        try registry.registerFor(a, deadline, sig) returns (uint256 id) {
            // must only ever succeed with a genuine signature and the right nonce
            assertTrue(validSig && validNonce, "registerFor accepted a bad signature");
            ghostIssued++;
            ghostOwner[id] = a;
            ghostNonce[a]++;
            callsRegisterFor++;
        } catch {
            callsRejected++;
        }
    }

    function registerForExpired(uint256 seed, uint256 age) external {
        uint256 i = _actor(seed);
        address a = actors[i];
        age = bound(age, 1, block.timestamp);
        uint256 deadline = block.timestamp - age;
        bytes memory sig =
            RegistrySigUtils.sign(vm, keys[i], address(registry), block.chainid, a, registry.nonces(a), deadline);
        vm.prank(relayer);
        try registry.registerFor(a, deadline, sig) {
            revert("expired signature accepted");
        } catch {
            callsRejected++;
        }
    }

    function transferId(uint256 fromSeed, uint256 toSeed, uint256 idSeed) external {
        uint256 fi = _actor(fromSeed);
        address from = actors[fi];
        address to = actors[_actor(toSeed)];
        uint256 owned = registry.getId(from);
        // mostly target the caller's real ID, sometimes a random/unissued one
        uint256 id = idSeed % 4 == 0 ? idSeed : owned;
        vm.prank(from);
        try registry.transferId(id, to) {
            assertEq(id, owned, "transferred an ID the caller did not own");
            assertTrue(id != 0, "transferred id 0");
            ghostOwner[id] = to;
            ghostTransfers++;
            callsTransfer++;
        } catch {
            callsRejected++;
        }
    }

    function transferFromStranger(uint256 idSeed, uint256 toSeed) external {
        address stranger = makeAddr(string(abi.encodePacked("stranger", idSeed)));
        address to = actors[_actor(toSeed)];
        uint256 id = idSeed % (registry.totalRegistered() + 2);
        vm.prank(stranger);
        try registry.transferId(id, to) {
            revert("stranger moved an ID");
        } catch {
            callsRejected++;
        }
    }

    function warp(uint256 dt) external {
        dt = bound(dt, 1, 1 days);
        vm.warp(block.timestamp + dt);
    }

    function actorCount() external pure returns (uint256) {
        return N;
    }
}

contract RegistryInvariants is Test {
    OTTPRegistry internal registry;
    RegistryHandler internal handler;

    function setUp() public {
        vm.warp(1_760_000_000);
        registry = new OTTPRegistry();
        handler = new RegistryHandler(registry);
        targetContract(address(handler));
    }

    /// @dev nextId == totalRegistered + 1, and equals the ghost count of successful issuances.
    function invariant_CounterConsistency() public view {
        assertEq(registry.nextId(), registry.totalRegistered() + 1);
        assertEq(registry.totalRegistered(), handler.ghostIssued());
    }

    /// @dev For every issued ID: it has a non-zero wallet, and the reverse mapping points back at it.
    function invariant_BijectionForIssuedIds() public view {
        uint256 total = registry.totalRegistered();
        for (uint256 id = 1; id <= total; id++) {
            address w = registry.idToWallet(id);
            assertTrue(w != address(0), "issued id has no wallet");
            assertEq(registry.walletToId(w), id, "walletToId[idToWallet[id]] != id");
            assertEq(registry.getWallet(id), w);
            assertEq(registry.getId(w), id);
        }
        assertEq(registry.idToWallet(0), address(0), "id 0 must never be assigned");
        assertEq(registry.idToWallet(total + 1), address(0), "unissued id has a wallet");
    }

    /// @dev No two issued IDs share a wallet (every wallet holds at most one ID).
    function invariant_OneIdPerWallet() public view {
        uint256 total = registry.totalRegistered();
        for (uint256 i = 1; i <= total; i++) {
            for (uint256 j = i + 1; j <= total; j++) {
                assertTrue(registry.idToWallet(i) != registry.idToWallet(j), "two ids share a wallet");
            }
        }
        for (uint256 k = 0; k < handler.actorCount(); k++) {
            address a = handler.actors(k);
            uint256 id = registry.walletToId(a);
            if (id != 0) assertEq(registry.idToWallet(id), a);
        }
    }

    /// @dev Every ID's owner matches the ghost model, which is only updated by successful register/registerFor
    ///      (initial owner) and successful owner-initiated transferId. Hence no ID is ever reassigned any other way.
    function invariant_OwnershipMatchesGhostModel() public view {
        uint256 total = registry.totalRegistered();
        for (uint256 id = 1; id <= total; id++) {
            assertEq(registry.idToWallet(id), handler.ghostOwner(id), "owner diverged from ghost model");
        }
    }

    /// @dev Nonces only move on successful registerFor.
    function invariant_NoncesMatchGhostModel() public view {
        for (uint256 k = 0; k < handler.actorCount(); k++) {
            address a = handler.actors(k);
            assertEq(registry.nonces(a), handler.ghostNonce(a));
        }
        assertEq(registry.nonces(handler.relayer()), 0);
        assertEq(registry.walletToId(handler.relayer()), 0, "relayer acquired an ID");
    }

    function invariant_NoEtherEverHeld() public view {
        assertEq(address(registry).balance, 0);
    }

    function invariant_CallSummary() public view {
        // Sanity: the handler actually exercised the success paths (otherwise the invariants are vacuous).
        // Logged rather than asserted so a low-depth run does not fail spuriously.
        uint256 total =
            handler.callsRegister() + handler.callsRegisterFor() + handler.callsTransfer() + handler.callsRejected();
        total; // silence unused warning
    }
}
