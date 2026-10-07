// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import { Test } from "forge-std/Test.sol";

import { OTTPRegistry } from "../../src/OTTPRegistry.sol";
import { RegistrySigUtils } from "../utils/RegistrySigUtils.sol";
import { AuthoritySigUtils } from "../utils/AuthoritySigUtils.sol";

/// @dev Lets random actors call every registry function (direct and by signature, valid and invalid), and keeps an
///      independent ghost model of ownership, epochs and every granted authority. The ghost model is updated only
///      from the handler's knowledge of what it asked for and whether the call succeeded — never by reading back
///      the authority views — so the invariants compare the contract against an independent model.
contract AuthorityHandler is Test {
    OTTPRegistry public immutable registry;

    uint256 internal constant N = 8;
    address[N] public actors;
    uint256[N] internal keys;
    address public relayer = makeAddr("relayer");

    struct GDelegate {
        uint64 expiry;
        uint256 epoch;
        bool set;
    }

    struct GAddrEpoch {
        address who;
        uint256 epoch;
    }

    struct GRecovery {
        address who;
        uint256 epoch;
        uint256 readyAt;
    }

    // ghost model
    mapping(uint256 id => address) public ghostOwner;
    mapping(uint256 id => uint256) public ghostEpoch;
    mapping(uint256 id => mapping(address => GDelegate)) internal _gDelegate;
    mapping(uint256 id => GAddrEpoch) internal _gGuardian;
    mapping(uint256 id => GAddrEpoch) internal _gTransfer;
    mapping(uint256 id => GRecovery) internal _gRecovery;
    uint256 public ghostIssued;

    // historical grant log: (kind, id, account, epoch) — kind 0 delegate, 1 guardian, 2 transfer, 3 recovery
    struct Grant {
        uint8 kind;
        uint256 id;
        address account;
        uint256 epoch;
    }

    Grant[] internal _grants;

    // violation flags (set by the handler, asserted by the invariants)
    bool public unconsentedGain;
    bool public monotonicityBroken;
    bool public badSigAccepted;

    // coverage counters
    mapping(bytes32 => uint256) public ok;
    uint256 public rejected;

    constructor(OTTPRegistry _registry) {
        registry = _registry;
        for (uint256 i = 0; i < N; i++) {
            (actors[i], keys[i]) = makeAddrAndKey(string(abi.encodePacked("auth-actor", i)));
        }
    }

    // ─── tracking ──────────────────────────────────────────────────────────────────────────────────────────

    /// @dev Snapshots every actor's id, every epoch and nextId; after the call, any actor that gained an id
    ///      (0 → x, or x → y) must be `consenter`, and no epoch / nextId may have decreased.
    modifier tracked(address consenter) {
        uint256[N + 1] memory idsBefore;
        for (uint256 i = 0; i < N; i++) {
            idsBefore[i] = registry.walletToId(actors[i]);
        }
        idsBefore[N] = registry.walletToId(relayer);
        uint256 nextBefore = registry.nextId();
        uint256[] memory epochsBefore = new uint256[](nextBefore);
        for (uint256 id = 1; id < nextBefore; id++) {
            epochsBefore[id] = registry.ownerEpoch(id);
        }
        _;
        for (uint256 i = 0; i <= N; i++) {
            address w = i < N ? actors[i] : relayer;
            uint256 nowId = registry.walletToId(w);
            if (nowId != 0 && nowId != idsBefore[i] && w != consenter) unconsentedGain = true;
        }
        if (registry.nextId() < nextBefore) monotonicityBroken = true;
        for (uint256 id = 1; id < nextBefore; id++) {
            if (registry.ownerEpoch(id) < epochsBefore[id]) monotonicityBroken = true;
        }
    }

    function _i(uint256 seed) internal pure returns (uint256) {
        return seed % N;
    }

    /// @dev Mostly an issued id; sometimes 0 or one past the end.
    function _id(uint256 seed) internal view returns (uint256) {
        uint256 next = registry.nextId();
        if (seed % 7 == 0) return seed % 2 == 0 ? 0 : next;
        return next == 1 ? 1 : 1 + (seed / 7) % (next - 1);
    }

    /// @dev An ID-free actor (searching from `seed`), or a random actor 1 time in 6 / when none is free.
    function _free(uint256 seed) internal view returns (address) {
        if (seed % 6 != 0) {
            for (uint256 k = 0; k < N; k++) {
                address a = actors[(seed + k) % N];
                if (registry.walletToId(a) == 0) return a;
            }
        }
        return actors[_i(seed)];
    }

    function _freeCount() internal view returns (uint256 n) {
        for (uint256 k = 0; k < N; k++) {
            if (registry.walletToId(actors[k]) == 0) n++;
        }
    }

    /// @dev Biased signer: the intended key 4 times in 5, otherwise another actor's.
    function _key(uint256 intended, uint256 seed) internal pure returns (uint256 idx) {
        return seed % 5 == 0 ? (intended + 1 + seed % (N - 1)) % N : intended;
    }

    function _idx(address a) internal view returns (uint256) {
        for (uint256 k = 0; k < N; k++) {
            if (actors[k] == a) return k;
        }
        return 0;
    }

    function _signAs(uint256 s, bytes32 structHash) internal view returns (bytes memory) {
        return AuthoritySigUtils.sign(vm, keys[s], address(registry), block.chainid, structHash);
    }

    function _owned(uint256 actorIdx, uint256 idSeed) internal view returns (uint256) {
        uint256 own = registry.walletToId(actors[actorIdx]);
        return (own != 0 && idSeed % 4 != 0) ? own : _id(idSeed);
    }

    function _onMove(uint256 id, address to) internal {
        ghostOwner[id] = to;
        ghostEpoch[id] += 1;
        delete _gTransfer[id];
        delete _gRecovery[id];
    }

    function _onRegister(uint256 id, address w) internal {
        ghostIssued++;
        ghostOwner[id] = w;
    }

    // ─── registration ──────────────────────────────────────────────────────────────────────────────────────

    function register(uint256 seed) external {
        _registerDirect(_freeCount() > 3 ? _free(seed) : actors[_i(seed)]); // the latter mostly exercises rejection
    }

    function _registerDirect(address a) internal tracked(a) {
        vm.prank(a);
        try registry.register() returns (uint256 id) {
            _onRegister(id, a);
            ok["register"]++;
        } catch {
            rejected++;
        }
    }

    function registerFor(uint256 seed, uint256 signerSeed) external {
        address a = _freeCount() > 3 ? _free(seed) : actors[_i(seed)];
        uint256 s = _key(_idx(a), signerSeed);
        _registerFor(a, s);
    }

    function _registerFor(address a, uint256 s) internal tracked(actors[s]) {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig =
            RegistrySigUtils.sign(vm, keys[s], address(registry), block.chainid, a, registry.nonces(a), deadline);
        vm.prank(relayer);
        try registry.registerFor(a, deadline, sig) returns (uint256 id) {
            if (actors[s] != a) badSigAccepted = true;
            _onRegister(id, a);
            ok["registerFor"]++;
        } catch {
            rejected++;
        }
    }

    // ─── B1: two-step transfer ─────────────────────────────────────────────────────────────────────────────

    function proposeTransfer(uint256 callerSeed, uint256 idSeed, uint256 toSeed) external tracked(address(0)) {
        uint256 c = _i(callerSeed);
        uint256 id = _owned(c, idSeed);
        address to = _free(toSeed);
        vm.prank(actors[c]);
        try registry.proposeTransfer(id, to) {
            _gTransfer[id] = GAddrEpoch(to, ghostEpoch[id]);
            _grants.push(Grant(2, id, to, ghostEpoch[id]));
            ok["proposeTransfer"]++;
        } catch {
            rejected++;
        }
    }

    function cancelTransfer(uint256 callerSeed, uint256 idSeed) external tracked(address(0)) {
        uint256 id = _busyId(idSeed);
        address owner = registry.idToWallet(id);
        address c = (owner != address(0) && callerSeed % 4 != 0) ? owner : actors[_i(callerSeed)];
        vm.prank(c);
        try registry.cancelTransfer(id) {
            delete _gTransfer[id];
            ok["cancelTransfer"]++;
        } catch {
            rejected++;
        }
    }

    /// @dev 3 times in 4, an issued id with a live pending transfer or recovery (searching from `seed`); else _id.
    function _busyId(uint256 seed) internal view returns (uint256) {
        uint256 next = registry.nextId();
        if (seed % 4 != 0 && next > 1) {
            for (uint256 k = 0; k < next - 1; k++) {
                uint256 id = 1 + (seed + k) % (next - 1);
                if (registry.pendingTransferOf(id) != address(0)) return id;
                (address r,) = registry.pendingRecoveryOf(id);
                if (r != address(0)) return id;
            }
        }
        return _id(seed);
    }

    /// @dev The live pending target of `id` (recovery or transfer, either first) 3 times in 4, else a random actor.
    function _acceptor(uint256 id, uint256 seed) internal view returns (address) {
        if (seed % 4 != 0) {
            address t = registry.pendingTransferOf(id);
            (address r,) = registry.pendingRecoveryOf(id);
            if (r != address(0) && (t == address(0) || seed % 2 == 0)) return r;
            if (t != address(0)) return t;
        }
        return actors[_i(seed)];
    }

    function acceptId(uint256 callerSeed, uint256 idSeed) external {
        uint256 id = _busyId(idSeed);
        _acceptId(id, _acceptor(id, callerSeed));
    }

    function _acceptId(uint256 id, address a) internal tracked(a) {
        vm.prank(a);
        try registry.acceptId(id) {
            _onMove(id, a);
            ok["acceptId"]++;
        } catch {
            rejected++;
        }
    }

    function acceptIdBySig(uint256 walletSeed, uint256 signerSeed, uint256 idSeed) external {
        uint256 id = _busyId(idSeed);
        address w = _acceptor(id, walletSeed);
        _acceptIdBySig(id, w, _key(_idx(w), signerSeed));
    }

    function _acceptIdBySig(uint256 id, address w, uint256 s) internal tracked(actors[s]) {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig =
            _signAs(s, AuthoritySigUtils.acceptIdHash(id, w, registry.ownerEpoch(id), registry.nonces(w), deadline));
        vm.prank(relayer);
        try registry.acceptIdBySig(id, w, deadline, sig) {
            if (actors[s] != w) badSigAccepted = true;
            _onMove(id, w);
            ok["acceptIdBySig"]++;
        } catch {
            rejected++;
        }
    }

    // ─── B2: delegates ─────────────────────────────────────────────────────────────────────────────────────

    function _expiry(uint256 seed) internal view returns (uint64) {
        uint256 m = seed % 5;
        if (m == 0) return 0; // revoke
        if (m == 1) return type(uint64).max;
        if (m == 2) return uint64(block.timestamp); // invalid
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint64(block.timestamp + 1 + seed % 3 days); // test timestamps stay far below 2^64
    }

    function _recordDelegate(uint256 id, address d, uint64 expiry) internal {
        if (expiry == 0) {
            delete _gDelegate[id][d];
        } else {
            _gDelegate[id][d] = GDelegate(expiry, ghostEpoch[id], true);
            _grants.push(Grant(0, id, d, ghostEpoch[id]));
        }
    }

    function setDelegate(uint256 callerSeed, uint256 idSeed, uint256 delSeed, uint256 expirySeed)
        external
        tracked(address(0))
    {
        uint256 c = _i(callerSeed);
        uint256 id = _owned(c, idSeed);
        address d = actors[_i(delSeed)];
        uint64 expiry = _expiry(expirySeed);
        vm.prank(actors[c]);
        try registry.setDelegate(id, d, expiry) {
            _recordDelegate(id, d, expiry);
            ok["setDelegate"]++;
        } catch {
            rejected++;
        }
    }

    function setDelegateBySig(uint256 signerSeed, uint256 idSeed, uint256 delSeed, uint256 expirySeed)
        external
        tracked(address(0))
    {
        uint256 id = _owned(_i(signerSeed), idSeed);
        address owner = registry.idToWallet(id);
        uint256 s = _key(owner == address(0) ? _i(signerSeed) : _idx(owner), signerSeed);
        address d = actors[_i(delSeed)];
        uint64 expiry = _expiry(expirySeed);
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _signAs(
            s,
            AuthoritySigUtils.setDelegateHash(id, d, expiry, registry.ownerEpoch(id), registry.nonces(owner), deadline)
        );
        vm.prank(relayer);
        try registry.setDelegateBySig(id, d, expiry, deadline, sig) {
            if (owner != actors[s]) badSigAccepted = true;
            _recordDelegate(id, d, expiry);
            ok["setDelegateBySig"]++;
        } catch {
            rejected++;
        }
    }

    // ─── B3: guardian recovery ─────────────────────────────────────────────────────────────────────────────

    function _recordGuardian(uint256 id, address g) internal {
        _gGuardian[id] = GAddrEpoch(g, ghostEpoch[id]);
        _grants.push(Grant(1, id, g, ghostEpoch[id]));
        delete _gRecovery[id];
    }

    function setGuardian(uint256 callerSeed, uint256 idSeed, uint256 gSeed) external tracked(address(0)) {
        uint256 c = _i(callerSeed);
        uint256 id = _owned(c, idSeed);
        if (_spareRecovery(id, gSeed)) return;
        address g = gSeed % 6 == 0 ? address(0) : actors[_i(gSeed)];
        vm.prank(actors[c]);
        try registry.setGuardian(id, g) {
            _recordGuardian(id, g);
            ok["setGuardian"]++;
        } catch {
            rejected++;
        }
    }

    function setGuardianBySig(uint256 signerSeed, uint256 idSeed, uint256 gSeed) external tracked(address(0)) {
        uint256 id = _owned(_i(signerSeed), idSeed);
        if (_spareRecovery(id, gSeed)) return;
        address owner = registry.idToWallet(id);
        uint256 s = _key(owner == address(0) ? _i(signerSeed) : _idx(owner), signerSeed);
        address g = gSeed % 6 == 0 ? address(0) : actors[_i(gSeed)];
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _signAs(
            s, AuthoritySigUtils.setGuardianHash(id, g, registry.ownerEpoch(id), registry.nonces(owner), deadline)
        );
        vm.prank(relayer);
        try registry.setGuardianBySig(id, g, deadline, sig) {
            if (owner != actors[s]) badSigAccepted = true;
            _recordGuardian(id, g);
            ok["setGuardianBySig"]++;
        } catch {
            rejected++;
        }
    }

    function initiateRecovery(uint256 callerSeed, uint256 idSeed, uint256 toSeed) external tracked(address(0)) {
        uint256 id = _id(idSeed);
        address g = registry.guardianOf(id);
        address c = (g != address(0) && callerSeed % 4 != 0) ? g : actors[_i(callerSeed)];
        address to = _free(toSeed);
        vm.prank(c);
        try registry.initiateRecovery(id, to) {
            uint256 readyAt = block.timestamp + registry.RECOVERY_DELAY();
            _gRecovery[id] = GRecovery(to, ghostEpoch[id], readyAt);
            _grants.push(Grant(3, id, to, ghostEpoch[id]));
            ok["initiateRecovery"]++;
        } catch {
            rejected++;
        }
    }

    function cancelRecovery(uint256 callerSeed, uint256 idSeed) external tracked(address(0)) {
        if (callerSeed % 7 < 3) return; // fire less often than initiateRecovery so some recoveries complete
        uint256 id = _busyId(idSeed);
        uint256 m = callerSeed % 3;
        address c = m == 0 ? registry.idToWallet(id) : m == 1 ? registry.guardianOf(id) : actors[_i(callerSeed)];
        vm.prank(c);
        try registry.cancelRecovery(id) {
            delete _gRecovery[id];
            ok["cancelRecovery"]++;
        } catch {
            rejected++;
        }
    }

    /// @dev Half the time, jump just past RECOVERY_DELAY so initiated recoveries mature within a run.
    function warp(uint256 dt) external {
        dt = dt % 2 == 0 ? 7 days + dt % 1 hours : bound(dt, 1, 2 days);
        vm.warp(block.timestamp + dt);
    }

    /// @dev Any guardian change cancels a live recovery; skip 3 in 4 such calls so recoveries can mature.
    function _spareRecovery(uint256 id, uint256 seed) internal view returns (bool) {
        (address r,) = registry.pendingRecoveryOf(id);
        return r != address(0) && seed % 4 != 0;
    }

    // ─── model views (for the invariants) ──────────────────────────────────────────────────────────────────

    function actorCount() external pure returns (uint256) {
        return N;
    }

    function ghostDelegateActive(uint256 id, address a) external view returns (bool) {
        GDelegate memory d = _gDelegate[id][a];
        // forge-lint: disable-next-line(block-timestamp)
        return d.set && d.epoch == ghostEpoch[id] && block.timestamp < d.expiry && ghostOwner[id] != address(0);
    }

    function ghostGuardian(uint256 id) external view returns (address) {
        GAddrEpoch memory g = _gGuardian[id];
        return g.epoch == ghostEpoch[id] ? g.who : address(0);
    }

    function ghostTransfer(uint256 id) external view returns (address) {
        GAddrEpoch memory t = _gTransfer[id];
        return t.epoch == ghostEpoch[id] ? t.who : address(0);
    }

    function ghostRecovery(uint256 id) external view returns (address, uint256) {
        GRecovery memory r = _gRecovery[id];
        return r.epoch == ghostEpoch[id] ? (r.who, r.readyAt) : (address(0), 0);
    }

    function grantCount() external view returns (uint256) {
        return _grants.length;
    }

    function grantAt(uint256 i) external view returns (Grant memory) {
        return _grants[i];
    }
}

contract AuthorityInvariants is Test {
    OTTPRegistry internal registry;
    AuthorityHandler internal handler;

    function setUp() public {
        vm.warp(1_760_000_000);
        registry = new OTTPRegistry();
        handler = new AuthorityHandler(registry);
        targetContract(address(handler));
    }

    /// @dev walletToId / idToWallet are a bijection over live IDs, and match the ghost owner.
    function invariant_Bijection() public view {
        uint256 total = registry.totalRegistered();
        for (uint256 id = 1; id <= total; id++) {
            address w = registry.idToWallet(id);
            assertTrue(w != address(0), "live id without wallet");
            assertEq(registry.walletToId(w), id, "walletToId[idToWallet[id]] != id");
            assertEq(w, handler.ghostOwner(id), "owner diverged from ghost model");
            for (uint256 j = id + 1; j <= total; j++) {
                assertTrue(registry.idToWallet(j) != w, "two ids share a wallet");
            }
        }
        for (uint256 k = 0; k < handler.actorCount(); k++) {
            address a = handler.actors(k);
            uint256 id = registry.walletToId(a);
            if (id != 0) assertEq(registry.idToWallet(id), a, "dangling walletToId");
        }
        assertEq(registry.idToWallet(0), address(0));
        assertEq(registry.idToWallet(total + 1), address(0));
    }

    /// @dev No wallet ever gained an ID without its own call or signature (checked on every handler call).
    function invariant_NoUnconsentedGain() public view {
        assertFalse(handler.unconsentedGain(), "a wallet gained an id without its own call or signature");
        assertEq(registry.walletToId(handler.relayer()), 0, "relayer acquired an id");
        assertFalse(handler.badSigAccepted(), "a signature by the wrong key was accepted");
    }

    /// @dev Every authority view equals the epoch-scoped ghost model. Since the ghost stamps each grant with the
    ///      epoch at grant time and only ownership changes move the epoch, this proves that after any ownership
    ///      change no previously granted delegate, guardian, pending transfer or pending recovery is active.
    function invariant_AuthorityMatchesEpochScopedModel() public view {
        uint256 total = registry.totalRegistered();
        for (uint256 id = 1; id <= total; id++) {
            assertEq(registry.ownerEpoch(id), handler.ghostEpoch(id), "epoch diverged");
            assertEq(registry.guardianOf(id), handler.ghostGuardian(id), "guardian diverged");
            assertEq(registry.pendingTransferOf(id), handler.ghostTransfer(id), "pending transfer diverged");
            (address r, uint256 readyAt) = registry.pendingRecoveryOf(id);
            (address gr, uint256 gReady) = handler.ghostRecovery(id);
            assertEq(r, gr, "pending recovery diverged");
            assertEq(readyAt, gReady, "recovery readyAt diverged");
            for (uint256 k = 0; k < handler.actorCount(); k++) {
                address a = handler.actors(k);
                assertEq(registry.isDelegate(id, a), handler.ghostDelegateActive(id, a), "delegate diverged");
            }
        }
    }

    /// @dev Explicitly: every grant recorded in an epoch older than the current one is inactive, unless the same
    ///      authority was granted again in the current epoch (which the model above tracks).
    function invariant_StaleGrantsInactive() public view {
        uint256 n = handler.grantCount();
        for (uint256 i = 0; i < n; i++) {
            AuthorityHandler.Grant memory g = handler.grantAt(i);
            if (g.epoch == registry.ownerEpoch(g.id)) continue;
            assertLt(g.epoch, registry.ownerEpoch(g.id));
            if (g.kind == 0 && registry.isDelegate(g.id, g.account)) {
                assertTrue(handler.ghostDelegateActive(g.id, g.account), "stale delegate active");
            } else if (g.kind == 1 && g.account != address(0) && registry.guardianOf(g.id) == g.account) {
                assertEq(handler.ghostGuardian(g.id), g.account, "stale guardian active");
            } else if (g.kind == 2 && registry.pendingTransferOf(g.id) == g.account) {
                assertEq(handler.ghostTransfer(g.id), g.account, "stale pending transfer live");
            } else if (g.kind == 3) {
                (address r,) = registry.pendingRecoveryOf(g.id);
                if (r == g.account) {
                    (address gr,) = handler.ghostRecovery(g.id);
                    assertEq(gr, g.account, "stale pending recovery live");
                }
            }
        }
    }

    /// @dev canAttest(id, x) ⇒ x is the owner, or an unexpired delegate set in the current epoch (and conversely).
    function invariant_CanAttestIsOwnerOrCurrentDelegate() public view {
        uint256 total = registry.totalRegistered();
        for (uint256 id = 0; id <= total + 1; id++) {
            address owner = registry.idToWallet(id);
            for (uint256 k = 0; k < handler.actorCount(); k++) {
                address a = handler.actors(k);
                bool expected = owner != address(0) && (a == owner || handler.ghostDelegateActive(id, a));
                assertEq(registry.canAttest(id, a), expected, "canAttest diverged");
            }
            assertFalse(registry.canAttest(id, handler.relayer()));
            assertFalse(registry.canAttest(id, address(0)));
        }
    }

    /// @dev ownerEpoch and nextId never decrease (checked around every handler call); counters consistent.
    function invariant_MonotonicAndCounters() public view {
        assertFalse(handler.monotonicityBroken(), "epoch or nextId decreased");
        assertEq(registry.totalRegistered(), registry.nextId() - 1);
        assertEq(registry.totalRegistered(), handler.ghostIssued());
    }

    function invariant_NoEtherHeld() public view {
        assertEq(address(registry).balance, 0);
    }
}
