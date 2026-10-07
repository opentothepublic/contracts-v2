# OTTP v2.1 — Contracts Addendum: Authority (PROPOSED)

**Status: PROPOSED — pending ratification (Nate + Ting, Oct 8 2026).** Nothing in this document is ratified.
**Extends:** `ottp-smart-contracts-spec.md` v1.2 (D1–D6). Every v1.2 rule not changed below still holds.
**Branch:** `v2.1-authority` (built from `v2.1-contracts`). One commit per item, in order: B0, B1, B2, B3.
**Date:** 2026-10-07

Each item can be ratified or dropped on its own. §7 says exactly what dropping each one implies.

---

## 1. Why — PROPOSED — pending ratification

The registry is immutable. Anything about *who controls an ID* cannot be added after deploy. A later
generation can add features, but it cannot retrofit control rules onto IDs that already live here.

- **Recovery.** Without it, a lost wallet means a lost ID. Target users with social-login or embedded wallets
  need it.
- **Delegates.** Base mainnet EAS 1.0.1 verifies delegated attestations with `ECDSA.recover` only. It cannot
  relay an ERC-1271 signature. Without delegates, a Safe-owned ID (Collab's operator) needs a Safe transaction
  for every attestation. Open Studios releases and agent/app keys have the same need.
- **Two-step transfer.** v1.2 `transferId` lets any owner push an ID into any ID-free wallet without that
  wallet's consent. That allows:
  - fat-finger permanent loss (a typo'd or dead target);
  - griefing: dump an ID with a toxic history onto someone's verified wallet, filling its one-ID slot.

---

## 2. B0 — Infrastructure (no behavior change) — PROPOSED — pending ratification

### 2.1 Ownership epoch

- `ownerEpoch(uint256 id) → uint96` (public). Starts at 0 when the ID is issued.
- It increments by exactly 1 on **every** ownership change: transfer accept, recovery accept, and (in B0 only,
  before B1 replaces it) `transferId`.
- Issuance (`register` / `registerFor`) is not an ownership change. No authority can be granted before an ID
  exists, so there is nothing to invalidate.
- It never decreases. A `uint96` cannot overflow in practice: one ownership change per transaction.

### 2.2 Epoch-scoped authority (lazy invalidation)

Every granted authority is stored together with the epoch it was granted in:

- delegates (B2);
- the guardian (B3);
- the pending transfer (B1);
- the pending recovery (B3).

Each one is **inactive unless `storedEpoch == ownerEpoch[id]`**. An ownership change therefore resets all
authority to the new owner's choices in O(1), with no loops and no enumeration.

### 2.3 `_move(id, newWallet)` — the single ownership-change path

Every ownership change goes through one internal function. It:

1. clears `walletToId[old]`, sets `idToWallet[id] = newWallet` and `walletToId[newWallet] = id`;
2. bumps `ownerEpoch[id]`;
3. deletes the pending transfer and the pending recovery (storage hygiene; the epoch already kills them);
4. emits `Transferred(id, old, newWallet)`.

`Transferred` is emitted for **every** path (transfer and recovery). Indexers that only watch `Transferred`
stay correct. Indexers SHOULD treat every `Transferred` as "all delegates, guardian, pending transfer and
pending recovery for this ID are now void". No per-item events are emitted for that implicit reset.

### 2.4 Nonces

- One shared counter, `nonces(address)`, is used by every signature path.
- Every signature path consumes **exactly one** nonce of its signer through a single `_useNonce(addr)` helper.
- `register()` also consumes one (v1.2 D6, unchanged).
- Other direct (non-signature) calls never touch nonces.
- The digest is built with the signer's *current* nonce, which `_useNonce` then increments. A failed call
  reverts, so its nonce is untouched.
- Clients may therefore pre-sign a chain of messages for one signer at `n`, `n+1`, … For example:
  `registerFor` at `n`, then `setDelegateBySig` at `n+1`.

| Path | Signer | Nonce consumed |
|---|---|---|
| `register()` | — (direct) | `nonces[msg.sender]` +1 (D6) |
| `registerFor` | `wallet` | `nonces[wallet]` +1 |
| `acceptIdBySig` (B1) | `wallet` (the receiver) | `nonces[wallet]` +1 |
| `setDelegateBySig` (B2) | current owner | `nonces[owner]` +1 |
| `setGuardianBySig` (B3) | current owner | `nonces[owner]` +1 |
| every other function | — | none |

### 2.5 Signatures

- Verified with OpenZeppelin `SignatureChecker.isValidSignatureNow`, which covers EOA ECDSA and ERC-1271.
- The EIP-712 domain is unchanged: `name = "OTTPRegistry"`, `version = "2"`, `chainId`,
  `verifyingContract`.
- Every signed struct has its own typehash:

| Struct | Typehash string |
|---|---|
| Register (v1.2) | `Register(address wallet,uint256 nonce,uint256 deadline)` |
| AcceptId (B1) | `AcceptId(uint256 id,address wallet,uint256 epoch,uint256 nonce,uint256 deadline)` |
| SetDelegate (B2) | `SetDelegate(uint256 id,address delegate,uint64 expiry,uint256 epoch,uint256 nonce,uint256 deadline)` |
| SetGuardian (B3) | `SetGuardian(uint256 id,address guardian,uint256 epoch,uint256 nonce,uint256 deadline)` |

How the `epoch` and `nonce` fields are filled:

- **Epoch.** The `BySig` functions take no `epoch` argument. The contract hashes the **current**
  `ownerEpoch[id]`, so a signature made in an earlier epoch fails `OTTPRegistry__InvalidSignature`.
- **Nonce.** The contract hashes the signer's **current** nonce, as in `registerFor`.

### 2.6 Order of checks in every `BySig` function

1. deadline (`block.timestamp > deadline` → `OTTPRegistry__SignatureExpired`);
2. the signer exists (owner-signed paths only: `OTTPRegistry__IdNotRegistered`);
3. the signature at `(current epoch, current nonce)` (`OTTPRegistry__InvalidSignature(signer)`);
4. the same semantic checks as the direct variant.

Reverts are atomic, so the nonce moves only on success.

---

## 3. B1 — Two-step transfer (replaces `transferId`) — PROPOSED — pending ratification

`transferId` is **removed**. Moving an ID now always takes two parties' consent.

### 3.1 Functions

**`proposeTransfer(uint256 id, address newWallet)`**
- Callable only by the current owner (`OTTPRegistry__NotOwner`).
- `newWallet` must be non-zero (`OTTPRegistry__ZeroAddress`) and ID-free
  (`OTTPRegistry__TargetAlreadyRegistered`). The owner's own wallet is never ID-free.
- Stores `{newWallet, epoch}`. A later proposal overwrites the earlier one.
- Emits `TransferProposed(id, owner, newWallet, epoch)`.

**`cancelTransfer(uint256 id)`**
- Callable only by the owner.
- Reverts `OTTPRegistry__NoPendingTransfer(id)` if there is no live pending transfer.
- Deletes the pending transfer and emits `TransferCancelled(id, newWallet)`.

**`acceptId(uint256 id)`** — `wallet = msg.sender`.

**`acceptIdBySig(uint256 id, address wallet, uint256 deadline, bytes signature)`**
- The gasless version: any relayer may submit it.
- `wallet` signs `AcceptId(id, wallet, ownerEpoch[id], nonces[wallet], deadline)`.

### 3.2 Accept rules, in order

1. There is a **live** pending transfer (stored epoch == current epoch) whose target is `wallet`, **or** (B3) a
   live pending recovery whose target is `wallet` and whose `readyAt <= block.timestamp`.
   - Otherwise the call reverts:
     - `OTTPRegistry__RecoveryNotReady(id, readyAt)` if a live recovery to `wallet` exists but has not matured;
     - `OTTPRegistry__NoPendingMove(id, wallet)` in every other case.
   - If both a transfer and a recovery target `wallet`, the transfer wins: no `RecoveryFinalized`.
2. `wallet` is still ID-free (`OTTPRegistry__TargetAlreadyRegistered`).
3. `_move(id, wallet)` runs. For a recovery, `RecoveryFinalized(id, old, wallet)` is also emitted.

The signed consent means "I accept ID #id into this wallet". One struct covers both transfer and recovery.

**Result:** no ID ever lands in a wallet without that wallet's own call (`register`, `acceptId`) or
signature (`registerFor`, `acceptIdBySig`).

---

## 4. B2 — Delegates (attest-only) — PROPOSED — pending ratification

### 4.1 Functions

**`setDelegate(uint256 id, address delegate, uint64 expiry)`**
- Callable only by the owner.
- `delegate` must be non-zero and must not be the owner (`OTTPRegistry__InvalidDelegate(delegate)`).
- `expiry` values:
  - `0` revokes (the record is deleted);
  - any other value must be `> block.timestamp` (`OTTPRegistry__InvalidExpiry(expiry)`);
  - `type(uint64).max` means no expiry.
- Stored per `(id, delegate)` as `{expiry, epoch}`.
- Emits `DelegateSet(id, delegate, expiry, epoch)`.

**`setDelegateBySig(uint256 id, address delegate, uint64 expiry, uint256 deadline, bytes signature)`**
- Signed by the **current** owner over
  `SetDelegate(id, delegate, expiry, ownerEpoch[id], nonces[owner], deadline)`.
- Because the current epoch is hashed in, an old owner's or a previous epoch's signature is dead.

### 4.2 Views

- **`isDelegate(id, account)`** is true iff all of these hold:
  - the ID exists;
  - the stored epoch equals `ownerEpoch[id]`;
  - `block.timestamp < expiry`.
- **`canAttest(id, account)`** is `owner != 0 && (account == owner || isDelegate(id, account))`.
- **`delegateExpiry(id, account)`** returns the active expiry, or 0 if the delegate is inactive.

### 4.3 What a delegate can and cannot do

A delegate can **only** attest Objects for `creatorId = id`. It cannot do any of these:

- transfer, propose, cancel or accept;
- set delegates or a guardian;
- touch recovery.

Delegate status is checked nowhere except `canAttest`.

### 4.4 Resolvers

- **`OTTPObjectResolver`**
  - Accepts iff `registry.canAttest(creatorId, attestation.attester)`.
  - On rejection it reads `getWallet` once more to report the reason:
    - `OTTPResolver__IdNotRegistered(id)`;
    - `OTTPResolver__AttesterNotOwner(id, attester, owner)`, which now means "neither the owner nor an active
      delegate". The error ABI is kept unchanged so SDKs decode one set.
  - It takes the registry through a new interface, `IOTTPRegistryAuthority is IOTTPRegistry`.
- **`OTTPSubjectResolver` is unchanged and stays OWNER-ONLY.** Delegates can act; they can't redefine identity.
  Indexer rule S-2 is unchanged.
  - `IOTTPRegistry.sol` is untouched, so the Subject resolver's bytecode, metadata hash included, is
    byte-identical to `v2.1-contracts`.

---

## 5. B3 — Guardian recovery — PROPOSED — pending ratification

### 5.1 Functions

**`setGuardian(uint256 id, address guardian)`**
- Callable only by the owner.
- `guardian != owner` (`OTTPRegistry__InvalidGuardian(guardian)`). `address(0)` clears the guardian.
- Stored as `{guardian, epoch}`.
- **Any** call deletes a live pending recovery, emitting `RecoveryCancelled(id, owner)` when one existed.
- Emits `GuardianSet(id, guardian, epoch)`.

**`setGuardianBySig(uint256 id, address guardian, uint256 deadline, bytes signature)`**
- Signed by the current owner over `SetGuardian(id, guardian, ownerEpoch[id], nonces[owner], deadline)`.
- Clients may offer a guardian at registration this way. A client can pre-sign `registerFor` at `n` and
  `setGuardianBySig` at `n+1`.

**`initiateRecovery(uint256 id, address newWallet)`**
- Callable only by the active guardian (`OTTPRegistry__NotGuardian(id, caller)`).
- `newWallet` must be non-zero and ID-free.
- Stores `{newWallet, readyAt = block.timestamp + RECOVERY_DELAY, epoch}`. Re-initiating overwrites the
  earlier request and restarts the clock.
- Emits `RecoveryInitiated(id, guardian, newWallet, readyAt)`.

**`cancelRecovery(uint256 id)`**
- Callable by the owner **or** the active guardian (`OTTPRegistry__NotOwnerOrGuardian`).
- Reverts `OTTPRegistry__NoPendingRecovery(id)` if there is none.
- Emits `RecoveryCancelled(id, by)`.

**Completion** happens only through `acceptId` / `acceptIdBySig` by `newWallet` once
`block.timestamp >= readyAt` (§3.2). It emits `Transferred` and also `RecoveryFinalized(id, old, new)`.

### 5.2 Constants and scope

- **`RECOVERY_DELAY = 7 days`**, a constant. **Decision for Nate** (§9).
- There is no protocol default guardian.
- A guardian can only initiate and cancel recovery. It cannot attest, transfer, set delegates or accept.
  It can attest only if the owner separately makes the same address a delegate.

### 5.3 Views

- `guardianOf(id)` returns the active guardian, or 0.
- `pendingTransferOf(id)` returns the live target, or 0.
- `pendingRecoveryOf(id)` returns `(newWallet, readyAt)` if live, otherwise zeros.

### 5.4 Threat model, stated plainly

- **Recovery protects against loss, not against compromise.**
  - Someone holding the owner key can cancel recovery, replace the guardian, or move the ID instantly with
    `proposeTransfer` + `acceptId` into a wallet they control.
  - Recovery wins only when the owner key is gone and no one else holds it.
  - This is the same accepted limitation as v1.2 (Security considerations), narrowed.
- **A malicious or compromised guardian can start a recovery.**
  - The owner has `RECOVERY_DELAY` to see `RecoveryInitiated` and call `cancelRecovery` or `setGuardian`.
  - Clients SHOULD notify owners on `RecoveryInitiated`.
- A guardian that cancels and re-initiates repeatedly can only delay. It cannot take the ID early, because
  every initiation restarts the clock.

---

## 6. Proposed indexer rules (paper only — no contract change) — PROPOSED — pending ratification

- **D-1 (Delegate attribution).** An Object attestation accepted onchain because its attester was an active
  delegate of `creatorId` is attributed to `creatorId`, exactly like an owner-signed one: O-2 ownership, V-1
  authority, V-3 owner content.
  - Clients MAY show "signed via delegate" when `attester != registry.getWallet(creatorId)` at attest time.
  - Indexers can reconstruct that from `DelegateSet` / `Transferred` events.
- **D-2 (Key disown).** An owner may publish an Object
  `{ "type": "key-disown", "key": "<address>", "fromTime": <unix seconds> }` under their `creatorId`, signed by
  the owner wallet (not by a delegate).
  - Attestations by `key` for that `creatorId` with `time >= fromTime` are **non-authoritative**: excluded
    from O-2 origin ownership and V-1 authority, and shown as disowned.
  - Schemas are non-revocable, so this is the remedy for a leaked delegate key after `setDelegate(…, 0)`
    stops new damage.
  - A `key-disown` signed by a delegate is ignored. Otherwise a leaked delegate key could disown the
    owner's other keys.
- **S-2 is unchanged.** Only the owner wallet writes Subjects; the Subject resolver enforces it.

---

## 7. Dropping an item — PROPOSED — pending ratification

- **Drop B3** (guardian recovery): delete the guardian/recovery state, functions, events and errors, and the
  recovery branch of accept. B0–B2 are unaffected. The B3 commit reverts cleanly.
- **Drop B2** (delegates): delete the delegate state, functions and views. Restore the Object resolver's
  owner-equality check and `IOTTPRegistry` type. B0, B1 and B3 are unaffected.
- **Drop B1** (two-step transfer): restore `transferId` (on top of `_move`).
  - If B3 is kept, `acceptId` / `acceptIdBySig` stay as the recovery-only completion path.
  - If B3 is also dropped, they go too.
  - Reverting the B1 commit while keeping B3 needs a manual merge in `acceptId`.
- **Drop B0:** not independently droppable. It is the substrate for B1–B3 and has no behavior of its own.
  Dropping all of B1–B3 leaves B0 behaviorally identical to `v2.1-contracts`, apart from the new
  `ownerEpoch` view.

---

## 8. Errors and events added — PROPOSED — pending ratification

**Errors (registry):**
- `OTTPRegistry__IdNotRegistered(uint256 id)`
- `OTTPRegistry__NoPendingTransfer(uint256 id)`
- `OTTPRegistry__NoPendingMove(uint256 id, address wallet)`
- `OTTPRegistry__RecoveryNotReady(uint256 id, uint256 readyAt)`
- `OTTPRegistry__InvalidDelegate(address delegate)`
- `OTTPRegistry__InvalidExpiry(uint64 expiry)`
- `OTTPRegistry__InvalidGuardian(address guardian)`
- `OTTPRegistry__NotGuardian(uint256 id, address caller)`
- `OTTPRegistry__NotOwnerOrGuardian(uint256 id, address caller)`
- `OTTPRegistry__NoPendingRecovery(uint256 id)`

The v1.2 errors are reused where they fit: `NotOwner`, `ZeroAddress`, `TargetAlreadyRegistered`,
`SignatureExpired`, `InvalidSignature`.

**Events:**
- `TransferProposed(uint256 indexed id, address indexed owner, address indexed newWallet, uint256 epoch)`
- `TransferCancelled(uint256 indexed id, address indexed newWallet)`
- `DelegateSet(uint256 indexed id, address indexed delegate, uint64 expiry, uint256 epoch)`
- `GuardianSet(uint256 indexed id, address indexed guardian, uint256 epoch)`
- `RecoveryInitiated(uint256 indexed id, address indexed guardian, address indexed newWallet, uint256 readyAt)`
- `RecoveryCancelled(uint256 indexed id, address indexed by)`
- `RecoveryFinalized(uint256 indexed id, address indexed oldWallet, address indexed newWallet)`

`Registered` and `Transferred` are unchanged.

---

## 9. Decisions needed — PROPOSED — pending ratification

1. **`RECOVERY_DELAY`**: 7 days (proposed). Shorter favours users who lost a key. Longer favours owners who
   rarely check notifications.
2. **Reset on ownership change.** Should delegates, guardian and pending moves all reset on every ownership
   change, recovery included? Proposed: yes, all of them.
   - Upside: a new owner never inherits someone else's agents or guardian.
   - Downside: after a recovery the user must re-grant delegates (for example Collab's operator key) and
     re-set a guardian.
3. **Recovery covers loss only, not live compromise** (§5.4). Accept as the scope, or add an owner-veto
   window to direct transfers? A veto window would make every honest transfer slower.
4. **D-2 `key-disown`** as an indexer rule: confirm the shape, and the owner-only signer, which is this
   addendum's addition to the brief.
5. **Object resolver error.** Keep `AttesterNotOwner` (the ABI stays stable, the meaning widens), or add a new
   `AttesterNotAuthorized`?
