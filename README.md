# OTTP v2.1 — contracts

The base-level primitive of the Open Attribution Protocol on Base. Three immutable contracts and two
non-revocable EAS schemas. Implements `ottp-smart-contracts-spec.md` v1.1 (ratified July 2026).

| Contract | Role |
|---|---|
| `OTTPRegistry` | Issues sequential, permanent OTTP IDs (`uint256`, starting at 1), one per wallet. Direct `register()` and sponsored `registerFor()` (EIP-712 + ERC-1271). `transferId()` by the current owner only. |
| `OTTPSubjectResolver` | EAS resolver for the Subject schema `uint256 ottpId, string name, string metadata`. Accepts an attestation only if `registry.getWallet(ottpId) == attestation.attester`. |
| `OTTPObjectResolver` | EAS resolver for the Object schema `bytes32 originUid, uint256 creatorId, string metadata`. Same check on `creatorId`. |

## Invariants

- **Immutable.** No proxy, no owner, no pause, no admin. The deployer has no powers after deployment.
- **Non-revocable.** Both schemas are registered with `revocable = false`. History is append-only; corrections are newer attestations. `onRevoke` denies as defense-in-depth on a path EAS never reaches.
- **Authenticity only.** Resolvers check identity ↔ wallet and nothing else. They never read `name`, `metadata`, `originUid`, `refUID`, or `recipient`. Authority, ownership, and status are derived offchain per `ottp-indexer-rules.md`.
- **One ID per wallet.** `transferId` requires an ID-free target. An old wallet may later register a fresh ID; it never gets the old one back.
- **Delegated writes validate the signer.** EAS stores the signer as `attestation.attester` for `attestByDelegation`, so relayed and direct attestations are checked identically.
- **No funds.** Neither the registry nor the resolvers accept ETH.
- **Generational migration.** All state is readable through public getters (`getWallet`, `getId`, `totalRegistered`, `nextId`, `idToWallet`, `walletToId`, `nonces`) so a future generation can prove v2.1 records.

## EIP-712 (`registerFor`)

- Domain: `name = "OTTPRegistry"`, `version = "2"`, `chainId = block.chainid`, `verifyingContract = <registry>` (ERC-5267 `eip712Domain()`).
- Type: `Register(address wallet,uint256 nonce,uint256 deadline)`; `nonce = registry.nonces(wallet)`.
- Any relayer may submit; the only possible outcome is `wallet` receiving the next ID.

## Integration notes (from the independent audit, 2026-09-20)

- **Delegated attestations on Base mainnet are ECDSA-only.** Base mainnet runs EAS 1.0.1, whose `attestByDelegation` uses `ECDSA.recover`; a Safe / ERC-1271 wallet can `registerFor` but must call `EAS.attest` directly (it cannot be relayed). Base Sepolia runs EAS 1.2.0 with different typed data. Build delegated typed data per chain (see `test/fork/EASFork.t.sol`).
- **Never use EAS's `EIP712Proxy` for OTTP writes**, and never `transferId` an ID to a permissionless forwarder contract. A proxy is recorded as the attester, so an ID held by a shared proxy could be used by anyone who can drive it.
- **`registerFor` signatures should carry short deadlines** (an hour or less). Only `registerFor` consumes a nonce; a long-lived signature left over after the wallet registered directly and later transferred its ID could be replayed to give the old wallet an unwanted fresh ID (gas griefing only; recoverable).
- **Signature format:** 65-byte `r || s || v` with `v ∈ {27, 28}`, low-s. ERC-2098 compact signatures and `v ∈ {0, 1}` are rejected. Counterfactual (undeployed) smart accounts cannot use `registerFor` (no ERC-6492); EIP-7702 delegated EOAs can only if their delegate implements ERC-1271.
- **Indexers must read the ID from the ABI head word** (word 0 for Subject, word 1 for Object). Solidity's `abi.decode` accepts some non-canonical string encodings that strict decoders reject; never drop a chain-accepted attestation because the strings failed to decode — treat them as raw bytes.
- **ID #1 is first-come-first-served** the moment the registry exists. If specific low IDs matter, register them inside the deploy broadcast.

## Toolchain (pinned)

- Solidity `0.8.26`, Foundry (`forge 1.7.x`), optimizer 10 000 runs, EVM `cancun`
- `lib/openzeppelin-contracts` — `v5.6.1` (`EIP712`, `SignatureChecker`)
- `lib/eas-contracts` — tag `v1.4.0` (`SchemaResolver` base reports `version() == "1.4.0"`; source identical to npm `1.9.0`)
- `lib/forge-std` — `v1.16.2`

## Test

```bash
forge test                                             # unit + fuzz + invariant (no network)
FOUNDRY_PROFILE=deep forge test                        # 20k fuzz runs, 1000×128 invariant runs
FORK_TESTS=true forge test --match-path 'test/fork/*'  # real EAS on Base mainnet (1.0.1) and Base Sepolia (1.2.0)
forge test --gas-report
slither .                                              # static analysis (config in slither.config.json)
```

Fork tests use the public RPCs by default; override with `BASE_RPC_URL` / `BASE_SEPOLIA_RPC_URL`.

## Deploy

EAS and SchemaRegistry are OP Stack predeploys at the same addresses on both chains:
`0x4200000000000000000000000000000000000021` (EAS) and `0x4200000000000000000000000000000000000020` (SchemaRegistry).

```bash
cp .env.example .env   # fill in, never commit
# Base Sepolia dry run (chain 84532)
forge script script/Deploy.s.sol --rpc-url base_sepolia --account <keystore> --broadcast --verify -vvvv
# Base mainnet (chain 8453) — guarded; requires an explicit opt-in
ALLOW_MAINNET=true forge script script/Deploy.s.sol --rpc-url base --account <keystore> --broadcast --verify -vvvv
```

The script deploys Registry → SubjectResolver → ObjectResolver, registers both schemas with `revocable = false`,
asserts the post-conditions, and prints a paste-ready block with all three addresses and both schema UIDs.
If `--verify` did not run, verify each contract afterwards with `forge verify-contract`.

## Record addresses

After each deployment, copy the printed block into:

1. `.env` (this repo) — `OTTP_*` variables
2. `ottp-smart-contracts-spec.md` → "Contract addresses" table
3. `ottp-eas-schema-spec.md` → schema UID tables
4. The frontend / SDK env (`NEXT_PUBLIC_EAS_SCHEMA_SUBJECT`, `NEXT_PUBLIC_EAS_SCHEMA_OBJECT`, registry address)

## Layout

```
src/        OTTPRegistry.sol, OTTPSubjectResolver.sol, OTTPObjectResolver.sol, IOTTPRegistry.sol, Schemas.sol
script/     Deploy.s.sol
test/       OTTPRegistry.t.sol, Resolvers.t.sol, invariant/, fork/, mocks/, utils/
```
