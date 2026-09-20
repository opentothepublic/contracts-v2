// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {
    Attestation,
    AccessDenied,
    NotFound,
    EMPTY_UID
} from "@ethereum-attestation-service/eas-contracts/contracts/Common.sol";
import { AttestationRequestData } from "@ethereum-attestation-service/eas-contracts/contracts/IEAS.sol";
import { ISchemaResolver } from "@ethereum-attestation-service/eas-contracts/contracts/resolver/ISchemaResolver.sol";

/// @title MockEAS
/// @notice A minimal EAS stand-in for unit tests. Mirrors the parts of EAS.sol's `_attest` / `_revoke` /
///         `_resolveAttestation` control flow that matter for resolver behaviour:
///         - schema record lookup (resolver + revocable flag)
///         - `Irrevocable()` when a revocable request hits a non-revocable schema, or on any revoke of one
///         - `NotPayable()` when value is sent to a non-payable resolver
///         - `InvalidAttestation()` / `InvalidRevocation()` when the resolver returns false
///         - `attestation.attester` = msg.sender for direct, = signer for delegated
///         Signature verification for delegated attestations is deliberately NOT modelled here; the fork tests
///         exercise it against the real EAS on Base mainnet and Base Sepolia.
contract MockEAS {
    error Irrevocable();
    error InvalidAttestation();
    error InvalidRevocation();
    error NotPayable();
    error AlreadyRevoked();

    struct SchemaRecord {
        ISchemaResolver resolver;
        bool revocable;
        string schema;
    }

    mapping(bytes32 uid => SchemaRecord) public schemas;
    mapping(bytes32 uid => Attestation) internal _attestations;
    uint256 private _salt;

    // ─── Schema registry (EAS's SchemaRegistry semantics, collapsed into the mock) ─────────────────────────

    function registerSchema(string calldata schema, ISchemaResolver resolver, bool revocable)
        external
        returns (bytes32 uid)
    {
        uid = keccak256(abi.encodePacked(schema, address(resolver), revocable));
        require(bytes(schemas[uid].schema).length == 0, "exists");
        schemas[uid] = SchemaRecord({ resolver: resolver, revocable: revocable, schema: schema });
    }

    // ─── Attest ────────────────────────────────────────────────────────────────────────────────────────────

    /// @notice Direct attestation: attester = msg.sender (as in EAS.attest).
    function attest(bytes32 schema, AttestationRequestData calldata data) external payable returns (bytes32) {
        return _attest(schema, data, msg.sender, msg.value);
    }

    /// @notice Delegated attestation: attester = the (already verified) signer, msg.sender is the relayer.
    ///         Real EAS recovers `attester` from the EIP-712 signature; the mock takes it as a parameter.
    function attestByDelegation(bytes32 schema, AttestationRequestData calldata data, address attester)
        external
        payable
        returns (bytes32)
    {
        return _attest(schema, data, attester, msg.value);
    }

    function _attest(bytes32 schema, AttestationRequestData calldata data, address attester, uint256 value)
        internal
        returns (bytes32 uid)
    {
        SchemaRecord storage rec = schemas[schema];
        require(bytes(rec.schema).length != 0, "schema not registered");
        if (!rec.revocable && data.revocable) revert Irrevocable();
        if (data.refUID != EMPTY_UID && _attestations[data.refUID].uid == EMPTY_UID) revert NotFound();

        uid = keccak256(abi.encode(schema, attester, data.data, _salt++));
        Attestation memory att = Attestation({
            uid: uid,
            schema: schema,
            time: uint64(block.timestamp),
            expirationTime: data.expirationTime,
            revocationTime: 0,
            refUID: data.refUID,
            recipient: data.recipient,
            attester: attester,
            revocable: data.revocable,
            data: data.data
        });

        if (address(rec.resolver) == address(0)) {
            if (value != 0) revert NotPayable();
        } else {
            if (value != 0 && !rec.resolver.isPayable()) revert NotPayable();
            if (!rec.resolver.attest{ value: value }(att)) revert InvalidAttestation();
        }
        _attestations[uid] = att;
    }

    // ─── Revoke ────────────────────────────────────────────────────────────────────────────────────────────

    /// @notice Mirrors EAS._revoke: `revocable` is checked in core BEFORE the resolver is reached.
    function revoke(bytes32 schema, bytes32 uid) external payable {
        Attestation storage att = _attestations[uid];
        if (att.uid == EMPTY_UID) revert NotFound();
        require(att.schema == schema, "schema mismatch");
        if (att.attester != msg.sender) revert AccessDenied();
        if (!att.revocable) revert Irrevocable();
        if (att.revocationTime != 0) revert AlreadyRevoked();
        att.revocationTime = uint64(block.timestamp);
        SchemaRecord storage rec = schemas[schema];
        if (address(rec.resolver) != address(0)) {
            if (!rec.resolver.revoke{ value: msg.value }(att)) revert InvalidRevocation();
        }
    }

    /// @notice Test-only: skip the core schema check and hit the resolver's onRevoke directly, to prove the
    ///         resolver denies revocation on its own even if core were misconfigured.
    function revokeBypassingCoreCheck(bytes32 uid) external {
        Attestation storage att = _attestations[uid];
        if (att.uid == EMPTY_UID) revert NotFound();
        SchemaRecord storage rec = schemas[att.schema];
        if (!rec.resolver.revoke(att)) revert InvalidRevocation();
    }

    // ─── Views ─────────────────────────────────────────────────────────────────────────────────────────────

    function getAttestation(bytes32 uid) external view returns (Attestation memory) {
        return _attestations[uid];
    }

    function isAttestationValid(bytes32 uid) external view returns (bool) {
        return _attestations[uid].uid != EMPTY_UID;
    }
}
