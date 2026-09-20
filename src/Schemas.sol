// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @title OTTPSchemas
/// @notice Canonical schema strings and EAS predeploy addresses shared by the deploy script and tests.
/// @dev Schema UID = keccak256(abi.encodePacked(schema, resolver, revocable)); the exact string matters.
library OTTPSchemas {
    /// @notice Subject schema, per ottp-smart-contracts-spec.md v1.1.
    string internal constant SUBJECT = "uint256 ottpId, string name, string metadata";
    /// @notice Object schema, per ottp-smart-contracts-spec.md v1.1.
    string internal constant OBJECT = "bytes32 originUid, uint256 creatorId, string metadata";
    /// @notice Both schemas are registered non-revocable. History is append-only.
    bool internal constant REVOCABLE = false;

    /// @notice EAS predeploy on OP Stack chains (Base mainnet 8453 and Base Sepolia 84532).
    ///         Verified onchain 2026-09-20 via `cast code` + `version()`; matches eas-contracts deployments/.
    address internal constant EAS = 0x4200000000000000000000000000000000000021;
    /// @notice SchemaRegistry predeploy on OP Stack chains.
    address internal constant SCHEMA_REGISTRY = 0x4200000000000000000000000000000000000020;

    uint256 internal constant BASE_MAINNET = 8453;
    uint256 internal constant BASE_SEPOLIA = 84532;
}
