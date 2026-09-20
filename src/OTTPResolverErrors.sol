// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @title OTTPResolverErrors
/// @notice Custom errors shared by OTTPSubjectResolver and OTTPObjectResolver, so SDKs decode one set.
/// @dev Spec v1.2 (D4): custom errors replace revert strings. Parameters carry the claimed id / attester for
///      debugging; they are cheap and never affect control flow.

/// @notice The attestation claims id 0, which is never issued.
error OTTPResolver__ZeroId();
/// @notice The claimed id has not been issued by the Registry (no current wallet).
error OTTPResolver__IdNotRegistered(uint256 id);
/// @notice The attester is not the current wallet of the claimed id.
error OTTPResolver__AttesterNotOwner(uint256 id, address attester, address owner);
/// @notice Constructor guard: the registry address is zero.
error OTTPResolver__ZeroRegistry();
