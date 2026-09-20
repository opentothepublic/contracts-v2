// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @title IOTTPRegistry
/// @notice Minimal read interface the resolvers (and any future generation) need from the Registry.
interface IOTTPRegistry {
    /// @notice Current wallet for an OTTP ID (zero address = nonexistent)
    function getWallet(uint256 id) external view returns (address);
    /// @notice OTTP ID for a wallet (0 = not registered)
    function getId(address wallet) external view returns (uint256);
    /// @notice Total number of IDs issued so far
    function totalRegistered() external view returns (uint256);
    /// @notice Next ID to be issued
    function nextId() external view returns (uint256);
}
