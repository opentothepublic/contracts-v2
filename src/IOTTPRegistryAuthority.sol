// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import { IOTTPRegistry } from "./IOTTPRegistry.sol";

/// @title IOTTPRegistryAuthority
/// @notice IOTTPRegistry plus the attest-authority reads the Object resolver needs (authority addendum B2, PROPOSED).
/// @dev A separate interface so `IOTTPRegistry.sol`, and with it the Subject resolver's bytecode, stays unchanged.
interface IOTTPRegistryAuthority is IOTTPRegistry {
    /// @notice True iff `account` is an active (current-epoch, unexpired) attest-only delegate of `id`.
    function isDelegate(uint256 id, address account) external view returns (bool);
    /// @notice True iff `id` is issued and `account` is its current wallet or an active delegate.
    function canAttest(uint256 id, address account) external view returns (bool);
}
