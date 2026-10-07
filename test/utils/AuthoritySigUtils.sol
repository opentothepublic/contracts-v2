// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import { Vm } from "forge-std/Vm.sol";

import { RegistrySigUtils } from "./RegistrySigUtils.sol";

/// @notice Client-side EIP-712 digests for the authority addendum's structs, built from the addendum's type strings
///         (not the contract's constants), so the tests also pin the published typed data.
library AuthoritySigUtils {
    bytes32 internal constant ACCEPT_ID_TYPEHASH =
        keccak256("AcceptId(uint256 id,address wallet,uint256 epoch,uint256 nonce,uint256 deadline)");
    bytes32 internal constant SET_DELEGATE_TYPEHASH = keccak256(
        "SetDelegate(uint256 id,address delegate,uint64 expiry,uint256 epoch,uint256 nonce,uint256 deadline)"
    );
    bytes32 internal constant SET_GUARDIAN_TYPEHASH =
        keccak256("SetGuardian(uint256 id,address guardian,uint256 epoch,uint256 nonce,uint256 deadline)");

    function toTypedData(address registry, uint256 chainId, bytes32 structHash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", RegistrySigUtils.domainSeparator(registry, chainId), structHash));
    }

    function acceptIdHash(uint256 id, address wallet, uint256 epoch, uint256 nonce, uint256 deadline)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(ACCEPT_ID_TYPEHASH, id, wallet, epoch, nonce, deadline));
    }

    function setDelegateHash(
        uint256 id,
        address delegate,
        uint64 expiry,
        uint256 epoch,
        uint256 nonce,
        uint256 deadline
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(SET_DELEGATE_TYPEHASH, id, delegate, expiry, epoch, nonce, deadline));
    }

    function setGuardianHash(uint256 id, address guardian, uint256 epoch, uint256 nonce, uint256 deadline)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(SET_GUARDIAN_TYPEHASH, id, guardian, epoch, nonce, deadline));
    }

    function sign(Vm vm, uint256 pk, address registry, uint256 chainId, bytes32 structHash)
        internal
        pure
        returns (bytes memory)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, toTypedData(registry, chainId, structHash));
        return abi.encodePacked(r, s, v);
    }
}
