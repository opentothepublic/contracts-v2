// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import { Vm } from "forge-std/Vm.sol";

/// @notice Helpers to build OTTPRegistry EIP-712 digests exactly as a client (viem/ethers) would — independently
///         of the contract's own hashing, so the tests also validate the spec's domain and type definitions.
library RegistrySigUtils {
    bytes32 internal constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 internal constant REGISTER_TYPEHASH = keccak256("Register(address wallet,uint256 nonce,uint256 deadline)");

    function domainSeparator(address registry, uint256 chainId) internal pure returns (bytes32) {
        return
            keccak256(abi.encode(EIP712_DOMAIN_TYPEHASH, keccak256("OTTPRegistry"), keccak256("2"), chainId, registry));
    }

    function digest(address registry, uint256 chainId, address wallet, uint256 nonce, uint256 deadline)
        internal
        pure
        returns (bytes32)
    {
        bytes32 structHash = keccak256(abi.encode(REGISTER_TYPEHASH, wallet, nonce, deadline));
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(registry, chainId), structHash));
    }

    function sign(Vm vm, uint256 pk, address registry, uint256 chainId, address wallet, uint256 nonce, uint256 deadline)
        internal
        pure
        returns (bytes memory)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest(registry, chainId, wallet, nonce, deadline));
        return abi.encodePacked(r, s, v);
    }
}
