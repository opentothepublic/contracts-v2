// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import { IERC1271 } from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @notice Minimal ERC-1271 smart-contract wallet: valid iff the signature is from `owner` (like a 1-of-1 Safe).
contract ERC1271Wallet is IERC1271 {
    address public immutable owner;

    constructor(address _owner) {
        owner = _owner;
    }

    function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4) {
        (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(hash, signature);
        if (err == ECDSA.RecoverError.NoError && recovered == owner) {
            return IERC1271.isValidSignature.selector;
        }
        return 0xffffffff;
    }
}

/// @notice ERC-1271 wallet that accepts a fixed opaque "password" as its signature — proves the ERC-1271 path is
///         exercised independently of ECDSA (e.g. a multisig with its own signature scheme).
contract PasswordWallet is IERC1271 {
    bytes32 private immutable _password;

    constructor(bytes32 password) {
        _password = password;
    }

    function isValidSignature(bytes32, bytes memory signature) external view returns (bytes4) {
        if (signature.length == 32 && abi.decode(signature, (bytes32)) == _password) {
            return IERC1271.isValidSignature.selector;
        }
        return 0xffffffff;
    }
}

/// @notice A contract with no ERC-1271 support at all. registerFor must reject it.
contract NotAWallet {
    function ping() external pure returns (uint256) {
        return 1;
    }
}
