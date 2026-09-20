// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import { Script, console2 } from "forge-std/Script.sol";
import { IEAS } from "@ethereum-attestation-service/eas-contracts/contracts/IEAS.sol";
import {
    ISchemaRegistry,
    SchemaRecord
} from "@ethereum-attestation-service/eas-contracts/contracts/ISchemaRegistry.sol";
import { ISchemaResolver } from "@ethereum-attestation-service/eas-contracts/contracts/resolver/ISchemaResolver.sol";

import { OTTPRegistry } from "../src/OTTPRegistry.sol";
import { OTTPSubjectResolver } from "../src/OTTPSubjectResolver.sol";
import { OTTPObjectResolver } from "../src/OTTPObjectResolver.sol";
import { OTTPSchemas } from "../src/Schemas.sol";

interface IVersioned {
    function version() external view returns (string memory);
}

interface IEASRegistryPointer {
    function getSchemaRegistry() external view returns (address);
}

/// @title Deploy
/// @notice Deploys the OTTP v2.1 primitive and registers both schemas, in spec order:
///         Registry → SubjectResolver → ObjectResolver → Subject schema → Object schema.
/// @dev Usage (Base Sepolia dry run):
///        forge script script/Deploy.s.sol --rpc-url base_sepolia --broadcast --verify -vvvv
///      Base mainnet additionally requires ALLOW_MAINNET=true in the environment (guard against accidents).
///      The sender comes from --private-key / --account / --ledger; nothing is read from DEPLOYER_PRIVATE_KEY here.
contract Deploy is Script {
    struct Deployment {
        address registry;
        address subjectResolver;
        address objectResolver;
        bytes32 subjectSchemaUid;
        bytes32 objectSchemaUid;
    }

    /// @notice The most recent deployment made by this script instance (for tests and tooling).
    Deployment internal _last;

    function last() external view returns (address, address, address, bytes32, bytes32) {
        return
            (_last.registry, _last.subjectResolver, _last.objectResolver, _last.subjectSchemaUid, _last.objectSchemaUid);
    }

    /// @notice Entry point for `forge script`. Reads the ALLOW_MAINNET opt-in from the environment.
    function run() external {
        runWith(vm.envOr("ALLOW_MAINNET", false));
    }

    /// @notice Same as run(), with the mainnet opt-in passed explicitly (tests use this to avoid the process-wide
    ///         env var; the guard logic is identical).
    function runWith(bool allowMainnet) public {
        uint256 chainId = block.chainid;
        require(
            chainId == OTTPSchemas.BASE_MAINNET || chainId == OTTPSchemas.BASE_SEPOLIA,
            "Deploy: only Base mainnet (8453) or Base Sepolia (84532)"
        );
        if (chainId == OTTPSchemas.BASE_MAINNET) {
            require(allowMainnet, "Deploy: set ALLOW_MAINNET=true to deploy to Base mainnet");
        }

        IEAS eas = IEAS(OTTPSchemas.EAS);
        ISchemaRegistry schemaRegistry = ISchemaRegistry(OTTPSchemas.SCHEMA_REGISTRY);
        require(address(eas).code.length != 0, "Deploy: EAS predeploy missing");
        require(address(schemaRegistry).code.length != 0, "Deploy: SchemaRegistry predeploy missing");
        string memory easVersion = IVersioned(address(eas)).version();
        require(
            IEASRegistryPointer(address(eas)).getSchemaRegistry() == address(schemaRegistry),
            "Deploy: EAS points at a different SchemaRegistry"
        );

        vm.startBroadcast();

        OTTPRegistry registry = new OTTPRegistry();
        OTTPSubjectResolver subjectResolver = new OTTPSubjectResolver(eas, registry);
        OTTPObjectResolver objectResolver = new OTTPObjectResolver(eas, registry);

        // Resolver addresses are CREATE-predictable, so a third party could pre-register the identical
        // (schema, resolver, revocable) triple to make our register() revert AlreadyExists(). The resulting record is
        // byte-identical to ours, so tolerate it: register only if the UID is not yet taken.
        bytes32 subjectSchemaUid = _ensureSchema(schemaRegistry, OTTPSchemas.SUBJECT, address(subjectResolver));
        bytes32 objectSchemaUid = _ensureSchema(schemaRegistry, OTTPSchemas.OBJECT, address(objectResolver));

        vm.stopBroadcast();

        _last = Deployment({
            registry: address(registry),
            subjectResolver: address(subjectResolver),
            objectResolver: address(objectResolver),
            subjectSchemaUid: subjectSchemaUid,
            objectSchemaUid: objectSchemaUid
        });

        // ── post-conditions ──
        require(registry.nextId() == 1 && registry.totalRegistered() == 0, "Deploy: registry not fresh");
        require(address(subjectResolver.registry()) == address(registry), "Deploy: subject resolver registry");
        require(address(objectResolver.registry()) == address(registry), "Deploy: object resolver registry");
        SchemaRecord memory s = schemaRegistry.getSchema(subjectSchemaUid);
        SchemaRecord memory o = schemaRegistry.getSchema(objectSchemaUid);
        require(address(s.resolver) == address(subjectResolver) && !s.revocable, "Deploy: subject schema record");
        require(address(o.resolver) == address(objectResolver) && !o.revocable, "Deploy: object schema record");
        require(
            subjectSchemaUid == keccak256(abi.encodePacked(OTTPSchemas.SUBJECT, address(subjectResolver), false)),
            "Deploy: subject uid derivation"
        );
        require(
            objectSchemaUid == keccak256(abi.encodePacked(OTTPSchemas.OBJECT, address(objectResolver), false)),
            "Deploy: object uid derivation"
        );

        // ── paste-ready block ──
        console2.log("");
        console2.log("==================== OTTP v2.1 deployment ====================");
        console2.log("chain id:              ", chainId);
        console2.log("EAS:                   ", address(eas));
        console2.log("EAS version:           ", easVersion);
        console2.log("SchemaRegistry:        ", address(schemaRegistry));
        console2.log("");
        console2.log("| Contract            | Address                                    |");
        console2.log("| OTTPRegistry        |", address(registry), "|");
        console2.log("| OTTPSubjectResolver |", address(subjectResolver), "|");
        console2.log("| OTTPObjectResolver  |", address(objectResolver), "|");
        console2.log("");
        console2.log("Subject schema:", OTTPSchemas.SUBJECT);
        console2.log("  uid:");
        console2.logBytes32(subjectSchemaUid);
        console2.log("Object schema: ", OTTPSchemas.OBJECT);
        console2.log("  uid:");
        console2.logBytes32(objectSchemaUid);
        console2.log("");
        console2.log("# .env");
        console2.log("OTTP_REGISTRY_ADDRESS=", address(registry));
        console2.log("OTTP_SUBJECT_RESOLVER_ADDRESS=", address(subjectResolver));
        console2.log("OTTP_OBJECT_RESOLVER_ADDRESS=", address(objectResolver));
        console2.log("OTTP_SUBJECT_SCHEMA_UID=");
        console2.logBytes32(subjectSchemaUid);
        console2.log("OTTP_OBJECT_SCHEMA_UID=");
        console2.logBytes32(objectSchemaUid);
        console2.log("==============================================================");
    }

    /// @dev Registers `schema` with `resolver` (revocable = false) unless an identical record already exists.
    function _ensureSchema(ISchemaRegistry schemaRegistry, string memory schema, address resolver)
        internal
        returns (bytes32 uid)
    {
        uid = keccak256(abi.encodePacked(schema, resolver, OTTPSchemas.REVOCABLE));
        SchemaRecord memory existing = schemaRegistry.getSchema(uid);
        if (existing.uid == bytes32(0)) {
            bytes32 registered = schemaRegistry.register(schema, ISchemaResolver(resolver), OTTPSchemas.REVOCABLE);
            require(registered == uid, "Deploy: unexpected schema uid");
        } else {
            console2.log("Schema already registered (identical record), reusing:", schema);
            require(
                address(existing.resolver) == resolver && !existing.revocable
                    && keccak256(bytes(existing.schema)) == keccak256(bytes(schema)),
                "Deploy: pre-existing schema record differs"
            );
        }
    }
}
