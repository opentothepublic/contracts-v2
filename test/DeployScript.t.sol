// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import { Test } from "forge-std/Test.sol";
import { ISchemaResolver } from "@ethereum-attestation-service/eas-contracts/contracts/resolver/ISchemaResolver.sol";
import { SchemaRecord } from "@ethereum-attestation-service/eas-contracts/contracts/ISchemaRegistry.sol";

import { Deploy } from "../script/Deploy.s.sol";
import { OTTPSchemas } from "../src/Schemas.sol";
import { OTTPRegistry } from "../src/OTTPRegistry.sol";
import { OTTPSubjectResolver } from "../src/OTTPSubjectResolver.sol";
import { OTTPObjectResolver } from "../src/OTTPObjectResolver.sol";

/// @dev Minimal SchemaRegistry with EAS's exact UID derivation and AlreadyExists semantics.
contract MockSchemaRegistry {
    error AlreadyExists();

    mapping(bytes32 => SchemaRecord) internal _records;
    uint256 public registrations;

    function register(string calldata schema, ISchemaResolver resolver, bool revocable) external returns (bytes32) {
        bytes32 uid = keccak256(abi.encodePacked(schema, address(resolver), revocable));
        if (_records[uid].uid != bytes32(0)) revert AlreadyExists();
        _records[uid] = SchemaRecord({ uid: uid, resolver: resolver, revocable: revocable, schema: schema });
        registrations++;
        return uid;
    }

    function getSchema(bytes32 uid) external view returns (SchemaRecord memory) {
        return _records[uid];
    }
}

contract MockEASPredeploy {
    function version() external pure returns (string memory) {
        return "1.0.1";
    }

    function getSchemaRegistry() external pure returns (address) {
        return OTTPSchemas.SCHEMA_REGISTRY;
    }
}

/// @title DeployScriptTest
/// @notice Runs script/Deploy.s.sol locally (no network) with mocks etched at the OP Stack predeploy addresses.
///         Pins spec v1.2 D5: the exact schema strings and the UID the script registers.
contract DeployScriptTest is Test {
    string internal constant SUBJECT = "uint256 ottpId, string name, string metadata";
    string internal constant OBJECT = "bytes32 originUid, uint256 creatorId, string metadata";

    function setUp() public {
        vm.etch(OTTPSchemas.SCHEMA_REGISTRY, address(new MockSchemaRegistry()).code);
        vm.etch(OTTPSchemas.EAS, address(new MockEASPredeploy()).code);
    }

    function test_D5_SchemaStringsAreByteForByte() public pure {
        assertEq(OTTPSchemas.SUBJECT, SUBJECT);
        assertEq(OTTPSchemas.OBJECT, OBJECT);
        assertEq(keccak256(bytes(OTTPSchemas.SUBJECT)), keccak256(bytes(SUBJECT)));
        assertEq(keccak256(bytes(OTTPSchemas.OBJECT)), keccak256(bytes(OBJECT)));
        assertFalse(OTTPSchemas.REVOCABLE);
    }

    function test_D5_ScriptRegistersExactUids_Sepolia() public {
        vm.chainId(OTTPSchemas.BASE_SEPOLIA);
        _runAndAssert();
    }

    /// @dev Mainnet guard and opt-in live in ONE test: vm.setEnv is process-wide and tests run in parallel, so
    ///      splitting "false" and "true" into two tests races.
    function test_D5_ScriptMainnet_RefusesWithoutOptIn_ThenRegistersExactUidsWithOptIn() public {
        vm.chainId(OTTPSchemas.BASE_MAINNET);
        vm.setEnv("ALLOW_MAINNET", "false");
        Deploy d = new Deploy();
        vm.expectRevert("Deploy: set ALLOW_MAINNET=true to deploy to Base mainnet");
        d.run();
        vm.setEnv("ALLOW_MAINNET", "true");
        _runAndAssert();
    }

    function test_Script_RefusesOtherChains() public {
        vm.chainId(1);
        Deploy d = new Deploy();
        vm.expectRevert("Deploy: only Base mainnet (8453) or Base Sepolia (84532)");
        d.run();
    }

    /// @dev LOW-3 regression: a third party pre-registers the identical (schema, resolver, false) triple using the
    ///      CREATE-predictable resolver address. The script must reuse the record instead of reverting.
    function test_Script_ReusesIdenticalPreRegisteredSchema() public {
        vm.chainId(OTTPSchemas.BASE_SEPOLIA);
        // Under vm.startBroadcast() with no sender argument the script deploys from DEFAULT_SENDER:
        // nonce n = registry, n+1 = subject resolver, n+2 = object resolver.
        uint64 n = vm.getNonce(DEFAULT_SENDER);
        address predictedSubjectResolver = vm.computeCreateAddress(DEFAULT_SENDER, n + 1);
        MockSchemaRegistry reg = MockSchemaRegistry(OTTPSchemas.SCHEMA_REGISTRY);
        bytes32 preUid = reg.register(SUBJECT, ISchemaResolver(predictedSubjectResolver), false);
        assertEq(reg.registrations(), 1);

        Deploy d = new Deploy();
        d.run(); // must not revert with AlreadyExists
        (, address subj,, bytes32 subjUid, bytes32 objUid) = d.last();
        assertEq(subj, predictedSubjectResolver, "prediction of the resolver address");
        assertEq(subjUid, preUid, "script reused the pre-registered identical record");
        assertEq(reg.registrations(), 2, "only the Object schema was newly registered");
        assertEq(reg.getSchema(objUid).uid, objUid);
    }

    function _runAndAssert() internal {
        Deploy d = new Deploy();
        d.run();
        (address reg, address subj, address obj, bytes32 subjUid, bytes32 objUid) = d.last();

        assertEq(subjUid, keccak256(abi.encodePacked(SUBJECT, subj, false)), "subject uid derivation");
        assertEq(objUid, keccak256(abi.encodePacked(OBJECT, obj, false)), "object uid derivation");

        MockSchemaRegistry sr = MockSchemaRegistry(OTTPSchemas.SCHEMA_REGISTRY);
        SchemaRecord memory s = sr.getSchema(subjUid);
        SchemaRecord memory o = sr.getSchema(objUid);
        assertEq(s.schema, SUBJECT);
        assertEq(o.schema, OBJECT);
        assertEq(address(s.resolver), subj);
        assertEq(address(o.resolver), obj);
        assertFalse(s.revocable);
        assertFalse(o.revocable);
        assertEq(sr.registrations(), 2);

        assertEq(OTTPRegistry(reg).nextId(), 1);
        assertEq(address(OTTPSubjectResolver(payable(subj)).registry()), reg);
        assertEq(address(OTTPObjectResolver(payable(obj)).registry()), reg);
    }
}
