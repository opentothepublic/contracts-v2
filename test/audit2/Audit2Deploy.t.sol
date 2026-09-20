// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

// AUDIT ROUND 2 (2026-09-20) — script/Deploy.s.sol: schema strings, revocable flag, resolver wiring, chain guard,
// and whether the idempotent "reuse" path can accept a WRONG record.
//   forge test --match-path 'test/audit2/*'

import { Test } from "forge-std/Test.sol";
import { ISchemaResolver } from "@ethereum-attestation-service/eas-contracts/contracts/resolver/ISchemaResolver.sol";
import { SchemaRecord } from "@ethereum-attestation-service/eas-contracts/contracts/ISchemaRegistry.sol";

import { Deploy } from "../../script/Deploy.s.sol";
import { OTTPSchemas } from "../../src/Schemas.sol";
import { OTTPRegistry } from "../../src/OTTPRegistry.sol";
import { OTTPSubjectResolver } from "../../src/OTTPSubjectResolver.sol";
import { OTTPObjectResolver } from "../../src/OTTPObjectResolver.sol";

/// @dev Faithful SchemaRegistry (EAS UID derivation + AlreadyExists), with test hooks to plant WRONG records.
contract PlantableSchemaRegistry {
    error AlreadyExists();

    mapping(bytes32 => SchemaRecord) internal _records;
    uint256 public registrations;
    bool public lieAboutUid;

    function register(string calldata schema, ISchemaResolver resolver, bool revocable) external returns (bytes32) {
        bytes32 uid = keccak256(abi.encodePacked(schema, address(resolver), revocable));
        if (_records[uid].uid != bytes32(0)) revert AlreadyExists();
        _records[uid] = SchemaRecord({ uid: uid, resolver: resolver, revocable: revocable, schema: schema });
        registrations++;
        return lieAboutUid ? bytes32(uint256(uid) ^ 1) : uid;
    }

    function getSchema(bytes32 uid) external view returns (SchemaRecord memory) {
        return _records[uid];
    }

    /// @dev Plant an arbitrary record at an arbitrary uid (models a buggy/malicious registry, or a hash collision).
    function plant(bytes32 uid, string calldata schema, address resolver, bool revocable) external {
        _records[uid] =
            SchemaRecord({ uid: uid, resolver: ISchemaResolver(resolver), revocable: revocable, schema: schema });
    }

    function setLie(bool v) external {
        lieAboutUid = v;
    }
}

contract EASPointer {
    address internal _reg;

    constructor(address reg) {
        _reg = reg;
    }

    function version() external pure returns (string memory) {
        return "1.0.1";
    }

    function getSchemaRegistry() external view returns (address) {
        return _reg;
    }
}

contract Audit2DeployTest is Test {
    PlantableSchemaRegistry internal reg;

    function setUp() public {
        vm.etch(OTTPSchemas.SCHEMA_REGISTRY, address(new PlantableSchemaRegistry()).code);
        vm.etch(OTTPSchemas.EAS, address(new EASPointer(OTTPSchemas.SCHEMA_REGISTRY)).code);
        vm.store(OTTPSchemas.EAS, bytes32(0), bytes32(uint256(uint160(OTTPSchemas.SCHEMA_REGISTRY))));
        reg = PlantableSchemaRegistry(OTTPSchemas.SCHEMA_REGISTRY);
        vm.chainId(OTTPSchemas.BASE_SEPOLIA);
    }

    function _predict() internal view returns (address registry, address subj, address obj) {
        uint64 n = vm.getNonce(DEFAULT_SENDER);
        registry = vm.computeCreateAddress(DEFAULT_SENDER, n);
        subj = vm.computeCreateAddress(DEFAULT_SENDER, n + 1);
        obj = vm.computeCreateAddress(DEFAULT_SENDER, n + 2);
    }

    /// D5 + wiring: exact strings, revocable=false, resolver addresses, registry pointers, UIDs, fresh registry.
    function test_HappyPath_ExactRecords() public {
        Deploy d = new Deploy();
        d.run();
        (address registry, address subj, address obj, bytes32 su, bytes32 ou) = d.last();
        assertEq(su, keccak256(abi.encodePacked("uint256 ottpId, string name, string metadata", subj, false)));
        assertEq(ou, keccak256(abi.encodePacked("bytes32 originUid, uint256 creatorId, string metadata", obj, false)));
        SchemaRecord memory s = reg.getSchema(su);
        SchemaRecord memory o = reg.getSchema(ou);
        assertEq(s.schema, "uint256 ottpId, string name, string metadata");
        assertEq(o.schema, "bytes32 originUid, uint256 creatorId, string metadata");
        assertEq(address(s.resolver), subj);
        assertEq(address(o.resolver), obj);
        assertFalse(s.revocable);
        assertFalse(o.revocable);
        assertEq(address(OTTPSubjectResolver(payable(subj)).registry()), registry);
        assertEq(address(OTTPObjectResolver(payable(obj)).registry()), registry);
        assertEq(OTTPRegistry(registry).nextId(), 1);
        assertEq(reg.registrations(), 2);
        // spec strings have single spaces after commas and no trailing whitespace
        assertEq(bytes(OTTPSchemas.SUBJECT).length, 44);
        assertEq(bytes(OTTPSchemas.OBJECT).length, 53);
    }

    /// REUSE PATH, wrong record #1: a record at the expected UID whose resolver differs (impossible for the real
    /// SchemaRegistry without a keccak collision; models a buggy registry). The script must refuse it.
    function test_ReusePath_RefusesWrongResolver() public {
        (, address subj,) = _predict();
        bytes32 uid = keccak256(abi.encodePacked(OTTPSchemas.SUBJECT, subj, false));
        reg.plant(uid, OTTPSchemas.SUBJECT, makeAddr("evilResolver"), false);
        Deploy d = new Deploy();
        vm.expectRevert(bytes("Deploy: pre-existing schema record differs"));
        d.run();
    }

    /// REUSE PATH, wrong record #2: revocable = true at the expected UID.
    function test_ReusePath_RefusesRevocableTrue() public {
        (, address subj,) = _predict();
        bytes32 uid = keccak256(abi.encodePacked(OTTPSchemas.SUBJECT, subj, false));
        reg.plant(uid, OTTPSchemas.SUBJECT, subj, true);
        Deploy d = new Deploy();
        vm.expectRevert(bytes("Deploy: pre-existing schema record differs"));
        d.run();
    }

    /// REUSE PATH, wrong record #3: different schema string (e.g. no space after comma) at the expected UID.
    function test_ReusePath_RefusesDifferentSchemaString() public {
        (,, address obj) = _predict();
        bytes32 uid = keccak256(abi.encodePacked(OTTPSchemas.OBJECT, obj, false));
        reg.plant(uid, "bytes32 originUid,uint256 creatorId,string metadata", obj, false);
        Deploy d = new Deploy();
        vm.expectRevert(bytes("Deploy: pre-existing schema record differs"));
        d.run();
    }

    /// REUSE PATH, benign front-run of BOTH schemas: script registers nothing and reports the same UIDs.
    function test_ReusePath_BothPreRegisteredIdentical() public {
        (, address subj, address obj) = _predict();
        bytes32 su = reg.register(OTTPSchemas.SUBJECT, ISchemaResolver(subj), false);
        bytes32 ou = reg.register(OTTPSchemas.OBJECT, ISchemaResolver(obj), false);
        Deploy d = new Deploy();
        d.run();
        (,,, bytes32 su2, bytes32 ou2) = d.last();
        assertEq(su, su2);
        assertEq(ou, ou2);
        assertEq(reg.registrations(), 2, "no new registrations");
    }

    /// A registry that returns a UID different from the derivation is refused.
    function test_RegisterPath_RefusesUnexpectedUid() public {
        reg.setLie(true);
        Deploy d = new Deploy();
        vm.expectRevert(bytes("Deploy: unexpected schema uid"));
        d.run();
    }

    /// EAS pointing at a different SchemaRegistry is refused before any deployment.
    function test_RefusesRegistryPointerMismatch() public {
        vm.store(OTTPSchemas.EAS, bytes32(0), bytes32(uint256(uint160(makeAddr("otherRegistry")))));
        Deploy d = new Deploy();
        vm.expectRevert(bytes("Deploy: EAS points at a different SchemaRegistry"));
        d.run();
    }

    /// Chain guard: only 8453 (with ALLOW_MAINNET=true) and 84532.
    function test_ChainGuard() public {
        uint256[4] memory bad = [uint256(1), 10, 31337, 8454];
        for (uint256 i = 0; i < bad.length; ++i) {
            vm.chainId(bad[i]);
            Deploy d = new Deploy();
            vm.expectRevert(bytes("Deploy: only Base mainnet (8453) or Base Sepolia (84532)"));
            d.run();
        }
        vm.chainId(OTTPSchemas.BASE_MAINNET);

        Deploy d2 = new Deploy();
        vm.expectRevert(bytes("Deploy: set ALLOW_MAINNET=true to deploy to Base mainnet"));
        d2.runWith(false);

        Deploy d3 = new Deploy();
        d3.runWith(true);
        (,,, bytes32 su,) = d3.last();
        assertTrue(su != bytes32(0));
    }

    /// Missing predeploy code is refused.
    function test_RefusesMissingPredeploys() public {
        vm.etch(OTTPSchemas.SCHEMA_REGISTRY, "");
        Deploy d = new Deploy();
        vm.expectRevert(bytes("Deploy: SchemaRegistry predeploy missing"));
        d.run();
    }
}
