// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

// AUDIT SCRATCH TESTS (2026-09-20). Run with:  FORK_TESTS=true forge test --match-path 'test/audit/AuditFork*' -vv
// Read-only forks of Base mainnet (EAS 1.0.1) and Base Sepolia (EAS 1.2.0). Nothing is broadcast.

import { Test, console2 } from "forge-std/Test.sol";
import {
    IEAS,
    AttestationRequest,
    AttestationRequestData,
    MultiAttestationRequest
} from "@ethereum-attestation-service/eas-contracts/contracts/IEAS.sol";
import {
    ISchemaRegistry,
    SchemaRecord
} from "@ethereum-attestation-service/eas-contracts/contracts/ISchemaRegistry.sol";
import {
    Signature,
    EMPTY_UID,
    NO_EXPIRATION_TIME
} from "@ethereum-attestation-service/eas-contracts/contracts/Common.sol";
import { ISchemaResolver } from "@ethereum-attestation-service/eas-contracts/contracts/resolver/ISchemaResolver.sol";

import { OTTPRegistry } from "../../src/OTTPRegistry.sol";
import {
    OTTPResolver__ZeroId,
    OTTPResolver__IdNotRegistered,
    OTTPResolver__AttesterNotOwner,
    OTTPResolver__ZeroRegistry
} from "../../src/OTTPResolverErrors.sol";
import { OTTPSubjectResolver } from "../../src/OTTPSubjectResolver.sol";
import { OTTPObjectResolver } from "../../src/OTTPObjectResolver.sol";
import { OTTPSchemas } from "../../src/Schemas.sol";
import { ERC1271Wallet } from "../mocks/ERC1271Wallet.sol";
import { Deploy } from "../../script/Deploy.s.sol";

struct DelegatedAttestationRequestV101 {
    bytes32 schema;
    AttestationRequestData data;
    Signature signature;
    address attester;
}

interface IEASv101 {
    function attestByDelegation(DelegatedAttestationRequestV101 calldata request) external payable returns (bytes32);
    function getAttestTypeHash() external view returns (bytes32);
    function getDomainSeparator() external view returns (bytes32);
    function getNonce(address account) external view returns (uint256);
    function getSchemaRegistry() external view returns (ISchemaRegistry);
    function version() external view returns (string memory);
}

contract AuditForkBaseMainnet is Test {
    IEAS internal eas = IEAS(OTTPSchemas.EAS);
    ISchemaRegistry internal schemaRegistry = ISchemaRegistry(OTTPSchemas.SCHEMA_REGISTRY);
    address internal deployer = makeAddr("deployer");
    address internal mallory = makeAddr("mallory");
    address internal alice;
    uint256 internal alicePk;
    address internal relayer = makeAddr("relayer");

    function setUp() public {
        if (!vm.envOr("FORK_TESTS", false)) {
            vm.skip(true);
            return;
        }
        vm.createSelectFork(vm.envOr("BASE_RPC_URL", string("https://mainnet.base.org")));
        assertEq(block.chainid, OTTPSchemas.BASE_MAINNET);
        (alice, alicePk) = makeAddrAndKey("alice");
        vm.deal(deployer, 1 ether);
        vm.deal(mallory, 1 ether);
        vm.deal(relayer, 1 ether);
    }

    // F1: the EAS predeploy really points at the SchemaRegistry predeploy (Deploy.s.sol does not assert this).
    function test_F1_EasUsesPredeploySchemaRegistry() public view {
        assertEq(address(IEASv101(address(eas)).getSchemaRegistry()), OTTPSchemas.SCHEMA_REGISTRY);
        assertEq(IEASv101(address(eas)).version(), "1.0.1");
    }

    // F2: schema-registration front-running. Resolver addresses are CREATE-predictable from the deployer's nonce;
    //     anyone can pre-register the identical (schema, resolver, revocable) triple, which makes the deployer's
    //     own `register` revert AlreadyExists() → Deploy.s.sol aborts AFTER the three contracts are deployed.
    //     Outcome is benign (same UID, same resolver) but the script must tolerate it.
    function test_F2_SchemaFrontRun_MakesDeployScriptRegisterRevert() public {
        uint64 n = vm.getNonce(deployer);
        address predictedRegistry = vm.computeCreateAddress(deployer, n);
        address predictedSubject = vm.computeCreateAddress(deployer, n + 1);

        // mallory front-runs with the exact triple
        vm.prank(mallory);
        bytes32 uidByMallory =
            schemaRegistry.register(OTTPSchemas.SUBJECT, ISchemaResolver(predictedSubject), OTTPSchemas.REVOCABLE);

        vm.startPrank(deployer);
        OTTPRegistry registry = new OTTPRegistry();
        OTTPSubjectResolver subjectResolver = new OTTPSubjectResolver(eas, registry);
        assertEq(address(registry), predictedRegistry);
        assertEq(address(subjectResolver), predictedSubject);
        vm.expectRevert(abi.encodeWithSignature("AlreadyExists()"));
        schemaRegistry.register(OTTPSchemas.SUBJECT, ISchemaResolver(address(subjectResolver)), OTTPSchemas.REVOCABLE);
        vm.stopPrank();

        // the front-run record is nevertheless the correct, usable one
        SchemaRecord memory s = schemaRegistry.getSchema(uidByMallory);
        assertEq(address(s.resolver), address(subjectResolver));
        assertFalse(s.revocable);
        assertEq(uidByMallory, keccak256(abi.encodePacked(OTTPSchemas.SUBJECT, address(subjectResolver), false)));
    }

    // F3: EAS 1.0.1 (Base mainnet) delegated attestation is ECDSA-only: a Safe-style ERC-1271 wallet cannot use
    //     attestByDelegation on mainnet even though it CAN use registerFor. (Contract-external, INFO; SDK impact.)
    function test_F3_Eas101_DelegatedAttestFromErc1271Wallet_Rejected() public {
        vm.startPrank(deployer);
        OTTPRegistry registry = new OTTPRegistry();
        OTTPSubjectResolver subjectResolver = new OTTPSubjectResolver(eas, registry);
        bytes32 subjectSchema = schemaRegistry.register(
            OTTPSchemas.SUBJECT, ISchemaResolver(address(subjectResolver)), OTTPSchemas.REVOCABLE
        );
        vm.stopPrank();

        ERC1271Wallet safe = new ERC1271Wallet(alice);
        vm.prank(address(safe));
        uint256 id = registry.register();

        AttestationRequestData memory d = AttestationRequestData({
            recipient: address(0),
            expirationTime: NO_EXPIRATION_TIME,
            revocable: false,
            refUID: EMPTY_UID,
            data: abi.encode(id, "safe", "{}"),
            value: 0
        });
        IEASv101 e = IEASv101(address(eas));
        bytes32 structHash = keccak256(
            abi.encode(
                e.getAttestTypeHash(),
                subjectSchema,
                d.recipient,
                d.expirationTime,
                d.revocable,
                d.refUID,
                keccak256(d.data),
                e.getNonce(address(safe))
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", e.getDomainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePk, digest); // alice is the Safe's owner
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSignature("InvalidSignature()"));
        e.attestByDelegation(
            DelegatedAttestationRequestV101({
                schema: subjectSchema, data: d, signature: Signature(v, r, s), attester: address(safe)
            })
        );
        // ... but the Safe can attest directly
        vm.prank(address(safe));
        eas.attest(AttestationRequest({ schema: subjectSchema, data: d }));
    }

    // F4: multiAttest through the REAL EAS 1.0.1 routes to resolver.multiAttest; one bad item reverts the batch.
    function test_F4_MultiAttest_ThroughRealEas101_OneBadItemRevertsBatch() public {
        vm.startPrank(deployer);
        OTTPRegistry registry = new OTTPRegistry();
        OTTPSubjectResolver subjectResolver = new OTTPSubjectResolver(eas, registry);
        bytes32 subjectSchema = schemaRegistry.register(
            OTTPSchemas.SUBJECT, ISchemaResolver(address(subjectResolver)), OTTPSchemas.REVOCABLE
        );
        vm.stopPrank();
        vm.prank(alice);
        registry.register(); // 1

        AttestationRequestData[] memory items = new AttestationRequestData[](2);
        items[0] = AttestationRequestData(address(0), 0, false, EMPTY_UID, abi.encode(uint256(1), "a", "{}"), 0);
        items[1] = AttestationRequestData(address(0), 0, false, EMPTY_UID, abi.encode(uint256(2), "b", "{}"), 0);
        MultiAttestationRequest[] memory reqs = new MultiAttestationRequest[](1);
        reqs[0] = MultiAttestationRequest({ schema: subjectSchema, data: items });
        vm.prank(alice);
        vm.expectPartialRevert(OTTPResolver__IdNotRegistered.selector); // id 2 is unissued in this fixture
        eas.multiAttest(reqs);

        items[1].data = abi.encode(uint256(1), "b", "{}");
        vm.prank(alice);
        bytes32[] memory uids = eas.multiAttest(reqs);
        assertEq(uids.length, 2);
        assertEq(eas.getAttestation(uids[1]).attester, alice);
    }

    // F5: value on a single attest / on a multiAttest item is refused by the real core (NotPayable) → nothing
    //     ever reaches the resolver's payable entrypoints.
    function test_F5_ValueRefusedByRealCore() public {
        vm.startPrank(deployer);
        OTTPRegistry registry = new OTTPRegistry();
        OTTPSubjectResolver subjectResolver = new OTTPSubjectResolver(eas, registry);
        bytes32 subjectSchema = schemaRegistry.register(
            OTTPSchemas.SUBJECT, ISchemaResolver(address(subjectResolver)), OTTPSchemas.REVOCABLE
        );
        vm.stopPrank();
        vm.deal(alice, 1 ether);
        vm.prank(alice);
        registry.register();
        AttestationRequestData memory d =
            AttestationRequestData(address(0), 0, false, EMPTY_UID, abi.encode(uint256(1), "a", "{}"), 1);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSignature("NotPayable()"));
        eas.attest{ value: 1 }(AttestationRequest({ schema: subjectSchema, data: d }));
        assertEq(address(subjectResolver).balance, 0);
    }

    // F6: the actual Deploy script runs end-to-end on a mainnet fork with ALLOW_MAINNET=true and refuses without it.
    function test_F6_DeployScriptOnMainnetFork() public {
        Deploy script = new Deploy();
        vm.setEnv("ALLOW_MAINNET", "false");
        vm.expectRevert("Deploy: set ALLOW_MAINNET=true to deploy to Base mainnet");
        script.run();
        vm.setEnv("ALLOW_MAINNET", "true");
        script.run();
    }
}

contract AuditForkBaseSepolia is Test {
    IEAS internal eas = IEAS(OTTPSchemas.EAS);

    function setUp() public {
        if (!vm.envOr("FORK_TESTS", false)) {
            vm.skip(true);
            return;
        }
        vm.createSelectFork(vm.envOr("BASE_SEPOLIA_RPC_URL", string("https://sepolia.base.org")));
        assertEq(block.chainid, OTTPSchemas.BASE_SEPOLIA);
    }

    function test_F1_EasUsesPredeploySchemaRegistry() public view {
        assertEq(address(IEASv101(address(eas)).getSchemaRegistry()), OTTPSchemas.SCHEMA_REGISTRY);
        assertEq(IEASv101(address(eas)).version(), "1.2.0");
    }

    // Deploy script: wrong-chain guard. Run on a Sepolia fork but with chain id forced to something else.
    function test_F7_DeployScriptRefusesUnknownChain() public {
        vm.chainId(1);
        Deploy script = new Deploy();
        vm.expectRevert("Deploy: only Base mainnet (8453) or Base Sepolia (84532)");
        script.run();
    }
}
