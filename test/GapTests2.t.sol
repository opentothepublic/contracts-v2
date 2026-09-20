// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import { Test, Vm } from "forge-std/Test.sol";
import { IEAS, AttestationRequestData } from "@ethereum-attestation-service/eas-contracts/contracts/IEAS.sol";
import {
    Attestation,
    EMPTY_UID,
    NO_EXPIRATION_TIME
} from "@ethereum-attestation-service/eas-contracts/contracts/Common.sol";
import { ISchemaResolver } from "@ethereum-attestation-service/eas-contracts/contracts/resolver/ISchemaResolver.sol";

import { Deploy } from "../script/Deploy.s.sol";
import { OTTPRegistry } from "../src/OTTPRegistry.sol";
import { IOTTPRegistry } from "../src/IOTTPRegistry.sol";
import {
    OTTPResolver__ZeroId,
    OTTPResolver__IdNotRegistered,
    OTTPResolver__AttesterNotOwner,
    OTTPResolver__ZeroRegistry
} from "../src/OTTPResolverErrors.sol";
import { OTTPSubjectResolver } from "../src/OTTPSubjectResolver.sol";
import { OTTPObjectResolver } from "../src/OTTPObjectResolver.sol";
import { OTTPSchemas } from "../src/Schemas.sol";
import { MockEAS } from "./mocks/MockEAS.sol";
import { RegistrySigUtils } from "./utils/RegistrySigUtils.sol";
import { MockSchemaRegistry } from "./DeployScript.t.sol";

// ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
// Tests added by the 2026-09-20 second mutation-based gap review (branch v2.1-contracts, spec v1.2).
// Every test here names the surviving mutant it kills (C/P/X numbers refer to the review's mutation table) or the
// spec sentence it pins. Nothing here depends on values read back from src/ constants where a literal is the point.
// ─────────────────────────────────────────────────────────────────────────────────────────────────────────────

/// @dev EAS predeploy stand-in that reports the LITERAL OP Stack SchemaRegistry address (not OTTPSchemas.*).
contract LiteralEASPredeploy {
    function version() external pure returns (string memory) {
        return "1.0.1";
    }

    function getSchemaRegistry() external pure returns (address) {
        return 0x4200000000000000000000000000000000000020;
    }
}

/// @dev EAS predeploy stand-in whose SchemaRegistry pointer disagrees with the predeploy the script registers on.
contract WrongPointerEASPredeploy {
    function version() external pure returns (string memory) {
        return "1.0.1";
    }

    function getSchemaRegistry() external pure returns (address) {
        return 0x000000000000000000000000000000000000dEaD;
    }
}

/// @title Gap2SchemasAndDeployTest
/// @notice Mutants C04–C08 (EAS / SchemaRegistry predeploy addresses, Base chain IDs) survived the whole non-fork
///         suite because DeployScript.t.sol etches its mocks at `OTTPSchemas.EAS` / `OTTPSchemas.SCHEMA_REGISTRY` and
///         selects chains via `OTTPSchemas.BASE_*` — the tests followed the constant wherever it went. These pin the
///         literals the way an SDK, a block explorer, or the real predeploy would.
contract Gap2SchemasAndDeployTest is Test {
    address internal constant EAS_LITERAL = 0x4200000000000000000000000000000000000021;
    address internal constant SCHEMA_REGISTRY_LITERAL = 0x4200000000000000000000000000000000000020;
    string internal constant ONLY_BASE = "Deploy: only Base mainnet (8453) or Base Sepolia (84532)";

    /// @dev C04, C05, C06, C07, C08 and D5: every constant in Schemas.sol pinned to a literal.
    function test_Schemas_ConstantsPinnedToLiterals() public pure {
        assertEq(OTTPSchemas.EAS, EAS_LITERAL, "EAS predeploy (OP Stack)");
        assertEq(OTTPSchemas.SCHEMA_REGISTRY, SCHEMA_REGISTRY_LITERAL, "SchemaRegistry predeploy (OP Stack)");
        assertEq(OTTPSchemas.BASE_MAINNET, 8453);
        assertEq(OTTPSchemas.BASE_SEPOLIA, 84532);
        assertFalse(OTTPSchemas.REVOCABLE);
        assertEq(
            keccak256(bytes(OTTPSchemas.SUBJECT)),
            keccak256("uint256 ottpId, string name, string metadata"),
            "D5 subject"
        );
        assertEq(
            keccak256(bytes(OTTPSchemas.OBJECT)),
            keccak256("bytes32 originUid, uint256 creatorId, string metadata"),
            "D5 object"
        );
    }

    /// @dev C04/C05/C07/C08: the script must talk to the LITERAL predeploys on chain 84532 (literal). Mocks are
    ///      etched at the literal addresses only; if the script looked anywhere else it would find no code.
    function test_DeployScript_TalksToLiteralPredeploys_OnLiteralSepoliaChainId() public {
        vm.etch(SCHEMA_REGISTRY_LITERAL, address(new MockSchemaRegistry()).code);
        vm.etch(EAS_LITERAL, address(new LiteralEASPredeploy()).code);
        vm.chainId(84532);

        Deploy d = new Deploy();
        d.run();
        (address reg, address subj, address obj, bytes32 subjUid, bytes32 objUid) = d.last();

        MockSchemaRegistry sr = MockSchemaRegistry(SCHEMA_REGISTRY_LITERAL);
        assertEq(sr.registrations(), 2, "both schemas registered on the literal SchemaRegistry predeploy");
        assertEq(sr.getSchema(subjUid).schema, "uint256 ottpId, string name, string metadata");
        assertEq(sr.getSchema(objUid).schema, "bytes32 originUid, uint256 creatorId, string metadata");
        assertEq(address(sr.getSchema(subjUid).resolver), subj);
        assertEq(address(sr.getSchema(objUid).resolver), obj);
        assertFalse(sr.getSchema(subjUid).revocable);
        assertFalse(sr.getSchema(objUid).revocable);
        assertEq(OTTPRegistry(reg).nextId(), 1);
    }

    /// @dev C06/C07: neighbouring chain IDs are refused with the chain-guard message. On the mutant (BASE_MAINNET =
    ///      8454) chain 8454 passes the guard and fails later with a different message (or not at all), so this
    ///      kills it regardless of the process-wide ALLOW_MAINNET env var that another test may be toggling.
    function test_DeployScript_RefusesNeighbouringChainIds_Literal() public {
        vm.etch(SCHEMA_REGISTRY_LITERAL, address(new MockSchemaRegistry()).code);
        vm.etch(EAS_LITERAL, address(new LiteralEASPredeploy()).code);
        uint256[4] memory bad = [uint256(8452), 8454, 84531, 84533];
        for (uint256 i = 0; i < bad.length; i++) {
            vm.chainId(bad[i]);
            Deploy d = new Deploy();
            vm.expectRevert(bytes(ONLY_BASE));
            d.run();
        }
    }

    /// @dev Spec v1.2 changelog: "asserts EAS.getSchemaRegistry()". DeployScript.t.sol's mock returns
    ///      OTTPSchemas.SCHEMA_REGISTRY, so that assertion was never exercised on its failing branch (X01 survived).
    function test_DeployScript_RefusesEasThatPointsAtAnotherSchemaRegistry() public {
        vm.etch(SCHEMA_REGISTRY_LITERAL, address(new MockSchemaRegistry()).code);
        vm.etch(EAS_LITERAL, address(new WrongPointerEASPredeploy()).code);
        vm.chainId(84532);
        Deploy d = new Deploy();
        vm.expectRevert("Deploy: EAS points at a different SchemaRegistry");
        d.run();
        assertEq(MockSchemaRegistry(SCHEMA_REGISTRY_LITERAL).registrations(), 0, "nothing registered");
    }

    /// @dev The script refuses to run where the predeploys are absent (a non-OP-Stack chain with the right ID).
    function test_DeployScript_RefusesMissingPredeploys() public {
        vm.chainId(84532);
        Deploy d = new Deploy();
        vm.expectRevert("Deploy: EAS predeploy missing");
        d.run();
        vm.etch(EAS_LITERAL, address(new LiteralEASPredeploy()).code);
        d = new Deploy();
        vm.expectRevert("Deploy: SchemaRegistry predeploy missing");
        d.run();
    }
}

/// @title Gap2ResolverErrorParamsTest
/// @notice D4 says the resolver errors "carry the claimed id / attester for debugging" and SDKs decode them. No test
///         asserted those parameters: every resolver test used `expectPartialRevert` (selector only), so mutants
///         P01–P04 (swapped attester/owner, id replaced by 0) survived. Pin the full encoding on both resolvers, on
///         the direct and delegated paths, and after a transfer.
contract Gap2ResolverErrorParamsTest is Test {
    OTTPRegistry internal registry;
    MockEAS internal eas;
    OTTPSubjectResolver internal subjectResolver;
    OTTPObjectResolver internal objectResolver;
    bytes32 internal subjectSchema;
    bytes32 internal objectSchema;

    address internal alice = makeAddr("alice"); // id 1
    address internal bob = makeAddr("bob"); // id 2
    address internal mallory = makeAddr("mallory"); // no id
    address internal relayer = makeAddr("relayer");

    function setUp() public {
        registry = new OTTPRegistry();
        eas = new MockEAS();
        subjectResolver = new OTTPSubjectResolver(IEAS(address(eas)), registry);
        objectResolver = new OTTPObjectResolver(IEAS(address(eas)), registry);
        subjectSchema =
            eas.registerSchema(OTTPSchemas.SUBJECT, ISchemaResolver(address(subjectResolver)), OTTPSchemas.REVOCABLE);
        objectSchema =
            eas.registerSchema(OTTPSchemas.OBJECT, ISchemaResolver(address(objectResolver)), OTTPSchemas.REVOCABLE);
        vm.prank(alice);
        registry.register();
        vm.prank(bob);
        registry.register();
    }

    function _req(bytes memory data) internal pure returns (AttestationRequestData memory) {
        return AttestationRequestData({
            recipient: address(0),
            expirationTime: NO_EXPIRATION_TIME,
            revocable: false,
            refUID: EMPTY_UID,
            data: data,
            value: 0
        });
    }

    function _subject(uint256 id) internal pure returns (bytes memory) {
        return abi.encode(id, "name", "{}");
    }

    function _object(uint256 id) internal pure returns (bytes memory) {
        return abi.encode(bytes32(0), id, "{}");
    }

    function _notOwner(uint256 id, address attester, address owner) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(OTTPResolver__AttesterNotOwner.selector, id, attester, owner);
    }

    function _notRegistered(uint256 id) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(OTTPResolver__IdNotRegistered.selector, id);
    }

    /// @dev P01/P02: Subject errors carry (id, attester, currentOwner) / (id) exactly.
    function test_D4_Subject_ErrorParametersExact() public {
        vm.prank(bob);
        vm.expectRevert(_notOwner(1, bob, alice));
        eas.attest(subjectSchema, _req(_subject(1)));

        vm.prank(mallory);
        vm.expectRevert(_notOwner(2, mallory, bob));
        eas.attest(subjectSchema, _req(_subject(2)));

        vm.prank(alice);
        vm.expectRevert(_notRegistered(3));
        eas.attest(subjectSchema, _req(_subject(3)));

        vm.prank(alice);
        vm.expectRevert(_notRegistered(type(uint256).max));
        eas.attest(subjectSchema, _req(_subject(type(uint256).max)));

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(OTTPResolver__ZeroId.selector));
        eas.attest(subjectSchema, _req(_subject(0)));
    }

    /// @dev P03/P04: Object errors carry (id, attester, currentOwner) / (id) exactly.
    function test_D4_Object_ErrorParametersExact() public {
        vm.prank(bob);
        vm.expectRevert(_notOwner(1, bob, alice));
        eas.attest(objectSchema, _req(_object(1)));

        vm.prank(mallory);
        vm.expectRevert(_notOwner(2, mallory, bob));
        eas.attest(objectSchema, _req(_object(2)));

        vm.prank(alice);
        vm.expectRevert(_notRegistered(3));
        eas.attest(objectSchema, _req(_object(3)));

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(OTTPResolver__ZeroId.selector));
        eas.attest(objectSchema, _req(_object(0)));
    }

    /// @dev Delegated path: the `attester` parameter is the SIGNER, never the relayer.
    function test_D4_Delegated_ErrorNamesTheSignerNotTheRelayer() public {
        vm.prank(relayer);
        vm.expectRevert(_notOwner(2, mallory, bob));
        eas.attestByDelegation(subjectSchema, _req(_subject(2)), mallory);

        vm.prank(bob); // relayer owns id 2 but signs nothing
        vm.expectRevert(_notOwner(2, mallory, bob));
        eas.attestByDelegation(objectSchema, _req(_object(2)), mallory);
    }

    /// @dev After a transfer the `owner` parameter is the CURRENT wallet (what an SDK would tell the old key).
    function test_D4_AfterTransfer_OwnerParameterIsCurrentWallet() public {
        address alice2 = makeAddr("alice2");
        vm.prank(alice);
        registry.transferId(1, alice2);

        vm.prank(alice);
        vm.expectRevert(_notOwner(1, alice, alice2));
        eas.attest(subjectSchema, _req(_subject(1)));
        vm.prank(alice);
        vm.expectRevert(_notOwner(1, alice, alice2));
        eas.attest(objectSchema, _req(_object(1)));
    }

    /// @dev The selectors an SDK hard-codes are derived from these exact signatures (D4) and are pairwise distinct.
    function test_D4_ErrorSelectorsDerivedFromSpecSignatures() public pure {
        assertEq(OTTPResolver__ZeroId.selector, bytes4(keccak256("OTTPResolver__ZeroId()")));
        assertEq(OTTPResolver__IdNotRegistered.selector, bytes4(keccak256("OTTPResolver__IdNotRegistered(uint256)")));
        assertEq(
            OTTPResolver__AttesterNotOwner.selector,
            bytes4(keccak256("OTTPResolver__AttesterNotOwner(uint256,address,address)"))
        );
        assertEq(OTTPResolver__ZeroRegistry.selector, bytes4(keccak256("OTTPResolver__ZeroRegistry()")));
        assertEq(OTTPRegistry.OTTPRegistry__ZeroAddress.selector, bytes4(keccak256("OTTPRegistry__ZeroAddress()")));
        assertEq(
            OTTPRegistry.OTTPRegistry__WalletAlreadyRegistered.selector,
            bytes4(keccak256("OTTPRegistry__WalletAlreadyRegistered(address,uint256)"))
        );
        assertEq(
            OTTPRegistry.OTTPRegistry__NotOwner.selector, bytes4(keccak256("OTTPRegistry__NotOwner(uint256,address)"))
        );
        assertEq(
            OTTPRegistry.OTTPRegistry__TargetAlreadyRegistered.selector,
            bytes4(keccak256("OTTPRegistry__TargetAlreadyRegistered(address,uint256)"))
        );
        assertEq(
            OTTPRegistry.OTTPRegistry__SignatureExpired.selector,
            bytes4(keccak256("OTTPRegistry__SignatureExpired(uint256,uint256)"))
        );
        assertEq(
            OTTPRegistry.OTTPRegistry__InvalidSignature.selector,
            bytes4(keccak256("OTTPRegistry__InvalidSignature(address)"))
        );
    }

    /// @dev Fuzz with an exact-encoding oracle built from the test's own knowledge of who owns what (ids 1, 2).
    function testFuzz_D4_Subject_ExactEncoding(address attester, uint256 id) public {
        vm.assume(attester != address(0));
        if (id == 0) {
            vm.expectRevert(abi.encodeWithSelector(OTTPResolver__ZeroId.selector));
        } else if (id > 2) {
            vm.expectRevert(_notRegistered(id));
        } else {
            address owner = id == 1 ? alice : bob;
            if (attester != owner) vm.expectRevert(_notOwner(id, attester, owner));
        }
        vm.prank(attester);
        eas.attest(subjectSchema, _req(_subject(id)));
    }
}

/// @dev A "wallet" whose signature check tries to re-enter the registry and mint itself an ID. OZ SignatureChecker
///      calls ERC-1271 via STATICCALL, so the inner register() must revert and the signature must read as invalid.
///      Not declared `view` on purpose (that is the point); the selector is the ERC-1271 one.
contract ReenteringWallet {
    OTTPRegistry internal immutable registry;
    bool public reachedRegister;

    constructor(OTTPRegistry r) {
        registry = r;
    }

    function isValidSignature(bytes32, bytes memory) external returns (bytes4) {
        try registry.register() returns (uint256) {
            reachedRegister = true;
            return 0x1626ba7e; // IERC1271 magic value
        } catch {
            return 0xffffffff;
        }
    }
}

/// @title Gap2RegistryTest
contract Gap2RegistryTest is Test {
    OTTPRegistry internal registry;
    address internal alice;
    uint256 internal alicePk;
    address internal relayer = makeAddr("relayer");

    event Registered(uint256 indexed id, address indexed wallet);

    function setUp() public {
        registry = new OTTPRegistry();
        (alice, alicePk) = makeAddrAndKey("alice");
        vm.warp(1_760_000_000);
    }

    function _sig(uint256 pk, address wallet, uint256 nonce, uint256 deadline) internal view returns (bytes memory) {
        return RegistrySigUtils.sign(vm, pk, address(registry), block.chainid, wallet, nonce, deadline);
    }

    /// @dev ERC-1271 verification cannot be used to re-enter the registry (STATICCALL). Pins the assumption behind
    ///      "the nonce is read before _register and consumed after verification" (D6 ordering) for contract wallets.
    function test_RegisterFor_Erc1271VerificationCannotReenterRegistry() public {
        ReenteringWallet w = new ReenteringWallet(registry);
        // Outside a static context the wallet really would mint itself an ID — the attempt is genuine.
        uint256 snap = vm.snapshotState();
        assertEq(w.isValidSignature(bytes32(0), ""), bytes4(0x1626ba7e));
        assertTrue(w.reachedRegister());
        assertEq(registry.getId(address(w)), 1);
        vm.revertToState(snap);

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__InvalidSignature.selector, address(w)));
        registry.registerFor(address(w), block.timestamp + 1, "");
        assertEq(registry.totalRegistered(), 0);
        assertEq(registry.getId(address(w)), 0);
        assertEq(registry.nonces(address(w)), 0);
        assertFalse(w.reachedRegister());
    }

    /// @dev P05: deadline 0 is simply expired — there is no "0 = no deadline" sentinel. Exact encoding.
    function test_RegisterFor_DeadlineZeroIsExpired_NoSentinel() public {
        bytes memory sig = _sig(alicePk, alice, 0, 0);
        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(OTTPRegistry.OTTPRegistry__SignatureExpired.selector, 0, block.timestamp)
        );
        registry.registerFor(alice, 0, sig);
    }

    /// @dev P06 and spec "Registered … (both paths)": registerFor emits exactly one event, and it names the SIGNER.
    function test_RegisterFor_EmitsExactlyOneRegisteredNamingTheSigner() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sig(alicePk, alice, 0, deadline);
        vm.recordLogs();
        vm.prank(relayer);
        registry.registerFor(alice, deadline, sig);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 1, "exactly one event");
        assertEq(logs[0].emitter, address(registry));
        assertEq(logs[0].topics[0], Registered.selector);
        assertEq(logs[0].topics[1], bytes32(uint256(1)));
        assertEq(logs[0].topics[2], bytes32(uint256(uint160(alice))), "wallet topic is the signer, not the relayer");
        assertEq(logs[0].data.length, 0);
    }

    /// @dev Migration & Continuity: a future generation reads ONLY through IOTTPRegistry, and it must get the same
    ///      answers as the concrete contract, including via the resolvers' immutable `registry()` handle.
    function test_IOTTPRegistry_ReadSurfaceMatchesConcreteContract() public {
        MockEAS eas = new MockEAS();
        OTTPSubjectResolver sr = new OTTPSubjectResolver(IEAS(address(eas)), registry);
        OTTPObjectResolver orr = new OTTPObjectResolver(IEAS(address(eas)), registry);
        IOTTPRegistry viaSubject = sr.registry();
        IOTTPRegistry viaObject = orr.registry();
        assertEq(address(viaSubject), address(registry));
        assertEq(address(viaObject), address(registry));

        vm.prank(alice);
        registry.register();
        address bob = makeAddr("bob");
        vm.prank(alice);
        registry.transferId(1, bob);
        vm.prank(alice);
        registry.register(); // id 2

        assertEq(viaSubject.nextId(), 3);
        assertEq(viaSubject.totalRegistered(), 2);
        assertEq(viaSubject.getWallet(1), bob);
        assertEq(viaSubject.getWallet(2), alice);
        assertEq(viaSubject.getWallet(3), address(0));
        assertEq(viaObject.getId(bob), 1);
        assertEq(viaObject.getId(alice), 2);
        assertEq(viaObject.getId(relayer), 0);
    }
}
