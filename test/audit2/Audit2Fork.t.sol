// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

// AUDIT ROUND 2 (2026-09-20) — the primitive against the REAL EAS predeploys.
//   FORK_TESTS=true forge test --match-path 'test/audit2/Audit2Fork.t.sol' --threads 1
// Base mainnet runs EAS 1.0.1 (delegated: ECDSA.recover only, no deadline); Base Sepolia runs EAS 1.2.0
// (delegated: SignatureChecker, deadline). Read-only forks; nothing is broadcast.

import { Test } from "forge-std/Test.sol";
import {
    IEAS,
    AttestationRequest,
    AttestationRequestData,
    RevocationRequest,
    RevocationRequestData,
    MultiAttestationRequest,
    DelegatedAttestationRequest
} from "@ethereum-attestation-service/eas-contracts/contracts/IEAS.sol";
import { ISchemaRegistry } from "@ethereum-attestation-service/eas-contracts/contracts/ISchemaRegistry.sol";
import {
    Attestation,
    Signature,
    EMPTY_UID,
    NO_EXPIRATION_TIME
} from "@ethereum-attestation-service/eas-contracts/contracts/Common.sol";
import { ISchemaResolver } from "@ethereum-attestation-service/eas-contracts/contracts/resolver/ISchemaResolver.sol";

import { OTTPRegistry } from "../../src/OTTPRegistry.sol";
import { OTTPSubjectResolver } from "../../src/OTTPSubjectResolver.sol";
import { OTTPObjectResolver } from "../../src/OTTPObjectResolver.sol";
import {
    OTTPResolver__ZeroId,
    OTTPResolver__IdNotRegistered,
    OTTPResolver__AttesterNotOwner
} from "../../src/OTTPResolverErrors.sol";
import { OTTPSchemas } from "../../src/Schemas.sol";
import { RegistrySigUtils } from "../utils/RegistrySigUtils.sol";
import { ERC1271Wallet } from "../mocks/ERC1271Wallet.sol";

/// @dev EAS 1.0.1 (Base mainnet) delegated request — no deadline field.
struct DelegatedAttestationRequestV101 {
    bytes32 schema;
    AttestationRequestData data;
    Signature signature;
    address attester;
}

interface IEASv101 {
    function attestByDelegation(DelegatedAttestationRequestV101 calldata request) external payable returns (bytes32);
}

interface IEASIntrospect {
    function version() external view returns (string memory);
    function getDomainSeparator() external view returns (bytes32);
    function getAttestTypeHash() external view returns (bytes32);
    function getNonce(address account) external view returns (uint256);
}

/// @dev EIP712Proxy 1.2.0 (deployed on Base mainnet at 0xF095…) delegated request.
struct DelegatedProxyAttestationRequest {
    bytes32 schema;
    AttestationRequestData data;
    Signature signature;
    address attester;
    uint64 deadline;
}

interface IEIP712Proxy {
    function attestByDelegation(DelegatedProxyAttestationRequest calldata request) external payable returns (bytes32);
    function getDomainSeparator() external view returns (bytes32);
    function getAttestTypeHash() external view returns (bytes32);
    function version() external view returns (string memory);
}

abstract contract Audit2ForkBase is Test {
    bytes32 internal constant EIP1967_IMPL = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    bytes32 internal constant EIP1967_ADMIN = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;
    address internal constant OP_PROXY_ADMIN = 0x4200000000000000000000000000000000000018;

    IEAS internal eas = IEAS(OTTPSchemas.EAS);
    ISchemaRegistry internal schemaRegistry = ISchemaRegistry(OTTPSchemas.SCHEMA_REGISTRY);

    OTTPRegistry internal registry;
    OTTPSubjectResolver internal subjectResolver;
    OTTPObjectResolver internal objectResolver;
    bytes32 internal subjectSchema;
    bytes32 internal objectSchema;

    address internal alice;
    uint256 internal alicePk;
    address internal bob;
    uint256 internal bobPk;
    address internal mallory;
    uint256 internal malloryPk;
    address internal relayer = makeAddr("relayer");

    function _rpc() internal pure virtual returns (string memory);
    function _chainId() internal pure virtual returns (uint256);
    function _easVersion() internal pure virtual returns (string memory);
    function _relaysErc1271() internal pure virtual returns (bool);
    /// @dev Signs with `signerPk` but DECLARES `declaredAttester`; returns the raw call result.
    function _delegated(bytes32 schema, AttestationRequestData memory data, uint256 signerPk, address declaredAttester)
        internal
        virtual
        returns (bool ok, bytes memory ret);

    function setUp() public {
        if (!vm.envOr("FORK_TESTS", false)) {
            vm.skip(true);
            return;
        }
        vm.createSelectFork(_rpc());
        assertEq(block.chainid, _chainId());
        assertEq(IEASIntrospect(address(eas)).version(), _easVersion(), "unexpected EAS version");

        (alice, alicePk) = makeAddrAndKey("alice");
        (bob, bobPk) = makeAddrAndKey("bob");
        (mallory, malloryPk) = makeAddrAndKey("mallory");
        vm.deal(alice, 1 ether);
        vm.deal(bob, 1 ether);
        vm.deal(mallory, 1 ether);
        vm.deal(relayer, 1 ether);

        registry = new OTTPRegistry();
        subjectResolver = new OTTPSubjectResolver(eas, registry);
        objectResolver = new OTTPObjectResolver(eas, registry);
        subjectSchema = schemaRegistry.register(
            OTTPSchemas.SUBJECT, ISchemaResolver(address(subjectResolver)), OTTPSchemas.REVOCABLE
        );
        objectSchema = schemaRegistry.register(
            OTTPSchemas.OBJECT, ISchemaResolver(address(objectResolver)), OTTPSchemas.REVOCABLE
        );

        vm.prank(alice);
        registry.register(); // 1
        vm.prank(bob);
        registry.register(); // 2
    }

    function _data(bytes memory payload) internal pure returns (AttestationRequestData memory) {
        return AttestationRequestData({
            recipient: address(0),
            expirationTime: NO_EXPIRATION_TIME,
            revocable: false,
            refUID: EMPTY_UID,
            data: payload,
            value: 0
        });
    }

    function _subject(uint256 id) internal pure returns (bytes memory) {
        return abi.encode(id, "name", "{}");
    }

    function _object(uint256 creatorId) internal pure returns (bytes memory) {
        return abi.encode(bytes32(0), creatorId, "{}");
    }

    // ── F1: predeploy facts, incl. the trust assumption that the EAS predeploy is an upgradeable proxy ──
    function test_F1_PredeployFacts() public view {
        assertEq(IEASIntrospect(address(eas)).version(), _easVersion());
        assertEq(address(eas.getSchemaRegistry()), OTTPSchemas.SCHEMA_REGISTRY);
        // OP-Stack predeploys are EIP-1967 proxies administered by the L2 ProxyAdmin (chain governance).
        assertEq(address(uint160(uint256(vm.load(address(eas), EIP1967_ADMIN)))), OP_PROXY_ADMIN, "EAS admin");
        assertTrue(vm.load(address(eas), EIP1967_IMPL) != bytes32(0), "EAS impl");
        assertEq(address(uint160(uint256(vm.load(address(schemaRegistry), EIP1967_ADMIN)))), OP_PROXY_ADMIN, "SR admin");
        // EIP-712 domain of the real EAS is ("EAS", version, chainid, 0x4200…21)
        bytes32 expected = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("EAS"),
                keccak256(bytes(_easVersion())),
                block.chainid,
                address(eas)
            )
        );
        assertEq(IEASIntrospect(address(eas)).getDomainSeparator(), expected, "EAS domain separator");
    }

    // ── F2: direct attestation through the real core — exact typed errors bubble out unchanged ──
    function test_F2_DirectAttest_ExactErrorsThroughRealEAS() public {
        vm.prank(alice);
        bytes32 uid = eas.attest(AttestationRequest({ schema: subjectSchema, data: _data(_subject(1)) }));
        Attestation memory a = eas.getAttestation(uid);
        assertEq(a.attester, alice);
        assertFalse(a.revocable);

        vm.prank(mallory);
        vm.expectRevert(abi.encodeWithSelector(OTTPResolver__AttesterNotOwner.selector, 1, mallory, alice));
        eas.attest(AttestationRequest({ schema: subjectSchema, data: _data(_subject(1)) }));

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(OTTPResolver__AttesterNotOwner.selector, 2, alice, bob));
        eas.attest(AttestationRequest({ schema: objectSchema, data: _data(_object(2)) }));

        vm.prank(alice);
        vm.expectRevert(OTTPResolver__ZeroId.selector);
        eas.attest(AttestationRequest({ schema: subjectSchema, data: _data(_subject(0)) }));

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(OTTPResolver__IdNotRegistered.selector, 3));
        eas.attest(AttestationRequest({ schema: objectSchema, data: _data(_object(3)) }));

        // value refused by core (resolver not payable)
        AttestationRequestData memory d = _data(_subject(1));
        d.value = 1;
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSignature("NotPayable()"));
        eas.attest{ value: 1 }(AttestationRequest({ schema: subjectSchema, data: d }));

        // revocable request and revocation both refused by core
        d = _data(_subject(1));
        d.revocable = true;
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSignature("Irrevocable()"));
        eas.attest(AttestationRequest({ schema: subjectSchema, data: d }));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSignature("Irrevocable()"));
        eas.revoke(RevocationRequest({ schema: subjectSchema, data: RevocationRequestData({ uid: uid, value: 0 }) }));
    }

    // ── F3: delegated attester spoofing is impossible; delegated == direct for the resolver ──
    function test_F3_DelegatedAttesterSpoofing() public {
        // (a) mallory signs but DECLARES alice as attester -> EAS rejects the signature
        (bool ok, bytes memory ret) = _delegated(subjectSchema, _data(_subject(1)), malloryPk, alice);
        assertFalse(ok, "declared attester != signer must be rejected");
        // forge-lint: disable-next-line(unsafe-typecast)
        assertTrue(bytes4(ret) != OTTPResolver__AttesterNotOwner.selector, "never reached the resolver");
        // (b) mallory signs as mallory, claims alice's id -> resolver rejects with exact params
        (ok, ret) = _delegated(subjectSchema, _data(_subject(1)), malloryPk, mallory);
        assertFalse(ok);
        assertEq(ret, abi.encodeWithSelector(OTTPResolver__AttesterNotOwner.selector, 1, mallory, alice));
        // (c) alice signs as alice -> stored attester == alice (signer, not relayer)
        (ok, ret) = _delegated(subjectSchema, _data(_subject(1)), alicePk, alice);
        assertTrue(ok);
        bytes32 uid = abi.decode(ret, (bytes32));
        assertEq(eas.getAttestation(uid).attester, alice);
        // (d) declared attester == address(0): can never produce a zero-attester attestation
        (ok,) = _delegated(subjectSchema, _data(_subject(1)), malloryPk, address(0));
        assertFalse(ok);
        // (e) relayer that itself holds an id gains nothing: bob relays alice's request claiming bob's id
        (ok, ret) = _delegated(objectSchema, _data(_object(2)), alicePk, alice);
        assertFalse(ok);
        assertEq(ret, abi.encodeWithSelector(OTTPResolver__AttesterNotOwner.selector, 2, alice, bob));
    }

    // ── F4: multiAttest across BOTH schemas in one tx: one bad item reverts everything ──
    function test_F4_MultiAttestMixedSchemas_Atomic() public {
        MultiAttestationRequest[] memory reqs = new MultiAttestationRequest[](2);
        AttestationRequestData[] memory s = new AttestationRequestData[](1);
        s[0] = _data(_subject(1));
        AttestationRequestData[] memory o = new AttestationRequestData[](2);
        o[0] = _data(_object(1));
        o[1] = _data(_object(2)); // alice claiming bob's creatorId
        reqs[0] = MultiAttestationRequest({ schema: subjectSchema, data: s });
        reqs[1] = MultiAttestationRequest({ schema: objectSchema, data: o });
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(OTTPResolver__AttesterNotOwner.selector, 2, alice, bob));
        eas.multiAttest(reqs);
        // all-good batch lands with alice as attester on every item
        o[1] = _data(_object(1));
        vm.prank(alice);
        bytes32[] memory uids = eas.multiAttest(reqs);
        assertEq(uids.length, 3);
        for (uint256 i = 0; i < 3; ++i) {
            assertEq(eas.getAttestation(uids[i]).attester, alice);
        }
    }

    // ── F5: ERC-1271 wallet: registerFor works on both chains; RELAYED attest depends on EAS version ──
    function test_F5_Erc1271Wallet_RegisterForAndAttest() public {
        ERC1271Wallet w = new ERC1271Wallet(alice);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = RegistrySigUtils.sign(vm, alicePk, address(registry), block.chainid, address(w), 0, dl);
        vm.prank(relayer);
        assertEq(registry.registerFor(address(w), dl, sig), 3);
        // direct attest from the wallet contract itself always works
        vm.prank(address(w));
        bytes32 uid = eas.attest(AttestationRequest({ schema: subjectSchema, data: _data(_subject(3)) }));
        assertEq(eas.getAttestation(uid).attester, address(w));
        // relayed (delegated) attest signed by the wallet's owner key, declaring the wallet as attester
        (bool ok,) = _delegated(subjectSchema, _data(_subject(3)), alicePk, address(w));
        assertEq(ok, _relaysErc1271(), "relayed ERC-1271 attest availability follows the EAS version");
    }

    // ── F6: after transferId through the real core ──
    function test_F6_AfterTransfer() public {
        vm.prank(alice);
        registry.transferId(1, mallory);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(OTTPResolver__AttesterNotOwner.selector, 1, alice, mallory));
        eas.attest(AttestationRequest({ schema: subjectSchema, data: _data(_subject(1)) }));
        vm.prank(mallory);
        eas.attest(AttestationRequest({ schema: subjectSchema, data: _data(_subject(1)) }));
        (bool ok,) = _delegated(subjectSchema, _data(_subject(1)), alicePk, alice);
        assertFalse(ok, "old wallet cannot relay either");
    }
}

/// Base mainnet — EAS 1.0.1.
contract Audit2ForkMainnet is Audit2ForkBase {
    IEIP712Proxy internal constant PROXY = IEIP712Proxy(0xF095fE4b23958b08D38e52d5d5674bBF0C03cbF6);

    function _rpc() internal pure override returns (string memory) {
        return "https://mainnet.base.org";
    }

    function _chainId() internal pure override returns (uint256) {
        return OTTPSchemas.BASE_MAINNET;
    }

    function _easVersion() internal pure override returns (string memory) {
        return "1.0.1";
    }

    function _relaysErc1271() internal pure override returns (bool) {
        return false;
    }

    /// EAS 1.0.1: Attest(bytes32 schema,address recipient,uint64 expirationTime,bool revocable,bytes32 refUID,bytes data,uint256 nonce)
    function _delegated(bytes32 schema, AttestationRequestData memory data, uint256 signerPk, address declared)
        internal
        override
        returns (bool ok, bytes memory ret)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, _digest101(schema, data, declared));
        DelegatedAttestationRequestV101 memory req = DelegatedAttestationRequestV101({
            schema: schema, data: data, signature: Signature(v, r, s), attester: declared
        });
        vm.prank(relayer);
        (ok, ret) = address(eas).call(abi.encodeWithSelector(IEASv101.attestByDelegation.selector, req));
    }

    function _digest101(bytes32 schema, AttestationRequestData memory d, address declared)
        internal
        view
        returns (bytes32)
    {
        IEASIntrospect e = IEASIntrospect(address(eas));
        bytes32 th = keccak256(
            "Attest(bytes32 schema,address recipient,uint64 expirationTime,bool revocable,bytes32 refUID,bytes data,uint256 nonce)"
        );
        assertEq(e.getAttestTypeHash(), th, "1.0.1 typehash");
        // abi.encode of static fields == concatenation of the two halves (all 32-byte words)
        bytes memory head = abi.encode(th, schema, d.recipient, d.expirationTime);
        bytes memory tail = abi.encode(d.revocable, d.refUID, keccak256(d.data), e.getNonce(declared));
        return keccak256(abi.encodePacked("\x19\x01", e.getDomainSeparator(), keccak256(bytes.concat(head, tail))));
    }

    /// F7: the REAL EIP712Proxy on Base mainnet records the PROXY as attester. A user routed through it is
    /// rejected; and if an id is ever transferred to the proxy, anyone with any EOA key can attest as that id.
    function test_F7_RealEIP712Proxy_IsThePermissionlessForwarderFootgun() public {
        assertEq(PROXY.version(), "1.2.0");
        bytes32 th = keccak256(
            "Attest(bytes32 schema,address recipient,uint64 expirationTime,bool revocable,bytes32 refUID,bytes data,uint256 value,uint64 deadline)"
        );
        assertEq(PROXY.getAttestTypeHash(), th);
        uint64 dl = uint64(block.timestamp + 1 hours);

        // alice, through the proxy, claiming her own id -> attester is the proxy -> rejected
        (bool ok, bytes memory ret) = _viaProxy(subjectSchema, _data(_subject(1)), alicePk, alice, dl);
        assertFalse(ok);
        assertEq(ret, abi.encodeWithSelector(OTTPResolver__AttesterNotOwner.selector, 1, address(PROXY), alice));

        // alice parks id 1 in the proxy (documented "never do this"); now mallory attests as id 1
        vm.prank(alice);
        registry.transferId(1, address(PROXY));
        (ok, ret) = _viaProxy(subjectSchema, _data(_subject(1)), malloryPk, mallory, dl);
        assertTrue(ok, "anyone can attest as an id held by a permissionless proxy");
        assertEq(eas.getAttestation(abi.decode(ret, (bytes32))).attester, address(PROXY));
    }

    function _proxyStructHash(bytes32 schema, AttestationRequestData memory d, uint64 dl)
        internal
        view
        returns (bytes32)
    {
        bytes memory head = abi.encode(PROXY.getAttestTypeHash(), schema, d.recipient, d.expirationTime);
        bytes memory tail = abi.encode(d.revocable, d.refUID, keccak256(d.data), d.value, dl);
        return keccak256(bytes.concat(head, tail));
    }

    function _viaProxy(bytes32 schema, AttestationRequestData memory data, uint256 pk, address declared, uint64 dl)
        internal
        returns (bool ok, bytes memory ret)
    {
        bytes32 digest =
            keccak256(abi.encodePacked("\x19\x01", PROXY.getDomainSeparator(), _proxyStructHash(schema, data, dl)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        DelegatedProxyAttestationRequest memory req = DelegatedProxyAttestationRequest({
            schema: schema, data: data, signature: Signature(v, r, s), attester: declared, deadline: dl
        });
        vm.prank(relayer);
        (ok, ret) = address(PROXY).call(abi.encodeWithSelector(IEIP712Proxy.attestByDelegation.selector, req));
    }
}

/// Base Sepolia — EAS 1.2.0.
contract Audit2ForkSepolia is Audit2ForkBase {
    function _rpc() internal pure override returns (string memory) {
        return "https://sepolia.base.org";
    }

    function _chainId() internal pure override returns (uint256) {
        return OTTPSchemas.BASE_SEPOLIA;
    }

    function _easVersion() internal pure override returns (string memory) {
        return "1.2.0";
    }

    function _relaysErc1271() internal pure override returns (bool) {
        return true;
    }

    /// EAS 1.2.0: Attest(bytes32 schema,address recipient,uint64 expirationTime,bool revocable,bytes32 refUID,bytes data,uint256 value,uint256 nonce,uint64 deadline)
    function _delegated(bytes32 schema, AttestationRequestData memory data, uint256 signerPk, address declared)
        internal
        override
        returns (bool ok, bytes memory ret)
    {
        uint64 dl = uint64(block.timestamp + 1 hours);
        bytes32 digest = _digest120(schema, data, declared, dl);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, digest);
        DelegatedAttestationRequest memory req = DelegatedAttestationRequest({
            schema: schema, data: data, signature: Signature(v, r, s), attester: declared, deadline: dl
        });
        vm.prank(relayer);
        (ok, ret) = address(eas).call(abi.encodeWithSelector(IEAS.attestByDelegation.selector, req));
    }

    function _digest120(bytes32 schema, AttestationRequestData memory d, address declared, uint64 dl)
        internal
        view
        returns (bytes32)
    {
        IEASIntrospect e = IEASIntrospect(address(eas));
        bytes32 th = keccak256(
            "Attest(bytes32 schema,address recipient,uint64 expirationTime,bool revocable,bytes32 refUID,bytes data,uint256 value,uint256 nonce,uint64 deadline)"
        );
        assertEq(e.getAttestTypeHash(), th, "1.2.0 typehash");
        bytes memory head = abi.encode(th, schema, d.recipient, d.expirationTime, d.revocable);
        bytes memory tail = abi.encode(d.refUID, keccak256(d.data), d.value, e.getNonce(declared), dl);
        return keccak256(abi.encodePacked("\x19\x01", e.getDomainSeparator(), keccak256(bytes.concat(head, tail))));
    }
}
