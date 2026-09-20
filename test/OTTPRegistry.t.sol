// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import { Test } from "forge-std/Test.sol";
import { IERC5267 } from "@openzeppelin/contracts/interfaces/IERC5267.sol";

import { OTTPRegistry } from "../src/OTTPRegistry.sol";
import { RegistrySigUtils } from "./utils/RegistrySigUtils.sol";
import { ERC1271Wallet, PasswordWallet, NotAWallet } from "./mocks/ERC1271Wallet.sol";

contract OTTPRegistryTest is Test {
    OTTPRegistry internal registry;

    address internal alice;
    uint256 internal alicePk;
    address internal bob;
    uint256 internal bobPk;
    address internal carol = makeAddr("carol");
    address internal relayer = makeAddr("relayer");

    event Registered(uint256 indexed id, address indexed wallet);
    event Transferred(uint256 indexed id, address indexed oldWallet, address indexed newWallet);

    function setUp() public {
        registry = new OTTPRegistry();
        (alice, alicePk) = makeAddrAndKey("alice");
        (bob, bobPk) = makeAddrAndKey("bob");
        vm.warp(1_760_000_000); // a realistic timestamp so deadline math is meaningful
    }

    // ─── helpers ───────────────────────────────────────────────────────────────────────────────────────────

    function _sig(uint256 pk, address wallet, uint256 nonce, uint256 deadline) internal view returns (bytes memory) {
        return RegistrySigUtils.sign(vm, pk, address(registry), block.chainid, wallet, nonce, deadline);
    }

    // ─── register ──────────────────────────────────────────────────────────────────────────────────────────

    function test_InitialState() public view {
        assertEq(registry.nextId(), 1);
        assertEq(registry.totalRegistered(), 0);
        assertEq(registry.getId(alice), 0);
        assertEq(registry.getWallet(0), address(0));
        assertEq(registry.getWallet(1), address(0));
        assertEq(registry.getWallet(type(uint256).max), address(0));
        assertEq(registry.nonces(alice), 0);
    }

    function test_RegisterIssuesSequentialIds() public {
        vm.prank(alice);
        assertEq(registry.register(), 1);
        vm.prank(bob);
        assertEq(registry.register(), 2);
        vm.prank(carol);
        assertEq(registry.register(), 3);

        assertEq(registry.totalRegistered(), 3);
        assertEq(registry.nextId(), 4);
        assertEq(registry.getId(alice), 1);
        assertEq(registry.getId(bob), 2);
        assertEq(registry.getId(carol), 3);
        assertEq(registry.getWallet(1), alice);
        assertEq(registry.getWallet(2), bob);
        assertEq(registry.getWallet(3), carol);
        // public mappings match the getters (future-generation reads)
        assertEq(registry.idToWallet(2), bob);
        assertEq(registry.walletToId(bob), 2);
    }

    function test_RegisterEmitsEvent() public {
        vm.expectEmit(true, true, true, true, address(registry));
        emit Registered(1, alice);
        vm.prank(alice);
        registry.register();
    }

    function test_DoubleRegisterReverts() public {
        vm.startPrank(alice);
        registry.register();
        vm.expectRevert("Wallet already has an OTTP ID");
        registry.register();
        vm.stopPrank();
        assertEq(registry.totalRegistered(), 1);
    }

    function test_RegisterDoesNotTouchNonce() public {
        vm.prank(alice);
        registry.register();
        assertEq(registry.nonces(alice), 0);
    }

    // ─── transferId ────────────────────────────────────────────────────────────────────────────────────────

    function test_TransferId_Success() public {
        vm.prank(alice);
        registry.register();

        vm.expectEmit(true, true, true, true, address(registry));
        emit Transferred(1, alice, bob);
        vm.prank(alice);
        registry.transferId(1, bob);

        assertEq(registry.getWallet(1), bob);
        assertEq(registry.getId(bob), 1);
        assertEq(registry.getId(alice), 0);
        assertEq(registry.totalRegistered(), 1); // no new ID issued
        assertEq(registry.nextId(), 2);
    }

    function test_TransferId_OldWalletMayRegisterAgainAsNewId() public {
        vm.prank(alice);
        registry.register();
        vm.prank(alice);
        registry.transferId(1, bob);
        // alice is ID-free now; a fresh registration gives her a brand-new ID, never #1 back
        vm.prank(alice);
        assertEq(registry.register(), 2);
        assertEq(registry.getWallet(1), bob);
    }

    function test_TransferId_NonOwnerReverts() public {
        vm.prank(alice);
        registry.register();
        vm.prank(bob);
        vm.expectRevert("Not the owner of this ID");
        registry.transferId(1, carol);
        assertEq(registry.getWallet(1), alice);
    }

    function test_TransferId_ZeroAddressReverts() public {
        vm.prank(alice);
        registry.register();
        vm.prank(alice);
        vm.expectRevert("Cannot transfer to zero address");
        registry.transferId(1, address(0));
    }

    function test_TransferId_TargetAlreadyRegisteredReverts() public {
        vm.prank(alice);
        registry.register();
        vm.prank(bob);
        registry.register();
        vm.prank(alice);
        vm.expectRevert("Target wallet already has an OTTP ID");
        registry.transferId(1, bob);
        assertEq(registry.getWallet(1), alice);
        assertEq(registry.getWallet(2), bob);
    }

    function test_TransferId_ToSelfReverts() public {
        vm.prank(alice);
        registry.register();
        vm.prank(alice);
        vm.expectRevert("Target wallet already has an OTTP ID");
        registry.transferId(1, alice);
    }

    function test_TransferId_UnissuedIdReverts() public {
        vm.prank(alice);
        registry.register();
        vm.prank(alice);
        vm.expectRevert("Not the owner of this ID");
        registry.transferId(2, bob);
        vm.prank(alice);
        vm.expectRevert("Not the owner of this ID");
        registry.transferId(0, bob);
        vm.prank(alice);
        vm.expectRevert("Not the owner of this ID");
        registry.transferId(type(uint256).max, bob);
    }

    function test_TransferId_WrongIdOwnedByOtherReverts() public {
        vm.prank(alice);
        registry.register();
        vm.prank(bob);
        registry.register();
        vm.prank(alice);
        vm.expectRevert("Not the owner of this ID");
        registry.transferId(2, carol);
    }

    function test_TransferId_ChainOfTransfers() public {
        vm.prank(alice);
        registry.register();
        vm.prank(alice);
        registry.transferId(1, bob);
        vm.prank(bob);
        registry.transferId(1, carol);
        assertEq(registry.getWallet(1), carol);
        assertEq(registry.getId(carol), 1);
        assertEq(registry.getId(bob), 0);
        assertEq(registry.getId(alice), 0);
        // the former owners cannot move it anymore
        vm.prank(alice);
        vm.expectRevert("Not the owner of this ID");
        registry.transferId(1, alice);
        vm.prank(bob);
        vm.expectRevert("Not the owner of this ID");
        registry.transferId(1, bob);
    }

    // ─── registerFor: EIP-712 domain ───────────────────────────────────────────────────────────────────────

    function test_Eip712Domain_ERC5267() public view {
        (bytes1 fields, string memory name, string memory version, uint256 chainId, address verifyingContract,,) =
            IERC5267(address(registry)).eip712Domain();
        assertEq(fields, hex"0f");
        assertEq(name, "OTTPRegistry");
        assertEq(version, "2");
        assertEq(chainId, block.chainid);
        assertEq(verifyingContract, address(registry));
    }

    function test_RegisterTypehashMatchesSpec() public view {
        assertEq(registry.REGISTER_TYPEHASH(), keccak256("Register(address wallet,uint256 nonce,uint256 deadline)"));
        assertEq(registry.REGISTER_TYPEHASH(), RegistrySigUtils.REGISTER_TYPEHASH);
    }

    // ─── registerFor: EOA path ─────────────────────────────────────────────────────────────────────────────

    function test_RegisterFor_ValidEoaSignature() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sig(alicePk, alice, 0, deadline);

        vm.expectEmit(true, true, true, true, address(registry));
        emit Registered(1, alice);
        vm.prank(relayer);
        uint256 id = registry.registerFor(alice, deadline, sig);

        assertEq(id, 1);
        assertEq(registry.getWallet(1), alice); // issued to the signer…
        assertEq(registry.getId(alice), 1);
        assertEq(registry.getId(relayer), 0); // …never to the relayer
        assertEq(registry.nonces(alice), 1);
        assertEq(registry.nonces(relayer), 0);
    }

    function test_RegisterFor_DeadlineExactlyNowIsValid() public {
        uint256 deadline = block.timestamp;
        vm.prank(relayer);
        registry.registerFor(alice, deadline, _sig(alicePk, alice, 0, deadline));
        assertEq(registry.getId(alice), 1);
    }

    function test_RegisterFor_ExpiredDeadlineReverts() public {
        uint256 deadline = block.timestamp - 1;
        bytes memory sig = _sig(alicePk, alice, 0, deadline);
        vm.prank(relayer);
        vm.expectRevert("Signature expired");
        registry.registerFor(alice, deadline, sig);
        assertEq(registry.nonces(alice), 0);
    }

    function test_RegisterFor_SignatureExpiresAfterWarp() public {
        uint256 deadline = block.timestamp + 10;
        bytes memory sig = _sig(alicePk, alice, 0, deadline);
        vm.warp(deadline + 1);
        vm.prank(relayer);
        vm.expectRevert("Signature expired");
        registry.registerFor(alice, deadline, sig);
    }

    function test_RegisterFor_WrongSignerReverts() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sig(bobPk, alice, 0, deadline); // bob signs for alice
        vm.prank(relayer);
        vm.expectRevert("Invalid signature");
        registry.registerFor(alice, deadline, sig);
        assertEq(registry.totalRegistered(), 0);
    }

    function test_RegisterFor_SignatureForOtherWalletParamReverts() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sig(alicePk, alice, 0, deadline); // alice signs for herself…
        vm.prank(relayer);
        vm.expectRevert("Invalid signature");
        registry.registerFor(bob, deadline, sig); // …relayer tries to register bob with it
        vm.prank(relayer);
        vm.expectRevert("Invalid signature");
        registry.registerFor(relayer, deadline, sig); // …or itself
        assertEq(registry.totalRegistered(), 0);
    }

    function test_RegisterFor_TamperedDeadlineReverts() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sig(alicePk, alice, 0, deadline);
        vm.prank(relayer);
        vm.expectRevert("Invalid signature");
        registry.registerFor(alice, deadline + 1, sig);
    }

    function test_RegisterFor_WrongNonceReverts() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sig(alicePk, alice, 1, deadline); // current nonce is 0
        vm.prank(relayer);
        vm.expectRevert("Invalid signature");
        registry.registerFor(alice, deadline, sig);
    }

    function test_RegisterFor_ReplayReverts() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sig(alicePk, alice, 0, deadline);
        vm.prank(relayer);
        registry.registerFor(alice, deadline, sig);

        // Same signature again: nonce moved on AND the wallet already holds an ID.
        vm.prank(relayer);
        vm.expectRevert("Invalid signature");
        registry.registerFor(alice, deadline, sig);

        // A fresh valid signature with the new nonce is still rejected: one ID per wallet.
        bytes memory sig2 = _sig(alicePk, alice, 1, deadline);
        vm.prank(relayer);
        vm.expectRevert("Wallet already has an OTTP ID");
        registry.registerFor(alice, deadline, sig2);
        assertEq(registry.totalRegistered(), 1);
    }

    function test_RegisterFor_NonceNotConsumedOnFailure() public {
        uint256 deadline = block.timestamp + 1 hours;
        vm.prank(relayer);
        vm.expectRevert("Invalid signature");
        registry.registerFor(alice, deadline, _sig(bobPk, alice, 0, deadline));
        assertEq(registry.nonces(alice), 0);
        // the correct signature still works afterwards
        vm.prank(relayer);
        registry.registerFor(alice, deadline, _sig(alicePk, alice, 0, deadline));
        assertEq(registry.nonces(alice), 1);
    }

    function test_RegisterFor_AfterDirectRegisterReverts() public {
        vm.prank(alice);
        registry.register();
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sig(alicePk, alice, 0, deadline);
        vm.prank(relayer);
        vm.expectRevert("Wallet already has an OTTP ID");
        registry.registerFor(alice, deadline, sig);
    }

    function test_RegisterFor_AfterTransferUsesNextNonce() public {
        uint256 deadline = block.timestamp + 1 hours;
        vm.prank(relayer);
        registry.registerFor(alice, deadline, _sig(alicePk, alice, 0, deadline));
        vm.prank(alice);
        registry.transferId(1, bob);
        // alice is ID-free again; the old signature (nonce 0) is dead, nonce 1 works and yields a new ID.
        vm.prank(relayer);
        vm.expectRevert("Invalid signature");
        registry.registerFor(alice, deadline, _sig(alicePk, alice, 0, deadline));
        vm.prank(relayer);
        assertEq(registry.registerFor(alice, deadline, _sig(alicePk, alice, 1, deadline)), 2);
    }

    function test_RegisterFor_WrongChainIdReverts() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = RegistrySigUtils.sign(vm, alicePk, address(registry), 8453, alice, 0, deadline);
        assertTrue(block.chainid != 8453, "test chain must differ");
        vm.prank(relayer);
        vm.expectRevert("Invalid signature");
        registry.registerFor(alice, deadline, sig);
    }

    function test_RegisterFor_WrongVerifyingContractReverts() public {
        OTTPRegistry other = new OTTPRegistry();
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = RegistrySigUtils.sign(vm, alicePk, address(other), block.chainid, alice, 0, deadline);
        vm.prank(relayer);
        vm.expectRevert("Invalid signature");
        registry.registerFor(alice, deadline, sig);
        // …but is valid on the contract it was made for
        vm.prank(relayer);
        assertEq(other.registerFor(alice, deadline, sig), 1);
    }

    function test_RegisterFor_DomainSeparatorTracksChainIdChange() public {
        // OZ EIP712 recomputes the separator when block.chainid changes (post-fork safety).
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sig(alicePk, alice, 0, deadline);
        vm.chainId(84532);
        vm.prank(relayer);
        vm.expectRevert("Invalid signature");
        registry.registerFor(alice, deadline, sig);
        bytes memory sig2 = RegistrySigUtils.sign(vm, alicePk, address(registry), 84532, alice, 0, deadline);
        vm.prank(relayer);
        assertEq(registry.registerFor(alice, deadline, sig2), 1);
    }

    function test_RegisterFor_MalformedSignatureReverts() public {
        uint256 deadline = block.timestamp + 1 hours;
        vm.startPrank(relayer);
        vm.expectRevert("Invalid signature");
        registry.registerFor(alice, deadline, "");
        vm.expectRevert("Invalid signature");
        registry.registerFor(alice, deadline, hex"deadbeef");
        vm.expectRevert("Invalid signature");
        registry.registerFor(alice, deadline, new bytes(64));
        vm.expectRevert("Invalid signature");
        registry.registerFor(alice, deadline, new bytes(65));
        vm.stopPrank();
    }

    function test_RegisterFor_HighSMalleatedSignatureReverts() public {
        uint256 deadline = block.timestamp + 1 hours;
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(alicePk, RegistrySigUtils.digest(address(registry), block.chainid, alice, 0, deadline));
        // Flip to the other valid (r, s', v') representation. OZ ECDSA rejects s > secp256k1n/2.
        bytes32 sMal = bytes32(uint256(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141) - uint256(s));
        uint8 vMal = v == 27 ? 28 : 27;
        vm.prank(relayer);
        vm.expectRevert("Invalid signature");
        registry.registerFor(alice, deadline, abi.encodePacked(r, sMal, vMal));
    }

    function test_RegisterFor_ZeroWalletReverts() public {
        uint256 deadline = block.timestamp + 1 hours;
        vm.prank(relayer);
        vm.expectRevert("Invalid signature");
        registry.registerFor(address(0), deadline, new bytes(65));
        vm.prank(relayer);
        vm.expectRevert("Invalid signature");
        registry.registerFor(address(0), deadline, "");
    }

    function test_RegisterFor_AnyoneCanRelay() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sig(alicePk, alice, 0, deadline);
        vm.prank(bob); // a different relayer than intended — harmless, outcome is identical
        registry.registerFor(alice, deadline, sig);
        assertEq(registry.getId(alice), 1);
        assertEq(registry.getId(bob), 0);
    }

    // ─── registerFor: ERC-1271 path ────────────────────────────────────────────────────────────────────────

    function test_RegisterFor_Erc1271WalletAccepts() public {
        ERC1271Wallet wallet = new ERC1271Wallet(alice);
        uint256 deadline = block.timestamp + 1 hours;
        // signed by alice's key, over a digest whose `wallet` field is the CONTRACT address
        bytes memory sig = _sig(alicePk, address(wallet), 0, deadline);

        vm.prank(relayer);
        uint256 id = registry.registerFor(address(wallet), deadline, sig);
        assertEq(id, 1);
        assertEq(registry.getWallet(1), address(wallet));
        assertEq(registry.getId(alice), 0); // the owner EOA is not registered, the contract wallet is
        assertEq(registry.getId(relayer), 0);
        assertEq(registry.nonces(address(wallet)), 1);
    }

    function test_RegisterFor_Erc1271WalletRejectsWrongSigner() public {
        ERC1271Wallet wallet = new ERC1271Wallet(alice);
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sig(bobPk, address(wallet), 0, deadline);
        vm.prank(relayer);
        vm.expectRevert("Invalid signature");
        registry.registerFor(address(wallet), deadline, sig);
    }

    function test_RegisterFor_Erc1271WalletRejectsReplay() public {
        ERC1271Wallet wallet = new ERC1271Wallet(alice);
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sig(alicePk, address(wallet), 0, deadline);
        vm.prank(relayer);
        registry.registerFor(address(wallet), deadline, sig);
        vm.prank(relayer);
        vm.expectRevert("Invalid signature");
        registry.registerFor(address(wallet), deadline, sig);
    }

    function test_RegisterFor_Erc1271NonEcdsaScheme() public {
        bytes32 password = keccak256("open sesame");
        PasswordWallet wallet = new PasswordWallet(password);
        uint256 deadline = block.timestamp + 1 hours;
        vm.prank(relayer);
        assertEq(registry.registerFor(address(wallet), deadline, abi.encode(password)), 1);
        vm.prank(relayer);
        vm.expectRevert("Invalid signature");
        registry.registerFor(address(wallet), deadline, abi.encode(keccak256("wrong")));
    }

    function test_RegisterFor_ContractWithoutErc1271Reverts() public {
        NotAWallet c = new NotAWallet();
        uint256 deadline = block.timestamp + 1 hours;
        vm.prank(relayer);
        vm.expectRevert("Invalid signature");
        registry.registerFor(address(c), deadline, _sig(alicePk, address(c), 0, deadline));
    }

    function test_Erc1271WalletCanRegisterDirectlyAndTransfer() public {
        // A contract wallet using the direct path (e.g. a Safe executing register()) then rotating keys.
        ERC1271Wallet wallet = new ERC1271Wallet(alice);
        vm.prank(address(wallet));
        assertEq(registry.register(), 1);
        vm.prank(address(wallet));
        registry.transferId(1, alice);
        assertEq(registry.getWallet(1), alice);
    }

    // ─── no admin surface ──────────────────────────────────────────────────────────────────────────────────

    function test_NoEtherAccepted() public {
        vm.deal(alice, 1 ether);
        vm.prank(alice);
        (bool ok,) = address(registry).call{ value: 1 }("");
        assertFalse(ok);
        assertEq(address(registry).balance, 0);
    }

    // ─── fuzz ──────────────────────────────────────────────────────────────────────────────────────────────

    function testFuzz_RegisterFor_ValidSignatureAlwaysRegistersSigner(
        uint256 pk,
        uint256 deadlineOffset,
        address relayer_
    ) public {
        pk = bound(pk, 1, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140);
        deadlineOffset = bound(deadlineOffset, 0, 365 days);
        address signer = vm.addr(pk);
        vm.assume(signer != relayer_);
        uint256 deadline = block.timestamp + deadlineOffset;

        vm.prank(relayer_);
        uint256 id = registry.registerFor(signer, deadline, _sig(pk, signer, 0, deadline));

        assertEq(id, 1);
        assertEq(registry.getWallet(1), signer);
        assertEq(registry.getId(relayer_), 0);
        assertEq(registry.nonces(signer), 1);
    }

    function testFuzz_RegisterFor_WrongNonceRejected(uint256 pk, uint256 nonce) public {
        pk = bound(pk, 1, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140);
        vm.assume(nonce != 0);
        address signer = vm.addr(pk);
        uint256 deadline = block.timestamp + 1 days;
        vm.prank(relayer);
        vm.expectRevert("Invalid signature");
        registry.registerFor(signer, deadline, _sig(pk, signer, nonce, deadline));
    }

    function testFuzz_RegisterFor_ExpiredRejected(uint256 pk, uint256 deadline) public {
        pk = bound(pk, 1, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140);
        deadline = bound(deadline, 0, block.timestamp - 1);
        address signer = vm.addr(pk);
        bytes memory sig = _sig(pk, signer, 0, deadline);
        vm.prank(relayer);
        vm.expectRevert("Signature expired");
        registry.registerFor(signer, deadline, sig);
    }

    function testFuzz_RegisterFor_WrongSignerRejected(uint256 pkA, uint256 pkB) public {
        pkA = bound(pkA, 1, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140);
        pkB = bound(pkB, 1, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140);
        vm.assume(pkA != pkB);
        address a = vm.addr(pkA);
        uint256 deadline = block.timestamp + 1 days;
        vm.prank(relayer);
        vm.expectRevert("Invalid signature");
        registry.registerFor(a, deadline, _sig(pkB, a, 0, deadline));
    }

    function testFuzz_RegisterFor_TamperedFieldsRejected(uint256 pk, uint256 deadline, uint256 tamper, address other)
        public
    {
        pk = bound(pk, 1, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140);
        deadline = bound(deadline, block.timestamp, type(uint256).max - 1);
        tamper = bound(tamper, 1, type(uint256).max - deadline);
        address signer = vm.addr(pk);
        vm.assume(other != signer && other != address(0));
        bytes memory sig = _sig(pk, signer, 0, deadline);

        vm.prank(relayer);
        vm.expectRevert("Invalid signature");
        registry.registerFor(signer, deadline + tamper, sig); // tampered deadline
        vm.prank(relayer);
        vm.expectRevert("Invalid signature");
        registry.registerFor(other, deadline, sig); // tampered wallet
    }

    function testFuzz_TransferId_OnlyOwnerCanMove(address caller, uint256 id, address to) public {
        vm.prank(alice);
        registry.register(); // id 1 owned by alice
        vm.assume(caller != alice);
        vm.prank(caller);
        vm.expectRevert("Not the owner of this ID");
        registry.transferId(id, to);
        assertEq(registry.getWallet(1), alice);
    }

    function testFuzz_TransferId_OwnerToFreshWallet(address to) public {
        vm.assume(to != address(0) && to != alice);
        vm.prank(alice);
        registry.register();
        vm.prank(alice);
        registry.transferId(1, to);
        assertEq(registry.getWallet(1), to);
        assertEq(registry.getId(to), 1);
        assertEq(registry.getId(alice), 0);
        assertEq(registry.totalRegistered(), 1);
    }

    function testFuzz_TransferId_UnissuedAlwaysReverts(uint256 id, address to) public {
        vm.prank(alice);
        registry.register();
        vm.assume(id != 1);
        vm.prank(alice);
        vm.expectRevert("Not the owner of this ID");
        registry.transferId(id, to);
    }

    function testFuzz_Register_ManyWalletsSequential(uint8 n) public {
        for (uint256 i = 1; i <= n; i++) {
            // forge-lint: disable-next-line(unsafe-typecast)
            address w = address(uint160(0x1000 + i));
            vm.prank(w);
            assertEq(registry.register(), i);
            assertEq(registry.getWallet(i), w);
        }
        assertEq(registry.totalRegistered(), n);
        assertEq(registry.nextId(), uint256(n) + 1);
    }
}
