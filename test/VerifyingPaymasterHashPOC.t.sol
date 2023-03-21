// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import "forge-std/Test.sol";
import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";
import {UserOperation, UserOperationLib} from "@eth-infinitism/account-abstraction/interfaces/UserOperation.sol";
import {ExampleAccountFactory} from "../src/ExampleAccountFactory.sol";
import {ExampleAccount} from "../src/ExampleAccount.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {VerifyingPaymaster} from "@eth-infinitism/account-abstraction/samples/VerifyingPaymaster.sol";

contract VerifyingPaymasterHashPOC is Test {
    EntryPoint entryPoint;
    VerifyingPaymaster verifyingPaymaster;

    using ECDSA for bytes32;

    // Declare event for `vm.expectEmit`
    event UserOperationEvent(bytes32 indexed userOpHash, address indexed sender, address indexed paymaster, uint256 nonce, bool success, uint256 actualGasCost, uint256 actualGasUsed);

    function setUp() public {
        entryPoint = new EntryPoint();

        address signer = makeAddr("Signer");

        verifyingPaymaster = new VerifyingPaymaster(entryPoint, signer);

    }

    function test_collideUOHashes() public {
        bytes memory calldata1 = 
/*args@0x000:                */ hex"0000000000000000000000000000000000000000000000000000000000000060"  // head(args[0]) = where tail(args[0]) starts within args
/*args@0x020:                */ hex"0000000000000000000000000000000000000000000000000000000000000020"  // validUntil
/*args@0x040:                */ hex"0000000000000000000000000000000000000000000000000000000000000020"  // validAfter
/*args@0x060: args[0]@0x000: */ hex"0000000000000000000000009a7908627581072a5be468464c32ac8bf2239466"  // uo.sender
/*args@0x080: args[0]@0x020: */ hex"0000000000000000000000000000000000000000000000000000000000000007"  // uo.nonce
/*args@0x0a0: args[0]@0x040: */ hex"00000000000000000000000000000000000000000000000000000000000001a0"  // where uo.initCode starts within args[0]
/*args@0x0c0: args[0]@0x060: */ hex"00000000000000000000000000000000000000000000000000000000000001e0"  // where uo.callData starts within args[0]
/*args@0x0e0: args[0]@0x080: */ hex"000000000000000000000000000000000000000000000000000000000000ab12"  // uo.callGasLimit
/*args@0x100: args[0]@0x0a0: */ hex"000000000000000000000000000000000000000000000000000000000000de34"  // uo.verificationGasLimit
/*args@0x120: args[0]@0x0c0: */ hex"00000000000000000000000000000000000000000000000000000000000000ef"  // uo.preVerificationGas
/*args@0x140: args[0]@0x0e0: */ hex"00000000000000000000000000000000000000000000000000000002540be400"  // uo.maxFeePerGas
/*args@0x160: args[0]@0x100: */ hex"000000000000000000000000000000000000000000000000000000003b9aca00"  // uo.maxPriorityFeePerGas
/*args@0x180: args[0]@0x120: */ hex"0000000000000000000000000000000000000000000000000000000000000160"  // where uo.paymasterAndData starts within args[0]
/*args@0x1a0: args[0]@0x140: */ hex"0000000000000000000000000000000000000000000000000000000000000220"  // where uo.signature starts within args[0]
/*args@0x1c0: args[0]@0x160: */ hex"0000000000000000000000000000000000000000000000000000000000000003"  // length of paymasterAndData
/*args@0x1e0: args[0]@0x180: */ hex"de12ad0000000000000000000000000000000000000000000000000000000000"  // paymasterAndData itself
/*args@0x200: args[0]@0x1a0: */ hex"0000000000000000000000000000000000000000000000000000000000000004"  // length of initCode
/*args@0x220: args[0]@0x1c0: */ hex"1517c0de00000000000000000000000000000000000000000000000000000000"  // initCode itself
/*args@0x240: args[0]@0x1e0: */ hex"0000000000000000000000000000000000000000000000000000000000000004"  // length of callData
/*args@0x260: args[0]@0x200: */ hex"ca11dada00000000000000000000000000000000000000000000000000000000"  // callData itself
/*args@0x280: args[0]@0x220: */ hex"0000000000000000000000000000000000000000000000000000000000000006"  // length of signature
/*args@0x2a0: args[0]@0x240: */ hex"dedede1234560000000000000000000000000000000000000000000000000000"; // signature itself

        bytes memory calldata2 = 
/*args@0x000:                */ hex"0000000000000000000000000000000000000000000000000000000000000060"  // head(args[0]) = where tail(args[0]) starts within args
/*args@0x020:                */ hex"0000000000000000000000000000000000000000000000000000000000000020"  // validUntil
/*args@0x040:                */ hex"0000000000000000000000000000000000000000000000000000000000000020"  // validAfter
/*args@0x060: args[0]@0x000: */ hex"0000000000000000000000009a7908627581072a5be468464c32ac8bf2239466"  // uo.sender
/*args@0x080: args[0]@0x020: */ hex"0000000000000000000000000000000000000000000000000000000000000007"  // uo.nonce
/*args@0x0a0: args[0]@0x040: */ hex"00000000000000000000000000000000000000000000000000000000000001a0"  // where uo.initCode starts within args[0]
/*args@0x0c0: args[0]@0x060: */ hex"00000000000000000000000000000000000000000000000000000000000001e0"  // where uo.callData starts within args[0]
/*args@0x0e0: args[0]@0x080: */ hex"000000000000000000000000000000000000000000000000000000000000ab12"  // uo.callGasLimit
/*args@0x100: args[0]@0x0a0: */ hex"000000000000000000000000000000000000000000000000000000000000de34"  // uo.verificationGasLimit
/*args@0x120: args[0]@0x0c0: */ hex"00000000000000000000000000000000000000000000000000000000000000ef"  // uo.preVerificationGas
/*args@0x140: args[0]@0x0e0: */ hex"00000000000000000000000000000000000000000000000000000002540be400"  // uo.maxFeePerGas
/*args@0x160: args[0]@0x100: */ hex"000000000000000000000000000000000000000000000000000000003b9aca00"  // uo.maxPriorityFeePerGas
/*args@0x180: args[0]@0x120: */ hex"0000000000000000000000000000000000000000000000000000000000000160"  // where uo.paymasterAndData starts within args[0]
/*args@0x1a0: args[0]@0x140: */ hex"0000000000000000000000000000000000000000000000000000000000000220"  // where uo.signature starts within args[0]
/*args@0x1c0: args[0]@0x160: */ hex"0000000000000000000000000000000000000000000000000000000000000003"  // length of paymasterAndData
/*args@0x1e0: args[0]@0x180: */ hex"de12ad0000000000000000000000000000000000000000000000000000000000"  // paymasterAndData itself
/*args@0x200: args[0]@0x1a0: */ hex"0000000000000000000000000000000000000000000000000000000000000005"  // length of initCode
/*args@0x220: args[0]@0x1c0: */ hex"1517c0de02000000000000000000000000000000000000000000000000000000"  // initCode itself
/*args@0x240: args[0]@0x1e0: */ hex"0000000000000000000000000000000000000000000000000000000000000005"  // length of callData
/*args@0x260: args[0]@0x200: */ hex"ca11dada02000000000000000000000000000000000000000000000000000000"  // callData itself
/*args@0x280: args[0]@0x220: */ hex"0000000000000000000000000000000000000000000000000000000000000006"  // length of signature
/*args@0x2a0: args[0]@0x240: */ hex"dedede1234560000000000000000000000000000000000000000000000000000"; // signature itself

        (, bytes memory uoHash1) = address(verifyingPaymaster).call(abi.encodePacked(verifyingPaymaster.getHash.selector, calldata1));
        (, bytes memory uoHash2) = address(verifyingPaymaster).call(abi.encodePacked(verifyingPaymaster.getHash.selector, calldata2));
        
        assertEq(uoHash1, uoHash2);

    }
}