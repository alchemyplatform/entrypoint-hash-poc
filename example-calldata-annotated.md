# Example of non-standard encoded calldata

Taken from this transaction: https://goerli.etherscan.io/tx/0xbee50381e09b1fbf21667255ae0c70f02aa5fe8e8167fe0a5253f7dd9a61d138

Note the extra zero word at `ops[0]@0x160`. Under a standard ABI encoding, zero length dynamic fields do not have any space allocated to them. This extra word changes the result of `UserOperation.pack()`.

```
Method selector:  1fad948c
args@0x000:               0000000000000000000000000000000000000000000000000000000000000040
args@0x020:               000000000000000000000000dbd510f9ebb7a81209fccd12a56f6c6354aa8cab
args@0x040:               0000000000000000000000000000000000000000000000000000000000000001
args@0x060:               0000000000000000000000000000000000000000000000000000000000000020
args@0x080: ops[0]@0x000: 0000000000000000000000003ba340bc4194d7315c6f9f19aabc5f4a5cdc2e22 // uo.sender
args@0x0a0: ops[0]@0x020: 0000000000000000000000000000000000000000000000000000000000000001 // uo.nonce
args@0x0c0: ops[0]@0x040: 0000000000000000000000000000000000000000000000000000000000000160 // where uo.initCode starts within args[0][0]
args@0x0e0: ops[0]@0x060: 00000000000000000000000000000000000000000000000000000000000001a0 // where uo.callData starts within args[0][0]
args@0x100: ops[0]@0x080: 00000000000000000000000000000000000000000000000000000000000493e0 // uo.callGasLimit
args@0x120: ops[0]@0x0a0: 000000000000000000000000000000000000000000000000000000000003d090 // uo.verificationGasLimit
args@0x140: ops[0]@0x0c0: 0000000000000000000000000000000000000000000000000000000000005e10 // uo.preVerificationGas
args@0x160: ops[0]@0x0e0: 0000000000000000000000000000000000000000000000000000000059777140 // uo.maxFeePerGas
args@0x180: ops[0]@0x100: 0000000000000000000000000000000000000000000000000000000059682f00 // uo.maxPriorityFeePerGas
args@0x1a0: ops[0]@0x120: 00000000000000000000000000000000000000000000000000000000000004c0 // where uo.paymasterAndData starts within args[0][0]
args@0x1c0: ops[0]@0x140: 0000000000000000000000000000000000000000000000000000000000000580 // where uo.signature starts within args[0][0]
args@0x1e0: ops[0]@0x160: 0000000000000000000000000000000000000000000000000000000000000000 // length of uo.initCode
args@0x200: ops[0]@0x180: 0000000000000000000000000000000000000000000000000000000000000000 // <------ EXTRA ZERO WORD
args@0x220: ops[0]@0x1a0: 00000000000000000000000000000000000000000000000000000000000002e4 // length of callData
args@0x240: ops[0]@0x1c0: f34308ef00000000000000000000000040a2accbd92bca938b02010e17a5b892 // callData ...
args@0x260: ops[0]@0x1e0: 9b49130d00000000000000000000000000000000000000000000000000000000 
args@0x280: ops[0]@0x200: 0000000000000000000000000000000000000000000000000000000000000000
args@0x2a0: ops[0]@0x220: 000000e000000000000000000000000000000000000000000000000000000000
args@0x2c0: ops[0]@0x240: 0000000100000000000000000000000000000000000000000000000000000000
args@0x2e0: ops[0]@0x260: 0000000000000000000000000000000000000000000000000000000000000000
args@0x300: ops[0]@0x280: 0000000000000000000000000000000000000000000000000000000000000000
args@0x320: ops[0]@0x2a0: 0000000000000000000000000000000000000000000000000000000000000000
args@0x340: ops[0]@0x2c0: 000001c48d80ff0a000000000000000000000000000000000000000000000000
args@0x360: ops[0]@0x2e0: 0000000000000020000000000000000000000000000000000000000000000000
args@0x380: ops[0]@0x300: 0000000000000172007ddefa2f027691116d0a7aa6418246622d70b12a000000
args@0x3a0: ops[0]@0x320: 0000000000000000000000000000000000000000000000000000000000000000
args@0x3c0: ops[0]@0x340: 0000000000000000000000000000000000000000000000000000000044095ea7
args@0x3e0: ops[0]@0x360: b3000000000000000000000000a275da33fe068cd62510b8e3af7818ede891cd
args@0x400: ops[0]@0x380: ff0000000000000000000000000000000000000000000000000005b81904eeb8
args@0x420: ops[0]@0x3a0: 00000014f33fc01017d9ac6762e8285b51ad07089e5100000000000000000000
args@0x440: ops[0]@0x3c0: 0000000000000000000000000000000000000000000000000000000000000000
args@0x460: ops[0]@0x3e0: 000000000000000000000000000000000000000000841a0487a0000000000000
args@0x480: ops[0]@0x400: 0000000000003ba340bc4194d7315c6f9f19aabc5f4a5cdc2e22000000000000
args@0x4a0: ops[0]@0x420: 0000000000000000000000000000000000000000000000000001000000000000
args@0x4c0: ops[0]@0x440: 000000000000dbd510f9ebb7a81209fccd12a56f6c6354aa8cab000000000000
args@0x4e0: ops[0]@0x460: 0000000000000000000000000000000000000000000000000000000000000000
args@0x500: ops[0]@0x480: 0000000000000000000000000000000000000000000000000000000000000000
args@0x520: ops[0]@0x4a0: 0000000000000000000000000000000000000000000000000000000000000000
args@0x540: ops[0]@0x4c0: 0000000000000000000000000000000000000000000000000000000000000091 // length of paymasterAndData
args@0x560: ops[0]@0x4e0: a275da33fe068cd62510b8e3af7818ede891cdff000000000000000000000000 // paymasterAndData ...
args@0x580: ops[0]@0x500: 0005ba482f72880000000000000000000000000000015549b2f3b4007ddefa2f
args@0x5a0: ops[0]@0x520: 027691116d0a7aa6418246622d70b12aae83895e738d98717f2b6dc29681dd82
args@0x5c0: ops[0]@0x540: e7c4e171f8e5123b7236a8315605d6bf398464266c2f644ed3224a70f0b8baab
args@0x5e0: ops[0]@0x560: c93906ee96b4862d0efb4a840c321a381c000000000000000000000000000000
args@0x600: ops[0]@0x580: 0000000000000000000000000000000000000000000000000000000000000041 // length of signature
args@0x620: ops[0]@0x5a0: 97302eead5cb71cdfca4f50c828a9077df10169eefd0116771be3ef4527f08ef // signature ...
args@0x640: ops[0]@0x5c0: 246027249e848d4e02d1d6d020044c0d5102b7ee030676e28d9c555bac63e4c4
args@0x660: ops[0]@0x5e0: 1c00000000000000000000000000000000000000000000000000000000000000
```