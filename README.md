## Overview

The `ethcrypto` library provides a collection of common Ethereum cryptographic primitives implemented in Go:

- `secp256k1`: ECDSA signing, signature validation and signer recovery
- `bn256`: BN256 pairing operations, with the EIP-196 and EIP-197 changes
- `blake2b`: BLAKE2b hashing, with the EIP-152 changes

## Usage

To use `ethcrypto` in your project, simply pull it in with:

```shell
go get -u github.com/sig-0/ethcrypto
```

To view the API reference, please refer to the [relevant Go doc](https://pkg.go.dev/github.com/sig-0/ethcrypto).
