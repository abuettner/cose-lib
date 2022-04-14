# cose-lib

## Introduction
This project provides a C library for the **CBOR Object Signing and Encryption (COSE)** protocol as defined in [`RFC8152`](https://www.rfc-editor.org/rfc/rfc8152.html). The main goal is to provide a simple API for creating COSE messages and to be easily portable, particularly for embedded environments. Please have a look at the examples under `examples/` to see how the library can be used.

## Status
This project is work in progress. Only few cryptographic algorithms are currently used for test purposes. The implementation will make it easy to include more algorithms in the near future. The following message types are currently under development:
* COSE Encrypt0
* COSE Sign1

## Planned features
* COSE Encrypt0 messages (single recipient)
* COSE Encrypt messages (multiple recipients)
* Further encryption algorithms as considered in [`RFC8152`](https://www.rfc-editor.org/rfc/rfc8152.html)
* COSE Sign1 messages (single recipient)
* COSE Sign messages (multiple recipients)
* Further signature algorithms as considered in [`RFC8152`](https://www.rfc-editor.org/rfc/rfc8152.html)
* COSE Key structures
* Key exchange
* ...


## Dependencies
The following libraries are currently used and included as submodules:
* TinyCBOR https://github.com/intel/tinycbor
* Mbed TLS https://github.com/Mbed-TLS/mbedtls
* micro-ecc https://github.com/kmackay/micro-ecc

## Building

### Getting the sources
```
git clone --recurse-submodules https://github.com/abuettner/cose-lib.git
cd cose-lib
```

### Build and run examples
```
// Build
make examples

// Run
./build/examples/encrypt0
...
```

## License
[`MIT License`](https://github.com/abuettner/cose-lib/blob/main/LICENSE)
