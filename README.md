# SHAKE128 for ConnectIQ

A pure Monkey C implementation of the SHAKE128 extendable-output function (XOF) for Garmin ConnectIQ devices.

## Overview

SHAKE128 is part of the SHA-3 family defined in FIPS 202. Unlike traditional hash functions with fixed output sizes, SHAKE128 is an extendable-output function that can produce output of any desired length.

This barrel provides a complete implementation based on the Keccak-f[1600] permutation with:
- Rate: 1344 bits (168 bytes)
- Capacity: 256 bits
- Security strength: 128 bits

## Installation

1. Download or clone this repository
2. Build the barrel using the ConnectIQ SDK:
   ```
   monkeyc -o shake128.barrel -f monkey.jungle
   ```
3. Add the barrel to your project's `manifest.xml`:
   ```xml
   <iq:barrels>
       <iq:depends name="shake128" version="1.0.0"/>
   </iq:barrels>
   ```
4. Import the module in your code:
   ```monkeyc
   using Crypto;
   ```

## Usage

### Single-shot hashing

For hashing data in one call:

```monkeyc
// Hash data and get 16 bytes of output
var data = [0x48, 0x65, 0x6c, 0x6c, 0x6f]b;  // "Hello"
var hash = Crypto.Shake128.hash(data, 16);
```

### Streaming API

For hashing large or chunked data:

```monkeyc
var shake = new Crypto.Shake128();

// Absorb data in chunks
shake.update(chunk1);
shake.update(chunk2);
shake.update(chunk3);

// Get output of any length
var hash = shake.digest(32);  // 32 bytes
```

### Debug helper

Print the hash result as hex:

```monkeyc
Crypto.Shake128.hashDebug(data, 16);
// Output: SHAKE128(5 bytes) = 1234abcd...
```

### Reusing the hasher

Reset to hash new data without creating a new instance:

```monkeyc
var shake = new Crypto.Shake128();
shake.update(data1);
var hash1 = shake.digest(16);

shake.reset();
shake.update(data2);
var hash2 = shake.digest(16);
```

## API Reference

### `Crypto.Shake128`

| Method | Description |
|--------|-------------|
| `initialize()` | Create a new SHAKE128 instance |
| `update(data as ByteArray)` | Absorb input data |
| `digest(outputLen as Number) as ByteArray` | Finalize and squeeze output |
| `reset()` | Reset state for reuse |
| `hash(data, outputLen)` | Static single-shot hash |
| `hashDebug(data, outputLen)` | Static hash with hex output |

## Supported Devices

This barrel supports all ConnectIQ devices with API level 3.0.0 or higher.

## Testing

Run tests using the ConnectIQ simulator:

```
monkeyc -o bin/shake128-test.prg -f monkey.jungle -t
connectiq
monkeydo bin/shake128-test.prg <device> -t
```

### Test Cases

| Test | Description |
|------|-------------|
| `testShake128Empty` | Empty input against NIST vector |
| `testShake128Abc` | "abc" input against NIST vector |
| `testShake128Streaming` | Streaming API matches single-shot |
| `testShake128Reset` | Reset produces consistent results |
| `testShake128VariableOutput` | Variable length outputs are prefixes |
| `testShake128LongInput` | Multi-block absorption (>168 bytes) |
| `testShake128LongOutput` | Multi-block squeeze (>168 bytes) |

## Implementation Notes

- Uses 32-bit emulation of 64-bit lanes (Monkey C `Number` is 32-bit signed)
- State represented as 50 Numbers: 25 lanes x 2 words (hi/lo)
- Implements all Keccak steps: Theta, Rho, Pi, Chi, Iota
- Domain separation suffix: 0x1F (SHAKE)

## License

MIT License

Copyright (c) 2025 Timothy Zander

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## References

- [FIPS 202: SHA-3 Standard](https://csrc.nist.gov/publications/detail/fips/202/final)
- [Keccak Reference](https://keccak.team/keccak.html)
