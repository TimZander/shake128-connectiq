import Toybox.Lang;
import Toybox.System;

module Crypto {

// SHAKE128 Extendable-Output Function (XOF)
// Based on Keccak-f[1600] with rate=1344 bits (168 bytes), capacity=256 bits
//
// SHAKE128 is part of the SHA-3 family (FIPS 202)
// Domain separation: suffix 0x1F for SHAKE
//
// Usage:
//   var hash = Crypto.Shake128.hash(data, 16);  // Get 16-byte hash
//
// Or for streaming:
//   var shake = new Crypto.Shake128();
//   shake.update(data1);
//   shake.update(data2);
//   var hash = shake.digest(16);
class Shake128 {

    // Rate in bytes (1344 bits / 8)
    private static const RATE = 168;

    // SHAKE domain separation suffix: 0x1F
    // After padding: 0x1F ... 0x80
    private static const SUFFIX = 0x1F;

    private var keccak as Keccak;
    private var absorbed as Number;     // Bytes absorbed in current block
    private var finalized as Boolean;   // Has digest() been called?

    public function initialize() {
        keccak = new Keccak();
        absorbed = 0;
        finalized = false;
    }

    // Reset for reuse
    public function reset() as Void {
        keccak.reset();
        absorbed = 0;
        finalized = false;
    }

    // Update with more data (absorb phase)
    public function update(data as ByteArray) as Void {
        if (finalized) {
            System.println("Shake128: Cannot update after finalize");
            return;
        }

        var dataLen = data.size();
        var dataOffset = 0;

        while (dataOffset < dataLen) {
            var spaceInBlock = RATE - absorbed;
            var toAbsorb = dataLen - dataOffset;
            if (toAbsorb > spaceInBlock) {
                toAbsorb = spaceInBlock;
            }

            // XOR data into state
            keccak.xorBytes(data, dataOffset, toAbsorb, absorbed);
            absorbed += toAbsorb;
            dataOffset += toAbsorb;

            // If block is full, permute
            if (absorbed == RATE) {
                keccak.permute();
                absorbed = 0;
            }
        }
    }

    // Finalize and get output (squeeze phase)
    // outputLen: number of output bytes to produce
    public function digest(outputLen as Number) as ByteArray {
        if (!finalized) {
            // Apply padding: SUFFIX || 10*1
            // Use xorByte() directly to avoid allocating a temporary array
            keccak.xorByte(SUFFIX, absorbed);

            // XOR 0x80 at last byte of rate (position RATE-1)
            keccak.xorByte(0x80, RATE - 1);

            // Final permutation
            keccak.permute();
            finalized = true;
        }

        // Squeeze output
        var output = new [outputLen]b;
        var outputOffset = 0;
        var squeezed = 0;  // Bytes squeezed from current block

        while (outputOffset < outputLen) {
            var available = RATE - squeezed;
            var toSqueeze = outputLen - outputOffset;
            if (toSqueeze > available) {
                toSqueeze = available;
            }

            keccak.extractBytes(output, outputOffset, toSqueeze, squeezed);
            outputOffset += toSqueeze;
            squeezed += toSqueeze;

            // If we need more output and exhausted current block, permute
            if (outputOffset < outputLen && squeezed == RATE) {
                keccak.permute();
                squeezed = 0;
            }
        }

        return output;
    }

    // Convenience: single-shot hash
    // data: input bytes
    // outputLen: desired output length in bytes
    public static function hash(data as ByteArray, outputLen as Number) as ByteArray {
        var shake = new Shake128();
        shake.update(data);
        return shake.digest(outputLen);
    }

    // Debug helper: hash and print hex result
    public static function hashDebug(data as ByteArray, outputLen as Number) as ByteArray {
        var result = hash(data, outputLen);
        var hex = "";
        for (var i = 0; i < result.size(); i++) {
            hex += result[i].format("%02x");
        }
        System.println("SHAKE128(" + data.size() + " bytes) = " + hex);
        return result;
    }
}

}
