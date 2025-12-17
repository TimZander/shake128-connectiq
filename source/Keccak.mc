import Toybox.Lang;
import Toybox.System;

module Crypto {

// Keccak-f[1600] permutation implementation for SHAKE128
// Uses 32-bit emulation of 64-bit lanes (MonkeyC Number is 32-bit signed)
//
// State is 25 lanes of 64-bits each = 1600 bits total
// Represented as 50 Numbers: [lane0_hi, lane0_lo, lane1_hi, lane1_lo, ...]
//
// Reference: FIPS 202 (SHA-3 Standard)
class Keccak {

    // State: 25 lanes x 2 words (hi/lo) = 50 Numbers
    private var state as Array<Number>;

    // Pre-allocated temporary arrays for permute() to avoid repeated allocations
    // These are reused across all permute() calls
    private var C_hi as Array<Number>;  // Column parity (hi words) - 5 elements
    private var C_lo as Array<Number>;  // Column parity (lo words) - 5 elements
    private var D_hi as Array<Number>;  // D values (hi words) - 5 elements
    private var D_lo as Array<Number>;  // D values (lo words) - 5 elements
    private var B_hi as Array<Number>;  // After rho+pi (hi words) - 25 elements
    private var B_lo as Array<Number>;  // After rho+pi (lo words) - 25 elements

    // 24 round constants for iota step (flattened for faster access)
    // Separate hi/lo arrays avoid nested array lookup overhead
    private static const RC_HI as Array<Number> = [
        0x00000000, 0x00000000, 0x80000000, 0x80000000,
        0x00000000, 0x00000000, 0x80000000, 0x80000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x80000000, 0x80000000, 0x80000000,
        0x80000000, 0x80000000, 0x00000000, 0x80000000,
        0x80000000, 0x80000000, 0x00000000, 0x80000000
    ];
    private static const RC_LO as Array<Number> = [
        0x00000001, 0x00008082, 0x0000808A, 0x80008000,
        0x0000808B, 0x80000001, 0x80008081, 0x00008009,
        0x0000008A, 0x00000088, 0x80008009, 0x8000000A,
        0x8000808B, 0x0000008B, 0x00008089, 0x00008003,
        0x00008002, 0x00000080, 0x0000800A, 0x8000000A,
        0x80008081, 0x00008080, 0x80000001, 0x80008008
    ];

    // Rotation offsets for rho step (indexed by lane position 0-24)
    private static const ROTATIONS as Array<Number> = [
         0,  1, 62, 28, 27,
        36, 44,  6, 55, 20,
         3, 10, 43, 25, 39,
        41, 45, 15, 21,  8,
        18,  2, 61, 56, 14
    ];

    // Pi step: destination index for each source lane
    // new[PI_DEST[i]] = old[i] (after rho rotation)
    private static const PI_DEST as Array<Number> = [
         0, 10, 20,  5, 15,
        16,  1, 11, 21,  6,
         7, 17,  2, 12, 22,
        23,  8, 18,  3, 13,
        14, 24,  9, 19,  4
    ];


    public function initialize() {
        // Initialize state to all zeros (50 Numbers = 25 lanes x 2 words)
        state = new Array<Number>[50];
        for (var i = 0; i < 50; i++) {
            state[i] = 0;
        }

        // Pre-allocate temporary arrays for permute() - avoids allocation on every call
        C_hi = new Array<Number>[5];
        C_lo = new Array<Number>[5];
        D_hi = new Array<Number>[5];
        D_lo = new Array<Number>[5];
        B_hi = new Array<Number>[25];
        B_lo = new Array<Number>[25];
        for (var i = 0; i < 5; i++) {
            C_hi[i] = 0;
            C_lo[i] = 0;
            D_hi[i] = 0;
            D_lo[i] = 0;
        }
        for (var i = 0; i < 25; i++) {
            B_hi[i] = 0;
            B_lo[i] = 0;
        }
    }

    // Unsigned right shift (MonkeyC only has signed >>)
    // This clears the sign bit after shifting
    private function ushr(value as Number, shift as Number) as Number {
        if (shift == 0) {
            return value;
        }
        if (shift >= 32) {
            return 0;
        }
        // Shift right (signed) then mask off the sign-extended bits
        var result = value >> shift;
        // Create mask to clear upper bits that were sign-extended
        var mask = (1 << (32 - shift)) - 1;
        return result & mask;
    }

    // Reset state to all zeros
    public function reset() as Void {
        for (var i = 0; i < 50; i++) {
            state[i] = 0;
        }
    }

    // Get state array for direct manipulation (absorb/squeeze)
    public function getState() as Array<Number> {
        return state;
    }

    // Apply Keccak-f[1600] permutation (24 rounds)
    public function permute() as Void {
        // Use pre-allocated class member arrays (C_hi, C_lo, D_hi, D_lo, B_hi, B_lo)
        // No need to zero-initialize - values are fully overwritten each round

        // 24 rounds
        for (var round = 0; round < 24; round++) {
            // === Theta step ===
            // C[x] = A[x,0] ^ A[x,1] ^ A[x,2] ^ A[x,3] ^ A[x,4]
            for (var x = 0; x < 5; x++) {
                var hi = state[x * 2];
                var lo = state[x * 2 + 1];
                for (var y = 1; y < 5; y++) {
                    var idx = (x + y * 5) * 2;
                    hi = hi ^ state[idx];
                    lo = lo ^ state[idx + 1];
                }
                C_hi[x] = hi;
                C_lo[x] = lo;
            }

            // D[x] = C[x-1] ^ ROT(C[x+1], 1)
            for (var x = 0; x < 5; x++) {
                var x1 = (x + 4) % 5;  // x - 1 mod 5
                var x2 = (x + 1) % 5;  // x + 1 mod 5
                // Rotate C[x2] left by 1
                // Inline ushr(_, 31) as (x >> 31) & 1 to avoid function call overhead
                var rotHi = (C_hi[x2] << 1) | ((C_lo[x2] >> 31) & 1);
                var rotLo = (C_lo[x2] << 1) | ((C_hi[x2] >> 31) & 1);
                D_hi[x] = C_hi[x1] ^ rotHi;
                D_lo[x] = C_lo[x1] ^ rotLo;
            }

            // A[x,y] ^= D[x]
            for (var i = 0; i < 25; i++) {
                var x = i % 5;
                state[i * 2] = state[i * 2] ^ D_hi[x];
                state[i * 2 + 1] = state[i * 2 + 1] ^ D_lo[x];
            }

            // === Rho and Pi steps combined ===
            // B[y, 2*x + 3*y] = ROT(A[x,y], r[x,y])
            for (var i = 0; i < 25; i++) {
                var hi = state[i * 2];
                var lo = state[i * 2 + 1];
                var r = ROTATIONS[i];

                // Rotate left by r bits
                // Inline ushr() to avoid function call overhead (~40 calls/round)
                if (r == 0) {
                    // No rotation needed
                } else if (r == 32) {
                    // Swap hi and lo
                    var tmp = hi;
                    hi = lo;
                    lo = tmp;
                } else if (r < 32) {
                    // Inline ushr(x, 32-r): shift is in range 1-31, mask has r bits set
                    var shift = 32 - r;
                    var mask = (1 << r) - 1;
                    var newHi = (hi << r) | ((lo >> shift) & mask);
                    var newLo = (lo << r) | ((hi >> shift) & mask);
                    hi = newHi;
                    lo = newLo;
                } else {
                    // r > 32: use s = r - 32
                    var s = r - 32;
                    var shift = 32 - s;
                    var mask = (1 << s) - 1;
                    var newHi = (lo << s) | ((hi >> shift) & mask);
                    var newLo = (hi << s) | ((lo >> shift) & mask);
                    hi = newHi;
                    lo = newLo;
                }

                var dest = PI_DEST[i];
                B_hi[dest] = hi;
                B_lo[dest] = lo;
            }

            // === Chi step ===
            // A[x,y] = B[x,y] ^ ((~B[x+1,y]) & B[x+2,y])
            for (var y = 0; y < 5; y++) {
                for (var x = 0; x < 5; x++) {
                    var i = x + y * 5;
                    var i1 = ((x + 1) % 5) + y * 5;
                    var i2 = ((x + 2) % 5) + y * 5;
                    state[i * 2] = B_hi[i] ^ ((~B_hi[i1]) & B_hi[i2]);
                    state[i * 2 + 1] = B_lo[i] ^ ((~B_lo[i1]) & B_lo[i2]);
                }
            }

            // === Iota step ===
            // A[0,0] ^= RC[round]
            state[0] = state[0] ^ RC_HI[round];
            state[1] = state[1] ^ RC_LO[round];
        }
    }

    // XOR a single byte into state at given position (for padding - avoids array allocation)
    // byteValue: the byte value to XOR
    // stateOffset: byte position in state (0-199)
    public function xorByte(byteValue as Number, stateOffset as Number) as Void {
        var laneIdx = stateOffset >> 3;       // stateOffset / 8
        var byteInLane = stateOffset & 7;     // stateOffset % 8
        var stateIdx = laneIdx << 1;          // laneIdx * 2
        byteValue = byteValue & 0xFF;

        if (byteInLane < 4) {
            // Low word (bytes 0-3)
            var shift = byteInLane << 3;
            state[stateIdx + 1] = state[stateIdx + 1] ^ (byteValue << shift);
        } else {
            // High word (bytes 4-7)
            var shift = (byteInLane - 4) << 3;
            state[stateIdx] = state[stateIdx] ^ (byteValue << shift);
        }
    }

    // XOR data into state at byte offset (for absorb)
    // data: input bytes
    // offset: starting byte position in data
    // len: number of bytes to absorb
    // stateOffset: starting byte position in state
    public function xorBytes(data as ByteArray, offset as Number, len as Number, stateOffset as Number) as Void {
        for (var i = 0; i < len; i++) {
            var bytePos = stateOffset + i;
            // Use bit operations instead of division/modulo for performance
            var laneIdx = bytePos >> 3;       // bytePos / 8 - Which 64-bit lane
            var byteInLane = bytePos & 7;     // bytePos % 8 - Which byte within lane (0-7)

            // State layout: [lane0_hi, lane0_lo, lane1_hi, lane1_lo, ...]
            // Lane bytes: hi = bytes 4-7, lo = bytes 0-3 (little-endian within each word)
            var stateIdx = laneIdx << 1;      // laneIdx * 2
            var byteValue = data[offset + i] & 0xFF;

            if (byteInLane < 4) {
                // Low word (bytes 0-3)
                var shift = byteInLane << 3;  // byteInLane * 8
                state[stateIdx + 1] = state[stateIdx + 1] ^ (byteValue << shift);
            } else {
                // High word (bytes 4-7)
                var shift = (byteInLane - 4) << 3;  // (byteInLane - 4) * 8
                state[stateIdx] = state[stateIdx] ^ (byteValue << shift);
            }
        }
    }

    // Extract bytes from state (for squeeze)
    // output: destination byte array
    // offset: starting position in output
    // len: number of bytes to extract
    // stateOffset: starting byte position in state
    public function extractBytes(output as ByteArray, offset as Number, len as Number, stateOffset as Number) as Void {
        for (var i = 0; i < len; i++) {
            var bytePos = stateOffset + i;
            // Use bit operations instead of division/modulo for performance
            var laneIdx = bytePos >> 3;       // bytePos / 8
            var byteInLane = bytePos & 7;     // bytePos % 8

            var stateIdx = laneIdx << 1;      // laneIdx * 2
            var byteValue = 0;

            if (byteInLane < 4) {
                // Low word
                var shift = byteInLane << 3;  // byteInLane * 8
                byteValue = ushr(state[stateIdx + 1], shift) & 0xFF;
            } else {
                // High word
                var shift = (byteInLane - 4) << 3;  // (byteInLane - 4) * 8
                byteValue = ushr(state[stateIdx], shift) & 0xFF;
            }

            output[offset + i] = byteValue;
        }
    }

    // Debug: print state as hex
    public function debugPrintState() as Void {
        System.println("Keccak State:");
        for (var i = 0; i < 25; i++) {
            var hi = state[i * 2];
            var lo = state[i * 2 + 1];
            System.println("  Lane[" + i + "]: " + hi.format("%08X") + lo.format("%08X"));
        }
    }
}

}
