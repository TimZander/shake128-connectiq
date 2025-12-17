import Toybox.Lang;
import Toybox.Test;

module Crypto {

(:test)
function testShake128Empty(logger as Test.Logger) as Boolean {
    // SHAKE128("") with 32 bytes output
    // Known test vector from NIST
    var data = []b;
    var result = Shake128.hash(data, 32);

    var expected = [
        0x7f, 0x9c, 0x2b, 0xa4, 0xe8, 0x8f, 0x82, 0x7d,
        0x61, 0x60, 0x45, 0x50, 0x76, 0x05, 0x85, 0x3e,
        0xd7, 0x3b, 0x80, 0x93, 0xf6, 0xef, 0xbc, 0x88,
        0xeb, 0x1a, 0x6e, 0xac, 0xfa, 0x66, 0xef, 0x26
    ]b;

    return assertBytesEqual(logger, expected, result, "Empty input");
}

(:test)
function testShake128Abc(logger as Test.Logger) as Boolean {
    // SHAKE128("abc") with 32 bytes output
    var data = [0x61, 0x62, 0x63]b;  // "abc"
    var result = Shake128.hash(data, 32);

    var expected = [
        0x58, 0x81, 0x09, 0x2d, 0xd8, 0x18, 0xbf, 0x5c,
        0xf8, 0xa3, 0xdd, 0xb7, 0x93, 0xfb, 0xcb, 0xa7,
        0x40, 0x97, 0xd5, 0xc5, 0x26, 0xa6, 0xd3, 0x5f,
        0x97, 0xb8, 0x33, 0x51, 0x94, 0x0f, 0x2c, 0xc8
    ]b;

    return assertBytesEqual(logger, expected, result, "abc input");
}

(:test)
function testShake128Streaming(logger as Test.Logger) as Boolean {
    // Test streaming API matches single-shot
    var data = [0x61, 0x62, 0x63, 0x64, 0x65, 0x66]b;  // "abcdef"

    // Single-shot
    var expected = Shake128.hash(data, 16);

    // Streaming in chunks
    var shake = new Shake128();
    shake.update([0x61, 0x62, 0x63]b);  // "abc"
    shake.update([0x64, 0x65, 0x66]b);  // "def"
    var result = shake.digest(16);

    return assertBytesEqual(logger, expected, result, "Streaming API");
}

(:test)
function testShake128Reset(logger as Test.Logger) as Boolean {
    // Test reset functionality
    var shake = new Shake128();

    shake.update([0x61, 0x62, 0x63]b);
    var hash1 = shake.digest(16);

    shake.reset();
    shake.update([0x61, 0x62, 0x63]b);
    var hash2 = shake.digest(16);

    return assertBytesEqual(logger, hash1, hash2, "Reset produces same hash");
}

(:test)
function testShake128VariableOutput(logger as Test.Logger) as Boolean {
    // Test that different output lengths work
    var data = [0x74, 0x65, 0x73, 0x74]b;  // "test"

    var out8 = Shake128.hash(data, 8);
    var out16 = Shake128.hash(data, 16);
    var out32 = Shake128.hash(data, 32);

    // Verify lengths
    if (out8.size() != 8 || out16.size() != 16 || out32.size() != 32) {
        logger.debug("Output length mismatch");
        return false;
    }

    // Verify that longer outputs are extensions of shorter ones
    for (var i = 0; i < 8; i++) {
        if (out8[i] != out16[i] || out8[i] != out32[i]) {
            logger.debug("Output prefix mismatch at byte " + i);
            return false;
        }
    }

    for (var i = 0; i < 16; i++) {
        if (out16[i] != out32[i]) {
            logger.debug("Output prefix mismatch at byte " + i);
            return false;
        }
    }

    logger.debug("Variable output lengths OK");
    return true;
}

(:test)
function testShake128LongInput(logger as Test.Logger) as Boolean {
    // Test input longer than rate (168 bytes) to verify multi-block absorption
    var data = new [200]b;
    for (var i = 0; i < 200; i++) {
        data[i] = (i & 0xFF);
    }

    var result = Shake128.hash(data, 32);

    // Just verify it produces output without error
    if (result.size() != 32) {
        logger.debug("Long input failed");
        return false;
    }

    logger.debug("Long input (200 bytes) OK");
    return true;
}

(:test)
function testShake128LongOutput(logger as Test.Logger) as Boolean {
    // Test output longer than rate (168 bytes) to verify multi-block squeeze
    var data = [0x78]b;  // "x"
    var result = Shake128.hash(data, 256);

    if (result.size() != 256) {
        logger.debug("Long output failed");
        return false;
    }

    logger.debug("Long output (256 bytes) OK");
    return true;
}

// Helper function to compare byte arrays
function assertBytesEqual(logger as Test.Logger, expected as ByteArray, actual as ByteArray, message as String) as Boolean {
    if (expected.size() != actual.size()) {
        logger.debug(message + ": size mismatch - expected " + expected.size() + ", got " + actual.size());
        return false;
    }

    for (var i = 0; i < expected.size(); i++) {
        if (expected[i] != actual[i]) {
            logger.debug(message + ": mismatch at byte " + i +
                        " - expected " + expected[i].format("%02x") +
                        ", got " + actual[i].format("%02x"));
            return false;
        }
    }

    logger.debug(message + ": OK");
    return true;
}

}
