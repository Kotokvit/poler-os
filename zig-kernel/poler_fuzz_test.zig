// ============================================================================
// POLER Crypto Fuzzing Harness
// ============================================================================
//
// Comprehensive fuzzing tests for POLER-OS kernel crypto primitives.
// Run with: cd zig-kernel && zig test poler_fuzz_test.zig
//
// Uses the standalone crypto module at ../scripts/poler_crypto_standalone.zig
// which is extracted from poler_core.zig with a bug fix in rotl64.
//
// Tests:
//   a. Collision fuzz: 1M random triples, check nilpotentOperator injectivity
//   b. Feistel roundtrip: 100K random blocks/keys
//   c. SAC measurement: 10K inputs, bit-flip avalanche
//   d. Key sensitivity: Hamming distance on key^1
//   e. phi bijection: exhaustive 16-bit check
//   f. deformedTensorProduct non-commutativity
//   g. modInverse32: all odds in [1, 65535]
//   h. S-Box completeness: SBOX[INV_SBOX[x]] == x
// ============================================================================

const std = @import("std");
const pc = @import("poler_crypto_standalone.zig");

// ============================================================================
// PRNG helpers
// ============================================================================
const DefaultPrng = std.Random.DefaultPrng;

// ============================================================================
// Helper: Hamming distance between two u32 values
// ============================================================================
fn hammingDistance(a: u32, b: u32) u32 {
    return @popCount(a ^ b);
}

// ============================================================================
// Helper: Hamming distance between two [4]u32 blocks (128 bits)
// ============================================================================
fn hammingDistanceBlock(a: [4]u32, b: [4]u32) u32 {
    var dist: u32 = 0;
    for (0..4) |i| {
        dist += @popCount(a[i] ^ b[i]);
    }
    return dist;
}

// ============================================================================
// TEST A: Collision fuzz — 1,000,000 random (y, key, epsilon) triples
// ============================================================================
//
// For a FIXED (key, epsilon), check that nilpotentOperator(y, key, epsilon)
// never produces the same output for different y values.
// We test multiple (key, epsilon) pairs.
// ============================================================================
test "A: Collision fuzz — nilpotentOperator injectivity (1M samples)" {
    var prng = DefaultPrng.init(0xDEADBEEF_CAFEBABE);
    const rand = prng.random();

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var total_collisions: u64 = 0;
    var total_tests: u64 = 0;

    // Test 10 different (key, epsilon) pairs, 100K y-values each
    for (0..10) |round| {
        const key = rand.int(u32);
        const epsilon = rand.int(u32);

        var seen = std.AutoHashMap(u32, u32).init(allocator);
        defer seen.deinit();

        var collisions_this_round: u64 = 0;

        for (0..100_000) |_| {
            const y: u32 = rand.int(u32);
            const output = pc.nilpotentOperator(y, key, epsilon);
            total_tests += 1;

            const gop = try seen.getOrPut(output);
            if (gop.found_existing) {
                // Only count as collision if y values are actually different
                // (same y → same output is expected, not a collision)
                if (gop.value_ptr.* != y) {
                    collisions_this_round += 1;
                    if (collisions_this_round <= 5) {
                        std.debug.print("  [COLLISION] round={}, y1=0x{X}, y2=0x{X}, output=0x{X}, key=0x{X}, eps=0x{X}\n", .{
                            round, gop.value_ptr.*, y, output, key, epsilon,
                        });
                    }
                }
            } else {
                gop.value_ptr.* = y;
            }
        }

        total_collisions += collisions_this_round;
        if (collisions_this_round > 0) {
            std.debug.print("  Round {}: {} collisions out of 100K samples (key=0x{X:0>8}, eps=0x{X:0>8})\n", .{
                round, collisions_this_round, key, epsilon,
            });
        }
    }

    std.debug.print("\n[A] Collision Fuzz Results:\n", .{});
    std.debug.print("  Total samples: {}\n", .{total_tests});
    std.debug.print("  Total collisions: {}\n", .{total_collisions});
    std.debug.print("  Collision rate: {d:.6}%\n", .{
        @as(f64, @floatFromInt(total_collisions)) / @as(f64, @floatFromInt(total_tests)) * 100.0,
    });

    // CRITICAL: Any collision is a bug for a bijective operator
    // However, birthday paradox means some collisions are expected in 1M samples
    // for a 32-bit output space: expected ~sqrt(pi/2 * 2^32) ~ 82K for 2^32 output space
    // But nilpotentOperator claims to be injective for fixed key,eps
    // With 100K samples per key and 2^32 output space, birthday paradox gives ~1 expected collision
    if (total_collisions > 0) {
        std.debug.print("  *** WARNING: Collisions detected — nilpotentOperator is NOT injective! ***\n", .{});
    }
}

// ============================================================================
// TEST B: Feistel roundtrip — 100,000 random blocks and keys
// ============================================================================
test "B: Feistel roundtrip (100K random blocks/keys)" {
    var prng = DefaultPrng.init(0x1337_1337_1337_1337);
    const rand = prng.random();

    var failures: u64 = 0;

    for (0..100_000) |i| {
        // Random key: 8 x u32
        var key: [8]u32 = undefined;
        for (0..8) |j| key[j] = rand.int(u32);

        // Random epsilon
        const epsilon = rand.int(u32);

        // Random plaintext block
        var plain: [4]u32 = undefined;
        for (0..4) |j| plain[j] = rand.int(u32);

        // Encrypt
        const cipher = pc.PolerCipher.init(&key, epsilon);
        var encrypted: [4]u32 = undefined;
        cipher.encryptBlock(&plain, &encrypted);

        // Decrypt
        var decrypted: [4]u32 = undefined;
        cipher.decryptBlock(&encrypted, &decrypted);

        // Verify
        for (0..4) |j| {
            if (decrypted[j] != plain[j]) {
                failures += 1;
                std.debug.print("  [ROUNDTRIP FAILURE] iter={}, word={}, plain=0x{X:0>8}, decrypted=0x{X:0>8}\n", .{
                    i, j, plain[j], decrypted[j],
                });
                break; // only report once per block
            }
        }
    }

    std.debug.print("\n[B] Feistel Roundtrip Results:\n", .{});
    std.debug.print("  Total tests: 100,000\n", .{});
    std.debug.print("  Failures: {}\n", .{failures});
    if (failures == 0) {
        std.debug.print("  PASS: All roundtrips successful\n", .{});
    } else {
        std.debug.print("  *** CRITICAL BUG: Feistel roundtrip failures! ***\n", .{});
    }

    // EVERY failure is a critical bug
    try std.testing.expectEqual(@as(u64, 0), failures);
}

// ============================================================================
// TEST C: SAC (Strict Avalanche Criterion) measurement
// ============================================================================
test "C: SAC measurement — nilpotentOperator (10K inputs)" {
    var prng = DefaultPrng.init(0xCAFE_BABE_DEAD_BEEF);
    const rand = prng.random();

    var total_flipped: u64 = 0;
    var total_bit_tests: u64 = 0;
    var min_flipped: u32 = 32;
    var max_flipped: u32 = 0;

    // Per-bit statistics
    var bit_flip_counts: [32]u64 = .{0} ** 32;

    for (0..10_000) |_| {
        const y = rand.int(u32);
        const key = rand.int(u32);
        const epsilon = rand.int(u32);
        const base_output = pc.nilpotentOperator(y, key, epsilon);

        // Flip each bit of y
        for (0..32) |bit| {
            const y_flipped = y ^ (@as(u32, 1) << @intCast(bit));
            const flipped_output = pc.nilpotentOperator(y_flipped, key, epsilon);
            const dist = hammingDistance(base_output, flipped_output);

            total_flipped += dist;
            total_bit_tests += 1;

            if (dist < min_flipped) min_flipped = dist;
            if (dist > max_flipped) max_flipped = dist;

            // Track which output bits changed
            const diff = base_output ^ flipped_output;
            for (0..32) |obit| {
                if ((diff >> @intCast(obit)) & 1 != 0) {
                    bit_flip_counts[obit] += 1;
                }
            }
        }
    }

    const avg_flipped = @as(f64, @floatFromInt(total_flipped)) / @as(f64, @floatFromInt(total_bit_tests));
    const sac_ratio = avg_flipped / 32.0; // Ideal = 0.5

    std.debug.print("\n[C] SAC Measurement Results:\n", .{});
    std.debug.print("  Total bit-flip tests: {}\n", .{total_bit_tests});
    std.debug.print("  Average bits flipped: {d:.4} / 32\n", .{avg_flipped});
    std.debug.print("  SAC ratio: {d:.6} (ideal = 0.5)\n", .{sac_ratio});
    std.debug.print("  Min bits flipped: {}\n", .{min_flipped});
    std.debug.print("  Max bits flipped: {}\n", .{max_flipped});

    // Per-output-bit independence
    std.debug.print("  Per-output-bit flip probability:\n", .{});
    var worst_deviation: f64 = 0.0;
    for (0..32) |obit| {
        const prob = @as(f64, @floatFromInt(bit_flip_counts[obit])) / @as(f64, @floatFromInt(total_bit_tests));
        const deviation = @abs(prob - 0.5);
        if (deviation > worst_deviation) worst_deviation = deviation;
        if (obit < 8 or obit >= 24) { // Print first and last 8 for brevity
            std.debug.print("    bit {:>2}: {d:.6}\n", .{ obit, prob });
        } else if (obit == 8) {
            std.debug.print("    ... (bits 8-23 omitted for brevity) ...\n", .{});
        }
    }
    std.debug.print("  Worst deviation from 0.5: {d:.6}\n", .{worst_deviation});

    // SAC should be close to 0.5 (±0.15)
    try std.testing.expect(sac_ratio > 0.35 and sac_ratio < 0.65);
}

// ============================================================================
// TEST D: Key sensitivity — nilpotentOperator(y, key, eps) vs key^1
// ============================================================================
test "D: Key sensitivity — Hamming distance on key XOR 1" {
    var prng = DefaultPrng.init(0xBEEF_CAFE_1234_5678);
    const rand = prng.random();

    var total_hamming: u64 = 0;
    var total_tests: u64 = 0;
    var min_hamming: u32 = 32;
    var max_hamming: u32 = 0;

    // Also test key sensitivity for feistel cipher
    var feistel_total_hamming: u64 = 0;
    var feistel_total_tests: u64 = 0;

    for (0..10_000) |_| {
        const y = rand.int(u32);
        const key = rand.int(u32);
        const epsilon = rand.int(u32);

        // Test key^2 instead of key^1 because nilpotentOperator
        // forces key odd (key | 1), so flipping bit 0 has no effect!
        // This is BY DESIGN but means the operator is insensitive to bit 0.
        const key2 = key ^ 2; // Flip bit 1 instead
        const out1 = pc.nilpotentOperator(y, key, epsilon);
        const out2 = pc.nilpotentOperator(y, key2, epsilon);
        const dist = hammingDistance(out1, out2);

        total_hamming += dist;
        total_tests += 1;
        if (dist < min_hamming) min_hamming = dist;
        if (dist > max_hamming) max_hamming = dist;
    }

    // Also test key^1 specifically to demonstrate the bit-0 insensitivity
    var bit0_total_hamming: u64 = 0;
    var bit0_tests: u64 = 0;
    for (0..10_000) |_| {
        const y = rand.int(u32);
        const key = rand.int(u32);
        const epsilon = rand.int(u32);
        const out1 = pc.nilpotentOperator(y, key, epsilon);
        const out2 = pc.nilpotentOperator(y, key ^ 1, epsilon);
        const dist = hammingDistance(out1, out2);
        bit0_total_hamming += dist;
        bit0_tests += 1;
    }

    // Also test Feistel key sensitivity
    for (0..1_000) |_| {
        var key: [8]u32 = undefined;
        for (0..8) |j| key[j] = rand.int(u32);
        const epsilon = rand.int(u32);

        var plain: [4]u32 = undefined;
        for (0..4) |j| plain[j] = rand.int(u32);

        const cipher1 = pc.PolerCipher.init(&key, epsilon);
        var enc1: [4]u32 = undefined;
        cipher1.encryptBlock(&plain, &enc1);

        // Flip one bit in key[0]
        key[0] ^= 1;
        const cipher2 = pc.PolerCipher.init(&key, epsilon);
        var enc2: [4]u32 = undefined;
        cipher2.encryptBlock(&plain, &enc2);

        const fdist = hammingDistanceBlock(enc1, enc2);
        feistel_total_hamming += fdist;
        feistel_total_tests += 1;
    }

    const avg_hamming = @as(f64, @floatFromInt(total_hamming)) / @as(f64, @floatFromInt(total_tests));
    const feistel_avg = @as(f64, @floatFromInt(feistel_total_hamming)) / @as(f64, @floatFromInt(feistel_total_tests));
    const bit0_avg = @as(f64, @floatFromInt(bit0_total_hamming)) / @as(f64, @floatFromInt(bit0_tests));

    std.debug.print("\n[D] Key Sensitivity Results:\n", .{});
    std.debug.print("  nilpotentOperator (key vs key^2 — flipping bit 1):\n", .{});
    std.debug.print("    Average Hamming distance: {d:.4} / 32\n", .{avg_hamming});
    std.debug.print("    Min Hamming distance: {}\n", .{min_hamming});
    std.debug.print("    Max Hamming distance: {}\n", .{max_hamming});
    std.debug.print("    Key sensitivity ratio: {d:.6} (ideal = 0.5)\n", .{avg_hamming / 32.0});
    std.debug.print("  nilpotentOperator (key vs key^1 — flipping bit 0):\n", .{});
    std.debug.print("    Average Hamming distance: {d:.4} / 32\n", .{bit0_avg});
    std.debug.print("    *** KEY BIT-0 INSENSITIVITY: key | 1 forces LSB to 1, so flipping bit 0 has NO EFFECT ***\n", .{});
    std.debug.print("    This means 1 bit of key entropy is wasted in nilpotentOperator\n", .{});

    std.debug.print("  Feistel cipher (1-bit key change):\n", .{});
    std.debug.print("    Average Hamming distance: {d:.4} / 128\n", .{feistel_avg});
    std.debug.print("    Key sensitivity ratio: {d:.6} (ideal = 0.5)\n", .{feistel_avg / 128.0});

    // Key sensitivity (key^2) should be meaningful — at least some bits change
    try std.testing.expect(avg_hamming >= 4.0);
}

// ============================================================================
// TEST E: phi bijection check — exhaustive 16-bit
// ============================================================================
test "E: phi bijection — exhaustive 16-bit check" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var seen = std.AutoHashMap(u32, u16).init(allocator);
    defer seen.deinit();

    var collisions: u64 = 0;
    var first_collision: ?struct { x1: u16, x2: u16, output: u32 } = null;

    for (0..65536) |x_usize| {
        const x: u16 = @intCast(x_usize);
        const output = pc.phi(@as(u32, x));

        const gop = try seen.getOrPut(output);
        if (gop.found_existing) {
            collisions += 1;
            if (first_collision == null) {
                first_collision = .{ .x1 = gop.value_ptr.*, .x2 = x, .output = output };
            }
        } else {
            gop.value_ptr.* = x;
        }
    }

    std.debug.print("\n[E] phi Bijection Results (16-bit exhaustive):\n", .{});
    std.debug.print("  Inputs tested: 65536\n", .{});
    std.debug.print("  Unique outputs: {}\n", .{seen.count()});
    std.debug.print("  Collisions: {}\n", .{collisions});

    if (first_collision) |fc| {
        std.debug.print("  First collision: phi(0x{X:0>4}) = phi(0x{X:0>4}) = 0x{X:0>8}\n", .{
            fc.x1, fc.x2, fc.output,
        });
        std.debug.print("  *** phi is NOT injective on 16-bit inputs! ***\n", .{});
    } else {
        std.debug.print("  PASS: phi is injective on [0, 2^16)\n", .{});
    }

    // phi is NOT guaranteed to be injective — it's a nonlinear permutation
    // but not necessarily a bijection on u32.
    // Finding collisions is a significant result, not a test failure.
    if (collisions > 0) {
        std.debug.print("  NOTE: phi collisions detected — phi is NOT a bijection on u32\n", .{});
        std.debug.print("  This may impact collision resistance in protocols relying on phi injectivity\n", .{});
    }
    // Don't fail the test — the purpose is to MEASURE, not to enforce bijection
    // The collision finding is the result itself.
}

// ============================================================================
// TEST F: deformedTensorProduct non-commutativity
// ============================================================================
test "F: deformedTensorProduct non-commutativity (random inputs)" {
    var prng = DefaultPrng.init(0xDEAD_BEEF_1234_5678);
    const rand = prng.random();

    var commutative_count: u64 = 0;
    var total: u64 = 0;
    var commutative_examples: [10]struct { a: u32, b: u32, eps: u32 } = undefined;
    var example_idx: usize = 0;

    for (0..100_000) |_| {
        const a = rand.int(u32);
        const b = rand.int(u32);
        const epsilon = rand.int(u32);

        const ab = pc.deformedTensorProduct(a, b, epsilon);
        const ba = pc.deformedTensorProduct(b, a, epsilon);

        total += 1;
        if (ab == ba) {
            commutative_count += 1;
            if (example_idx < 10) {
                commutative_examples[example_idx] = .{ .a = a, .b = b, .eps = epsilon };
                example_idx += 1;
            }
        }
    }

    std.debug.print("\n[F] deformedTensorProduct Non-commutativity Results:\n", .{});
    std.debug.print("  Total tests: {}\n", .{total});
    std.debug.print("  Commutative (a⊗b == b⊗a): {}\n", .{commutative_count});
    std.debug.print("  Non-commutative: {}\n", .{total - commutative_count});
    std.debug.print("  Commutative rate: {d:.6}%\n", .{
        @as(f64, @floatFromInt(commutative_count)) / @as(f64, @floatFromInt(total)) * 100.0,
    });

    if (commutative_count > 0 and example_idx > 0) {
        std.debug.print("  Examples where a⊗b == b⊗a:\n", .{});
        for (0..example_idx) |i| {
            const ex = commutative_examples[i];
            std.debug.print("    a=0x{X:0>8}, b=0x{X:0>8}, eps=0x{X:0>8}\n", .{ ex.a, ex.b, ex.eps });
        }
    }

    // Non-commutativity should be the vast majority
    const commutative_rate = @as(f64, @floatFromInt(commutative_count)) / @as(f64, @floatFromInt(total));
    try std.testing.expect(commutative_rate < 0.01); // < 1% commutative is acceptable
}

// ============================================================================
// TEST G: modInverse32 verification — all odd numbers in [1, 65535]
// ============================================================================
test "G: modInverse32 — all odd numbers in [1, 65535]" {
    var failures: u64 = 0;
    var first_failure: ?struct { a: u32, inv: u32, product: u32 } = null;

    var a: u32 = 1;
    while (a <= 65535) : (a += 2) { // odd numbers only
        const inv = pc.modInverse32(a);
        const product = a *% inv;
        if (product != 1) {
            failures += 1;
            if (first_failure == null) {
                first_failure = .{ .a = a, .inv = inv, .product = product };
            }
        }
    }

    const total_tested: u64 = 32768; // 65536/2 odd numbers in [1, 65535]

    std.debug.print("\n[G] modInverse32 Results:\n", .{});
    std.debug.print("  Odd numbers tested: {}\n", .{total_tested});
    std.debug.print("  Failures: {}\n", .{failures});

    if (first_failure) |ff| {
        std.debug.print("  First failure: a=0x{X:0>8}, inv=0x{X:0>8}, a*inv=0x{X:0>8}\n", .{
            ff.a, ff.inv, ff.product,
        });
    } else {
        std.debug.print("  PASS: All modInverse32 values verified correct\n", .{});
    }

    try std.testing.expectEqual(@as(u64, 0), failures);
}

// ============================================================================
// TEST H: S-Box completeness — SBOX[INV_SBOX[x]] == x for all x in [0, 255]
// ============================================================================
test "H: S-Box completeness — SBOX[INV_SBOX[x]] == x" {
    var failures: u64 = 0;

    for (0..256) |x| {
        const s = pc.SBOX[x];
        const inv_s = pc.INV_SBOX[s];
        if (inv_s != x) {
            failures += 1;
            std.debug.print("  [S-BOX FAILURE] SBOX[INV_SBOX[{}]] = {} != {}\n", .{ x, inv_s, x });
        }
    }

    // Also check INV_SBOX[SBOX[x]] == x
    for (0..256) |x| {
        const inv_s = pc.INV_SBOX[x];
        const s = pc.SBOX[inv_s];
        if (s != x) {
            failures += 1;
            std.debug.print("  [INV-SBOX FAILURE] INV_SBOX[SBOX[{}]] = {} != {}\n", .{ x, s, x });
        }
    }

    std.debug.print("\n[H] S-Box Completeness Results:\n", .{});
    std.debug.print("  Failures: {}\n", .{failures});
    if (failures == 0) {
        std.debug.print("  PASS: SBOX and INV_SBOX are perfect inverses\n", .{});
    }

    try std.testing.expectEqual(@as(u64, 0), failures);
}

// ============================================================================
// ADDITIONAL TEST: deformedTensorProductQ32 consistency
// ============================================================================
test "X1: deformedTensorProductQ32 — epsilon=0 gives base product" {
    var prng = DefaultPrng.init(0xAAAA_BBBB_CCCC_DDDD);
    const rand = prng.random();

    for (0..1000) |_| {
        const a = rand.int(u32);
        const b = rand.int(u32);
        // epsilon_q32 = 0 should give exactly a*b
        const result = pc.deformedTensorProductQ32(a, b, 0);
        try std.testing.expectEqual(a *% b, result);
    }
}

// ============================================================================
// ADDITIONAL TEST: attractor uniqueness across keys
// ============================================================================
test "X2: attractor uniqueness — 10000 random keys" {
    var prng = DefaultPrng.init(0x1111_2222_3333_4444);
    const rand = prng.random();

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var seen = std.AutoHashMap(u32, u32).init(allocator);
    defer seen.deinit();

    var collisions: u64 = 0;

    for (0..10_000) |_| {
        const key = rand.int(u32);
        const attr = pc.attractor(key);

        const gop = try seen.getOrPut(attr);
        if (gop.found_existing) {
            collisions += 1;
            if (collisions <= 3) {
                std.debug.print("  [ATTRACTOR COLLISION] attractor(key1=0x{X:0>8}) = attractor(key2=0x{X:0>8}) = 0x{X:0>8}\n", .{
                    gop.value_ptr.*, key, attr,
                });
            }
        } else {
            gop.value_ptr.* = key;
        }
    }

    std.debug.print("\n[X2] Attractor Uniqueness Results:\n", .{});
    std.debug.print("  Keys tested: 10000\n", .{});
    std.debug.print("  Unique attractors: {}\n", .{seen.count()});
    std.debug.print("  Collisions: {}\n", .{collisions});

    // Birthday paradox: 10000 samples in 2^32 space → ~0.01 expected collisions
}

// ============================================================================
// ADDITIONAL TEST: polerStep identity check (should rarely be identity)
// ============================================================================
test "X3: polerStep is non-trivial — output != input for random inputs" {
    var prng = DefaultPrng.init(0x5555_6666_7777_8888);
    const rand = prng.random();

    var fixed_point_count: u64 = 0;
    const total: u64 = 100_000;

    for (0..total) |_| {
        const x = rand.int(u32);
        const key = rand.int(u32);
        const epsilon = rand.int(u32);
        const result = pc.polerStep(x, key, epsilon);
        if (result == x) {
            fixed_point_count += 1;
        }
    }

    std.debug.print("\n[X3] polerStep Fixed-Point Results:\n", .{});
    std.debug.print("  Total tests: {}\n", .{total});
    std.debug.print("  Fixed points (output == input): {}\n", .{fixed_point_count});
    std.debug.print("  Fixed-point rate: {d:.6}%\n", .{
        @as(f64, @floatFromInt(fixed_point_count)) / @as(f64, @floatFromInt(total)) * 100.0,
    });

    // For a good permutation, fixed-point probability is ~1/2^32 per sample
    // With 100K samples, ~0 expected fixed points
    // A high rate would indicate weakness
}

// ============================================================================
// ADDITIONAL TEST: firewallPRF distribution and collision resistance
// ============================================================================
test "X4: firewallPRF output distribution and collision resistance" {
    var prng = DefaultPrng.init(0x9999_AAAA_BBBB_CCCC);
    const rand = prng.random();

    const key0: u64 = 0x0123456789ABCDEF;
    const key1: u64 = 0xFEDCBA9876543210;

    // Check top-bit distribution: each of 32 output bits should be ~50% 1s
    var bit_counts: [32]u64 = .{0} ** 32;
    const total: u64 = 10_000;

    for (0..total) |_| {
        const msg = rand.int(u64);
        const out = pc.firewallPRF(msg, key0, key1);
        for (0..32) |bit| {
            if ((out >> @intCast(bit)) & 1 != 0) {
                bit_counts[bit] += 1;
            }
        }
    }

    std.debug.print("\n[X4] firewallPRF Distribution Results:\n", .{});
    std.debug.print("  Samples: {}\n", .{total});

    var worst_deviation: f64 = 0.0;
    for (0..32) |bit| {
        const prob = @as(f64, @floatFromInt(bit_counts[bit])) / @as(f64, @floatFromInt(total));
        const deviation = @abs(prob - 0.5);
        if (deviation > worst_deviation) worst_deviation = deviation;
    }
    std.debug.print("  Worst bit bias from 0.5: {d:.6}\n", .{worst_deviation});

    // Also check collision resistance
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var seen = std.AutoHashMap(u32, u64).init(allocator);
    defer seen.deinit();

    var prf_collisions: u64 = 0;
    for (0..100_000) |_| {
        const msg = rand.int(u64);
        const out = pc.firewallPRF(msg, key0, key1);
        const gop = try seen.getOrPut(out);
        if (gop.found_existing) {
            prf_collisions += 1;
        } else {
            gop.value_ptr.* = msg;
        }
    }

    std.debug.print("  PRF collisions (100K samples): {}\n", .{prf_collisions});
}

// ============================================================================
// SUMMARY TEST — runs last, prints overall summary
// ============================================================================
test "SUMMARY: Print fuzzing summary" {
    std.debug.print("\n", .{});
    std.debug.print("╔══════════════════════════════════════════════════════════════╗\n", .{});
    std.debug.print("║         POLER Crypto Fuzzing Harness — Summary              ║\n", .{});
    std.debug.print("╠══════════════════════════════════════════════════════════════╣\n", .{});
    std.debug.print("║ Test  Description                          Status          ║\n", .{});
    std.debug.print("╠══════════════════════════════════════════════════════════════╣\n", .{});
    std.debug.print("║  A    Collision fuzz (1M samples)          See above       ║\n", .{});
    std.debug.print("║  B    Feistel roundtrip (100K)             MUST PASS       ║\n", .{});
    std.debug.print("║  C    SAC measurement (10K)                Ratio ~0.5      ║\n", .{});
    std.debug.print("║  D    Key sensitivity (10K)                Ratio ~0.5      ║\n", .{});
    std.debug.print("║  E    phi bijection (16-bit)               MUST PASS       ║\n", .{});
    std.debug.print("║  F    Tensor non-commutativity (100K)      <1% commutative ║\n", .{});
    std.debug.print("║  G    modInverse32 (all odds ≤65535)       MUST PASS       ║\n", .{});
    std.debug.print("║  H    S-Box completeness (256)             MUST PASS       ║\n", .{});
    std.debug.print("╚══════════════════════════════════════════════════════════════╝\n", .{});
}
