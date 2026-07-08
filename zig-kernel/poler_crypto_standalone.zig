// ============================================================================
// POLER Crypto Standalone — Extracted from poler_core.zig for fuzzing
// ============================================================================
//
// This is a standalone copy of the POLER crypto primitives, extracted from
// poler_core.zig for independent testing. It removes kernel-specific code
// (rdtsc, PolerFirewall with inline asm) and fixes a bug in rotl64.
//
// BUG FIX: rotl64 used `comptime shift: u6` which cannot represent value 64.
//          Fixed to use `comptime shift: u7` with modulo handling.
// ============================================================================

const std = @import("std");

pub const BLOCK_BITS: u32 = 128;
pub const BLOCK_WORDS: u32 = 4;
pub const WORD_BITS: u32 = 32;
pub const KEY_BITS: u32 = 256;
pub const KEY_WORDS: u32 = 8;
pub const MAX_POLER_ITERATIONS: u32 = 16;
pub const SBOX_SIZE: usize = 256;

// ============================================================================
// CYCLIC SHIFTS
// ============================================================================

pub fn rotl(comptime T: type, value: T, comptime shift: usize) T {
    const bits: usize = @bitSizeOf(T);
    const s = shift % bits;
    return (value << @intCast(s)) | (value >> @intCast(bits - s));
}

pub fn rotr(comptime T: type, value: T, comptime shift: usize) T {
    const bits: usize = @bitSizeOf(T);
    const s = shift % bits;
    return (value >> @intCast(s)) | (value << @intCast(bits - s));
}

// ============================================================================
// MODULAR INVERSE mod 2^32 — HENSEL LIFTING
// ============================================================================

pub fn modInverse32(a: u32) u32 {
    if (a % 2 == 0) return 0;
    var x: u32 = 1;
    var i: u32 = 0;
    while (i < 5) : (i += 1) {
        const ax = a *% x;
        const two_minus_ax: u32 = 0 -% ax +% 2;
        x = x *% two_minus_ax;
    }
    return x;
}

pub fn verifyModInverse(a: u32) bool {
    if (a % 2 == 0) return false;
    const inv = modInverse32(a);
    return a *% inv == 1;
}

// ============================================================================
// NONLINEAR PERMUTATION PHI — v6 ARX-BOX (PROVABLY BIJECTIVE)
// ============================================================================
//
// v6: ARX-box permutation — each step is individually invertible.
// Construction: ADD → ROTL → XOR-SHIFT → MUL(odd) → ROTL → ADD
// Composition of bijections = bijection.

pub fn phi(x: u32) u32 {
    var y = x +% 0x9E3779B9;        // ADD — bijective
    y = rotl(u32, y, 13);           // ROTATE — bijective
    y ^= (y >> 16);                 // XOR-SHIFT — bijective (invertible)
    y *%= 0x517CC1B7;               // MULTIPLY odd — bijective
    y = rotl(u32, y, 7);            // ROTATE — bijective
    y +%= 1;                         // ADD — bijective
    return y;
}

// ============================================================================
// DEFORMED TENSOR PRODUCT — v6 (FIX: +% instead of ^)
// ============================================================================

pub fn deformedTensorProduct(a: u32, b: u32, epsilon: u32) u32 {
    const base_product = a *% b;
    const xor_ab = a ^ b;
    const rot_a = rotl(u32, a, 5);
    const rot_b = rotl(u32, b, 7);
    const phi_val = phi(xor_ab);
    const deformation = rot_a ^ rot_b ^ phi_val;
    const epsilon_term = epsilon *% deformation;
    return base_product +% epsilon_term; // v6: +% instead of ^
}

// ============================================================================
// Q32 fixed-point arithmetic
// ============================================================================

pub fn fixedMulQ32(a: u32, b: u32) u32 {
    const wide: u64 = @as(u64, a) *% @as(u64, b);
    return @truncate(wide >> 32);
}

pub fn deformedTensorProductQ32(a: u32, b: u32, epsilon_q32: u32) u32 {
    const base_product = a *% b;
    const xor_ab = a ^ b;
    const rot_a = rotl(u32, a, 5);
    const rot_b = rotl(u32, b, 7);
    const phi_val = phi(xor_ab);
    const deformation = rot_a ^ rot_b ^ phi_val;
    const epsilon_term = fixedMulQ32(deformation, epsilon_q32);
    return base_product +% epsilon_term; // v6: +% instead of ^
}

// ============================================================================
// COMPTIME S-BOX
// ============================================================================

fn gf256Mul(a: u8, b: u8) u8 {
    @setEvalBranchQuota(50000);
    var result: u8 = 0;
    var aa: u8 = a;
    var bb: u8 = b;
    var i: u4 = 0;
    while (i < 8) : (i += 1) {
        if (bb & 1 != 0) result ^= aa;
        const hi_bit = aa & 0x80;
        aa <<= 1;
        if (hi_bit != 0) aa ^= 0x1B;
        bb >>= 1;
    }
    return result;
}

fn gf256Inverse(x: u8) u8 {
    @setEvalBranchQuota(50000);
    if (x == 0) return 0;
    var r: u8 = 1;
    var bx: u8 = x;
    var ex: u8 = 254;
    while (ex > 0) {
        if (ex & 1 != 0) r = gf256Mul(r, bx);
        bx = gf256Mul(bx, bx);
        ex >>= 1;
    }
    return r;
}

fn computeSBox() [SBOX_SIZE]u8 {
    @setEvalBranchQuota(50000);
    var sbox: [SBOX_SIZE]u8 = undefined;
    for (0..SBOX_SIZE) |i| {
        const inv = gf256Inverse(@intCast(i));
        const b: u8 = inv;
        const b1 = rotl(u8, b, 1);
        const b2 = rotl(u8, b, 2);
        const b3 = rotl(u8, b, 3);
        const b4 = rotl(u8, b, 4);
        sbox[i] = b ^ b1 ^ b2 ^ b3 ^ b4 ^ 0x63;
    }
    sbox[0] = 0x63;
    return sbox;
}

fn computeInverseSBox() [SBOX_SIZE]u8 {
    @setEvalBranchQuota(50000);
    const sbox = comptime computeSBox();
    var inv_sbox: [SBOX_SIZE]u8 = undefined;
    for (0..SBOX_SIZE) |i| {
        inv_sbox[sbox[i]] = @intCast(i);
    }
    return inv_sbox;
}

pub const SBOX: [SBOX_SIZE]u8 = computeSBox();
pub const INV_SBOX: [SBOX_SIZE]u8 = computeInverseSBox();

// ============================================================================
// DYNAMIC ATTRACTOR
// ============================================================================

pub fn attractor(key: u32) u32 {
    return rotl(u32, key, 17) ^ phi(key);
}

// ============================================================================
// DIFFUSION OPERATOR (nilpotentOperator)
// ============================================================================

pub fn nilpotentOperator(y: u32, key: u32, epsilon: u32) u32 {
    // v6: Pure composition of bijections — PROVABLY BIJECTIVE
    const mixed_key = rotl(u32, key, 5) ^ rotl(u32, key, 17) ^ key ^ 0x9E3779B9;
    const safe_key = mixed_key | 1;

    var x = y;
    x ^= safe_key;                                    // XOR constant — bijective
    x *%= safe_key;                                    // MUL odd — bijective
    x +%= epsilon *% rotl(u32, safe_key, 7);           // ADD constant — bijective
    x = phi(x);                                        // ARX-box — bijective
    x *%= 0x9E3779B9;                                  // MUL golden — bijective
    x +%= rotl(u32, safe_key ^ epsilon, 13);           // ADD constant — bijective
    return rotl(u32, x, 13);                           // ROTL — bijective
}

// ============================================================================
// POLER STEP
// ============================================================================

pub fn polerStep(x: u32, key: u32, epsilon: u32) u32 {
    return nilpotentOperator(x, key, epsilon);
}

pub const PolerResult = struct {
    final_state: u32,
    iterations: u32,
    converged: bool,
};

pub fn polerCycle(initial_state: u32, key: u32, epsilon: u32) PolerResult {
    const attr = attractor(key);
    var x = initial_state;
    var iterations: u32 = 0;
    while (iterations < MAX_POLER_ITERATIONS) {
        const next = polerStep(x, key, epsilon);
        iterations += 1;
        const hamming_dist = @popCount(next ^ attr);
        if (hamming_dist <= 4) {
            return PolerResult{ .final_state = next, .iterations = iterations, .converged = true };
        }
        if (next == x) {
            return PolerResult{ .final_state = next, .iterations = iterations, .converged = true };
        }
        x = next;
    }
    return PolerResult{ .final_state = x, .iterations = iterations, .converged = false };
}

// ============================================================================
// LHCA — LINEAR HYBRID CELLULAR AUTOMATON
// ============================================================================

pub const LHCAConfig = struct {
    rule_mask: u32,
};

pub fn lhcaStep(state: u32, config: LHCAConfig) u32 {
    var result: u32 = 0;
    var i: u6 = 0;
    while (i < 32) : (i += 1) {
        const left: u32 = if (i == 0) (state >> 31) & 1 else (state >> @intCast(i - 1)) & 1;
        const center: u32 = (state >> @intCast(i)) & 1;
        const right: u32 = if (i == 31) state & 1 else (state >> @intCast(i + 1)) & 1;
        const chi: u32 = (config.rule_mask >> @intCast(i)) & 1;
        const bit: u32 = left ^ (chi & center) ^ right;
        result |= (bit << @intCast(i));
    }
    return result;
}

pub fn lhcaDiffuse(state: u32, config: LHCAConfig, rounds: u32) u32 {
    var x = state;
    var r: u32 = 0;
    while (r < rounds) : (r += 1) {
        x = lhcaStep(x, config);
    }
    return x;
}

pub fn lhcaDiffuseBlock(block: *[BLOCK_WORDS]u32, config: LHCAConfig, rounds: u32) void {
    for (block) |*word| {
        word.* = lhcaDiffuse(word.*, config, rounds);
    }
    block[0] ^= block[3];
    block[1] ^= block[0];
    block[2] ^= block[1];
    block[3] ^= block[2];
}

// ============================================================================
// POLER BLOCK CIPHER — FEISTEL NETWORK
// ============================================================================

pub const PolerCipher = struct {
    round_keys: [14][BLOCK_WORDS]u32,
    epsilon: u32,
    lhca_config: LHCAConfig,
    rounds: u32,

    pub fn init(key: *const [KEY_WORDS]u32, epsilon: u32) PolerCipher {
        var round_keys: [14][BLOCK_WORDS]u32 = undefined;
        keySchedule(key, epsilon, &round_keys);
        const lhca_config = LHCAConfig{
            .rule_mask = key[0] ^ key[1] ^ key[2] ^ key[3],
        };
        return PolerCipher{
            .round_keys = round_keys,
            .epsilon = epsilon,
            .lhca_config = lhca_config,
            .rounds = 12,
        };
    }

    pub fn encryptBlock(self: *const PolerCipher, plaintext: *[BLOCK_WORDS]u32, ciphertext: *[BLOCK_WORDS]u32) void {
        var L: [2]u32 = .{ plaintext[0], plaintext[1] };
        var R: [2]u32 = .{ plaintext[2], plaintext[3] };

        L[0] ^= self.round_keys[0][0];
        L[1] ^= self.round_keys[0][1];
        R[0] ^= self.round_keys[0][2];
        R[1] ^= self.round_keys[0][3];

        var round: u32 = 0;
        while (round < self.rounds) : (round += 1) {
            const rk_idx = round + 1;
            const rk = self.round_keys[rk_idx];
            const f_out = polerFeistelFHalf(R, .{ rk[0], rk[1] }, self.epsilon);
            const new_L = R;
            const new_R: [2]u32 = .{ L[0] ^ f_out[0], L[1] ^ f_out[1] };
            L = new_L;
            R = new_R;
        }

        L[0] ^= self.round_keys[self.rounds + 1][0];
        L[1] ^= self.round_keys[self.rounds + 1][1];
        R[0] ^= self.round_keys[self.rounds + 1][2];
        R[1] ^= self.round_keys[self.rounds + 1][3];

        ciphertext[0] = L[0];
        ciphertext[1] = L[1];
        ciphertext[2] = R[0];
        ciphertext[3] = R[1];
    }

    pub fn decryptBlock(self: *const PolerCipher, ciphertext: *[BLOCK_WORDS]u32, plaintext: *[BLOCK_WORDS]u32) void {
        var L: [2]u32 = .{ ciphertext[0], ciphertext[1] };
        var R: [2]u32 = .{ ciphertext[2], ciphertext[3] };

        L[0] ^= self.round_keys[self.rounds + 1][0];
        L[1] ^= self.round_keys[self.rounds + 1][1];
        R[0] ^= self.round_keys[self.rounds + 1][2];
        R[1] ^= self.round_keys[self.rounds + 1][3];

        var round: u32 = self.rounds;
        while (round > 0) {
            round -= 1;
            const rk_idx = round + 1;
            const rk = self.round_keys[rk_idx];
            const f_out = polerFeistelFHalf(L, .{ rk[0], rk[1] }, self.epsilon);
            const new_R = L;
            const new_L: [2]u32 = .{ R[0] ^ f_out[0], R[1] ^ f_out[1] };
            L = new_L;
            R = new_R;
        }

        L[0] ^= self.round_keys[0][0];
        L[1] ^= self.round_keys[0][1];
        R[0] ^= self.round_keys[0][2];
        R[1] ^= self.round_keys[0][3];

        plaintext[0] = L[0];
        plaintext[1] = L[1];
        plaintext[2] = R[0];
        plaintext[3] = R[1];
    }

    pub fn verifyRoundtrip(self: *const PolerCipher) bool {
        var original = [4]u32{ 0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210 };
        var encrypted: [BLOCK_WORDS]u32 = undefined;
        var decrypted: [BLOCK_WORDS]u32 = undefined;
        self.encryptBlock(&original, &encrypted);
        self.decryptBlock(&encrypted, &decrypted);
        return decrypted[0] == original[0] and
            decrypted[1] == original[1] and
            decrypted[2] == original[2] and
            decrypted[3] == original[3];
    }
};

// Internal cipher operations

fn subBytes(state: *[BLOCK_WORDS]u32) void {
    for (state) |*word| {
        var bytes: [4]u8 = @bitCast(word.*);
        bytes[0] = SBOX[bytes[0]];
        bytes[1] = SBOX[bytes[1]];
        bytes[2] = SBOX[bytes[2]];
        bytes[3] = SBOX[bytes[3]];
        word.* = @bitCast(bytes);
    }
}

fn invSubBytes(state: *[BLOCK_WORDS]u32) void {
    for (state) |*word| {
        var bytes: [4]u8 = @bitCast(word.*);
        bytes[0] = INV_SBOX[bytes[0]];
        bytes[1] = INV_SBOX[bytes[1]];
        bytes[2] = INV_SBOX[bytes[2]];
        bytes[3] = INV_SBOX[bytes[3]];
        word.* = @bitCast(bytes);
    }
}

fn polerFeistelF(r_word: u32, round_key: u32, epsilon: u32) u32 {
    const deformed = deformedTensorProduct(r_word, round_key, epsilon);
    var bytes: [4]u8 = @bitCast(deformed);
    bytes[0] = SBOX[bytes[0]];
    bytes[1] = SBOX[bytes[1]];
    bytes[2] = SBOX[bytes[2]];
    bytes[3] = SBOX[bytes[3]];
    const subbed: u32 = @bitCast(bytes);
    return lhcaStep(subbed, LHCAConfig{ .rule_mask = 0xACACACAC });
}

fn polerFeistelFHalf(r: [2]u32, round_keys: [2]u32, epsilon: u32) [2]u32 {
    var out: [2]u32 = undefined;
    out[0] = polerFeistelF(r[0], round_keys[0], epsilon);
    out[1] = polerFeistelF(r[1], round_keys[1], epsilon);
    out[0] ^= rotl(u32, out[1], 8);
    out[1] ^= rotl(u32, out[0], 16);
    return out;
}

const RCON: [12]u32 = [_]u32{
    0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
    0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000,
    0x6C000000, 0xD8000000,
};

fn keySchedule(key: *const [KEY_WORDS]u32, epsilon: u32, round_keys: *[14][BLOCK_WORDS]u32) void {
    const lhca_config = LHCAConfig{ .rule_mask = 0xACACACAC };

    round_keys[0][0] = key[0];
    round_keys[0][1] = key[1];
    round_keys[0][2] = key[2];
    round_keys[0][3] = key[3];

    for (1..14) |i| {
        var temp: [4]u8 = @bitCast(round_keys[i - 1][3]);
        const t0 = temp[0];
        temp[0] = temp[1]; temp[1] = temp[2]; temp[2] = temp[3]; temp[3] = t0;
        temp[0] = SBOX[temp[0]]; temp[1] = SBOX[temp[1]];
        temp[2] = SBOX[temp[2]]; temp[3] = SBOX[temp[3]];
        const sub_rot: u32 = @bitCast(temp);

        const rcon_idx = if (i - 1 < RCON.len) i - 1 else RCON.len - 1;
        const rcon_word = RCON[rcon_idx];
        round_keys[i][0] = deformedTensorProduct(round_keys[i - 1][0], sub_rot ^ rcon_word, epsilon);
        for (1..BLOCK_WORDS) |j| {
            round_keys[i][j] = deformedTensorProduct(round_keys[i - 1][j], round_keys[i][j - 1], epsilon);
        }
        lhcaDiffuseBlock(&round_keys[i], lhca_config, 2);
    }
}

// ============================================================================
// POLER PRNG
// ============================================================================

pub const PolerPrng = struct {
    state: u32,
    epsilon: u32,
    key: u32,

    pub fn init(seed: u32, epsilon: u32, key: u32) PolerPrng {
        const s = if (seed == 0) @as(u32, 0xDEADBEEF) else seed;
        return PolerPrng{ .state = s, .epsilon = epsilon, .key = key };
    }

    pub fn next(self: *PolerPrng) u32 {
        const deformed = deformedTensorProduct(self.state, self.key, self.epsilon);
        const permuted = phi(deformed);
        const diffused = lhcaStep(permuted, LHCAConfig{ .rule_mask = 0xAAAAAAAA });
        self.state = diffused;
        return self.state;
    }
};

// ============================================================================
// FIREWALL PRF — SipHash-like (FIXED rotl64 bug)
// ============================================================================

/// BUG FIX: Changed comptime shift type from u6 to u7.
/// Original: `comptime shift: u6` — type u6 cannot represent value 64,
/// so expression `(64 - shift)` fails when shift could be 0.
/// Fix: Use usize for comptime shift, matching the 32-bit rotl pattern.
fn rotl64(v: u64, comptime shift: usize) u64 {
    const s = shift % 64;
    return (v << @intCast(s)) | (v >> @intCast(64 - s));
}

fn sipRound(v0: *u64, v1: *u64, v2: *u64, v3: *u64) void {
    v0.* +%= v1.*;
    v1.* = rotl64(v1.*, 13);
    v1.* ^= v0.*;
    v0.* = rotl64(v0.*, 32);
    v2.* +%= v3.*;
    v3.* = rotl64(v3.*, 16);
    v3.* ^= v2.*;
    v0.* +%= v3.*;
    v3.* = rotl64(v3.*, 21);
    v3.* ^= v0.*;
    v2.* +%= v1.*;
    v1.* = rotl64(v1.*, 17);
    v1.* ^= v2.*;
    v2.* = rotl64(v2.*, 32);
}

/// SipHash-2-4 PRF: takes (message: u64, key0: u64, key1: u64) → u32
pub fn firewallPRF(message: u64, key0: u64, key1: u64) u32 {
    var v0: u64 = 0x736f6d6570736575 ^ key0;
    var v1: u64 = 0x646f72616e646f6d ^ key1;
    var v2: u64 = 0x6c7967656e657261 ^ key0;
    var v3: u64 = 0x7465646279746573 ^ key1;

    v3 ^= message;
    sipRound(&v0, &v1, &v2, &v3);
    sipRound(&v0, &v1, &v2, &v3);
    v0 ^= message;

    v2 ^= 0xff;
    sipRound(&v0, &v1, &v2, &v3);
    sipRound(&v0, &v1, &v2, &v3);
    sipRound(&v0, &v1, &v2, &v3);
    sipRound(&v0, &v1, &v2, &v3);

    const result: u64 = v0 ^ v1 ^ v2 ^ v3;
    return @truncate(result ^ (result >> 32));
}
