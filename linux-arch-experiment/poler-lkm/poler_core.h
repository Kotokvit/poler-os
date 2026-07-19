/* ============================================================================
 * POLER Core v8 — Параметрическая Нелинейная Диффузия (PND)
 * C port for Linux Kernel Module
 *
 * Ported from poler_core.zig (Zig 0.13.0 → C, kernel-safe)
 * All operations: stack-only, no heap, no FP, constant-time crypto
 * ============================================================================ */

#ifndef POLER_CORE_H
#define POLER_CORE_H

/* ============================================================================
 * COMPAT LAYER — works in both kernel and userspace
 * ============================================================================ */
#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/bitops.h>
#include <linux/string.h>
#else
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t  u8;
typedef uint64_t u64;

static inline unsigned int hweight32(unsigned int w)
{
    w -= (w >> 1) & 0x55555555;
    w = (w & 0x33333333) + ((w >> 2) & 0x33333333);
    w = (w + (w >> 4)) & 0x0F0F0F0F;
    return (w * 0x01010101) >> 24;
}
#endif

/* ============================================================================
 * CONSTANTS
 * ============================================================================ */

#define POLER_BLOCK_BITS      128
#define POLER_BLOCK_WORDS     4
#define POLER_WORD_BITS       32
#define POLER_KEY_BITS        256
#define POLER_KEY_WORDS       8
#define POLER_FEISTEL_ROUNDS  20
#define POLER_MAX_ITERATIONS  16
#define POLER_SBOX_SIZE       256

/* Golden ratio constant */
#define POLER_GOLDEN          0x9E3779B9U

/* ARX-box phi() constants */
#define PHI_C1                0x9E3779B9U  /* golden ratio */
#define PHI_C2                0x517CC1B7U  /* 7th Mersenne prime hash */
#define PHI_C2_INV            0x38D5EA1BU  /* modInverse(PHI_C2, 2^32) */

/* Default LHCA rule mask */
#define LHCA_DEFAULT_RULE     0xACACACACU
#define LHCA_PRNG_RULE        0xAAAAAAAAU

/* ============================================================================
 * INLINE HELPERS — wrapping arithmetic for u32
 * ============================================================================ */

static inline u32 rotl32(u32 v, unsigned int shift)
{
    const unsigned int s = shift % 32;
    return (v << s) | (v >> (32 - s));
}

static inline u32 rotr32(u32 v, unsigned int shift)
{
    const unsigned int s = shift % 32;
    return (v >> s) | (v << (32 - s));
}

static inline u8 rotl8(u8 v, unsigned int shift)
{
    const unsigned int s = shift % 8;
    return (v << s) | (v >> (8 - s));
}

/* Wrapping u32 multiplication */
static inline u32 wmul32(u32 a, u32 b)
{
    return a * b;
}

/* Wrapping u32 addition */
static inline u32 wadd32(u32 a, u32 b)
{
    return a + b;
}

/* Wrapping u32 subtraction */
static inline u32 wsub32(u32 a, u32 b)
{
    return a - b;
}

/* ============================================================================
 * MODULAR INVERSE mod 2^32 — HENSEL LIFTING
 * ============================================================================ */

static inline u32 poler_mod_inverse32(u32 a)
{
    if ((a & 1) == 0)
        return 0; /* no inverse for even */

    u32 x = 1;
    /* 5 iterations: 2→4→8→16→32 bits */
    for (int i = 0; i < 5; i++) {
        u32 ax = wmul32(a, x);
        u32 two_minus_ax = wsub32(wadd32(0, 2), ax);  /* 2 - a*x wrapping */
        x = wmul32(x, two_minus_ax);
    }
    return x;
}

/* ============================================================================
 * ARX-BOX PHI — bijective permutation
 *
 * phi(x) = rotl(mul(add(x, C1), C2), 7) + 1
 * Full: ADD(C1) → ROTL(13) → XORSHIFT(16) → MUL(C2) → ROTL(7) → ADD(1)
 * ============================================================================ */

static inline u32 poler_phi(u32 x)
{
    u32 y = wadd32(x, PHI_C1);     /* ADD — bijective */
    y = rotl32(y, 13);              /* ROTATE — bijective */
    y ^= (y >> 16);                 /* XOR-SHIFT — bijective */
    y = wmul32(y, PHI_C2);         /* MUL odd — bijective */
    y = rotl32(y, 7);               /* ROTATE — bijective */
    y = wadd32(y, 1);              /* ADD — bijective */
    return y;
}

/* ============================================================================
 * PND MIX v8 — φ-обёртка обоих компонент
 *
 * pndMix(a, b, ε) = φ(a·b) +% ε·φ(a⊕b)
 * Even at ε=0: result = φ(a·b) — nonlinear!
 * Auto-correction: ε=0 → ε=1 (No Excuses principle)
 * ============================================================================ */

static inline u32 poler_pnd_mix(u32 a, u32 b, u32 epsilon)
{
    u32 eps = (epsilon == 0) ? 1 : epsilon;  /* auto-correction */
    u32 base_product = wmul32(a, b);
    u32 xor_ab = a ^ b;
    u32 phi_product = poler_phi(base_product);  /* φ(a·b) */
    u32 phi_xor = poler_phi(xor_ab);            /* φ(a⊕b) */
    u32 epsilon_term = wmul32(eps, phi_xor);
    return wadd32(phi_product, epsilon_term);    /* v8: φ-wrap both terms */
}

/* ============================================================================
 * CONSTANT-TIME GF(2^8) OPERATIONS
 * ============================================================================ */

static inline u8 ct_gf256_mul(u8 a, u8 b)
{
    u8 p = 0;
    u8 aa = a;

    for (int i = 0; i < 8; i++) {
        /* Constant-time conditional: mask = 0xFF if bit set, 0x00 otherwise */
        u8 bit = (b >> i) & 1;
        u8 mask = (u8)(0 - bit);  /* 0xFF or 0x00 */
        p ^= mask & aa;

        /* Constant-time reduction */
        u8 hi = aa >> 7;
        aa <<= 1;
        u8 hi_mask = (u8)(0 - hi);
        aa ^= hi_mask & 0x1B;
    }
    return p;
}

static inline u8 ct_gf256_inverse(u8 x)
{
    /* x^254 via repeated squaring in GF(2^8) */
    u8 x2   = ct_gf256_mul(x, x);
    u8 x4   = ct_gf256_mul(x2, x2);
    u8 x8   = ct_gf256_mul(x4, x4);
    u8 x16  = ct_gf256_mul(x8, x8);
    u8 x32  = ct_gf256_mul(x16, x16);
    u8 x64  = ct_gf256_mul(x32, x32);
    u8 x128 = ct_gf256_mul(x64, x64);

    /* x^254 = x^128 * x^64 * x^32 * x^16 * x^8 * x^4 * x^2 */
    u8 inv = ct_gf256_mul(x128, x64);   /* x^192 */
    inv = ct_gf256_mul(inv, x32);        /* x^224 */
    inv = ct_gf256_mul(inv, x16);        /* x^240 */
    inv = ct_gf256_mul(inv, x8);         /* x^248 */
    inv = ct_gf256_mul(inv, x4);         /* x^252 */
    inv = ct_gf256_mul(inv, x2);         /* x^254 */

    return inv;
}

/* Constant-time AES S-box: S(x) = Affine(GF256_Inv(x)) */
static inline u8 poler_ct_sbox(u8 x)
{
    u8 inv = ct_gf256_inverse(x);
    /* AES affine transform */
    return inv ^ rotl8(inv, 1) ^ rotl8(inv, 2) ^
           rotl8(inv, 3) ^ rotl8(inv, 4) ^ 0x63;
}

/* Constant-time AES inverse S-box */
static inline u8 poler_ct_inv_sbox(u8 x)
{
    /* Inverse affine: t = rotl(x,1) ^ rotl(x,3) ^ rotl(x,6) ^ 0x05 */
    u8 t = rotl8(x, 1) ^ rotl8(x, 3) ^ rotl8(x, 6) ^ 0x05;
    return ct_gf256_inverse(t);
}

/* ============================================================================
 * DYNAMIC ATTRACTOR — derived from key
 * ============================================================================ */

static inline u32 poler_attractor(u32 key)
{
    return rotl32(key, 17) ^ poler_phi(key);
}

/* ============================================================================
 * NILPOTENT OPERATOR (Diffusion Operator) — v6 composition of bijections
 * ============================================================================ */

static inline u32 poler_nilpotent_operator(u32 y, u32 key, u32 epsilon)
{
    u32 mixed_key = rotl32(key, 5) ^ rotl32(key, 17) ^ key ^ POLER_GOLDEN;
    u32 safe_key = mixed_key | 1;  /* odd → multiplication bijective */

    u32 x = y;
    x ^= safe_key;                                     /* XOR — bijective */
    x = wmul32(x, safe_key);                          /* MUL odd — bijective */
    x = wadd32(x, wmul32(epsilon, rotl32(safe_key, 7)));  /* ADD — bijective */
    x = poler_phi(x);                                  /* ARX-box — bijective */
    x = wmul32(x, POLER_GOLDEN);                      /* MUL golden — bijective */
    x = wadd32(x, rotl32(safe_key ^ epsilon, 13));    /* ADD — bijective */
    return rotl32(x, 13);                              /* ROTL — bijective */
}

/* ============================================================================
 * POLER STEP / CYCLE
 * ============================================================================ */

static inline u32 poler_step(u32 x, u32 key, u32 epsilon)
{
    return poler_nilpotent_operator(x, key, epsilon);
}

struct poler_result {
    u32 final_state;
    u32 iterations;
    bool converged;
};

static inline struct poler_result poler_cycle(u32 initial_state, u32 key, u32 epsilon)
{
    u32 attr = poler_attractor(key);
    u32 x = initial_state;
    u32 iterations = 0;

    while (iterations < POLER_MAX_ITERATIONS) {
        u32 next = poler_step(x, key, epsilon);
        iterations++;
        /* Convergence: Hamming distance to attractor ≤ 4 */
        u32 hamming = hweight32(next ^ attr);
        if (hamming <= 4) {
            return (struct poler_result){ .final_state = next,
                                          .iterations = iterations,
                                          .converged = true };
        }
        if (next == x) {
            return (struct poler_result){ .final_state = next,
                                          .iterations = iterations,
                                          .converged = true };
        }
        x = next;
    }
    return (struct poler_result){ .final_state = x,
                                  .iterations = iterations,
                                  .converged = false };
}

/* ============================================================================
 * LHCA — Linear Hybrid Cellular Automaton
 * ============================================================================ */

struct lhca_config {
    u32 rule_mask;
};

static inline u32 poler_lhca_step(u32 state, struct lhca_config config)
{
    u32 result = 0;
    for (int i = 0; i < 32; i++) {
        u32 left   = (i == 0)  ? (state >> 31) & 1 : (state >> (i - 1)) & 1;
        u32 center = (state >> i) & 1;
        u32 right  = (i == 31) ? state & 1          : (state >> (i + 1)) & 1;
        u32 chi    = (config.rule_mask >> i) & 1;
        u32 bit    = left ^ (chi & center) ^ right;
        result |= (bit << i);
    }
    return result;
}

static inline u32 poler_lhca_diffuse(u32 state, struct lhca_config config, u32 rounds)
{
    u32 x = state;
    for (u32 r = 0; r < rounds; r++)
        x = poler_lhca_step(x, config);
    return x;
}

static inline void poler_lhca_diffuse_block(u32 block[POLER_BLOCK_WORDS],
                                             struct lhca_config config, u32 rounds)
{
    for (int i = 0; i < POLER_BLOCK_WORDS; i++)
        block[i] = poler_lhca_diffuse(block[i], config, rounds);

    /* Inter-word diffusion (cascading XOR — self-inverse) */
    block[0] ^= block[3];
    block[1] ^= block[0];
    block[2] ^= block[1];
    block[3] ^= block[2];
}

/* ============================================================================
 * MIXCOLUMNS — AES MDS matrix (branching = 5)
 * ============================================================================ */

static inline u32 poler_mix_columns(u32 word)
{
    u8 a[4];
    memcpy(a, &word, 4);

    u8 r0 = ct_gf256_mul(0x02, a[0]) ^ ct_gf256_mul(0x03, a[1]) ^ a[2] ^ a[3];
    u8 r1 = a[0] ^ ct_gf256_mul(0x02, a[1]) ^ ct_gf256_mul(0x03, a[2]) ^ a[3];
    u8 r2 = a[0] ^ a[1] ^ ct_gf256_mul(0x02, a[2]) ^ ct_gf256_mul(0x03, a[3]);
    u8 r3 = ct_gf256_mul(0x03, a[0]) ^ a[1] ^ a[2] ^ ct_gf256_mul(0x02, a[3]);

    u32 result;
    u8 r[4] = {r0, r1, r2, r3};
    memcpy(&result, r, 4);
    return result;
}

/* ============================================================================
 * POLER BLOCK CIPHER — Generalized Feistel Network (20 rounds)
 * ============================================================================ */

struct poler_cipher {
    u32 round_keys[22][POLER_BLOCK_WORDS]; /* 20 rounds + initial + final whitening */
    u32 round_epsilons[22];                 /* v8.1: round-dependent ε */
    u32 epsilon;                            /* base ε */
    struct lhca_config lhca_config;
    u32 rounds;                             /* = 20 */
};

/* Key schedule RCON */
static const u32 POLER_RCON[20] = {
    0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
    0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000,
    0x6C000000, 0xD8000000, 0xAB000000, 0x4D000000, 0x9A000000,
    0x2F000000, 0x5E000000, 0xBC000000, 0x63000000, 0xC6000000,
};

/* Derive round-dependent epsilon from round keys */
static inline u32 poler_derive_round_epsilon(
    const u32 round_keys[22][POLER_BLOCK_WORDS], unsigned int round_idx)
{
    u32 eps = poler_phi(round_keys[round_idx][0] ^ round_keys[round_idx][1])
            ^ round_keys[round_idx][2] ^ round_keys[round_idx][3];
    eps = wadd32(eps, wmul32((u32)(round_idx + 1), POLER_GOLDEN));
    if (eps == 0) eps = 1;  /* No Excuses */
    return eps;
}

/* Key schedule */
static inline void poler_key_schedule(
    const u32 key[POLER_KEY_WORDS], u32 epsilon,
    u32 round_keys[22][POLER_BLOCK_WORDS])
{
    struct lhca_config lcfg = { .rule_mask = LHCA_DEFAULT_RULE };

    round_keys[0][0] = key[0];
    round_keys[0][1] = key[1];
    round_keys[0][2] = key[2];
    round_keys[0][3] = key[3];

    for (int i = 1; i < 22; i++) {
        /* RotWord */
        u8 temp[4];
        memcpy(temp, &round_keys[i - 1][3], 4);
        u8 t0 = temp[0];
        temp[0] = temp[1]; temp[1] = temp[2];
        temp[2] = temp[3]; temp[3] = t0;

        /* SubWord */
        temp[0] = poler_ct_sbox(temp[0]);
        temp[1] = poler_ct_sbox(temp[1]);
        temp[2] = poler_ct_sbox(temp[2]);
        temp[3] = poler_ct_sbox(temp[3]);

        u32 sub_rot;
        memcpy(&sub_rot, temp, 4);

        unsigned int rcon_idx = (unsigned int)(i - 1);
        if (rcon_idx >= 20) rcon_idx = 19;
        u32 rcon_word = POLER_RCON[rcon_idx];

        round_keys[i][0] = poler_pnd_mix(round_keys[i - 1][0],
                                          sub_rot ^ rcon_word, epsilon);
        for (int j = 1; j < POLER_BLOCK_WORDS; j++) {
            round_keys[i][j] = poler_pnd_mix(round_keys[i - 1][j],
                                              round_keys[i][j - 1], epsilon);
        }
        poler_lhca_diffuse_block(round_keys[i], lcfg, 2);
    }
}

/* Initialize cipher */
static inline void poler_cipher_init(
    struct poler_cipher *cipher,
    const u32 key[POLER_KEY_WORDS], u32 epsilon)
{
    poler_key_schedule(key, epsilon, cipher->round_keys);

    /* Derive round-dependent epsilons */
    for (int i = 0; i < 22; i++)
        cipher->round_epsilons[i] = poler_derive_round_epsilon(cipher->round_keys, i);

    cipher->lhca_config.rule_mask = key[0] ^ key[1] ^ key[2] ^ key[3];
    cipher->epsilon = epsilon;
    cipher->rounds = POLER_FEISTEL_ROUNDS;
}

/* F-function for Feistel round — v8: ctSbox → pndMix → mixColumns → lhcaStep */
static inline u32 poler_feistel_f(u32 r_word, u32 round_key, u32 epsilon)
{
    /* v8: S-box BEFORE PND — non-linearize inputs before multiplication */
    u8 bytes[4];
    u32 subbed;
    memcpy(bytes, &r_word, 4);
    bytes[0] = poler_ct_sbox(bytes[0]);
    bytes[1] = poler_ct_sbox(bytes[1]);
    bytes[2] = poler_ct_sbox(bytes[2]);
    bytes[3] = poler_ct_sbox(bytes[3]);
    memcpy(&subbed, bytes, 4);

    /* PND with φ-wrap */
    u32 mixed = poler_pnd_mix(subbed, round_key, epsilon);

    /* MDS diffusion */
    u32 mds = poler_mix_columns(mixed);

    /* LHCA step */
    struct lhca_config lcfg = { .rule_mask = LHCA_DEFAULT_RULE };
    return poler_lhca_step(mds, lcfg);
}

/* F-function on half-block (2 words = 64 bits) with inter-word phi-coupling */
static inline void poler_feistel_f_half(
    u32 r[2], u32 round_keys[2], u32 epsilon, u32 out[2])
{
    out[0] = poler_feistel_f(r[0], round_keys[0], epsilon);
    out[1] = poler_feistel_f(r[1], round_keys[1], epsilon);

    /* v7: Nonlinear phi-coupling between words */
    u32 cross0 = poler_phi(out[0] ^ out[1]);
    u32 cross1 = poler_phi(out[1] ^ wadd32(out[0], POLER_GOLDEN));
    out[0] = wadd32(out[0], rotl32(cross0, 5));
    out[1] = wadd32(out[1], rotl32(cross1, 7));
}

/* Encrypt one 128-bit block */
static inline void poler_encrypt_block(
    const struct poler_cipher *cipher,
    const u32 plaintext[POLER_BLOCK_WORDS],
    u32 ciphertext[POLER_BLOCK_WORDS])
{
    u32 L[2] = { plaintext[0], plaintext[1] };
    u32 R[2] = { plaintext[2], plaintext[3] };

    /* Initial whitening */
    L[0] ^= cipher->round_keys[0][0];
    L[1] ^= cipher->round_keys[0][1];
    R[0] ^= cipher->round_keys[0][2];
    R[1] ^= cipher->round_keys[0][3];

    /* Feistel rounds */
    for (u32 round = 0; round < cipher->rounds; round++) {
        u32 rk_idx = round + 1;
        u32 rk[2] = { cipher->round_keys[rk_idx][0],
                       cipher->round_keys[rk_idx][1] };
        u32 eps = cipher->round_epsilons[rk_idx];

        u32 f_out[2];
        poler_feistel_f_half(R, rk, eps, f_out);

        u32 new_L[2] = { R[0], R[1] };
        u32 new_R[2] = { L[0] ^ f_out[0], L[1] ^ f_out[1] };

        L[0] = new_L[0]; L[1] = new_L[1];
        R[0] = new_R[0]; R[1] = new_R[1];
    }

    /* Final whitening */
    L[0] ^= cipher->round_keys[cipher->rounds + 1][0];
    L[1] ^= cipher->round_keys[cipher->rounds + 1][1];
    R[0] ^= cipher->round_keys[cipher->rounds + 1][2];
    R[1] ^= cipher->round_keys[cipher->rounds + 1][3];

    ciphertext[0] = L[0];
    ciphertext[1] = L[1];
    ciphertext[2] = R[0];
    ciphertext[3] = R[1];
}

/* Decrypt one 128-bit block */
static inline void poler_decrypt_block(
    const struct poler_cipher *cipher,
    const u32 ciphertext[POLER_BLOCK_WORDS],
    u32 plaintext[POLER_BLOCK_WORDS])
{
    u32 L[2] = { ciphertext[0], ciphertext[1] };
    u32 R[2] = { ciphertext[2], ciphertext[3] };

    /* Reverse final whitening */
    L[0] ^= cipher->round_keys[cipher->rounds + 1][0];
    L[1] ^= cipher->round_keys[cipher->rounds + 1][1];
    R[0] ^= cipher->round_keys[cipher->rounds + 1][2];
    R[1] ^= cipher->round_keys[cipher->rounds + 1][3];

    /* Reverse Feistel rounds */
    for (u32 round = cipher->rounds; round > 0; round--) {
        u32 rk_idx = round;  /* was round + 1 in encrypt, now round since we swapped */
        u32 rk[2] = { cipher->round_keys[rk_idx][0],
                       cipher->round_keys[rk_idx][1] };
        u32 eps = cipher->round_epsilons[rk_idx];

        u32 f_out[2];
        poler_feistel_f_half(L, rk, eps, f_out);

        u32 new_R[2] = { L[0], L[1] };
        u32 new_L[2] = { R[0] ^ f_out[0], R[1] ^ f_out[1] };

        L[0] = new_L[0]; L[1] = new_L[1];
        R[0] = new_R[0]; R[1] = new_R[1];
    }

    /* Reverse initial whitening */
    L[0] ^= cipher->round_keys[0][0];
    L[1] ^= cipher->round_keys[0][1];
    R[0] ^= cipher->round_keys[0][2];
    R[1] ^= cipher->round_keys[0][3];

    plaintext[0] = L[0];
    plaintext[1] = L[1];
    plaintext[2] = R[0];
    plaintext[3] = R[1];
}

/* Verify roundtrip: encrypt → decrypt → compare */
static inline bool poler_verify_roundtrip(const struct poler_cipher *cipher)
{
    u32 original[4] = { 0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210 };
    u32 encrypted[4], decrypted[4];

    poler_encrypt_block(cipher, original, encrypted);
    poler_decrypt_block(cipher, encrypted, decrypted);

    return decrypted[0] == original[0] && decrypted[1] == original[1] &&
           decrypted[2] == original[2] && decrypted[3] == original[3];
}

/* ============================================================================
 * POLER PRNG
 * ============================================================================ */

struct poler_prng {
    u32 state;
    u32 epsilon;
    u32 key;
};

static inline void poler_prng_init(struct poler_prng *prng,
                                    u32 seed, u32 epsilon, u32 key)
{
    prng->state = (seed == 0) ? 0xDEADBEEFU : seed;
    prng->epsilon = epsilon;
    prng->key = key;
}

static inline u32 poler_prng_next(struct poler_prng *prng)
{
    u32 pnd_result = poler_pnd_mix(prng->state, prng->key, prng->epsilon);
    u32 permuted = poler_phi(pnd_result);
    struct lhca_config lcfg = { .rule_mask = LHCA_PRNG_RULE };
    prng->state = poler_lhca_step(permuted, lcfg);
    return prng->state;
}

static inline u32 poler_prng_next_range(struct poler_prng *prng, u32 max)
{
    return poler_prng_next(prng) % max;
}

static inline void poler_prng_fill_bytes(struct poler_prng *prng,
                                          u8 *buf, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (i % 4 == 0) {
            u32 val = poler_prng_next(prng);
            buf[i] = (u8)(val & 0xFF);
            if (i + 1 < len) buf[i + 1] = (u8)((val >> 8) & 0xFF);
            if (i + 2 < len) buf[i + 2] = (u8)((val >> 16) & 0xFF);
            if (i + 3 < len) buf[i + 3] = (u8)((val >> 24) & 0xFF);
        }
    }
}

#endif /* POLER_CORE_H */
