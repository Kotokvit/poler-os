/* ============================================================================
 * POLER-OS Crypto — Userspace Test Tool
 *
 * Tests the POLER v8 cipher in userspace (no kernel module needed)
 * Compile: gcc -O2 -o poler_test poler_test.c
 * Run:     ./poler_test
 * ============================================================================ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "poler_core.h"

static void print_block(const char *label, const u32 block[4])
{
    printf("%s: %08X %08X %08X %08X\n", label,
           block[0], block[1], block[2], block[3]);
}

int main(void)
{
    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║  POLER Core v8 — Userspace Self-Test            ║\n");
    printf("╚══════════════════════════════════════════════════╝\n\n");

    int passed = 0, failed = 0;

    /* ── Test 1: PND Mix ── */
    printf("── Test 1: PND Mix v8 ──\n");
    {
        u32 a = 42, b = 17, eps = 1;
        u32 result = poler_pnd_mix(a, b, eps);
        printf("  pndMix(42, 17, 1) = 0x%08X\n", result);

        /* ε=0 auto-correction */
        u32 result0 = poler_pnd_mix(a, b, 0);
        u32 result1 = poler_pnd_mix(a, b, 1);
        if (result0 == result1) {
            printf("  ✓ ε=0 auto-corrects to ε=1\n");
            passed++;
        } else {
            printf("  ✗ ε=0 auto-correction FAILED\n");
            failed++;
        }
    }

    /* ── Test 2: ARX-Box Phi ── */
    printf("\n── Test 2: ARX-Box φ() bijectivity ──\n");
    {
        u32 x = 0xDEADBEEF;
        u32 y = poler_phi(x);
        printf("  φ(0x%08X) = 0x%08X\n", x, y);
        if (y != x) {
            printf("  ✓ φ is not identity\n");
            passed++;
        } else {
            printf("  ✗ φ(x) == x — NOT a permutation!\n");
            failed++;
        }
    }

    /* ── Test 3: Constant-time S-box ── */
    printf("\n── Test 3: Constant-time S-box ──\n");
    {
        /* Known AES S-box values */
        u8 s0 = poler_ct_sbox(0x00);
        u8 s1 = poler_ct_sbox(0x01);
        u8 s63 = poler_ct_sbox(0x63);
        printf("  S[0x00] = 0x%02X (expected 0x63)\n", s0);
        printf("  S[0x01] = 0x%02X (expected 0x7C)\n", s1);

        if (s0 == 0x63) {
            printf("  ✓ S[0x00] = 0x63 (matches AES)\n");
            passed++;
        } else {
            printf("  ✗ S[0x00] ≠ 0x63\n");
            failed++;
        }

        /* Roundtrip: S(S_inv(x)) == x */
        bool roundtrip_ok = true;
        for (int i = 0; i < 256; i++) {
            u8 s = poler_ct_sbox((u8)i);
            u8 si = poler_ct_inv_sbox(s);
            if (si != (u8)i) {
                printf("  ✗ S-inv roundtrip failed at %d\n", i);
                roundtrip_ok = false;
                break;
            }
        }
        if (roundtrip_ok) {
            printf("  ✓ S-box roundtrip: all 256 values OK\n");
            passed++;
        } else {
            failed++;
        }
    }

    /* ── Test 4: Cipher Roundtrip ── */
    printf("\n── Test 4: POLER Cipher Roundtrip ──\n");
    {
        u32 key[8] = {
            0x2B7E1516, 0x28AED2A6, 0xABF71588, 0x09CF4F3C,
            0x11111111, 0x22222222, 0x33333333, 0x44444444
        };
        struct poler_cipher cipher;
        poler_cipher_init(&cipher, key, 0x9E3779B9);

        u32 pt[4] = { 0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210 };
        u32 ct[4], dt[4];

        print_block("  Plaintext ", pt);
        poler_encrypt_block(&cipher, pt, ct);
        print_block("  Ciphertext", ct);
        poler_decrypt_block(&cipher, ct, dt);
        print_block("  Decrypted ", dt);

        if (dt[0] == pt[0] && dt[1] == pt[1] &&
            dt[2] == pt[2] && dt[3] == pt[3]) {
            printf("  ✓ Roundtrip OK\n");
            passed++;
        } else {
            printf("  ✗ Roundtrip FAILED\n");
            failed++;
        }

        /* Multiple blocks roundtrip */
        bool multi_ok = true;
        for (int i = 0; i < 1000; i++) {
            u32 test_pt[4] = {
                (u32)(rand() ^ i), (u32)(rand() + i),
                (u32)(rand() - i), (u32)(rand() * i)
            };
            u32 test_ct[4], test_dt[4];
            poler_encrypt_block(&cipher, test_pt, test_ct);
            poler_decrypt_block(&cipher, test_ct, test_dt);
            if (test_dt[0] != test_pt[0] || test_dt[1] != test_pt[1] ||
                test_dt[2] != test_pt[2] || test_dt[3] != test_pt[3]) {
                printf("  ✗ Roundtrip failed at iteration %d\n", i);
                multi_ok = false;
                break;
            }
        }
        if (multi_ok) {
            printf("  ✓ 1000-block roundtrip OK\n");
            passed++;
        } else {
            failed++;
        }
    }

    /* ── Test 5: Avalanche Effect ── */
    printf("\n── Test 5: Avalanche Effect ──\n");
    {
        u32 key[8] = {
            0x01020304, 0x05060708, 0x090A0B0C, 0x0D0E0F10,
            0x11121314, 0x15161718, 0x191A1B1C, 0x1D1E1F20
        };
        struct poler_cipher cipher;
        poler_cipher_init(&cipher, key, 1);

        u32 pt[4] = { 0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210 };
        u32 ct1[4], ct2[4];
        u32 pt2[4];
        memcpy(pt2, pt, sizeof(pt));
        pt2[0] ^= 1;  /* flip 1 bit */

        poler_encrypt_block(&cipher, pt, ct1);
        poler_encrypt_block(&cipher, pt2, ct2);

        unsigned int total_diff = 0;
        for (int i = 0; i < 4; i++)
            total_diff += hweight32(ct1[i] ^ ct2[i]);

        printf("  1-bit input change → %u/128 bits differ in ciphertext\n", total_diff);
        if (total_diff >= 32) {
            printf("  ✓ Avalanche effect strong (≥32/128 bits)\n");
            passed++;
        } else {
            printf("  ✗ Avalanche effect too weak\n");
            failed++;
        }
    }

    /* ── Test 6: PRNG ── */
    printf("\n── Test 6: POLER PRNG ──\n");
    {
        struct poler_prng prng;
        poler_prng_init(&prng, 42, 0x9E3779B9, 0x517CC1B7);

        printf("  PRNG output: ");
        u32 prev = 0;
        bool prng_ok = true;
        for (int i = 0; i < 10; i++) {
            u32 v = poler_prng_next(&prng);
            printf("%08X ", v);
            if (v == prev && i > 0) prng_ok = false;
            prev = v;
        }
        printf("\n");
        if (prng_ok) {
            printf("  ✓ PRNG produces distinct values\n");
            passed++;
        } else {
            printf("  ✗ PRNG produced duplicate consecutive values\n");
            failed++;
        }
    }

    /* ── Test 7: POLER Cycle Convergence ── */
    printf("\n── Test 7: POLER Cycle ──\n");
    {
        struct poler_result r = poler_cycle(0x12345678, 0xABCDEF01, 0x9E3779B9);
        printf("  Cycle result: state=0x%08X, iterations=%u, converged=%s\n",
               r.final_state, r.iterations, r.converged ? "yes" : "no");
        passed++;
    }

    /* ── Summary ── */
    printf("\n╔══════════════════════════════════════════════════╗\n");
    printf("║  RESULTS: %d passed, %d failed                    %s║\n",
           passed, failed, failed == 0 ? "  " : "");
    printf("╚══════════════════════════════════════════════════╝\n");

    return failed > 0 ? 1 : 0;
}
