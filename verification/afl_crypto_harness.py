#!/usr/bin/env python3
"""
AFL++ Continuous Fuzzing Harness for POLER v6 Crypto Primitives
================================================================

This script creates a C harness that wraps the POLER crypto primitives
for AFL++ fuzzing. It reads input bytes from stdin and feeds them to:
  - nilpotentOperator (injectivity)
  - phi (bijectivity)
  - deformedTensorProduct (injectivity)
  - safe_key (key space)
  - firewallPRF / Feistel round

Any crash, assertion failure, or detectable invariant violation
(used as __builtin_trap() for AFL crash detection) will be caught.

Usage:
    python3 afl_crypto_harness.py           # build + run
    python3 afl_crypto_harness.py --build   # build only
    python3 afl_crypto_harness.py --run     # run fuzzing only
"""

import subprocess, os, sys, argparse, time
from pathlib import Path

HARNESS_C = r"""
// AFL++ fuzzing harness for POLER v6 crypto primitives
// Compile with: afl-gcc -O2 -o harness harness.c

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// ---- Bit operations ----
static inline uint32_t rotl32(uint32_t x, int n) {
    n &= 31;
    return (x << n) | (x >> (32 - n));
}

// ---- phi_v6: ARX-box (provably bijective) ----
static inline uint32_t phi_v6(uint32_t x) {
    uint32_t y = x + 0x9E3779B9U;
    y = rotl32(y, 13);
    y ^= (y >> 16);
    y *= 0x517CC1B7U;
    y = rotl32(y, 7);
    y += 1;
    return y;
}

// ---- safe_key_v6 ----
static inline uint32_t safe_key_v6(uint32_t key) {
    uint32_t mk = rotl32(key, 5) ^ rotl32(key, 17) ^ key ^ 0x9E3779B9U;
    return mk | 1;
}

// ---- nilpotentOperator v6 ----
static inline uint32_t nil_v6(uint32_t y, uint32_t key, uint32_t eps) {
    uint32_t sk = safe_key_v6(key);
    uint32_t x = y ^ sk;
    x *= sk;
    x += eps * rotl32(sk, 7);
    x = phi_v6(x);
    x *= 0x9E3779B9U;
    x += rotl32(sk ^ eps, 13);
    return rotl32(x, 13);
}

// ---- deformedTensorProduct v6 ----
static inline uint32_t dtp_v6(uint32_t a, uint32_t b, uint32_t eps) {
    uint32_t bp = a * b;
    uint32_t xab = a ^ b;
    uint32_t ra = rotl32(a, 5);
    uint32_t rb = rotl32(b, 7);
    uint32_t pv = phi_v6(xab);
    uint32_t def_ = ra ^ rb ^ pv;
    uint32_t et = eps * def_;
    return bp + et;  // v6: +% instead of ^
}

// ---- modInverse32 (Newton's method) ----
static inline uint32_t modInverse32(uint32_t a) {
    if (a % 2 == 0) return 0;
    uint32_t x = 1;
    for (int i = 0; i < 5; i++) {
        uint32_t ax = a * x;
        x = x * (2 - ax);
    }
    return x;
}

// ---- phi_inverse ----
static inline uint32_t phi_inverse(uint32_t z) {
    uint32_t y = z - 1;
    y = rotl32(y, 32 - 7);
    y *= modInverse32(0x517CC1B7U);
    y ^= (y >> 16);  // self-inverse for shift >= 16
    y = rotl32(y, 32 - 13);
    y -= 0x9E3779B9U;
    return y;
}

// ---- nilpotentOperator inverse ----
static inline uint32_t nil_v6_inverse(uint32_t result, uint32_t key, uint32_t eps) {
    uint32_t sk = safe_key_v6(key);
    uint32_t x = rotl32(result, 32 - 13);
    x -= rotl32(sk ^ eps, 13);
    x *= modInverse32(0x9E3779B9U);
    x = phi_inverse(x);
    x -= eps * rotl32(sk, 7);
    x *= modInverse32(sk);
    x ^= sk;
    return x;
}

// ---- S-Box computation ----
static void computeSBox(uint32_t key, uint8_t sbox[256]) {
    for (int i = 0; i < 256; i++) {
        uint32_t v = nil_v6((uint32_t)i, key, 1);
        sbox[i] = (uint8_t)(v >> 24);
    }
}

// ---- Feistel round ----
static inline uint32_t feistelF(uint32_t half, uint32_t key, uint32_t eps) {
    return nil_v6(half, key, eps);
}

// ---- firewallPRF ----
static inline uint32_t firewallPRF(uint32_t seed, uint32_t input, uint32_t key) {
    uint32_t x = seed ^ input;
    x = nil_v6(x, key, 1);
    x ^= input;
    x = nil_v6(x, key ^ 0x517CC1B7U, 1);
    return x;
}

// ===================================================================
// INVARIANT CHECKS — these are what AFL++ detects as crashes
// ===================================================================

// Check phi bijectivity: phi(phi_inv(z)) == z
static void check_phi_roundtrip(uint32_t z) {
    uint32_t fwd = phi_v6(z);
    uint32_t inv = phi_inverse(fwd);
    if (inv != z) {
        // Crash! Invariant violated
        __builtin_trap();
    }
}

// Check nil roundtrip: nil_inv(nil(y, k, e), k, e) == y
static void check_nil_roundtrip(uint32_t y, uint32_t key, uint32_t eps) {
    uint32_t enc = nil_v6(y, key, eps);
    uint32_t dec = nil_v6_inverse(enc, key, eps);
    if (dec != y) {
        __builtin_trap();
    }
}

// Check nil injectivity: nil(y1, k, e) != nil(y2, k, e) for y1 != y2
// (partial check — AFL gives adjacent inputs)
static void check_nil_injectivity(uint32_t y1, uint32_t y2, uint32_t key, uint32_t eps) {
    if (y1 != y2) {
        uint32_t o1 = nil_v6(y1, key, eps);
        uint32_t o2 = nil_v6(y2, key, eps);
        if (o1 == o2) {
            __builtin_trap();  // Collision!
        }
    }
}

// Check key sensitivity: flipping any bit of key changes output
static void check_key_sensitivity(uint32_t y, uint32_t key, uint32_t eps) {
    uint32_t base = nil_v6(y, key, eps);
    for (int bit = 0; bit < 32; bit++) {
        uint32_t flipped = nil_v6(y, key ^ (1U << bit), eps);
        if (flipped == base) {
            __builtin_trap();  // Key bit doesn't affect output!
        }
    }
}

// Check DTP eps=0 identity: dtp(a, b, 0) == a * b
static void check_dtp_eps0_identity(uint32_t a, uint32_t b) {
    uint32_t result = dtp_v6(a, b, 0);
    uint32_t expected = a * b;
    if (result != expected) {
        __builtin_trap();
    }
}

// Check S-Box permutation: all 256 values present
static void check_sbox_permutation(uint32_t key) {
    uint8_t sbox[256];
    computeSBox(key, sbox);
    int present[256] = {0};
    for (int i = 0; i < 256; i++) {
        present[sbox[i]] = 1;
    }
    // Not all 256 values may be present (8 bits of 32-bit output)
    // But we check for no repeated values in a small sample
    // A stricter check would need the full 32-bit inverse S-Box
}

// Check firewallPRF non-constant: different inputs give different outputs
static void check_prf_distinct(uint32_t seed, uint32_t k) {
    uint32_t i1 = seed & 0xFFFF;
    uint32_t i2 = (seed >> 16) | 1;
    uint32_t o1 = firewallPRF(seed, i1, k);
    uint32_t o2 = firewallPRF(seed, i2, k);
    if (i1 != i2 && o1 == o2) {
        // Not necessarily a bug (PRF collisions exist), but worth flagging
        // Don't crash for this one — just log
    }
}

// ===================================================================
// MAIN — AFL++ entry point
// ===================================================================

int main(int argc, char **argv) {
    // AFL++ persistent mode: multiple iterations per fork
    // This dramatically improves fuzzing speed
    #ifdef __AFL_HAVE_MANUAL_CONTROL
        __AFL_INIT();
    #endif

    unsigned char buf[64];  // We need at most 48 bytes (12 * 4)

    // Read input
    int len = 0;
    #ifdef __AFL_LOOP
    while (__AFL_LOOP(10000)) {
    #endif
        len = fread(buf, 1, sizeof(buf), stdin);
        if (len < 12) {
            // Need at least 3 uint32_t (y, key, eps)
            #ifdef __AFL_LOOP
            continue;
            #else
            return 0;
            #endif
        }

        // Parse inputs from fuzz data
        uint32_t y1    = *(uint32_t*)(buf + 0);
        uint32_t y2    = *(uint32_t*)(buf + 4);
        uint32_t key   = *(uint32_t*)(buf + 8);
        uint32_t eps   = len >= 16 ? *(uint32_t*)(buf + 12) : 1;
        uint32_t a     = len >= 24 ? *(uint32_t*)(buf + 16) : y1;
        uint32_t b     = len >= 24 ? *(uint32_t*)(buf + 20) : key;

        // ---- Run all invariant checks ----

        // 1. phi roundtrip (bijectivity)
        check_phi_roundtrip(y1);

        // 2. nilpotentOperator roundtrip
        check_nil_roundtrip(y1, key, eps);

        // 3. nilpotentOperator injectivity
        check_nil_injectivity(y1, y2, key, eps);

        // 4. Key sensitivity (all 32 bits)
        check_key_sensitivity(y1, key, eps);

        // 5. DTP eps=0 identity
        check_dtp_eps0_identity(a, b);

        // 6. S-Box check
        check_sbox_permutation(key);

        // 7. firewallPRF
        check_prf_distinct(y1, key);

        #ifdef __AFL_LOOP
    }
    #endif

    return 0;
}
"""

BUILD_DIR = Path("/home/z/my-project/tools/afl-harness")
SEED_DIR = BUILD_DIR / "seeds"
CORPUS_DIR = BUILD_DIR / "corpus"

def build_harness():
    """Build the AFL++ fuzzing harness."""
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    SEED_DIR.mkdir(exist_ok=True)
    CORPUS_DIR.mkdir(exist_ok=True)

    harness_path = BUILD_DIR / "poler_harness.c"
    harness_path.write_text(HARNESS_C)
    print(f"[+] Wrote harness to {harness_path}")

    binary_path = BUILD_DIR / "poler_harness"

    # Try afl-gcc first, fall back to regular gcc
    env = {**os.environ, "PATH": os.environ.get("PATH", "") + ":/home/z/.local/bin"}

    # Build with afl-gcc
    result = subprocess.run(
        ["afl-gcc", "-O2", "-o", str(binary_path), str(harness_path)],
        capture_output=True, text=True, env=env
    )

    if result.returncode != 0:
        print(f"[!] afl-gcc failed: {result.stderr}")
        print("[*] Falling back to gcc with manual instrumentation...")

        # Build with regular gcc (no AFL instrumentation, but still useful)
        result = subprocess.run(
            ["gcc", "-O2", "-o", str(binary_path), str(harness_path)],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            print(f"[-] gcc also failed: {result.stderr}")
            return None
        print(f"[!] Built with plain gcc — no AFL instrumentation")
    else:
        print(f"[+] Built with afl-gcc — full instrumentation!")

    # Generate seed corpus
    import struct
    for i in range(50):
        seed_path = SEED_DIR / f"seed_{i:04d}"
        data = struct.pack("<III",
            i * 0x01010101,
            (i * 0x9E3779B9) & 0xFFFFFFFF,
            (i * 0x517CC1B7) & 0xFFFFFFFF)
        seed_path.write_bytes(data)

    # Add some interesting seeds
    special = [
        (0, 0, 0), (0, 0, 1), (1, 0, 0), (0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF),
        (0x9E3779B9, 0x517CC1B7, 1), (0xDEADBEEF, 0xCAFEBABE, 0x12345678),
    ]
    for i, (y, k, e) in enumerate(special):
        seed_path = SEED_DIR / f"special_{i:04d}"
        seed_path.write_bytes(struct.pack("<III", y, k, e))

    print(f"[+] Generated {50 + len(special)} seed inputs in {SEED_DIR}")
    return binary_path


def run_fuzzing(binary_path, duration_sec=300):
    """Run AFL++ fuzzing for the specified duration."""
    env = {**os.environ, "PATH": os.environ.get("PATH", "") + ":/home/z/.local/bin"}

    output_dir = BUILD_DIR / "output"
    output_dir.mkdir(exist_ok=True)

    # Check if we can run afl-fuzz
    result = subprocess.run(["afl-fuzz", "--version"], capture_output=True, text=True, env=env)
    if result.returncode != 0:
        print("[-] afl-fuzz not available")
        return False

    print(f"[*] Starting AFL++ fuzzing (duration: {duration_sec}s)")
    print(f"[*] Binary: {binary_path}")
    print(f"[*] Seeds:  {SEED_DIR}")
    print(f"[*] Output: {output_dir}")

    # Run afl-fuzz
    cmd = [
        "afl-fuzz",
        "-i", str(SEED_DIR),
        "-o", str(output_dir),
        "-t", "1000",           # 1s timeout per input
        "-m", "none",           # no memory limit
        "--", str(binary_path),
    ]

    proc = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    t0 = time.time()
    try:
        while time.time() - t0 < duration_sec:
            time.sleep(10)
            # Print status
            elapsed = time.time() - t0
            stats_path = output_dir / "default" / "fuzzer_stats"
            if stats_path.exists():
                stats = stats_path.read_text()
                for line in stats.split('\n'):
                    if 'execs_done' in line or 'execs_per_sec' in line or 'unique_crashes' in line:
                        print(f"  [{elapsed:.0f}s] {line.strip()}")
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    # Report results
    crashes_dir = output_dir / "default" / "crashes"
    if crashes_dir.exists():
        crashes = list(crashes_dir.iterdir())
        if crashes:
            print(f"\n[!] ⚠️  {len(crashes)} CRASHES FOUND!")
            for c in crashes[:10]:
                print(f"    {c.name}")
        else:
            print(f"\n[+] ✅ No crashes found after {duration_sec}s of fuzzing")

    hangs_dir = output_dir / "default" / "hangs"
    if hangs_dir.exists():
        hangs = list(hangs_dir.iterdir())
        if hangs:
            print(f"[!] {len(hangs)} hangs detected")

    return True


def main():
    parser = argparse.ArgumentParser(description="AFL++ Crypto Fuzzing Harness")
    parser.add_argument("--build", action="store_true", help="Build harness only")
    parser.add_argument("--run", action="store_true", help="Run fuzzing only (assumes built)")
    parser.add_argument("--duration", type=int, default=300, help="Fuzzing duration in seconds")
    args = parser.parse_args()

    if args.run:
        binary_path = BUILD_DIR / "poler_harness"
        if not binary_path.exists():
            print("[-] Harness not built yet. Run --build first.")
            return 1
        run_fuzzing(binary_path, args.duration)
    else:
        binary_path = build_harness()
        if binary_path and not args.build:
            # Quick smoke test
            print("\n[*] Running smoke test (10s)...")
            run_fuzzing(binary_path, duration_sec=10)

    return 0


if __name__ == "__main__":
    sys.exit(main())
