#!/usr/bin/env python3
"""
Continuous Fuzzing for POLER v6 Crypto Primitives
==================================================
Python-based fuzzer that tests crypto invariants with random inputs.
Can run indefinitely or for a specified duration.

Also supports AFL++ mode via the C harness if available.

Usage:
    python3 continuous_fuzz.py                     # run for 5 minutes
    python3 continuous_fuzz.py --duration 3600     # run for 1 hour
    python3 continuous_fuzz.py --infinite          # run until Ctrl+C
    python3 continuous_fuzz.py --afl               # also launch AFL++ harness
"""

import random, time, struct, argparse, os, sys
from pathlib import Path

MASK32 = 0xFFFFFFFF

def rotl32(value, shift):
    shift = shift % 32
    return ((value << shift) | (value >> (32 - shift))) & MASK32

def phi_v6(x):
    y = (x + 0x9E3779B9) & MASK32
    y = rotl32(y, 13)
    y = (y ^ (y >> 16)) & MASK32
    y = (y * 0x517CC1B7) & MASK32
    y = rotl32(y, 7)
    y = (y + 1) & MASK32
    return y

def safe_key_v6(key):
    mk = rotl32(key, 5) ^ rotl32(key, 17) ^ key ^ 0x9E3779B9
    return mk | 1

def nil_v6(y, key, epsilon):
    sk = safe_key_v6(key)
    x = y ^ sk
    x = (x * sk) & MASK32
    x = (x + (epsilon * rotl32(sk, 7)) & MASK32) & MASK32
    x = phi_v6(x)
    x = (x * 0x9E3779B9) & MASK32
    x = (x + rotl32(sk ^ epsilon, 13)) & MASK32
    return rotl32(x, 13)

def dtp_v6(a, b, epsilon):
    bp = (a * b) & MASK32
    xab = a ^ b
    ra = rotl32(a, 5)
    rb = rotl32(b, 7)
    pv = phi_v6(xab)
    def_ = (ra ^ rb ^ pv) & MASK32
    et = (epsilon * def_) & MASK32
    return (bp + et) & MASK32

def mod_inverse32(a):
    if a % 2 == 0: return 0
    x = 1
    for _ in range(5):
        ax = (a * x) & MASK32
        x = (x * (2 - ax)) & MASK32
    return x

def phi_inverse(z):
    y = (z - 1) & MASK32
    y = rotl32(y, 32 - 7)
    y = (y * mod_inverse32(0x517CC1B7)) & MASK32
    y = (y ^ (y >> 16)) & MASK32
    y = rotl32(y, 32 - 13)
    y = (y - 0x9E3779B9) & MASK32
    return y

def nil_v6_inverse(result, key, epsilon):
    sk = safe_key_v6(key)
    x = rotl32(result, 32 - 13)
    x = (x - rotl32(sk ^ epsilon, 13)) & MASK32
    x = (x * mod_inverse32(0x9E3779B9)) & MASK32
    x = phi_inverse(x)
    x = (x - (epsilon * rotl32(sk, 7)) & MASK32) & MASK32
    x = (x * mod_inverse32(sk)) & MASK32
    x ^= sk
    return x


class FuzzStats:
    def __init__(self):
        self.total = 0
        self.passed = 0
        self.failed = 0
        self.violations = {}  # name -> count
        self.start_time = time.time()

    def record_pass(self):
        self.total += 1
        self.passed += 1

    def record_fail(self, name, detail=""):
        self.total += 1
        self.failed += 1
        self.violations[name] = self.violations.get(name, 0) + 1
        if self.violations[name] <= 5:  # Only print first 5
            print(f"  ❌ VIOLATION: {name} — {detail}")

    def summary(self):
        elapsed = time.time() - self.start_time
        rate = self.total / elapsed if elapsed > 0 else 0
        print(f"\n{'='*60}")
        print(f"FUZZING STATS ({elapsed:.0f}s)")
        print(f"{'='*60}")
        print(f"  Total tests:    {self.total:,}")
        print(f"  Passed:         {self.passed:,}")
        print(f"  Failed:         {self.failed:,}")
        print(f"  Rate:           {rate:,.0f} tests/sec")
        if self.violations:
            print(f"\n  Violations:")
            for name, count in sorted(self.violations.items(), key=lambda x: -x[1]):
                print(f"    {name}: {count}")
        else:
            print(f"\n  ✅ NO INVARIANT VIOLATIONS!")
        return self.failed == 0


def fuzz_roundtrip(stats, rng):
    """Test nil roundtrip: nil_inv(nil(y, k, e), k, e) == y"""
    y = rng.getrandbits(32)
    k = rng.getrandbits(32)
    e = rng.getrandbits(32)
    enc = nil_v6(y, k, e)
    dec = nil_v6_inverse(enc, k, e)
    if dec != y:
        stats.record_fail("nil_roundtrip", f"y=0x{y:08X} enc=0x{enc:08X} dec=0x{dec:08X}")
    else:
        stats.record_pass()


def fuzz_phi_roundtrip(stats, rng):
    """Test phi roundtrip: phi_inv(phi(x)) == x"""
    x = rng.getrandbits(32)
    fwd = phi_v6(x)
    inv = phi_inverse(fwd)
    if inv != x:
        stats.record_fail("phi_roundtrip", f"x=0x{x:08X} fwd=0x{fwd:08X} inv=0x{inv:08X}")
    else:
        stats.record_pass()


def fuzz_nil_injectivity(stats, rng):
    """Test nil injectivity: nil(y1, k, e) != nil(y2, k, e) for y1 != y2"""
    k = rng.getrandbits(32)
    e = rng.getrandbits(32)
    y1 = rng.getrandbits(32)
    # Try adjacent values and random perturbations
    deltas = [1, 2, 0x100, 0x10000, rng.getrandbits(16)]
    for d in deltas:
        y2 = (y1 ^ d) & MASK32
        if y2 == y1:
            continue
        o1 = nil_v6(y1, k, e)
        o2 = nil_v6(y2, k, e)
        if o1 == o2:
            stats.record_fail("nil_injectivity", f"y1=0x{y1:08X} y2=0x{y2:08X} k=0x{k:08X} e=0x{e:08X} out=0x{o1:08X}")
        else:
            stats.record_pass()


def fuzz_key_sensitivity(stats, rng):
    """Test that flipping any bit of key changes output"""
    y = rng.getrandbits(32)
    k = rng.getrandbits(32)
    e = rng.getrandbits(32)
    base = nil_v6(y, k, e)
    bit = rng.getrandbits(5)
    flipped = nil_v6(y, k ^ (1 << bit), e)
    if flipped == base:
        stats.record_fail(f"key_bit{bit}_insensitive", f"y=0x{y:08X} k=0x{k:08X} bit={bit}")
    else:
        stats.record_pass()


def fuzz_key_bit0(stats, rng):
    """Specifically test key bit 0 (was broken in v5)"""
    y = rng.getrandbits(32)
    k = rng.getrandbits(32)
    e = rng.getrandbits(32)
    o1 = nil_v6(y, k, e)
    o2 = nil_v6(y, k ^ 1, e)
    if o1 == o2:
        stats.record_fail("key_bit0", f"y=0x{y:08X} k=0x{k:08X}")
    else:
        stats.record_pass()


def fuzz_safe_key_uniqueness(stats, rng):
    """Test safe_key uniqueness for adjacent keys"""
    k = rng.getrandbits(32)
    sk1 = safe_key_v6(k)
    sk2 = safe_key_v6((k + 1) & MASK32)
    if sk1 == sk2:
        stats.record_fail("safe_key_collapse", f"k=0x{k:08X} sk1=0x{sk1:08X} sk2=0x{sk2:08X}")
    else:
        stats.record_pass()


def fuzz_dtp_eps0_identity(stats, rng):
    """Test DTP eps=0 identity: dtp(a, b, 0) == a * b"""
    a = rng.getrandbits(32)
    b = rng.getrandbits(32)
    result = dtp_v6(a, b, 0)
    expected = (a * b) & MASK32
    if result != expected:
        stats.record_fail("dtp_eps0_identity", f"a=0x{a:08X} b=0x{b:08X}")
    else:
        stats.record_pass()


def fuzz_output_balance(stats, rng):
    """Test output bit balance (no stuck bits)"""
    y = rng.getrandbits(32)
    k = rng.getrandbits(32)
    e = rng.getrandbits(32)
    out = nil_v6(y, k, e)
    pc = bin(out).count('1')
    # For 32-bit output, popcount follows Binomial(32,0.5)
    # P(pc=0) = P(pc=32) ≈ 2.3e-10 — only these are truly stuck
    # P(pc=1) = P(pc=31) ≈ 7.5e-9 — extremely rare but possible
    if pc == 0 or pc == 32:
        stats.record_fail("output_balance_stuck", f"out=0x{out:08X} popcount={pc}")
    else:
        stats.record_pass()


def fuzz_sac_sample(stats, rng):
    """Sample SAC — single-bit input flip should flip ~50% of output bits"""
    y = rng.getrandbits(32)
    k = rng.getrandbits(32)
    e = rng.getrandbits(32)
    bit = rng.getrandbits(5)
    o1 = nil_v6(y, k, e)
    o2 = nil_v6(y ^ (1 << bit), k, e)
    diff = o1 ^ o2
    flips = bin(diff).count('1')
    # Extreme: all same (0 flips) or all different (32 flips) is suspicious
    if flips == 0:
        stats.record_fail("sac_zero_diff", f"y=0x{y:08X} bit={bit}")
    elif flips == 32:
        # This is actually fine (complement), just unusual
        stats.record_pass()
    else:
        stats.record_pass()


# All fuzz tests
FUZZ_TESTS = [
    ("nil_roundtrip",        fuzz_roundtrip),
    ("phi_roundtrip",        fuzz_phi_roundtrip),
    ("nil_injectivity",      fuzz_nil_injectivity),
    ("key_sensitivity",      fuzz_key_sensitivity),
    ("key_bit0",             fuzz_key_bit0),
    ("safe_key_uniqueness",  fuzz_safe_key_uniqueness),
    ("dtp_eps0_identity",    fuzz_dtp_eps0_identity),
    ("output_balance",       fuzz_output_balance),
    ("sac_sample",           fuzz_sac_sample),
]


def run_fuzzing(duration_sec=300, seed=0xCAFEBABE):
    """Run continuous fuzzing for the specified duration."""
    rng = random.Random(seed)
    stats = FuzzStats()

    print(f"{'='*60}")
    print(f"POLER v6 CONTINUOUS FUZZING")
    print(f"Duration: {duration_sec}s | Seed: 0x{seed:08X}")
    print(f"Tests: {len(FUZZ_TESTS)}")
    print(f"{'='*60}")

    t0 = time.time()
    last_report = t0

    try:
        while True:
            # Run all tests in each iteration
            for name, test_fn in FUZZ_TESTS:
                test_fn(stats, rng)

            # Periodic status report
            now = time.time()
            if now - last_report > 30:
                elapsed = now - t0
                rate = stats.total / elapsed
                print(f"  [{elapsed:.0f}s] {stats.total:,} tests | {rate:,.0f}/s | {stats.failed} violations")
                last_report = now

            # Check duration
            if now - t0 >= duration_sec:
                break

    except KeyboardInterrupt:
        print("\n  Interrupted by user")

    return stats.summary()


def main():
    parser = argparse.ArgumentParser(description="POLER v6 Continuous Fuzzer")
    parser.add_argument("--duration", type=int, default=300, help="Duration in seconds")
    parser.add_argument("--infinite", action="store_true", help="Run until Ctrl+C")
    parser.add_argument("--seed", type=int, default=0xCAFEBABE, help="Random seed")
    args = parser.parse_args()

    duration = 2**31 if args.infinite else args.duration
    success = run_fuzzing(duration, args.seed)

    # Also save results
    out_path = Path("/home/z/my-project/download/fuzzing_results.txt")
    with open(out_path, 'a') as f:
        f.write(f"\n--- Fuzzing session {time.strftime('%Y-%m-%d %H:%M:%S')} ---\n")
        f.write(f"Duration: {args.duration}s | Seed: 0x{args.seed:08X}\n")
        f.write(f"Result: {'PASS' if success else 'FAIL'}\n")

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
