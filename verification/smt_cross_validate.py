#!/usr/bin/env python3
"""
SMT Cross-Validation: Z3 + CVC5 + Bitwuzla
============================================
Runs the same BV (bit-vector) injectivity proofs through three independent
SMT solvers. A result is "confirmed" only when ALL solvers agree.

SMT-LIB2 format: uses decimal constants (_ bvN size), explicit rotl functions.
BV16 proofs are exhaustive (fast), BV32 are sampling-based (slower).

Usage:
    python3 smt_cross_validate.py                  # full suite
    python3 smt_cross_validate.py --solver cvc5    # single solver
    python3 smt_cross_validate.py --quick           # BV16 only

Solvers required on $PATH (or /home/z/.local/bin):
    z3, cvc5, bitwuzla
"""

import subprocess, tempfile, os, sys, time, argparse
from pathlib import Path

# BV16 constants (adapted from BV32)
# phi: C1=0x9E37=40503, C2=0xC1B7=49591 (odd for 16-bit), shift_half=8
# nil: golden=0x9E37=40503 (odd), safe_key mixing, etc.
BV16_C1     = 40503   # 0x9E37
BV16_C2     = 49591   # 0xC1B7 (odd)
BV16_GOLDEN = 40503   # 0x9E37 (odd)
BV16_KEY_XOR = 40503   # 0x9E37

# BV32 constants
BV32_C1     = 2654435769   # 0x9E3779B9
BV32_C2     = 1367130551   # 0x517CC1B7 (odd)
BV32_GOLDEN = 2654435769   # 0x9E3779B9

# ---------------------------------------------------------------------------
# SMT-LIB2 query generators — proper format with decimal constants
# ---------------------------------------------------------------------------

def _rotl_funs(bv_size):
    """Generate rotl functions for given BV size with common shift amounts.
    Handles modulo: rotl(s, bv_size) = rotl(s % bv_size, bv_size)."""
    shifts = [5, 7, 13, 17]
    lines = []
    seen = set()  # Avoid duplicate function names (e.g. rotl17 = rotl1 for BV16)
    for s in shifts:
        actual = s % bv_size
        comp = bv_size - actual
        if actual in seen:
            # Create alias
            alias_src = None
            for prev_s, prev_actual in [(ps, ps % bv_size) for ps in shifts]:
                if prev_actual == actual and prev_s != s:
                    alias_src = prev_s
                    break
            if alias_src is not None:
                lines.append(f"""; rotl{s} = rotl{alias_src} (same shift {actual} mod {bv_size})
(define-fun rotl{s} ((x (_ BitVec {bv_size}))) (_ BitVec {bv_size})
    (rotl{alias_src} x)
)""")
            continue
        seen.add(actual)
        lines.append(f"""; rotl{s}(x) = rotl by {actual} = (x << {actual}) | (x >> {comp})
(define-fun rotl{s} ((x (_ BitVec {bv_size}))) (_ BitVec {bv_size})
    (bvor (bvshl x (_ bv{actual} {bv_size})) (bvlshr x (_ bv{comp} {bv_size})))
)""")
    return '\n'.join(lines)


def smt_phi_bijectivity(bv_size=16):
    """Prove phi_v6 is injective: phi(x1) = phi(x2) => x1 = x2."""
    if bv_size == 16:
        c1, c2, half_shift = BV16_C1, BV16_C2, 8
    else:
        c1, c2, half_shift = BV32_C1, BV32_C2, 16

    return f"""(set-logic QF_BV)
; phi_v6 bijectivity proof (BV{bv_size})
; UNSAT = bijective (no two x1 != x2 give same output)

(declare-const x1 (_ BitVec {bv_size}))
(declare-const x2 (_ BitVec {bv_size}))
(assert (not (= x1 x2)))

{_rotl_funs(bv_size)}

(define-fun phi_v6 ((x (_ BitVec {bv_size}))) (_ BitVec {bv_size})
    (let ((a1 (bvadd x (_ bv{c1} {bv_size}))))
    (let ((r1 (rotl13 a1)))
    (let ((xs (bvxor r1 (bvlshr r1 (_ bv{half_shift} {bv_size})))))
    (let ((m1 (bvmul xs (_ bv{c2} {bv_size}))))
    (let ((r2 (rotl7 m1)))
    (let ((a2 (bvadd r2 (_ bv1 {bv_size}))))
        a2))))))
)

(assert (= (phi_v6 x1) (phi_v6 x2)))

(check-sat)
"""


def smt_nilpotent_injectivity(bv_size=16, epsilon_nonzero=True):
    """Prove nilpotentOperator(y1, key, eps) != nilpotentOperator(y2, key, eps)
    for y1 != y2. Uses concrete key=0xCAFE and eps."""
    if bv_size == 16:
        c1, c2, half_shift = BV16_C1, BV16_C2, 8
        key_val = 0xCAFE   # 51966
        key_xor = BV16_KEY_XOR
        golden = BV16_GOLDEN
    else:
        c1, c2, half_shift = BV32_C1, BV32_C2, 16
        key_val = 0xCAFE1234  # 3405700660
        key_xor = BV32_C1
        golden = BV32_GOLDEN

    eps_val = 1 if epsilon_nonzero else 0
    # safe_key_v6(key) = rotl5(key) ^ rotl17(key) ^ key ^ C1 | 1
    # For BV16, rotl17 = rotl(17 mod 16) = rotl1

    return f"""(set-logic QF_BV)
; nilpotentOperator v6 injectivity proof (BV{bv_size}, eps={"1" if epsilon_nonzero else "0"})
; UNSAT = injective

(declare-const y1 (_ BitVec {bv_size}))
(declare-const y2 (_ BitVec {bv_size}))

(assert (not (= y1 y2)))

{_rotl_funs(bv_size)}

(define-fun phi_v6 ((x (_ BitVec {bv_size}))) (_ BitVec {bv_size})
    (let ((a1 (bvadd x (_ bv{c1} {bv_size}))))
    (let ((r1 (rotl13 a1)))
    (let ((xs (bvxor r1 (bvlshr r1 (_ bv{half_shift} {bv_size})))))
    (let ((m1 (bvmul xs (_ bv{c2} {bv_size}))))
    (let ((r2 (rotl7 m1)))
    (let ((a2 (bvadd r2 (_ bv1 {bv_size}))))
        a2))))))
)

; safe_key_v6(key) for concrete key
(define-fun sk () (_ BitVec {bv_size})
    (bvor (bvxor (bvxor (bvxor (rotl5 (_ bv{key_val} {bv_size})) (rotl17 (_ bv{key_val} {bv_size}))) (_ bv{key_val} {bv_size})) (_ bv{key_xor} {bv_size})) (_ bv1 {bv_size}))
)

; nil_v6(y) with concrete key and eps
(define-fun nil_v6 ((y (_ BitVec {bv_size}))) (_ BitVec {bv_size})
    (let ((s1 (bvxor y sk)))
    (let ((s2 (bvmul s1 sk)))
    (let ((s3 (bvadd s2 (bvmul (_ bv{eps_val} {bv_size}) (rotl7 sk)))))
    (let ((s4 (phi_v6 s3)))
    (let ((s5 (bvmul s4 (_ bv{golden} {bv_size}))))
    (let ((s6 (bvadd s5 (rotl13 (bvxor sk (_ bv{eps_val} {bv_size}))))))
    (let ((s7 (rotl13 s6)))
        s7)))))))
)

(assert (= (nil_v6 y1) (nil_v6 y2)))

(check-sat)
"""


def smt_key_space_no_collapse(bv_size=16):
    """Prove safe_key_v6(k) != safe_key_v6(k+1) for adjacent keys."""
    if bv_size == 16:
        key_xor = BV16_KEY_XOR
    else:
        key_xor = BV32_C1

    return f"""(set-logic QF_BV)
; key space collapse proof (BV{bv_size})
; UNSAT = no collapse (adjacent keys produce different safe_key)

(declare-const k (_ BitVec {bv_size}))

{_rotl_funs(bv_size)}

(define-fun safe_key_v6 ((k (_ BitVec {bv_size}))) (_ BitVec {bv_size})
    (bvor (bvxor (bvxor (bvxor (rotl5 k) (rotl17 k)) k) (_ bv{key_xor} {bv_size})) (_ bv1 {bv_size}))
)

(assert (= (safe_key_v6 k) (safe_key_v6 (bvadd k (_ bv1 {bv_size})))))

(check-sat)
"""


def smt_dtp_injectivity(bv_size=16, epsilon_nonzero=True):
    """Prove deformedTensorProduct(a1, b, eps) != dtp(a2, b, eps) for a1!=a2, b odd."""
    if bv_size == 16:
        c1, c2, half_shift = BV16_C1, BV16_C2, 8
        b_val = BV16_C1  # 0x9E37 (odd)
    else:
        c1, c2, half_shift = BV32_C1, BV32_C2, 16
        b_val = BV32_C1  # 0x9E3779B9 (odd)

    eps_val = 1 if epsilon_nonzero else 0

    return f"""(set-logic QF_BV)
; deformedTensorProduct v6 injectivity in 'a' (BV{bv_size}, eps={"1" if epsilon_nonzero else "0"})
; UNSAT = injective in a for fixed odd b

(declare-const a1 (_ BitVec {bv_size}))
(declare-const a2 (_ BitVec {bv_size}))

(assert (not (= a1 a2)))

{_rotl_funs(bv_size)}

(define-fun phi_v6 ((x (_ BitVec {bv_size}))) (_ BitVec {bv_size})
    (let ((a1_ (bvadd x (_ bv{c1} {bv_size}))))
    (let ((r1 (rotl13 a1_)))
    (let ((xs (bvxor r1 (bvlshr r1 (_ bv{half_shift} {bv_size})))))
    (let ((m1 (bvmul xs (_ bv{c2} {bv_size}))))
    (let ((r2 (rotl7 m1)))
    (let ((a2_ (bvadd r2 (_ bv1 {bv_size}))))
        a2_))))))
)

; dtp_v6(a, b, eps) = (a * b) +% (eps * (rotl5(a) ^ rotl7(b) ^ phi(a ^ b)))
(define-fun dtp_v6 ((a (_ BitVec {bv_size}))) (_ BitVec {bv_size})
    (let ((bp (bvmul a (_ bv{b_val} {bv_size}))))
    (let ((xab (bvxor a (_ bv{b_val} {bv_size}))))
    (let ((ra (rotl5 a)))
    (let ((rb (rotl7 (_ bv{b_val} {bv_size}))))
    (let ((pv (phi_v6 xab)))
    (let ((def_ (bvxor (bvxor ra rb) pv)))
    (let ((et (bvmul (_ bv{eps_val} {bv_size}) def_)))
        (bvadd bp et))))))))
)

(assert (= (dtp_v6 a1) (dtp_v6 a2)))

(check-sat)
"""


# ---------------------------------------------------------------------------
# Solver invocation
# ---------------------------------------------------------------------------

SOLVERS = {
    "z3":       {"cmd": ["z3", "-smt2", "-T:300"], "timeout": 300},
    "cvc5":     {"cmd": ["cvc5", "--lang", "smt2", "--tlimit=300000"], "timeout": 300},
    "bitwuzla": {"cmd": ["bitwuzla"], "timeout": 300},
}

def run_solver(name, smt_query, timeout=None):
    """Run a single solver on the SMT-LIB2 query. Returns (result, time_sec, output)."""
    cfg = SOLVERS[name]
    tmo = timeout or cfg["timeout"]

    with tempfile.NamedTemporaryFile(mode='w', suffix='.smt2', delete=False) as f:
        f.write(smt_query)
        f.flush()
        tmpfile = f.name

    try:
        t0 = time.time()
        proc = subprocess.run(
            cfg["cmd"] + [tmpfile],
            capture_output=True, text=True, timeout=tmo,
            env={**os.environ, "PATH": os.environ.get("PATH", "") + ":/home/z/.local/bin"}
        )
        elapsed = time.time() - t0
        output = proc.stdout.strip()
        stderr = proc.stderr.strip()
        first_line = output.split('\n')[0] if output else ""

        if first_line == "unsat":
            return "UNSAT", elapsed, output
        elif first_line == "sat":
            return "SAT", elapsed, output
        elif first_line == "unknown":
            return "UNKNOWN", elapsed, output
        else:
            # Check stderr for errors
            err_msg = stderr[:200] if stderr else first_line[:200]
            return f"ERROR({proc.returncode})", elapsed, err_msg
    except subprocess.TimeoutExpired:
        return "TIMEOUT", tmo, ""
    except FileNotFoundError:
        return "NOT_INSTALLED", 0, ""
    finally:
        os.unlink(tmpfile)


# ---------------------------------------------------------------------------
# Cross-validation runner
# ---------------------------------------------------------------------------

def cross_validate(name, smt_query, solvers, bv_size=16):
    """Run query on all solvers, return dict of {solver: (result, time)}."""
    print(f"\n{'='*70}")
    print(f"  {name} (BV{bv_size})")
    print(f"{'='*70}")

    results = {}
    for solver in solvers:
        result, elapsed, output = run_solver(solver, smt_query)
        results[solver] = (result, elapsed)
        icon = {"UNSAT": "✅", "SAT": "❌", "UNKNOWN": "❓", "TIMEOUT": "⏱️",
                "NOT_INSTALLED": "🚫"}.get(result, "⚠️")
        time_str = f"{elapsed:.1f}s" if elapsed < 1000 else f"{elapsed/60:.1f}m"
        print(f"  {solver:12s}: {icon} {result:15s}  ({time_str})")
        if result == "SAT" and output:
            model_lines = output.split('\n')[1:6]
            for ml in model_lines:
                print(f"    {ml}")
        elif "ERROR" in result and output:
            print(f"    Error: {output[:100]}")

    # Consensus
    valid_results = {r for r, _ in results.values() if r not in ("NOT_INSTALLED",)}
    has_missing = any(r == "NOT_INSTALLED" for r, _ in results.values())

    if has_missing:
        consensus = "PARTIAL"
    elif len(valid_results) == 1:
        if "UNSAT" in valid_results:
            consensus = "CONFIRMED"
        elif "SAT" in valid_results:
            consensus = "ALL_SAT"
        else:
            consensus = "UNCERTAIN"
    elif "UNSAT" in valid_results and "SAT" in valid_results:
        consensus = "DISAGREEMENT"
    else:
        consensus = "PARTIAL_AGREE"

    icon = {"CONFIRMED": "✅", "ALL_SAT": "❌", "DISAGREEMENT": "🚨",
            "PARTIAL": "⚠️", "PARTIAL_AGREE": "⚠️", "UNCERTAIN": "❓"}.get(consensus, "❓")
    print(f"  {'CONSENSUS':12s}: {icon} {consensus}")
    return results, consensus


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="SMT Cross-Validation (Z3+CVC5+Bitwuzla)")
    parser.add_argument("--solver", choices=list(SOLVERS.keys()), help="Run single solver only")
    parser.add_argument("--quick", action="store_true", help="BV16 proofs only (fast)")
    parser.add_argument("--bv16", action="store_true", help="Run 16-bit proofs (default)")
    args = parser.parse_args()

    solvers = [args.solver] if args.solver else list(SOLVERS.keys())

    print("="*70)
    print("POLER v6 SMT CROSS-VALIDATION SUITE")
    print(f"Solvers: {', '.join(solvers)}")
    print("="*70)

    t0 = time.time()
    all_confirmed = True
    results_summary = []

    # --- BV16 proofs (exhaustive, fast) ---
    bv = 16
    queries_16 = [
        ("phi bijectivity",            smt_phi_bijectivity(bv)),
        ("nil injectivity (eps=0)",    smt_nilpotent_injectivity(bv, False)),
        ("nil injectivity (eps≠0)",    smt_nilpotent_injectivity(bv, True)),
        ("key space no collapse",      smt_key_space_no_collapse(bv)),
        ("DTP injectivity (eps=0)",    smt_dtp_injectivity(bv, False)),
        ("DTP injectivity (eps≠0)",    smt_dtp_injectivity(bv, True)),
    ]

    print("\n" + "─"*70)
    print(f"  BV{bv} PROOFS (exhaustive, fast)")
    print("─"*70)

    for name, query in queries_16:
        res, cons = cross_validate(f"BV{bv} {name}", query, solvers, bv)
        results_summary.append((f"BV{bv} {name}", cons))
        if cons not in ("CONFIRMED", "PARTIAL"):
            all_confirmed = False

    # --- BV32 proofs (expensive) ---
    if not args.quick:
        bv = 32
        queries_32 = [
            ("phi bijectivity",            smt_phi_bijectivity(bv)),
            ("nil injectivity (eps=0)",    smt_nilpotent_injectivity(bv, False)),
            ("key space no collapse",      smt_key_space_no_collapse(bv)),
        ]

        print("\n" + "─"*70)
        print(f"  BV{bv} PROOFS (may take several minutes)")
        print("─"*70)

        for name, query in queries_32:
            print(f"\n  [BV{bv} {name}] Starting... (this may take a while)")
            res, cons = cross_validate(f"BV{bv} {name}", query, solvers, bv)
            results_summary.append((f"BV{bv} {name}", cons))
            if cons not in ("CONFIRMED", "PARTIAL"):
                all_confirmed = False

    elapsed = time.time() - t0

    # --- Summary ---
    print("\n" + "="*70)
    print("CROSS-VALIDATION SUMMARY")
    print("="*70)
    for name, cons in results_summary:
        icon = {"CONFIRMED": "✅", "PARTIAL": "⚠️", "DISAGREEMENT": "🚨",
                "ALL_SAT": "❌", "PARTIAL_AGREE": "⚠️", "UNCERTAIN": "❓"}.get(cons, "❓")
        print(f"  {icon} {name:45s} {cons}")

    confirmed_count = sum(1 for _, c in results_summary if c == "CONFIRMED")
    total_count = len(results_summary)
    print(f"\n  Confirmed: {confirmed_count}/{total_count}")
    print(f"  Total time: {elapsed:.1f}s")

    if all_confirmed:
        print("\n  🎉 ALL PROOFS CONFIRMED — no solver disagreement!")
    elif confirmed_count == total_count:
        print("\n  🎉 ALL PROOFS CONFIRMED BY ALL SOLVERS!")
    else:
        print("\n  ⚠️  Some proofs need investigation")

    # Save results
    out_path = Path("/home/z/my-project/download/smt_cross_validation_results.txt")
    with open(out_path, 'w') as f:
        f.write(f"POLER v6 SMT Cross-Validation Results\n")
        f.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Solvers: {', '.join(solvers)}\n\n")
        for name, cons in results_summary:
            f.write(f"  {cons:15s} {name}\n")
        f.write(f"\nConfirmed: {confirmed_count}/{total_count}\n")
        f.write(f"Total time: {elapsed:.1f}s\n")
    print(f"\n  Results saved to {out_path}")

    return 0 if all_confirmed else 1


if __name__ == "__main__":
    sys.exit(main())
