"""Replay the published host observations. No solver, cluster or network required."""
import argparse
import hashlib
import json
from fractions import Fraction
from pathlib import Path

HERE = Path(__file__).resolve().parent
STATUS = HERE.parents[2] / "status/euf-single-audit-host-2026-11-10.json"
RECEIPT = "08ced82808487bcf8cb3708515aa7e7739f52f1f4b74ad9ac368a5246086b8c8"
REVISION = "967d4d0bce9cb55a9b889e2cda5e8619ff512810"
CASES = {"724": ("sat", 209, 8013, 16808), "990001": ("unsat", 64, 94, 4)}
PHASE_KEYS = {"target_calls", "target_ok", "target_errors", "empty_roots", "nonempty_roots",
              "neighbors", "first_physical", "second_physical", "second_virtual",
              "duplicated_physical", "id_join_errors"}
for name in ("impact_calls", "impact_seed", "impact_neighbor", "impact_seed_repeat",
             "impact_neighbor_repeat", "batch_hits", "batch_misses"):
    PHASE_KEYS.update((name, name + "_mixed"))


def need(test, message):
    if not test:
        raise ValueError(message)


def sha(buf):
    return hashlib.sha256(buf).hexdigest()


def read(buf):
    def pairs(items):
        result = dict(items)
        need(len(result) == len(items), "duplicate JSON key")
        return result
    return json.loads(buf, object_pairs_hook=pairs)


def load(path):
    need(path.is_file() and not path.is_symlink(), "missing/nonregular file: " + str(path))
    return path.read_bytes()


def phase(z, expected):
    need(set(z) == PHASE_KEYS and all(type(x) is int and x >= 0 for x in z.values()), "counter schema")
    need(z["target_errors"] == z["id_join_errors"] == 0 and
         z["target_calls"] == z["target_ok"] == z["empty_roots"] + z["nonempty_roots"] == expected,
         "incomplete target phase")
    need(z["nonempty_roots"] <= z["neighbors"] <= z["second_physical"] + z["second_virtual"] and
         z["first_physical"] == z["second_physical"] == z["duplicated_physical"], "physical ID join")
    for name in PHASE_KEYS:
        if name.endswith("_mixed"):
            need(z[name] <= z[name[:-6]], "mixed subset")
    for suffix in ("", "_mixed"):
        for role in ("seed", "neighbor"):
            need(z["impact_" + role + "_repeat" + suffix] <= z["impact_" + role + suffix], "repeated root count")
    need(z["impact_neighbor_mixed"] <= z["target_ok"], "impact/target overlap")


def reduce_case(k, a, row, catalog):
    status, n, fixed, post = CASES[k]
    need(a["schema"] == "single-audit-v1" and a["pid"] == row["pid"] and
         a["complete"] is True and a["errors"] == [] and a["terminal_outcome"] == status, "wrong PID/outcome")
    need(a["fixed_all_singleton"] is True and len(set(a["member_terms"])) == len(a["member_terms"]) == a["arity"] == n and
         len(a["row_atoms"]) == n - 1 and all(type(t) is int and 0 <= t < a["term_count"] for t in a["member_terms"]) and
         n*(n-1)//2 == a["fixed_live_pairs"] == a["full_group_pairs"] == a["terminal_materialized_pairs"] and
         a["terminal_live_pairs"] == 0, "wrong group or boundary")
    if k == "724":
        need(catalog["original_sha256"] == row["input_sha256"] and
             all(catalog[x] == a[x] for x in ("member_terms", "row_atoms")), "original group catalogue")
    selected = ("target_calls", "empty_roots", "duplicated_physical", "second_physical", "second_virtual")
    phases = {}
    for p, expected in (("fixed", fixed), ("post", post)):
        phase(a[p], expected)
        phases[p] = {x: a[p][x] for x in selected}

    def total(*keys):
        return sum(a[p][key] for p in phases for key in keys)
    dup = total("duplicated_physical")
    visits = total("second_physical", "second_virtual")
    return dict(answer=status, calls=1, phases=phases, duplicated_physical=dup, witness_visits=visits,
                share=str(Fraction(dup, visits)) if visits else None,
                mixed_root_repeats=total("impact_seed_repeat_mixed", "impact_neighbor_repeat_mixed"),
                mixed_root_audits=total("impact_seed_mixed", "impact_neighbor_mixed"))


def verify():
    run = read(load(HERE/"runs.json"))
    summary = read(load(STATUS))
    env_bytes = load(HERE/"base-env.json")
    need(run["schema"] == "single-audit-public-run-v1" and run["revision"] == summary["revision"] == REVISION and
         run["original_receipt_sha256"] == summary["receipt_sha256"] == RECEIPT and
         run["host_exe_sha256"] == summary["host_exe"] and run["host"] == summary["host"] == "aarch64-apple-darwin" and
         run["opt_level"] == summary["optimization_level"] == 0 and run["base_env_sha256"] == sha(env_bytes),
         "different source/build provenance")
    need(set(run["cases"]) == set(CASES) and len({r["pid"] for r in run["cases"].values()}) == len(CASES),
         "missing run or reused PID")
    catalog = read(load(HERE/"members-724.json"))
    result = {}
    for k, row in run["cases"].items():
        d = HERE/"raw"/k
        packet = load(d/"audit.json")
        stdout, stderr = load(d/"stdout"), load(d/"stderr")
        status = CASES[k][0]
        ext = "inputs/" + k + ".smt2"
        env = {**read(env_bytes), "EUF_VIPER_FABRIC_CHECKED_ROOT_RELATIONS": "1", "VPR_DESCRIPTOR": "off",
               "VPR_ANTECEDENTS": "off", "VPR_GROUP_ROWS": "on", "VPR_VIRTUAL_ADJACENCY": "on",
               "VPR_SINGLE_AUDIT": "<TMP>/" + k + "/audit.json", "TMPDIR": "<TMP>"}
        if k == "990001":
            env["EUF_VIPER_STREAM_PARSER"] = "1"
        need(sha(load(HERE/ext)) == row["input_sha256"] and row["rc"] == 0 and row["outcome"] == status and
             row["argv"] == ["<HOST_EXE>", "fabric-solve", "--engine", "quotient-portfolio", ext] and row["env"] == env,
             "wrong input or launch configuration")
        need(set(p.name for p in d.iterdir()) == {"audit.json", "stdout", "stderr"} and
             row["audit_sha256"] == sha(packet) and row["stdout_sha256"] == sha(stdout) and row["stderr_sha256"] == sha(stderr)
             and stdout == (status + "\n").encode() and stderr == b"", "output bytes or answer changed")
        result[k] = reduce_case(k, read(packet), row, catalog)
    need(summary["cases"] == result and summary["measured_speedup"] is None and
         summary["selected_candidate"] is None and summary["native_wmi_jobs"] == 0 and summary["competitor_rerun"] is False,
         "status does not reproduce")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        results = verify()
        if args.json:
            print(json.dumps(results, sort_keys=True, indent=2))
        else:
            for key, row in results.items():
                print(f"{key}: {row['answer']}, {row['duplicated_physical']:,}/{row['witness_visits']:,} duplicate physical checks")
    except (ValueError, TypeError, OSError, KeyError) as exc:
        raise SystemExit(f"replay rejected: {exc}") from exc
