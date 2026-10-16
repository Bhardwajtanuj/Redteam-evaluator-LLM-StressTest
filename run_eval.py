import argparse
import json
import pathlib
import sys

from redteam.llm import AnthropicBackend, SimulatedDefender, SimulatedJudgeLLM
from redteam.orchestrator import Orchestrator, load_scenarios


def build(args, profile, guard, enforce):
    if args.backend == "sim":
        return Orchestrator(SimulatedDefender(profile), None, SimulatedJudgeLLM(),
                            "scripted", guard, enforce, args.rounds)
    model = AnthropicBackend(args.model)
    judge = AnthropicBackend(args.model, max_tokens=10, temperature=0) if args.llm_judge else None
    if args.attacker == "llm":
        return Orchestrator(model, model, judge, "llm", guard, enforce, args.rounds)
    return Orchestrator(model, None, judge, "scripted", guard, enforce, args.rounds)


def show(title, rep):
    s = rep["summary"]
    print(f"\n== {title} ==")
    print(f"ASR {s['asr_pct']}% | policy-violation rate {s['policy_violation_rate_pct']}% | "
          f"executed violations {s['executed_violations']} | trajectory errors {s['trajectory_error_count']}")
    print(f"avg tokens {s['avg_tokens_per_scenario']} | avg latency {s['avg_latency_s']}s | "
          f"guard blocks {s['guard_blocks']} | resource abuse {s['resource_abuse_scenarios']}")
    print("by category:", s["asr_by_category_pct"])
    print("cumulative ASR by round:", " ".join(f"r{c['round']}={c['cumulative_asr_pct']}%" for c in s["safety_boundary_curve"]))
    for r in rep["results"]:
        status = "BREACH" if r["breached"] else "held"
        print(f"  {status:<7}{r['scenario_id']:<20} rounds={r['rounds_run']} {r['reasons']}")


def run_matrix(args, scenarios, out):
    rows = []
    for prof in ("weak", "medium", "strong"):
        for guard in ("none", "heuristic"):
            for enforce in (False, True):
                s = build(args, prof, guard, enforce).run_all(scenarios)["summary"]
                rows.append({"profile": prof, "guard": guard, "enforce_tool_policy": enforce,
                             "asr_pct": s["asr_pct"], "executed_violations": s["executed_violations"],
                             "policy_violation_rate_pct": s["policy_violation_rate_pct"],
                             "trajectory_errors": s["trajectory_error_count"]})
    (out / "matrix.json").write_text(json.dumps(rows, indent=2))
    print(f"{'profile':<8} {'guard':<10} {'enforce':<8} {'ASR%':>6} {'exec.viol':>10} {'PV rate%':>9} {'traj.err':>9}")
    for r in rows:
        print(f"{r['profile']:<8} {r['guard']:<10} {str(r['enforce_tool_policy']):<8} {r['asr_pct']:>6} "
              f"{r['executed_violations']:>10} {r['policy_violation_rate_pct']:>9} {r['trajectory_errors']:>9}")
    print(f"\nsaved {out / 'matrix.json'}")


def main(argv=None):
    p = argparse.ArgumentParser(description="Red-team a sandboxed LLM agent.")
    p.add_argument("--backend", choices=["sim", "anthropic"], default="sim")
    p.add_argument("--profile", choices=["weak", "medium", "strong"], default="medium", help="sim defender only")
    p.add_argument("--guard", choices=["heuristic", "none"], default="heuristic")
    p.add_argument("--no-enforce-tool-policy", action="store_true", help="log violations but let them run")
    p.add_argument("--rounds", type=int, default=5)
    p.add_argument("--scenarios", help="path to your own scenarios.json")
    p.add_argument("--attacker", choices=["scripted", "llm"], default="scripted")
    p.add_argument("--llm-judge", action="store_true")
    p.add_argument("--model")
    p.add_argument("--out", default="reports")
    p.add_argument("--matrix", action="store_true", help="sim only: try every profile/guard/enforcement combo")
    args = p.parse_args(argv)

    scenarios = load_scenarios(args.scenarios)
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    if args.matrix:
        if args.backend != "sim":
            sys.exit("--matrix only works with --backend sim")
        return run_matrix(args, scenarios, out)

    enforce = not args.no_enforce_tool_policy
    rep = build(args, args.profile, args.guard, enforce).run_all(scenarios)
    (out / "report.json").write_text(json.dumps(rep, indent=2))
    show(f"{args.backend}/{args.profile} guard={args.guard} enforce={enforce}", rep)
    print(f"\nfull report: {out / 'report.json'}")


if __name__ == "__main__":
    main()
