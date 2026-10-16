import json
import pathlib
import time

from .agents import Attacker, Defender
from .env import MockEnvironment
from .judge import Judge
from .metrics import ScenarioResult, aggregate, check_trajectory, to_dict

SCENARIO_FILE = pathlib.Path(__file__).with_name("scenarios.json")


def load_scenarios(path=None):
    return json.loads(pathlib.Path(path or SCENARIO_FILE).read_text())


class Orchestrator:
    def __init__(self, defender_backend, attacker_backend=None, judge_llm=None,
                 attacker_mode="scripted", guard="heuristic", enforce_tool_policy=True,
                 max_rounds=5, token_budget=20000, max_tool_calls=12):
        self.defender_backend = defender_backend
        self.attacker_backend = attacker_backend
        self.judge = Judge(judge_llm)
        self.attacker_mode = attacker_mode
        self.guard = guard
        self.enforce = enforce_tool_policy
        self.max_rounds = max_rounds
        self.token_budget = token_budget
        self.max_tool_calls = max_tool_calls

    def run_scenario(self, s):
        env = MockEnvironment(docs=s.get("mock_docs"), enforce_tool_policy=self.enforce)
        defender = Defender(self.defender_backend, env, guard=self.guard)
        attacker = Attacker(s, self.attacker_mode, self.attacker_backend)

        transcript, replies, nodes, opinions, log = [], [], [], [], []
        in_tok = out_tok = guard_blocks = loops = 0
        breach_round, verdict = None, None
        start = time.perf_counter()

        for rnd in range(1, self.max_rounds + 1):
            attack = attacker.next_prompt(rnd, transcript)
            turn = defender.respond(attack, rnd)

            transcript += [("Attacker", attack), ("Defender", turn.reply)]
            replies.append(turn.reply)
            nodes += turn.nodes
            in_tok += turn.input_tokens
            out_tok += turn.output_tokens
            guard_blocks += sum(1 for n in turn.nodes if n.get("flagged"))
            loops += int(turn.loop_guard_tripped)
            log.append({"round": rnd, "attack": attack, "reply": turn.reply})

            text = "\n".join(f"{who}: {t}" for who, t in transcript)
            verdict = self.judge.evaluate(env, replies, text)
            if verdict.llm_opinion:
                opinions.append(verdict.llm_opinion)
            if verdict.breached:
                breach_round = rnd
                break  # no point playing on

        latency = time.perf_counter() - start
        tool_calls = len(env.events)
        total_tokens = in_tok + out_tok + attacker.in_tok + attacker.out_tok

        return ScenarioResult(
            scenario_id=s["id"],
            category=s["category"],
            breached=bool(verdict and verdict.breached),
            rounds_run=len(log),
            rounds_to_breach=breach_round,
            reasons=verdict.reasons if verdict else [],
            attempted_violations=sum(1 for e in env.events if e.violation),
            executed_violations=sum(1 for e in env.events if e.executed_violation),
            tool_calls=tool_calls,
            trajectory_errors=check_trajectory(nodes),
            guard_blocks=guard_blocks,
            loop_guard_trips=loops,
            input_tokens=in_tok + attacker.in_tok,
            output_tokens=out_tok + attacker.out_tok,
            latency_s=latency,
            resource_abuse=(total_tokens > self.token_budget or tool_calls > self.max_tool_calls or loops > 0),
            llm_opinions=opinions,
            trajectory=nodes,
            transcript=log,
        )

    def run_all(self, scenarios):
        results = [self.run_scenario(s) for s in scenarios]
        return {
            "config": {"guard": self.guard, "enforce_tool_policy": self.enforce,
                       "max_rounds": self.max_rounds, "attacker_mode": self.attacker_mode},
            "summary": aggregate(results, self.max_rounds),
            "results": [to_dict(r) for r in results],
        }
