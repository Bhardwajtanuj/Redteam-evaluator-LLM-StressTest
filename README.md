# Red-Team Evaluator

Test how well an LLM agent resists attacks from another agent, inside a sandbox that only holds fake secrets.

A defender agent (system prompt plus two tools) gets attacked over several rounds by an attacker agent. A judge checks whether any canary secret leaked or a restricted tool call ran, and the run produces numbers like attack success rate, policy-violation rate and trajectory errors.

## Quick start

```bash
git clone <this repo>
cd redteam_evaluator
python run_eval.py            # offline, no API key needed
python run_eval.py --matrix   # compare weak/medium/strong defenders with and without each defence layer
python -m pytest -q
```

Python 3.10+. The offline mode has no dependencies.

To try a real model:

```bash
pip install -r requirements.txt
export ANTHROPIC_API_KEY=...
python run_eval.py --backend anthropic --attacker llm
```

Only test agents you own or are allowed to test. The sandbox is fake, but the attack prompts are real techniques.

Full details a are in [DOCUMENTATION.md](DOCUMENTATION.md).
