"""
train.py
══════════════════════════════════════════════════════════════
AI Cyber Warfare Simulation — Main Training Engine
══════════════════════════════════════════════════════════════

Usage:
    python train.py                        # default 300 episodes
    python train.py --episodes 500
    python train.py --episodes 100 --quiet
    python train.py --resume               # load saved models + continue
    python train.py --eval                 # greedy evaluation only (no training)

Prerequisites:
    1. DVWA running (Docker recommended — see README.md)
    2. .env configured (copy .env.example → .env, set DVWA_URL)
    3. pip install -r requirements.txt
"""

import sys
import os
import time
import argparse

# ── path fix so all imports resolve regardless of CWD ─────────────────────────
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

from config.settings       import (MAX_EPISODES, MAX_STEPS_PER_EP,
                                    ATTACK_ACTIONS, DEFEND_ACTIONS, DVWA_URL)
from environment.dvwa_session  import DVWASession
from environment.cyber_env     import CyberEnv
from agents.attacker_agent     import AttackerAgent
from agents.defender_agent     import DefenderAgent
from forensics.forensics       import ForensicsModule
from utils.logger              import get_logger

log = get_logger("Train")


# ─────────────────────────────────────────────────────────────────────────────
BANNER = r"""
  ██████╗██╗   ██╗██████╗ ███████╗██████╗     ██╗    ██╗ █████╗ ██████╗
 ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗    ██║    ██║██╔══██╗██╔══██╗
 ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝    ██║ █╗ ██║███████║██████╔╝
 ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗    ██║███╗██║██╔══██║██╔══██╗
 ╚██████╗   ██║   ██████╔╝███████╗██║  ██║    ╚███╔███╔╝██║  ██║██║  ██║
  ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝     ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝
     AI Cyber Warfare Simulation v2.0 — DVWA Integration
"""
# ─────────────────────────────────────────────────────────────────────────────


def print_step(ep, step, info, atk_eps, def_eps):
    """Single-step console output."""
    status = "✅ BREACH " if info["attack_succeeded"] else \
             "🛡  BLOCKED" if info["was_blocked"]     else "❌ MISSED "
    print(
        f"  Ep {ep:>4} | Step {step:>2} | "
        f"ATK: {info['atk_action']:<22} "
        f"DEF: {info['def_action']:<18} "
        f"{status} | "
        f"R_atk={info['atk_reward']:+3d}  R_def={info['def_reward']:+3d}"
    )


def print_ep_summary(ep, n_episodes, summary, atk, defender):
    atk_r = summary["atk_total_reward"]
    def_r = summary["def_total_reward"]
    won   = summary["attacks_won"]
    blkd  = summary["attacks_blocked"]
    steps = summary["steps"]
    win_r = won / max(won + blkd, 1)
    bar   = "█" * int(win_r * 20) + "░" * (20 - int(win_r * 20))
    print(
        f"\n  ── Ep {ep:>4}/{n_episodes}  "
        f"ε={atk.epsilon:.3f}  "
        f"ATK_R={atk_r:+5.0f}  DEF_R={def_r:+5.0f}  "
        f"Wins={won}/{steps}  [{bar}] {win_r:.0%}\n"
    )


# ─────────────────────────────────────────────────────────────────────────────
def run(n_episodes: int, quiet: bool, resume: bool, eval_only: bool):

    print(BANNER)
    print(f"  Target  : {DVWA_URL}")
    print(f"  Episodes: {n_episodes}   Steps/ep: {MAX_STEPS_PER_EP}")
    print(f"  Mode    : {'EVALUATION' if eval_only else 'TRAINING'}")
    if resume:
        print(f"  Resuming from saved models …")
    print()

    # ── Connect to DVWA ───────────────────────────────────────────────────────
    dvwa = DVWASession()
    if not dvwa.connect(retries=8, delay=4.0):
        print("\n[ERROR] Cannot reach DVWA. Make sure it is running.")
        print(f"        Expected URL: {DVWA_URL}")
        print("        See README.md → 'Starting DVWA with Docker'\n")
        sys.exit(1)

    # ── Init components ───────────────────────────────────────────────────────
    env       = CyberEnv(dvwa)
    attacker  = AttackerAgent()
    defender  = DefenderAgent()
    forensics = ForensicsModule()

    if resume or eval_only:
        attacker.load()
        defender.load()
        if eval_only:
            attacker.epsilon = 0.0
            defender.epsilon = 0.0

    os.makedirs("models",  exist_ok=True)
    sim_start = time.time()

    # ── Episode loop ──────────────────────────────────────────────────────────
    for ep in range(1, n_episodes + 1):
        state, _vec = env.reset()
        attacker.new_episode()
        defender.new_episode()

        last_atk_action = ""

        for step in range(MAX_STEPS_PER_EP):

            # Agents choose actions
            atk_idx = attacker.choose_action(state, greedy=eval_only)
            def_idx = defender.choose_action(state, greedy=eval_only,
                                             last_atk_action=last_atk_action)

            # Environment step
            next_state, _nv, atk_r, def_r, done, info = env.step(atk_idx, def_idx)

            # Agents learn (skip in eval mode)
            if not eval_only:
                attacker.update(state, atk_idx, atk_r, next_state, done)
                defender.update(state, def_idx, def_r, next_state, done)

            # Domain updates
            attacker.observe_result(atk_idx, info["attack_succeeded"])
            defender.observe_outcome(info["attack_succeeded"])

            # Logging
            forensics.log_step(info)

            if not quiet:
                print_step(ep, step + 1, info, attacker.epsilon, defender.epsilon)

            last_atk_action = info["atk_action"]
            state = next_state
            if done:
                break

        # Episode wrap-up
        attacker.decay_epsilon()
        defender.decay_epsilon()

        summary = env.get_episode_summary()
        forensics.log_episode(summary)

        if not quiet or ep % 25 == 0:
            print_ep_summary(ep, n_episodes, summary, attacker, defender)

        # Periodic model save every 50 episodes
        if ep % 50 == 0 and not eval_only:
            attacker.save()
            defender.save()
            log.info(f"Models auto-saved at episode {ep}")

        # Health-check every 25 episodes
        if ep % 25 == 0:
            if not dvwa.health_check():
                log.warning("DVWA health-check failed — attempting reconnect …")
                dvwa.connect(retries=3, delay=2.0)

    # ── Final save ────────────────────────────────────────────────────────────
    if not eval_only:
        attacker.save()
        defender.save()

    elapsed = time.time() - sim_start

    # ── Forensic report ───────────────────────────────────────────────────────
    report = forensics.generate_report(attacker.stats(), defender.stats())
    forensics.print_summary(report)

    print(f"\n[DONE] Total time: {elapsed:.1f}s")
    print(f"  Models  → models/")
    print(f"  Log     → logs/battle.jsonl")
    print(f"  Report  → reports/forensics_report.json")
    print(f"  Dashboard → open dashboard/index.html in browser\n")

    return attacker, defender, forensics, report


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="AI Cyber Warfare Simulation — DVWA Training Engine"
    )
    parser.add_argument("--episodes", type=int, default=MAX_EPISODES,
                        help=f"Number of training episodes (default: {MAX_EPISODES})")
    parser.add_argument("--quiet",  action="store_true",
                        help="Suppress per-step output (episode summaries only)")
    parser.add_argument("--resume", action="store_true",
                        help="Load saved Q-tables and continue training")
    parser.add_argument("--eval",   action="store_true",
                        help="Evaluation mode: run greedy agents, no learning")
    args = parser.parse_args()

    run(
        n_episodes = args.episodes,
        quiet      = args.quiet,
        resume     = args.resume,
        eval_only  = args.eval,
    )
