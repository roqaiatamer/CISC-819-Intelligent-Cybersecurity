"""
forensics/forensics.py

Digital forensics module:
  • Logs every battle event to JSONL file
  • Detects attack patterns (frequency, success chains, pivot sequences)
  • Reconstructs attack timeline
  • Generates JSON + human-readable forensic report
"""

import json
import os
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from config.settings import (
    ATTACK_ACTIONS, DEFEND_ACTIONS,
    BATTLE_LOG, FORENSIC_REPORT, LOG_DIR, REPORT_DIR,
)
from utils.logger import get_logger

log = get_logger("Forensics")


class ForensicsModule:

    def __init__(self):
        os.makedirs(LOG_DIR,    exist_ok=True)
        os.makedirs(REPORT_DIR, exist_ok=True)

        # Clear stale log
        open(BATTLE_LOG, "w").close()

        self._events    : List[dict]  = []
        self._episodes  : List[dict]  = []
        self._start_time: float       = time.time()
        self._attack_chains: List[List[str]] = []   # sequences of successful attacks
        self._current_chain: List[str]       = []

    # ── Event ingestion ───────────────────────────────────────────────────────

    def log_step(self, info: dict):
        event = {
            "ts":               datetime.now(timezone.utc).isoformat(),
            "episode":          info["episode"],
            "step":             info["step"],
            "atk_action":       info["atk_action"],
            "def_action":       info["def_action"],
            "atk_payload":      info.get("atk_payload", ""),
            "atk_evidence":     info.get("atk_evidence", ""),
            "atk_result_code":  info.get("atk_result_code", 0),
            "attack_succeeded": info["attack_succeeded"],
            "was_blocked":      info["was_blocked"],
            "def_method":       info.get("def_method", ""),
            "atk_reward":       info["atk_reward"],
            "def_reward":       info["def_reward"],
            "atk_ms":           info.get("atk_duration_ms", 0),
            "def_ms":           info.get("def_duration_ms", 0),
        }
        self._events.append(event)

        # Track attack chains
        if info["attack_succeeded"]:
            self._current_chain.append(info["atk_action"])
        else:
            if len(self._current_chain) >= 2:
                self._attack_chains.append(self._current_chain[:])
            self._current_chain = []

        # Write to JSONL log immediately (real-time)
        with open(BATTLE_LOG, "a") as f:
            f.write(json.dumps(event) + "\n")

    def log_episode(self, summary: dict):
        self._episodes.append(summary)

    # ── Pattern detection ─────────────────────────────────────────────────────

    def detect_patterns(self) -> dict:
        if not self._events:
            return {}

        atk_counts   = Counter(e["atk_action"]  for e in self._events)
        def_counts   = Counter(e["def_action"]   for e in self._events)
        atk_successes= Counter(e["atk_action"]   for e in self._events if e["attack_succeeded"])
        def_blocks   = Counter(e["def_action"]   for e in self._events if e["was_blocked"])

        # Success rate per attack
        atk_rates = {
            a: round(atk_successes[a] / atk_counts[a], 4) if atk_counts[a] else 0.0
            for a in ATTACK_ACTIONS
        }

        # Block rate per defense
        def_rates = {
            d: round(def_blocks[d] / def_counts[d], 4) if def_counts[d] else 0.0
            for d in DEFEND_ACTIONS
        }

        # Response time analysis
        avg_atk_ms = round(sum(e["atk_ms"] for e in self._events) / max(len(self._events),1), 1)
        avg_def_ms = round(sum(e["def_ms"] for e in self._events) / max(len(self._events),1), 1)

        total     = len(self._events)
        successes = sum(1 for e in self._events if e["attack_succeeded"])
        blocked   = sum(1 for e in self._events if e["was_blocked"])

        # Reward trends per episode
        ep_rewards = [
            {"ep": s["episode"],
             "atk": s["atk_total_reward"],
             "def": s["def_total_reward"]}
            for s in self._episodes
        ]

        return {
            "total_events":          total,
            "total_successes":       successes,
            "total_blocked":         blocked,
            "overall_atk_win_rate":  round(successes / max(total, 1), 4),
            "overall_def_win_rate":  round(blocked   / max(total, 1), 4),
            "attack_usage_counts":   dict(atk_counts),
            "defense_usage_counts":  dict(def_counts),
            "attack_success_rates":  atk_rates,
            "defense_block_rates":   def_rates,
            "most_used_attack":      atk_counts.most_common(1)[0] if atk_counts else None,
            "most_used_defense":     def_counts.most_common(1)[0] if def_counts else None,
            "most_successful_attack":atk_successes.most_common(1)[0] if atk_successes else None,
            "most_effective_defense":def_blocks.most_common(1)[0] if def_blocks else None,
            "attack_chains_detected":len(self._attack_chains),
            "avg_chain_length":      round(sum(len(c) for c in self._attack_chains) /
                                           max(len(self._attack_chains), 1), 2),
            "avg_atk_response_ms":   avg_atk_ms,
            "avg_def_response_ms":   avg_def_ms,
            "episode_rewards":       ep_rewards,
        }

    # ── Timeline ──────────────────────────────────────────────────────────────

    def get_timeline(self, last_n: int = 100) -> List[dict]:
        return self._events[-last_n:]

    def reconstruct_attack_path(self, episode: int) -> List[str]:
        """Return ordered list of successful attacks in one episode."""
        return [
            e["atk_action"]
            for e in self._events
            if e["episode"] == episode and e["attack_succeeded"]
        ]

    # ── Report generation ─────────────────────────────────────────────────────

    def generate_report(self, attacker_stats: dict, defender_stats: dict) -> dict:
        patterns = self.detect_patterns()
        elapsed  = round(time.time() - self._start_time, 1)

        report = {
            "meta": {
                "generated_at":      datetime.now(timezone.utc).isoformat(),
                "simulation_time_s": elapsed,
                "total_episodes":    len(self._episodes),
                "total_steps":       len(self._events),
            },
            "attacker_stats":  attacker_stats,
            "defender_stats":  defender_stats,
            "patterns":        patterns,
            "attack_chains":   self._attack_chains[:20],   # top 20 chains
            "recommendations": self._recommendations(patterns),
        }

        with open(FORENSIC_REPORT, "w") as f:
            json.dump(report, f, indent=2)
        log.info(f"Forensic report saved → {FORENSIC_REPORT}")
        return report

    def _recommendations(self, p: dict) -> List[str]:
        recs = []
        for atk, rate in p.get("attack_success_rates", {}).items():
            if rate >= 0.7:
                recs.append({
                    "level":   "CRITICAL",
                    "message": f"'{atk}' has {rate*100:.0f}% success — implement specific countermeasure immediately.",
                })
            elif rate >= 0.4:
                recs.append({
                    "level":   "HIGH",
                    "message": f"'{atk}' has {rate*100:.0f}% success — increase defender response priority.",
                })
            elif rate < 0.1:
                recs.append({
                    "level":   "OK",
                    "message": f"'{atk}' well-contained at {rate*100:.0f}% — current defense is effective.",
                })

        for d, rate in p.get("defense_block_rates", {}).items():
            if rate >= 0.6:
                recs.append({
                    "level":   "INFO",
                    "message": f"'{d}' is most effective defense ({rate*100:.0f}% block rate) — prioritise this.",
                })

        atk_win = p.get("overall_atk_win_rate", 0)
        if atk_win > 0.6:
            recs.append({"level":"WARNING", "message":"Attacker is dominating — increase max_episodes or adjust reward weights."})
        elif atk_win < 0.3:
            recs.append({"level":"SUCCESS", "message":"Defender is winning — consider raising security level in DVWA for next run."})
        else:
            recs.append({"level":"INFO",    "message":"Balanced battle — both agents learning effectively."})

        return recs

    # ── Console summary ───────────────────────────────────────────────────────

    def print_summary(self, report: dict):
        p   = report["patterns"]
        meta= report["meta"]
        sep = "═" * 65

        print(f"\n{sep}")
        print("  📋  DIGITAL FORENSIC REPORT")
        print(sep)
        print(f"  Simulation time : {meta['simulation_time_s']}s")
        print(f"  Episodes        : {meta['total_episodes']}")
        print(f"  Total steps     : {meta['total_steps']}")
        print(f"  Attacker wins   : {p.get('overall_atk_win_rate',0)*100:.1f}%")
        print(f"  Defender wins   : {p.get('overall_def_win_rate',0)*100:.1f}%")
        print(f"  Attack chains   : {p.get('attack_chains_detected',0)} (avg len {p.get('avg_chain_length',0)})")
        print(f"\n  Attack Success Rates:")
        for atk, rate in p.get("attack_success_rates", {}).items():
            bar  = "█" * int(rate * 25)
            flag = " ⚠" if rate > 0.6 else (" ✅" if rate < 0.1 else "")
            print(f"    {atk:<24} {bar:<25} {rate*100:.1f}%{flag}")
        print(f"\n  Defense Block Rates:")
        for d, rate in p.get("defense_block_rates", {}).items():
            bar = "█" * int(rate * 25)
            print(f"    {d:<22} {bar:<25} {rate*100:.1f}%")
        print(f"\n  Recommendations:")
        for r in report.get("recommendations", []):
            icon = {"CRITICAL":"🔴","HIGH":"🟠","WARNING":"🟡","OK":"🟢","SUCCESS":"✅","INFO":"🔵"}.get(r["level"],"•")
            print(f"    {icon} [{r['level']}] {r['message']}")
        print(sep)
