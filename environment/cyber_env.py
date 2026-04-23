"""
environment/cyber_env.py

The core RL environment wrapper around DVWA.
Manages state observation, action dispatch, reward assignment,
and episode bookkeeping.
"""

import numpy as np
import time
import sys
import os
from typing import Tuple, Dict, Any

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from config.settings import (
    ATTACK_ACTIONS, DEFEND_ACTIONS,
    MAX_STEPS_PER_EP,
    REWARD_ATTACK_SUCCESS, REWARD_ATTACK_FAIL,
    REWARD_DEFEND_SUCCESS, REWARD_DEFEND_FAIL,
    REWARD_FALSE_POSITIVE,
)
from environment.attack_modules  import execute_attack
from environment.defend_modules  import execute_defense
from utils.logger import get_logger

log = get_logger("CyberEnv")


class CyberEnv:
    """
    Gym-style environment wrapping a live DVWA instance.

    State vector (10 float features, discretised for Q-table):
      [0]  successful_attacks      normalised 0-1 (cap 20)
      [1]  failed_attacks          normalised 0-1 (cap 20)
      [2]  blocked_by_defender     normalised 0-1 (cap 20)
      [3]  session_resets          normalised 0-1 (cap 5)
      [4]  waf_triggers            normalised 0-1 (cap 10)
      [5]  ip_blocked              binary
      [6]  in_honeypot             binary
      [7]  rate_limited            binary
      [8]  step_fraction           fraction of episode elapsed 0-1
      [9]  last_attack_success     binary (last step result)
    """

    N_STATE_FEATURES  = 10
    N_ATK_ACTIONS     = len(ATTACK_ACTIONS)
    N_DEF_ACTIONS     = len(DEFEND_ACTIONS)

    def __init__(self, dvwa_session):
        self.session    = dvwa_session
        self.step_count = 0
        self.episode    = 0
        self._counters  = self._blank_counters()
        self._atk_hist  = []
        self._def_hist  = []
        self._shared_state = {}   # passed to defense context

    # ── Public API ────────────────────────────────────────────────────────────

    def reset(self) -> Tuple[tuple, np.ndarray]:
        """Start a new episode. Returns (discrete_state, float_state_vec)."""
        self.step_count    = 0
        self.episode      += 1
        self._counters     = self._blank_counters()
        self._atk_hist     = []
        self._def_hist     = []
        self._shared_state = {
            "ip_blocked":  False,
            "in_honeypot": False,
            "rate_limited":False,
        }
        vec = self._build_state_vec()
        log.debug(f"[Env] Episode {self.episode} reset")
        return self._discretize(vec), vec

    def step(self, atk_idx: int, def_idx: int) -> Tuple[tuple, np.ndarray, float, float, bool, Dict]:
        """
        Execute one attacker + defender action pair.
        Returns: (next_state, next_vec, atk_reward, def_reward, done, info)
        """
        atk_name = ATTACK_ACTIONS[atk_idx]
        def_name = DEFEND_ACTIONS[def_idx]

        # ── 1. Build defense context (includes current payload knowledge) ──
        defense_ctx = {
            "session":       self.session,
            "state":         self._shared_state,
            "attack_action": atk_name,
            "payload":       self._get_representative_payload(atk_name),
        }

        # ── 2. Defender acts first (pre-emptive WAF / IP block) ──
        def_result = execute_defense(def_name, defense_ctx)

        # ── 3. Attacker executes — unless blocked ──
        is_blocked_pre = (
            self._shared_state.get("ip_blocked")   or
            self._shared_state.get("in_honeypot")
        )

        if is_blocked_pre:
            # Defender already neutralised — fake a blocked result
            from environment.attack_modules import AttackResult
            atk_result = AttackResult(
                action=atk_name, success=False, payload="[BLOCKED]",
                response_code=403, evidence="Blocked before execution",
                raw_snippet="", duration_ms=0.0
            )
        else:
            atk_result = execute_attack(atk_name, self.session)

        # ── 4. Update counters ──
        attack_succeeded = atk_result.success and not def_result.would_block
        was_blocked      = def_result.would_block or is_blocked_pre

        if attack_succeeded:
            self._counters["successful_attacks"] += 1
            self._counters["last_attack_success"] = 1
        else:
            self._counters["failed_attacks"] += 1
            self._counters["last_attack_success"] = 0

        if was_blocked:
            self._counters["blocked_by_defender"] += 1

        if def_name == "waf_rule_sqli" or def_name == "waf_rule_xss":
            if def_result.would_block:
                self._counters["waf_triggers"] += 1

        if def_name == "reset_session":
            self._counters["session_resets"] += 1

        # ── 5. Assign rewards ──
        if was_blocked:
            atk_reward = REWARD_ATTACK_FAIL
            def_reward = REWARD_DEFEND_SUCCESS
        elif attack_succeeded:
            atk_reward = REWARD_ATTACK_SUCCESS
            def_reward = REWARD_DEFEND_FAIL
        else:
            atk_reward = REWARD_ATTACK_FAIL // 2
            def_reward = REWARD_DEFEND_SUCCESS // 4

        # Penalise false positives (block_ip when attack didn't even succeed yet)
        if def_name == "block_ip" and not atk_result.success:
            def_reward += REWARD_FALSE_POSITIVE

        # ── 6. Advance state ──
        self.step_count += 1
        done = self.step_count >= MAX_STEPS_PER_EP

        next_vec   = self._build_state_vec()
        next_state = self._discretize(next_vec)

        info = {
            "episode":          self.episode,
            "step":             self.step_count,
            "atk_action":       atk_name,
            "def_action":       def_name,
            "atk_payload":      atk_result.payload,
            "atk_evidence":     atk_result.evidence,
            "atk_result_code":  atk_result.response_code,
            "attack_succeeded": attack_succeeded,
            "was_blocked":      was_blocked,
            "def_would_block":  def_result.would_block,
            "def_method":       def_result.method,
            "atk_reward":       atk_reward,
            "def_reward":       def_reward,
            "atk_duration_ms":  atk_result.duration_ms,
            "def_duration_ms":  def_result.duration_ms,
            "done":             done,
        }

        self._atk_hist.append({"action": atk_name, "reward": atk_reward, "success": attack_succeeded})
        self._def_hist.append({"action": def_name, "reward": def_reward, "blocked": was_blocked})

        return next_state, next_vec, atk_reward, def_reward, done, info

    def get_episode_summary(self) -> dict:
        atk_rewards = [e["reward"] for e in self._atk_hist]
        def_rewards = [e["reward"] for e in self._def_hist]
        return {
            "episode":          self.episode,
            "steps":            self.step_count,
            "atk_total_reward": sum(atk_rewards),
            "def_total_reward": sum(def_rewards),
            "attacks_won":      sum(1 for e in self._atk_hist if e["success"]),
            "attacks_blocked":  sum(1 for e in self._def_hist if e["blocked"]),
            "atk_history":      self._atk_hist,
            "def_history":      self._def_hist,
        }

    # ── Private helpers ───────────────────────────────────────────────────────

    def _blank_counters(self) -> dict:
        return {
            "successful_attacks":  0,
            "failed_attacks":      0,
            "blocked_by_defender": 0,
            "session_resets":      0,
            "waf_triggers":        0,
            "last_attack_success": 0,
        }

    def _build_state_vec(self) -> np.ndarray:
        c = self._counters
        s = self._shared_state
        step_frac = self.step_count / MAX_STEPS_PER_EP

        vec = np.array([
            min(c["successful_attacks"],  20) / 20,
            min(c["failed_attacks"],      20) / 20,
            min(c["blocked_by_defender"], 20) / 20,
            min(c["session_resets"],       5) /  5,
            min(c["waf_triggers"],        10) / 10,
            float(s.get("ip_blocked",   False)),
            float(s.get("in_honeypot",  False)),
            float(s.get("rate_limited", False)),
            step_frac,
            float(c["last_attack_success"]),
        ], dtype=np.float32)
        return vec

    def _discretize(self, vec: np.ndarray) -> tuple:
        """Quantise to 5 bins per feature → hashable tuple for Q-table."""
        return tuple((vec * 5).astype(int).clip(0, 5).tolist())

    def _get_representative_payload(self, action_name: str) -> str:
        """Return a sample payload string for WAF pattern matching."""
        payloads = {
            "sqli_union":         "1' UNION SELECT user(),database()-- -",
            "sqli_boolean_blind": "1' AND 1=1-- -",
            "xss_reflected":      "<script>alert('XSS')</script>",
            "xss_stored":         "<script>alert('STORED')</script>",
            "cmd_injection":      "127.0.0.1; id",
            "file_inclusion":     "../../../../etc/passwd",
            "brute_force":        "admin:password",
            "csrf_probe":         "password_new=hacked",
        }
        return payloads.get(action_name, "")
