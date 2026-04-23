"""
agents/defender_agent.py
Blue-team AI defender — subclasses QLearningAgent with defensive strategy.
"""

import random
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from agents.q_agent      import QLearningAgent
from config.settings     import DEFEND_ACTIONS, ATTACK_ACTIONS
from utils.logger        import get_logger

log = get_logger("Defender")


class DefenderAgent(QLearningAgent):
    """
    AI-driven blue-team agent.

    Strategy enhancements:
    - Threat escalation: intensifies response after consecutive successful attacks
    - Attack-type awareness: maps observed attack category to specialised WAF rules
    - False-positive avoidance: reluctant to block_ip too early
    """

    # Maps attack action → preferred defense action
    THREAT_RESPONSE_MAP = {
        "sqli_union":         "waf_rule_sqli",
        "sqli_boolean_blind": "waf_rule_sqli",
        "xss_reflected":      "waf_rule_xss",
        "xss_stored":         "waf_rule_xss",
        "cmd_injection":      "block_ip",
        "file_inclusion":     "block_ip",
        "brute_force":        "rate_limit",
        "csrf_probe":         "reset_session",
    }

    def __init__(self):
        super().__init__(
            n_actions=len(DEFEND_ACTIONS),
            name="DefenderAgent",
            color="cyan"
        )
        self._attack_streak  : int  = 0    # consecutive successful attacks
        self._last_atk_action: str  = ""
        self._threat_level   : int  = 0    # 0=low 1=med 2=high

    def new_episode(self):
        self._attack_streak   = 0
        self._last_atk_action = ""
        self._threat_level    = 0

    def choose_action(self, state: tuple, greedy: bool = False,
                      last_atk_action: str = "") -> int:
        self._last_atk_action = last_atk_action

        # Pure greedy exploitation
        if greedy:
            return int(__import__("numpy").argmax(self.get_q_values(state)))

        # Escalation logic — override Q-table during high-threat periods
        if self._threat_level >= 2 and random.random() < 0.5:
            preferred = "block_ip"
            if preferred in DEFEND_ACTIONS:
                log.debug("[Defender] High threat — forcing block_ip")
                return DEFEND_ACTIONS.index(preferred)

        # Attack-type aware response (50% of the time when threat > 0)
        if self._threat_level >= 1 and last_atk_action and random.random() < 0.4:
            preferred = self.THREAT_RESPONSE_MAP.get(last_atk_action)
            if preferred and preferred in DEFEND_ACTIONS:
                log.debug(f"[Defender] Attack-aware response: {preferred}")
                return DEFEND_ACTIONS.index(preferred)

        # Epsilon-greedy with Q-table
        if random.random() < self.epsilon:
            return random.randrange(self.n_actions)

        q_vals = self.get_q_values(state).copy()

        # Discourage aggressive early block (false-positive risk)
        if self._attack_streak == 0:
            block_idx = DEFEND_ACTIONS.index("block_ip")
            q_vals[block_idx] *= 0.7

        return int(q_vals.argmax())

    def observe_outcome(self, attack_succeeded: bool):
        """Update threat level based on recent events."""
        if attack_succeeded:
            self._attack_streak += 1
        else:
            self._attack_streak = max(0, self._attack_streak - 1)

        # Update threat level
        if self._attack_streak == 0:
            self._threat_level = 0
        elif self._attack_streak <= 2:
            self._threat_level = 1
        else:
            self._threat_level = 2

    def action_name(self, idx: int) -> str:
        return DEFEND_ACTIONS[idx]

    def best_defense(self) -> str:
        return self.best_action_name(DEFEND_ACTIONS)
