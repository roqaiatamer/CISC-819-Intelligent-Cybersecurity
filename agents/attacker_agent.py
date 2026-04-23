"""
agents/attacker_agent.py
Red-team AI attacker — subclasses QLearningAgent with offensive strategy.
"""

import random
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from agents.q_agent      import QLearningAgent
from config.settings     import ATTACK_ACTIONS
from utils.logger        import get_logger

log = get_logger("Attacker")


class AttackerAgent(QLearningAgent):
    """
    AI-driven red-team agent.

    Strategy enhancements over base Q-learning:
    - Recon-first bias: prefers brute_force / sqli early in episode
    - Exploit persistence: once an attack succeeds, slightly biases toward repeating it
    - Diversification: penalises repeatedly choosing the same failed action
    """

    def __init__(self):
        super().__init__(
            n_actions=len(ATTACK_ACTIONS),
            name="AttackerAgent",
            color="red"
        )
        self._last_success: int    = -1    # index of last successful attack
        self._action_fails: dict   = {}    # action_idx → consecutive fail count
        self._recon_phase : bool   = True
        self._steps_this_ep: int   = 0

    def new_episode(self):
        self._last_success  = -1
        self._action_fails  = {i: 0 for i in range(self.n_actions)}
        self._recon_phase   = True
        self._steps_this_ep = 0

    def choose_action(self, state: tuple, greedy: bool = False) -> int:
        self._steps_this_ep += 1

        # Pure exploitation if requested
        if greedy:
            return int(__import__("numpy").argmax(self.get_q_values(state)))

        # Exploration
        if random.random() < self.epsilon:
            # Recon phase: bias toward reconnaissance-style attacks first
            if self._recon_phase and self._steps_this_ep <= 3:
                recon_actions = [
                    ATTACK_ACTIONS.index("brute_force"),
                    ATTACK_ACTIONS.index("sqli_union"),
                    ATTACK_ACTIONS.index("xss_reflected"),
                ]
                return random.choice(recon_actions)
            return random.randrange(self.n_actions)

        # Exploitation with strategic nudge
        q_vals = self.get_q_values(state).copy()

        # Boost last successful action slightly
        if self._last_success >= 0:
            q_vals[self._last_success] *= 1.15

        # Penalise repeatedly failing actions
        for idx, fails in self._action_fails.items():
            if fails >= 3:
                q_vals[idx] *= 0.85

        return int(q_vals.argmax())

    def observe_result(self, action_idx: int, success: bool):
        """Called after each step to update strategy state."""
        if success:
            self._last_success = action_idx
            self._action_fails[action_idx] = 0
            self._recon_phase  = False
        else:
            self._action_fails[action_idx] = self._action_fails.get(action_idx, 0) + 1

    def action_name(self, idx: int) -> str:
        return ATTACK_ACTIONS[idx]

    def best_attack(self) -> str:
        return self.best_action_name(ATTACK_ACTIONS)
