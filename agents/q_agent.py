"""
agents/q_agent.py
Tabular Q-Learning agent — base class for Attacker and Defender.
Implements Bellman equation, epsilon-greedy selection, model persistence.
"""

import numpy as np
import random
import json
import os
import sys
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from config.settings import (
    LEARNING_RATE, DISCOUNT_FACTOR,
    EPSILON_START, EPSILON_MIN, EPSILON_DECAY,
    MODEL_DIR,
)
from utils.logger import get_logger


class QLearningAgent:
    """
    Tabular Q-Learning with:
      - Epsilon-greedy exploration
      - Bellman equation update
      - Q-table persistence (JSON)
      - Training statistics
    """

    def __init__(self, n_actions: int, name: str, color: str = "white"):
        self.n_actions   = n_actions
        self.name        = name
        self.color       = color        # for display only

        self.q_table     : dict         = {}
        self.epsilon     : float        = EPSILON_START
        self.lr          : float        = LEARNING_RATE
        self.gamma       : float        = DISCOUNT_FACTOR

        # Episode-level tracking
        self._ep_rewards : list         = []
        self._ep_wins    : list         = []

        # Lifetime tracking
        self.total_steps : int          = 0
        self.total_wins  : int          = 0
        self.total_losses: int          = 0

        self.log = get_logger(name)

    # ── Q-table ───────────────────────────────────────────────────────────────

    def _init_state(self, state: tuple):
        if state not in self.q_table:
            self.q_table[state] = np.zeros(self.n_actions, dtype=np.float64)

    def get_q_values(self, state: tuple) -> np.ndarray:
        self._init_state(state)
        return self.q_table[state]

    # ── Action selection (ε-greedy) ───────────────────────────────────────────

    def choose_action(self, state: tuple, greedy: bool = False) -> int:
        """
        Epsilon-greedy action selection.
        greedy=True → pure exploitation (used for evaluation).
        """
        if not greedy and random.random() < self.epsilon:
            return random.randrange(self.n_actions)
        return int(np.argmax(self.get_q_values(state)))

    # ── Bellman update ────────────────────────────────────────────────────────

    def update(self, state: tuple, action: int, reward: float,
               next_state: tuple, done: bool):
        """
        Q(s,a) ← Q(s,a) + α · [r + γ · max Q(s',·) − Q(s,a)]
        """
        self._init_state(state)
        self._init_state(next_state)

        q_sa      = self.q_table[state][action]
        q_next    = 0.0 if done else float(np.max(self.q_table[next_state]))
        td_target = reward + self.gamma * q_next
        td_error  = td_target - q_sa

        self.q_table[state][action] += self.lr * td_error

        # Stats
        self.total_steps += 1
        if reward > 0:
            self.total_wins   += 1
        elif reward < 0:
            self.total_losses += 1

    # ── Epsilon decay ─────────────────────────────────────────────────────────

    def decay_epsilon(self):
        self.epsilon = max(EPSILON_MIN, self.epsilon * EPSILON_DECAY)

    # ── Persistence ───────────────────────────────────────────────────────────

    def save(self, filename: Optional[str] = None):
        os.makedirs(MODEL_DIR, exist_ok=True)
        path = filename or os.path.join(MODEL_DIR, f"{self.name}.json")
        data = {
            "name":         self.name,
            "epsilon":      self.epsilon,
            "total_steps":  self.total_steps,
            "total_wins":   self.total_wins,
            "total_losses": self.total_losses,
            "q_table": {
                str(k): v.tolist()
                for k, v in self.q_table.items()
            }
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        self.log.info(f"Model saved → {path}  ({len(self.q_table)} states)")

    def load(self, filename: Optional[str] = None):
        path = filename or os.path.join(MODEL_DIR, f"{self.name}.json")
        if not os.path.exists(path):
            self.log.warning(f"No saved model found at {path} — starting fresh")
            return
        with open(path) as f:
            data = json.load(f)
        self.epsilon      = data.get("epsilon", self.epsilon)
        self.total_steps  = data.get("total_steps", 0)
        self.total_wins   = data.get("total_wins",  0)
        self.total_losses = data.get("total_losses",0)
        for k_str, v in data["q_table"].items():
            # Parse "(1, 2, 3, ...)" string back to tuple
            key = tuple(int(x) for x in k_str.strip("()").split(",") if x.strip())
            self.q_table[key] = np.array(v, dtype=np.float64)
        self.log.info(f"Model loaded ← {path}  ({len(self.q_table)} states)")

    # ── Stats ─────────────────────────────────────────────────────────────────

    def stats(self) -> dict:
        win_rate = (self.total_wins / max(self.total_steps, 1))
        return {
            "name":         self.name,
            "epsilon":      round(self.epsilon, 5),
            "total_steps":  self.total_steps,
            "total_wins":   self.total_wins,
            "total_losses": self.total_losses,
            "win_rate":     round(win_rate, 4),
            "q_states":     len(self.q_table),
        }

    def best_action_name(self, action_names: list) -> str:
        """Return name of action with highest average Q across all known states."""
        if not self.q_table:
            return action_names[0]
        total_q = np.zeros(self.n_actions)
        for q_vals in self.q_table.values():
            total_q += q_vals
        return action_names[int(np.argmax(total_q))]
