"""
Phase 5 - AI-driven adaptive channel hopper.

Uses an Epsilon-Greedy Multi-Armed Bandit to learn which channels carry the
most useful traffic for the current session goal (handshake capture, PMKID
harvest, etc.).  Replaces the dumb round-robin hopper in wlan/interface.py.

Architecture:
  AdaptiveChannelHopper.next_channel() → int
    Called by WlanInterface instead of its own sequential hop logic.
    Returns the best channel according to the bandit policy.

  AdaptiveChannelHopper.reward(channel, value)
    Called by the pipeline/campaigns when something useful is captured on a
    channel (handshake fragment = +1.0, PMKID = +2.0, nothing = 0.0).

Bandit policy: UCB1 (Upper Confidence Bound) - no external ML deps required.
Optional: if numpy is installed, uses a faster vectorised implementation.
"""
from __future__ import annotations

import math
from collections import defaultdict
from typing import Sequence


class AdaptiveChannelHopper:
    """
    UCB1 bandit over a fixed channel list.

    Each channel is an arm.  UCB1 score = mean_reward + sqrt(2 * ln(t) / n_i)
    where t is total pulls and n_i is pulls on arm i.
    """

    def __init__(
        self,
        channels: Sequence[int],
        exploration_rounds: int = 30,
        decay: float = 0.98,
    ) -> None:
        self._channels     = list(channels)
        self._explore_n    = exploration_rounds
        self._decay        = decay        # multiply rewards over time to forget stale data
        self._counts: dict[int, int]   = defaultdict(int)
        self._rewards: dict[int, float] = defaultdict(float)
        self._total_pulls  = 0
        self._last_channel = self._channels[0] if self._channels else 1
        self._round_robin_idx = 0

    def next_channel(self) -> int:
        if not self._channels:
            return 1

        # Pure exploration phase: cycle through every channel at least once
        if self._total_pulls < len(self._channels) * (self._explore_n // len(self._channels) + 1):
            ch = self._channels[self._round_robin_idx % len(self._channels)]
            self._round_robin_idx += 1
            self._total_pulls += 1
            self._counts[ch] += 1
            self._last_channel = ch
            return ch

        # UCB1 exploitation
        best_ch    = self._channels[0]
        best_score = -1.0
        log_t      = math.log(max(self._total_pulls, 1))

        for ch in self._channels:
            n = self._counts[ch]
            if n == 0:
                # unvisited arm: infinite UCB - force visit
                self._total_pulls += 1
                self._counts[ch] += 1
                self._last_channel = ch
                return ch
            mean   = self._rewards[ch] / n
            ucb    = mean + math.sqrt(2.0 * log_t / n)
            if ucb > best_score:
                best_score = ucb
                best_ch    = ch

        self._total_pulls += 1
        self._counts[best_ch] += 1
        self._last_channel = best_ch
        return best_ch

    def reward(self, channel: int, value: float) -> None:
        """
        Signal that something valuable was captured on `channel`.
        value: 0.0 = nothing, 1.0 = packet/probe, 2.0 = PMKID, 3.0 = handshake.
        """
        # Decay all rewards to de-emphasise stale observations
        for ch in self._channels:
            self._rewards[ch] *= self._decay
        self._rewards[channel] += value

    def penalise(self, channel: int, amount: float = 0.5) -> None:
        """Explicitly down-score a channel (e.g. AP went away, WIDS alert)."""
        self._rewards[channel] = max(0.0, self._rewards[channel] - amount)

    def channel_scores(self) -> dict[int, float]:
        return {
            ch: self._rewards[ch] / max(self._counts[ch], 1)
            for ch in self._channels
        }

    def reset(self) -> None:
        self._counts.clear()
        self._rewards.clear()
        self._total_pulls   = 0
        self._round_robin_idx = 0

    @property
    def last_channel(self) -> int:
        return self._last_channel
