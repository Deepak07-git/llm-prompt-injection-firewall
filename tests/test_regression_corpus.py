"""Detection-accuracy regression test.

Runs the full attack corpus (data/attack_corpus.json) through the engine and
asserts detection accuracy stays above a floor. This guards against future
changes that silently reduce recall (attacks slipping through) or precision
(benign prompts getting blocked). Pure firewall_core — no DB required.
"""

from __future__ import annotations

import json
from pathlib import Path

from firewall_core.engine import Action, FirewallEngine

_CORPUS = Path(__file__).resolve().parent.parent / "data" / "attack_corpus.json"

# Accuracy floors. Tune upward as detection improves; never downward silently.
MIN_ATTACK_RECALL = 0.85     # share of attacks flagged (warn/sanitize/block)
MAX_BENIGN_BLOCK = 0.10      # share of benign prompts hard-blocked (false positives)


def _load_samples():
    data = json.loads(_CORPUS.read_text(encoding="utf-8"))
    return data["samples"]


def test_corpus_present():
    samples = _load_samples()
    assert len(samples) >= 30, "corpus should contain a meaningful sample set"
    assert any(s["is_attack"] for s in samples)
    assert any(not s["is_attack"] for s in samples)


def test_attack_recall_above_floor():
    engine = FirewallEngine()
    attacks = [s for s in _load_samples() if s["is_attack"]]
    flagged = 0
    misses = []
    for s in attacks:
        r = engine.inspect_request(s["text"])
        if r.action in (Action.warn, Action.sanitize, Action.block):
            flagged += 1
        else:
            misses.append(s["text"][:60])
    recall = flagged / len(attacks)
    assert recall >= MIN_ATTACK_RECALL, f"recall {recall:.2f} below floor; missed: {misses}"


def test_benign_false_positive_below_ceiling():
    engine = FirewallEngine()
    benign = [s for s in _load_samples() if not s["is_attack"]]
    blocked = 0
    fps = []
    for s in benign:
        r = engine.inspect_request(s["text"])
        if r.action == Action.block:
            blocked += 1
            fps.append(s["text"][:60])
    fp_rate = blocked / len(benign)
    assert fp_rate <= MAX_BENIGN_BLOCK, f"benign block rate {fp_rate:.2f} too high; {fps}"
