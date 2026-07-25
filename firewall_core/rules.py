"""Regex rule engine for prompt-injection detection.

Rules are data, not code: each carries a severity, category, mitigation, and
enabled flag so they can be stored in the DB and managed from the dashboard.
`default_rules()` seeds the catalog; the Django layer loads/overrides from the
`Rule` table and passes them here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Severity weights feed the risk score. Category groups rules for analytics.
SEVERITY_WEIGHTS = {
    "info": 0.1,
    "low": 0.25,
    "medium": 0.5,
    "high": 0.75,
    "critical": 0.95,
}


@dataclass
class Rule:
    id: str
    pattern: str
    severity: str
    category: str
    description: str
    mitigation: str = ""
    enabled: bool = True
    # MITRE-ATLAS-style tag for AI-specific attacks (best-effort mapping).
    atlas: str = ""

    def compiled(self) -> re.Pattern:
        return re.compile(self.pattern, re.IGNORECASE | re.DOTALL)


@dataclass
class RuleMatch:
    rule_id: str
    severity: str
    category: str
    description: str
    mitigation: str
    atlas: str
    excerpt: str
    weight: float


class RuleEngine:
    def __init__(self, rules: list[Rule] | None = None) -> None:
        self._rules = rules if rules is not None else default_rules()
        self._compiled = [
            (r, r.compiled()) for r in self._rules if r.enabled
        ]

    def inspect(self, text: str) -> list[RuleMatch]:
        matches: list[RuleMatch] = []
        for rule, regex in self._compiled:
            m = regex.search(text)
            if m:
                excerpt = _excerpt(text, m.start(), m.end())
                matches.append(
                    RuleMatch(
                        rule_id=rule.id,
                        severity=rule.severity,
                        category=rule.category,
                        description=rule.description,
                        mitigation=rule.mitigation,
                        atlas=rule.atlas,
                        excerpt=excerpt,
                        weight=SEVERITY_WEIGHTS.get(rule.severity, 0.5),
                    )
                )
        return matches


def _excerpt(text: str, start: int, end: int, ctx: int = 24) -> str:
    lo = max(0, start - ctx)
    hi = min(len(text), end + ctx)
    snippet = text[lo:hi].replace("\n", " ")
    return (("…" if lo else "") + snippet + ("…" if hi < len(text) else "")).strip()


def default_rules() -> list[Rule]:
    """Seed catalog. IDs are stable so DB rows can override by id."""
    R = Rule
    return [
        # --- Instruction override / hijacking ---
        R("override-ignore-previous",
          r"ignore\s+(all\s+|any\s+|the\s+)?(previous|prior|above|earlier|preceding)\s+(instructions|prompts?|messages?|context|rules?)",
          "critical", "instruction-override",
          "Attempt to override prior system/user instructions.",
          "Block request; system instructions must be immutable.",
          atlas="AML.T0051 LLM Prompt Injection"),
        R("override-forget-everything",
          r"forget\s+(everything|all|your\s+(instructions|rules|training|guidelines))",
          "high", "instruction-override",
          "Attempt to erase prior instructions.",
          "Block; do not honor memory-wipe requests."),
        R("override-disregard",
          r"disregard\s+(all\s+|the\s+|any\s+)?(previous|prior|above|your)\s+",
          "high", "instruction-override",
          "Disregard-instruction phrasing.",
          "Block or sanitize the overriding clause."),
        R("override-new-instructions",
          r"(here\s+are|these\s+are)\s+your\s+new\s+(instructions|rules)",
          "high", "instruction-override",
          "Injecting replacement instructions.",
          "Block; reject externally supplied instruction sets."),
        # --- Jailbreak personas ---
        R("jailbreak-dan",
          r"\b(DAN|do\s+anything\s+now)\b",
          "high", "jailbreak",
          "DAN 'do anything now' jailbreak persona.",
          "Block; refuse persona reassignment.",
          atlas="AML.T0054 LLM Jailbreak"),
        R("jailbreak-developer-mode",
          r"developer\s+mode|dev\s+mode\s+enabled",
          "high", "jailbreak",
          "'Developer mode' jailbreak.",
          "Block; there is no unrestricted developer mode."),
        R("jailbreak-sudo",
          r"\bsudo\s+mode\b|enable\s+sudo",
          "high", "jailbreak",
          "'sudo mode' privilege-escalation framing.",
          "Block."),
        R("jailbreak-unrestricted",
          r"(simulate|pretend|act)\s+(an?\s+)?(unrestricted|unfiltered|uncensored)\s+(ai|model|assistant)",
          "high", "jailbreak",
          "Requesting an unrestricted AI simulation.",
          "Block."),
        R("jailbreak-no-restrictions",
          r"without\s+(any\s+)?(restrictions|filters|rules|limitations|safety|guidelines)",
          "medium", "jailbreak",
          "Requesting removal of safety constraints.",
          "Block or warn."),
        R("jailbreak-disable-safety",
          r"(disable|turn\s+off|bypass|ignore)\s+(your\s+)?(safety|content\s+filter|guardrails?|moderation|filters?)",
          "critical", "jailbreak",
          "Explicit request to disable safety systems.",
          "Block."),
        # --- Role reassignment / roleplay ---
        R("role-you-are-now",
          r"you\s+are\s+now\s+(a|an|the|in)\s+",
          "medium", "role-override",
          "Role reassignment.",
          "Warn; verify against allowed personas."),
        R("role-act-as",
          r"act\s+as\s+(if\s+you\s+(are|were)|an?\b)",
          "low", "role-override",
          "Roleplay framing (often benign, sometimes a jailbreak vector).",
          "Warn."),
        R("role-pretend",
          r"pretend\s+(to\s+be|you\s+are|that\s+you)",
          "low", "role-override",
          "Pretend framing.",
          "Warn."),
        # --- System-prompt / secret extraction ---
        R("extract-system-prompt",
          r"(reveal|show|print|repeat|display|output|expose|leak)\s+(me\s+)?(your|the)\s+(system\s+|hidden\s+|initial\s+)?(prompt|instructions|rules|guidelines)",
          "critical", "prompt-extraction",
          "System-prompt extraction attempt.",
          "Block; never disclose system prompt.",
          atlas="AML.T0051.000 System Prompt Extraction"),
        R("extract-repeat-instructions",
          r"(repeat|say)\s+(back\s+)?(your|the)\s+(instructions|system\s+prompt|guidelines)\s*(verbatim|exactly|word\s+for\s+word)?",
          "high", "prompt-extraction",
          "Asking the model to echo its instructions.",
          "Block."),
        R("extract-what-are-instructions",
          r"what\s+(is|are)\s+your\s+(system\s+prompt|initial\s+instructions|hidden\s+(prompt|instructions))",
          "high", "prompt-extraction",
          "Interrogating the model for its instructions.",
          "Block."),
        R("extract-print-apikey",
          r"(print|show|reveal|give\s+me|what('?s|\s+is))\s+(your|the)\s+(api[_\s-]*key|secret\s+key|access\s+token|credentials?)",
          "critical", "secret-extraction",
          "Attempt to extract API keys/credentials.",
          "Block; secrets are never returned."),
        # --- Delimiter / structured injection ---
        R("delimiter-chat-tags",
          r"</?(system|assistant|user|im_start|im_end)\s*\|?>",
          "high", "delimiter-injection",
          "Chat-template delimiter injection.",
          "Sanitize; strip control delimiters."),
        R("delimiter-inst",
          r"\[/?INST\]|<<SYS>>|<</SYS>>",
          "high", "delimiter-injection",
          "Llama-style instruction delimiter injection.",
          "Sanitize."),
        R("delimiter-markdown-heading",
          r"###\s*(system|new\s+instruction|override|admin)",
          "medium", "delimiter-injection",
          "Markdown heading used to fake an instruction section.",
          "Sanitize."),
        R("injection-html-comment",
          r"<!--.*?(ignore|instruction|system|prompt|reveal).*?-->",
          "high", "structured-injection",
          "Hidden instruction inside an HTML comment.",
          "Strip HTML comments before use."),
        R("injection-xml-tag",
          r"<(instruction|system|prompt|command)>.*?</\1>",
          "medium", "structured-injection",
          "XML-tag-wrapped injected instruction.",
          "Sanitize structured tags."),
        R("injection-json-role",
          r"[\"']role[\"']\s*:\s*[\"']system[\"']",
          "medium", "structured-injection",
          "JSON payload asserting a system role.",
          "Reject client-supplied system roles."),
        R("injection-tool-abuse",
          r"(call|invoke|use|execute)\s+(the\s+)?(tool|function|api)\s+.{0,40}(delete|drop|exfiltrate|send|email|transfer)",
          "high", "tool-abuse",
          "Attempt to abuse tool/function calling.",
          "Block dangerous tool invocations.",
          atlas="AML.T0053 LLM Plugin Compromise"),
        R("injection-sql-tool",
          r"(drop\s+table|delete\s+from|union\s+select|';\s*--)",
          "medium", "tool-abuse",
          "SQL directed at an LLM database tool.",
          "Parameterize; block raw SQL from prompts."),
        # --- Indirect / context poisoning ---
        R("indirect-when-you-read",
          r"when\s+you\s+(read|see|process|encounter)\s+this[,\s].{0,60}(send|email|post|forward|reply|execute|ignore)",
          "high", "indirect-injection",
          "Indirect injection embedded in content to be processed.",
          "Treat fetched/uploaded content as untrusted data.",
          atlas="AML.T0051.001 Indirect Prompt Injection"),
        R("indirect-exfil-destination",
          r"(send|email|forward|post|upload)\s+.{0,40}(to\s+)?[\w.+-]+@[\w-]+\.\w+",
          "medium", "indirect-injection",
          "Instruction to exfiltrate to an external destination.",
          "Block outbound exfil instructions."),
        R("context-poison-remember",
          r"(from\s+now\s+on|going\s+forward|for\s+all\s+future),?\s+(always|never|you\s+(will|must))",
          "low", "context-poisoning",
          "Attempt to persist manipulated behavior across turns.",
          "Warn; do not persist untrusted directives."),
    ]
