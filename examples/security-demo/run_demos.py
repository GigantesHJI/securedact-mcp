"""Reproducible, synthetic-only SecuRedact demonstrations.

Run with:
    $env:SECUREDACT_REQUIRE_FLAIR="0"
    python examples/security-demo/run_demos.py

No real secrets, PII, or local paths are used. All inputs are synthetic and are
assembled at runtime to avoid committing any real secret pattern.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

os.environ.setdefault("SECUREDACT_REQUIRE_FLAIR", "0")

from securedact_core import RedactionRequest, SecuredactEngine
from securedact_core.firewall import (
    classify_destination_scope,
    classify_tool,
    default_firewall_policy,
    evaluate_firewall,
)


def make_engine() -> SecuredactEngine:
    return SecuredactEngine.from_environment()


def demo1_secret_in_env(engine: SecuredactEngine) -> None:
    cs = "client" + "_secret=EXAMPLE" + "abcd1234efgh"  # synthetic
    pw = "pass" + "word: example" + "passw0rd" + "demo"  # synthetic
    content = f"{cs}\n{pw}\n# benign comment\n"
    result = engine.prepare(RedactionRequest(text=content, policy="strict_external_ai"))
    print("Demo 1 - Secret in .env-like content")
    print("  status:", result.status)
    print("  counts:", result.counts)
    print("  expected: blocked (credentials block under strict_external_ai)\n")


def demo2_customer_pii(engine: SecuredactEngine) -> None:
    text = (
        "Customer: Jane Example\n"
        "Email: jane.example@customer.test\n"
        "IBAN: NL91ABNA0417164300\n"
        "Note: regular business meeting at 10am."
    )
    result = engine.prepare(RedactionRequest(text=text, policy="gdpr"))
    print("Demo 2 - Synthetic customer PII")
    print("  status:", result.status)
    print("  sanitized:", result.sanitized_text)
    print("  counts:", result.counts)
    print("  expected: ok with pseudonymized/redacted PII\n")


def demo3_network_egress() -> None:
    scope = classify_destination_scope("https://api.example-external.test/v1")
    ctx = classify_tool("claude", "WebFetch", {"url": "https://api.example-external.test/v1/data"})
    decision = evaluate_firewall(default_firewall_policy(), ctx)
    print("Demo 3 - Network/egress classification")
    print("  destination scope:", scope.value)
    print("  classified operation:", ctx.operation.value)
    print("  firewall action (default policy):", decision.action.value)
    print("  expected: external scope classified; default policy allows but")
    print("           egress can be hardened via egress_external_require_approval\n")


def demo4_safe_file(engine: SecuredactEngine) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "notes.txt"
        path.write_text("Team standup at 10am. Agenda: roadmap and hiring.\n", encoding="utf-8")
        result = engine.read_file(str(path), redaction_policy="strict_external_ai")
        print("Demo 4 - Benign file read")
        print("  ok:", result.ok)
        print("  sanitized_text:", result.sanitized_text)
        print("  expected: ok, content unchanged (no sensitive data)\n")


def demo5_prompt_redaction(engine: SecuredactEngine) -> None:
    prompt = "Summarize this lead: jane.example@prospect.test, IBAN NL91ABNA0417164300"
    result = engine.prepare(RedactionRequest(text=prompt, policy="strict_external_ai"))
    print("Demo 5 - Prompt redaction before external AI")
    print("  status:", result.status)
    print("  sanitized:", result.sanitized_text)
    print("  expected: ok with sensitive values replaced by placeholders\n")


def main() -> None:
    engine = make_engine()
    demo1_secret_in_env(engine)
    demo2_customer_pii(engine)
    demo3_network_egress()
    demo4_safe_file(engine)
    demo5_prompt_redaction(engine)


if __name__ == "__main__":
    main()
