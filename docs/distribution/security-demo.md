# SecuRedact — Security Demonstrations (synthetic only)

All demonstrations below use **synthetic, non-sensitive data** and are
reproducible from the repository. They run with the deterministic detector
stack (no contextual model required), so anyone can try them quickly.

Run the bundled script:

```powershell
$env:SECUREDACT_REQUIRE_FLAIR = "0"
python examples/security-demo/run_demos.py
```

(Linux/macOS: `SECUREDACT_REQUIRE_FLAIR=0 python examples/security-demo/run_demos.py`.)

The contained `api_key` / `client_secret` / `password` strings are obviously
fake and are assembled at runtime to avoid committing any real secret pattern.

---

## Demo 1 — Secret in a `.env`-like file

An agent (or a prompt) that would otherwise forward a file containing fake
credentials is stopped.

```python
import os
os.environ["SECUREDACT_REQUIRE_FLAIR"] = "0"
from securedact_core import RedactionRequest, SecuredactEngine

engine = SecuredactEngine.from_environment()
cs = "client" + "_secret=EXAMPLE" + "abcd1234efgh"   # synthetic
pw = "pass" + "word: example" + "passw0rd" + "demo"  # synthetic
content = f"{cs}\n{pw}\n# benign comment\n"

result = engine.prepare(RedactionRequest(text=content, policy="strict_external_ai"))
print(result.status)   # blocked
print(result.counts)   # {'api_token': 1, 'password': 1}
```

**Expected:** the content is **blocked** (`status == "blocked"`) because
credentials are not approved for external AI under `strict_external_ai`. No
sanitized output is returned. This is the same decision the enforced Claude
Code / Gemini hooks apply before a tool or model call.

(Equivalently, `securedact_read_file` on a real `.env` path is blocked by the
firewall's protected-path rule before any content is read.)

---

## Demo 2 — Synthetic customer PII

```python
text = (
    "Customer: Jane Example\n"
    "Email: jane.example@customer.test\n"
    "IBAN: NL91ABNA0417164300\n"
    "Note: regular business meeting at 10am."
)
result = engine.prepare(RedactionRequest(text=text, policy="gdpr"))
print(result.status)          # ok
print(result.sanitized_text)  # Customer: Jane Example, Email: [EMAIL_1], IBAN: [IBAN_1], ...
print(result.counts)          # {'email': 1, 'iban': 1, ...}
```

**Expected:** PII is detected and replaced with stable placeholders
(pseudonymization). The `gdpr` policy is a detection/policy profile, **not** a
legal compliance certification.

---

## Demo 3 — Network / egress classification

No network call is made; this shows how outbound tool calls are classified and
how the firewall evaluates them.

```python
from securedact_core.firewall import (
    classify_tool, classify_destination_scope,
    default_firewall_policy, evaluate_firewall,
)

scope = classify_destination_scope("https://api.example-external.test/v1")
ctx = classify_tool("claude", "WebFetch",
                    {"url": "https://api.example-external.test/v1/data"})
decision = evaluate_firewall(default_firewall_policy(), ctx)

print(scope.value)        # external
print(ctx.operation.value) # network_read
print(decision.action.value)  # allow (default policy)
```

**Expected:** the destination is classified `external`, the tool is classified
as a network read, and the default firewall **allows** it. The default policy is
fail-closed for protected *file paths* (e.g. `.env`, SSH keys) but treats
external egress as policy-driven. Operators can harden egress by enabling
`egress_external_require_approval` or adding explicit `NETWORK_WRITE` rules, so
outbound transfers of sensitive content can require approval or be blocked
according to configured policy.

---

## Demo 4 — Safe (benign) file

```python
import tempfile
from pathlib import Path

with tempfile.TemporaryDirectory() as tmp:
    p = Path(tmp) / "notes.txt"
    p.write_text("Team standup at 10am. Agenda: roadmap and hiring.\n", encoding="utf-8")
    res = engine.read_file(str(p), redaction_policy="strict_external_ai")
    print(res.ok)             # True
    print(res.sanitized_text) # unchanged benign text
```

**Expected:** the file is read and returned unchanged because it contains no
sensitive data. Path traversal, symlinks, and protected paths are still
defended regardless of content.

---

## Demo 5 — Prompt redaction before external AI

```python
prompt = "Summarize this lead: jane.example@prospect.test, IBAN NL91ABNA0417164300"
result = engine.prepare(RedactionRequest(text=prompt, policy="strict_external_ai"))
print(result.status)         # ok
print(result.sanitized_text) # Summarize this lead: [EMAIL_1], IBAN [IBAN_1]
```

**Expected:** the host receives only `sanitized_text` (placeholders) to forward
to the external model. Raw values stay local.

---

## What these demos do **not** prove

- They do not prove every leak is prevented. Detection can miss novel,
  ambiguous, or adversarial disclosure.
- They do not prove GDPR (or any regulation) compliance — only detection and
  policy behavior.
- MCP mode requires the host to actually invoke the tool and use only approved
  output; these demos show the engine decision, not host enforcement.
