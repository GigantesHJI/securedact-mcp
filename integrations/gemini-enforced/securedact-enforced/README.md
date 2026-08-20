# SecuRedact Enforced for Gemini CLI

This extension runs SecuRedact locally before Gemini CLI planning, at the final
model boundary, and for configured external tool calls. It uses a local,
authenticated loopback runtime; prompt and tool text are never written to disk.

`BeforeAgent` blocks review-required or unsafe prompts and caches only exact
unchanged approvals. Transformable prompts proceed to `BeforeModel`, which
scans Gemini's stable text-only request representation and replaces only the
selected model-bound text with the provider-neutral core's signed sanitized
output. `BeforeTool` covers MCP and commonly named network/web tools, preserving
safe input structure while replacing only inspected textual fields. Prompt
instructions cannot disable deterministic hooks.

Gemini does not own the automatic-pseudonymization decision. The
provider-neutral policy setting `automatic_pseudonymization` defaults to
`true`; the process-start override
`SECUREDACT_AUTOMATIC_PSEUDONYMIZATION=0` disables automatic transformation.
In that state the core returns `review_required`, and Gemini denies before
provider transmission rather than falling back to the original text. Setting
it to `0` therefore makes enforcement more restrictive; it does not disable
privacy protection. Start a fresh Gemini session after changing the value.

Gemini's initial utility-router request can wrap the original prompt in
host-generated text. The warmed daemon therefore keeps a one-shot, in-memory
entry for the exact `BeforeAgent` prompt. An unchanged approval is reused only
when that exact text is present; a transformation replaces only exact matches
with the core-provided sanitized text. The entry is consumed on the first model
request and is never written to receipts or other diagnostics.

When the selected outbound text contains a recognized SecuRedact token, the
same `BeforeModel` request replacement appends concise provider-only handling
guidance to that selected message. The recognized token labels are generated
from the default policy's automatic-pseudonymisation rules rather than copied
into the Gemini adapter. The guidance tells Gemini to preserve the opaque
stand-ins, maintain repeated-token identity, and never search files, workspace
history, tools, MCP servers, or network resources to recover an original. It is
not added to benign requests and a private marker prevents duplicate insertion.

The guidance is model steering, not a security boundary. Deterministic
`BeforeAgent`, `BeforeModel`, and `BeforeTool` decisions remain responsible for
blocking review-required, unsafe, malformed, unauthenticated, and runtime
failure paths. `BeforeTool` does not add token-specific rewriting beyond its
existing core-provided sanitized-output handling.

## Prerequisites

Install Gemini CLI, then install SecuRedact with its local contextual models:

```powershell
python -m pip install "securedact-mcp[ml]"
securedact-mcp setup --host gemini
```

Setup reuses the existing SecuRedact model terms/installation/verifier flow,
then supplies the wheel-packaged extension to Gemini's official `extensions`
commands. Gemini's installation confirmation remains authoritative; setup never
passes `--consent`, edits credentials, or invokes a Gemini model.

For development, link this extension and start a fresh Gemini session:

```powershell
gemini extensions validate integrations/gemini-enforced/securedact-enforced
gemini extensions link integrations/gemini-enforced/securedact-enforced
gemini extensions list
```

Run `/hooks` to confirm the five SecuRedact hooks. Test with `What is 2 + 2?`,
then use synthetic protected data only. Update a linked extension by restarting
Gemini; uninstall with `gemini extensions uninstall securedact-enforced`.

## Security boundary

The extension can prevent a protected prompt or request from proceeding through
the Gemini CLI lifecycle once Gemini invokes these hooks. It does not claim that
Gemini never receives or displays text entered in its terminal. Runtime startup
is asynchronous; prompts before readiness fail closed. Receipts may record that
guidance was injected and the recognized category labels, but never original
values, sanitized text, or restoration mappings.

For public gallery discovery, this repository is itself a Gemini CLI extension
root: the repository `gemini-extension.json` and `hooks/hooks.json` at the
repository root are byte-identical copies of the artifacts under
`integrations/gemini-enforced/securedact-enforced/` and the wheel's
`setup_assets/gemini/`. The three copies must stay identical; a unit test
enforces that parity. Gallery indexing requires the `gemini-cli-extension`
GitHub topic on the repository. The public install command
(`gemini extensions install https://github.com/GigantesHJI/securedact-mcp`)
only resolves from a release whose tag tree contains the root manifest; until
that release exists, use `gemini extensions install <url> --ref main`,
`gemini extensions link .`, or `securedact-mcp setup --host gemini`.

Installing the extension alone is not enough. The hooks run
`python -m securedact_enforced.gemini_hook`, so `pip install "securedact-mcp[ml]"`
must be installed and the contextual models set up; without the Python package
and models the hooks do not enforce anything.
