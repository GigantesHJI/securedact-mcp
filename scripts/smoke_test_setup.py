"""Exercise setup from an installed wheel without models or provider API calls."""

from __future__ import annotations

import os
import shutil
import subprocess
import sysconfig
import tempfile
from importlib import resources
from pathlib import Path

MODEL_SUFFIXES = {".bin", ".ckpt", ".model", ".onnx", ".pt", ".pth", ".safetensors"}


def _entrypoint() -> str:
    explicit = os.getenv("SECUREDACT_ENTRYPOINT")
    if explicit and Path(explicit).is_file():
        return explicit
    discovered = shutil.which("securedact-mcp")
    if discovered:
        return discovered
    scripts = Path(sysconfig.get_path("scripts"))
    for name in ("securedact-mcp.exe", "securedact-mcp"):
        candidate = scripts / name
        if candidate.is_file():
            return str(candidate)
    raise RuntimeError("securedact-mcp console entry point is not installed")


def _verify_resources() -> None:
    packaged = resources.files("securedact_mcp.setup_assets")
    required = (
        "claude/.claude-plugin/marketplace.json",
        "claude/integrations/claude-code-enforced/securedact-enforced/.claude-plugin/plugin.json",
        "claude/integrations/claude-code-enforced/securedact-enforced/hooks/hooks.json",
        "gemini/gemini-extension.json",
        "gemini/hooks/hooks.json",
    )
    for relative in required:
        if not packaged.joinpath(relative).is_file():
            raise RuntimeError(f"installed wheel is missing setup resource: {relative}")


def main() -> int:
    _verify_resources()
    command = _entrypoint()
    with tempfile.TemporaryDirectory(
        prefix="securedact setup smoke ", dir=Path.cwd().resolve().parent
    ) as temporary:
        root = Path(temporary)
        fake_modules = root / "dependency stubs"
        for name in ("flair", "huggingface_hub", "torch", "transformers"):
            package = fake_modules / name
            package.mkdir(parents=True)
            (package / "__init__.py").write_text("", encoding="utf-8")
        app_data = root / "application data"
        environment = dict(os.environ)
        environment.update(
            {
                "PATH": str(Path(command).parent),
                "PYTHONPATH": str(fake_modules),
                "PYTHONUTF8": "1",
                "SECUREDACT_APP_DATA_DIR": str(app_data),
            }
        )
        completed = subprocess.run(  # noqa: S603 - exact installed entrypoint
            [command, "setup", "--non-interactive", "--language", "none"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            env=environment,
        )
        if completed.returncode != 0:
            raise RuntimeError(
                f"installed setup smoke failed safely with exit {completed.returncode}: "
                f"{completed.stderr}"
            )
        if completed.stdout:
            raise RuntimeError("setup wrote unexpected stdout")
        if "Model setup skipped" in completed.stderr:
            raise RuntimeError("explicit setup selection was not applied")
        if "Models: disabled by local configuration" not in completed.stderr:
            raise RuntimeError("setup did not report the explicit model state")
        files = [path for path in app_data.rglob("*") if path.is_file()]
        if any(path.suffix.casefold() in MODEL_SUFFIXES for path in files):
            raise RuntimeError("setup unexpectedly installed model weights")
    print("Installed setup onboarding smoke test passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
