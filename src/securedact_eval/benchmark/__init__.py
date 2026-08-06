# SPDX-License-Identifier: Apache-2.0
"""Migration-ready benchmark data generation, adapters, and integrity checks."""

from .generator import generate_profile
from .integrity import IntegrityReport, validate_integrity
from .manifest import BenchmarkManifest, verify_benchmark
from .profiles import BenchmarkProfile, load_profiles
from .registry import SourceRegistry, load_registry
from .workspace import BenchmarkWorkspace, resolve_workspace

__all__ = [
    "BenchmarkManifest",
    "BenchmarkProfile",
    "BenchmarkWorkspace",
    "IntegrityReport",
    "SourceRegistry",
    "generate_profile",
    "load_profiles",
    "load_registry",
    "resolve_workspace",
    "validate_integrity",
    "verify_benchmark",
]
