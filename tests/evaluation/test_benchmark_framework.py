from __future__ import annotations

import unicodedata
from hashlib import sha256
from pathlib import Path

import pytest

from securedact_core import EntityType, PrivacyEngine
from securedact_core.detectors.regex_detector import iban_valid
from securedact_core.taxonomy import CATEGORY_DEFINITIONS, SPECIAL_CATEGORY_TYPES
from securedact_eval.benchmark import (
    BenchmarkManifest,
    generate_profile,
    load_profiles,
    load_registry,
    resolve_workspace,
    validate_integrity,
    verify_benchmark,
)
from securedact_eval.benchmark.adapters import adapt_multiconer
from securedact_eval.benchmark.generator import load_jsonl
from securedact_eval.benchmark.manifest import sha256_file, write_manifest
from securedact_eval.benchmark.registry import SourceFile, verify_source_file
from securedact_eval.models import Annotation, CorpusSample
from securedact_eval.quality import EvaluationConfigurationError, run_quality_evaluation

ROOT = Path(__file__).resolve().parents[2]
SMOKE = ROOT / "benchmarks" / "fixtures" / "smoke"


def _write_dataset(root: Path, samples: list[CorpusSample], *, tier: str) -> None:
    root.mkdir()
    corpus = root / "corpus.jsonl"
    corpus.write_text(
        "".join(sample.model_dump_json() + "\n" for sample in samples),
        encoding="utf-8",
        newline="\n",
    )
    manifest = BenchmarkManifest(
        profile="test-profile",
        generator_version="test",
        seed=1,
        dependency_lock_digest="0" * 64,
        tier=tier,
        document_count=len(samples),
        entity_count=sum(len(sample.entities) for sample in samples),
        negative_count=sum(not sample.entities for sample in samples),
        adversarial_count=0,
        mixed_entity_count=0,
        language_counts={"en": len(samples)},
        source_counts={sample.source: 1 for sample in samples},
        split_counts={"validation": len(samples)},
        assertion_type_counts={"current": sum(len(sample.entities) for sample in samples)},
        category_counts={"email": sum(len(sample.entities) for sample in samples)},
        domain_counts={"testing": len(samples)},
        transformation_counts={"original": len(samples)},
        template_family_counts={"test": len(samples)},
        files={"corpus.jsonl": sha256_file(corpus)},
        generation={"synthetic_only": True},
    )
    write_manifest(root / "manifest.json", manifest)


def test_committed_smoke_corpus_is_representative_and_integral() -> None:
    manifest = verify_benchmark(SMOKE)
    samples = load_jsonl(SMOKE / "corpus.jsonl")

    assert 100 <= manifest.document_count <= 300
    assert manifest.entity_count >= 250
    assert manifest.language_counts == {"en": 80, "nl": 80}
    assert manifest.negative_count >= 30
    assert manifest.adversarial_count >= 120
    assert set(manifest.assertion_type_counts) == {
        "current",
        "negated",
        "uncertain",
        "hypothetical",
        "quotation",
        "historical",
        "family_history",
        "general_discussion",
        "organization_level",
        "near_miss",
    }
    assert validate_integrity(samples).valid
    assert all(sample.tier == "public" for sample in samples)
    assert all(
        sample.split not in {"private_holdout", "private_release_gate"} for sample in samples
    )


def test_smoke_generator_does_not_contaminate_scores_with_fixture_defects() -> None:
    samples = load_jsonl(SMOKE / "corpus.jsonl")

    negatives = [sample for sample in samples if not sample.entities]
    assert negatives
    assert all(sample.transformation == "original" for sample in negatives)
    assert all(
        sample.metadata.get("control_kind") in {"negative", "near_miss"} for sample in negatives
    )

    transformed = [
        sample for sample in samples if sample.entities and sample.transformation != "original"
    ]
    assert transformed
    assert all(sample.metadata.get("transformation_applied") is True for sample in transformed)

    for sample in samples:
        if "[synthetic-record:" in sample.text:
            suffix = sample.text.rpartition("[synthetic-record:")[2]
            assert not any(character.isdigit() for character in suffix)
        for entity in sample.entities:
            assert entity.expected_action == CATEGORY_DEFINITIONS[entity.entity_type].default_action
            if entity.entity_type in SPECIAL_CATEGORY_TYPES:
                assert not (entity.text or "").casefold().startswith("fictional ")
            if (
                entity.entity_type == EntityType.IBAN
                and sample.transformation_support == "supported"
            ):
                assert iban_valid(entity.text or "")


def test_unicode_normalization_challenges_are_applied_without_offset_damage() -> None:
    samples = load_jsonl(SMOKE / "corpus.jsonl")
    transformed = [sample for sample in samples if sample.transformation == "unicode-normalization"]

    assert transformed
    assert any(sample.text != unicodedata.normalize("NFC", sample.text) for sample in transformed)
    assert all(
        sample.text[entity.start : entity.end] == entity.text
        for sample in transformed
        for entity in sample.entities
    )
    assert validate_integrity(transformed).valid


def test_generation_is_deterministic_and_profiles_meet_targets(tmp_path: Path) -> None:
    profiles = load_profiles(ROOT / "benchmarks" / "generators" / "profiles.yml")
    assert profiles["benchmark-v0.2"].documents >= 20_000
    assert profiles["benchmark-v0.2"].minimum_entities >= 30_000
    assert profiles["benchmark-v0.2"].dutch_fraction >= 0.40
    first = tmp_path / "first"
    second = tmp_path / "second"
    first_manifest = generate_profile(profiles["smoke"], first, repository_root=ROOT)
    second_manifest = generate_profile(profiles["smoke"], second, repository_root=ROOT)
    assert first_manifest == second_manifest
    assert (first / "corpus.jsonl").read_bytes() == (second / "corpus.jsonl").read_bytes()


def test_workspace_is_external_explicit_and_never_uses_repository(tmp_path: Path) -> None:
    workspace = resolve_workspace(
        repository_root=ROOT,
        environment={"SECUREDACT_BENCHMARK_DATA_DIR": str(tmp_path / "benchmark-data")},
    )
    assert workspace.external.is_dir()
    assert workspace.restricted.is_dir()
    assert workspace.private_holdout.is_dir()
    assert workspace.cache.is_dir()
    with pytest.raises(ValueError, match="outside_repository"):
        resolve_workspace(
            repository_root=ROOT,
            environment={"SECUREDACT_BENCHMARK_DATA_DIR": str(ROOT / "benchmark-data")},
        )
    with pytest.raises(ValueError, match="path_must_be_absolute"):
        resolve_workspace(
            repository_root=ROOT,
            environment={"SECUREDACT_BENCHMARK_DATA_DIR": "relative-benchmark-data"},
        )


def test_workspace_rejects_linked_paths(tmp_path: Path) -> None:
    target = tmp_path / "real-workspace"
    target.mkdir()
    linked = tmp_path / "linked-workspace"
    try:
        linked.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is not available")
    with pytest.raises(ValueError, match="symlink_forbidden"):
        resolve_workspace(
            repository_root=ROOT,
            environment={"SECUREDACT_BENCHMARK_DATA_DIR": str(linked / "benchmark-data")},
        )


def test_external_and_restricted_profiles_fail_closed(tmp_path: Path) -> None:
    profiles = load_profiles(ROOT / "benchmarks" / "generators" / "profiles.yml")
    with pytest.raises(ValueError, match="requires_adapter"):
        generate_profile(profiles["external-full"], tmp_path / "external", repository_root=ROOT)
    with pytest.raises(ValueError, match="requires_adapter"):
        generate_profile(
            profiles["restricted-local"], tmp_path / "restricted", repository_root=ROOT
        )


def test_source_registry_is_approved_and_unknown_sources_are_rejected() -> None:
    registry = load_registry(ROOT / "benchmarks" / "registry" / "sources.yml")
    multiconer = registry.require("multiconer-1-en-nl")
    assert multiconer.version == "multiconer2022-release-1"
    assert multiconer.commercial_use is True
    assert multiconer.label_mapping == {
        "CORP": "organization",
        "GRP": "organization",
        "LOC": "location",
        "PER": "person",
    }
    with pytest.raises(ValueError, match="not_registered"):
        registry.require("unknown-source")
    with pytest.raises(ValueError, match="not_enabled"):
        registry.require("dutch-open-government-generic")


def test_source_file_size_and_changed_hash_are_rejected(tmp_path: Path) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"approved")
    approved = SourceFile(
        name="source.bin",
        url="https://example.com/source.bin",
        size=8,
        sha256=sha256(b"approved").hexdigest(),
    )
    verify_source_file(source, approved)
    source.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="digest_mismatch"):
        verify_source_file(source, approved)


def test_multiconer_reports_unmapped_labels_and_preserves_offsets(tmp_path: Path) -> None:
    source = tmp_path / "sample.conll"
    source.write_text(
        "Ada B-PER\nLovelace I-PER\nvisits O\nDelft B-LOC\nWidget B-PROD\n", encoding="utf-8"
    )
    result = adapt_multiconer(source, language="en")
    assert result.unmapped_labels == {"PROD": 1}
    assert [entity.text for entity in result.samples[0].entities] == ["Ada Lovelace", "Delft"]
    assert "CC BY 4.0" in result.attribution


def test_integrity_detects_group_leakage_approximate_duplicates_and_bad_provenance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    left = CorpusSample(
        id="left-sample",
        language="en",
        domain="testing",
        text="alpha beta gamma delta one",
        split="development",
        template_group="shared-template",
    )
    right = left.model_copy(
        update={"id": "right-sample", "text": "alpha beta gamma delta two", "split": "validation"}
    )
    monkeypatch.setattr("securedact_eval.benchmark.integrity._simhash", lambda _text: 7)
    report = validate_integrity([left, right])
    assert report.approximate_duplicates == [["left-sample", "right-sample"]]
    assert report.leakage["template_group"] == [["left-sample", "right-sample"]]

    malformed = CorpusSample(
        id="bad-provenance",
        language="en",
        domain="testing",
        text="😀 Ada",
        split="validation",
        entities=[Annotation(start=2, end=5, text="Ada", entity_type=EntityType.PERSON)],
    )
    assert validate_integrity([malformed]).provenance_errors == ["bad-provenance:0"]


def test_unicode_offsets_and_annotation_text_mutations() -> None:
    sample = CorpusSample(
        id="unicode-sample",
        language="nl",
        domain="testing",
        text=unicodedata.normalize("NFC", "😀 José"),
        split="validation",
        entities=[
            Annotation(
                start=2,
                end=6,
                text="José",
                entity_type=EntityType.PERSON,
                provenance={"source": "test"},
            )
        ],
    )
    assert validate_integrity([sample]).valid
    with pytest.raises(ValueError, match="does not match"):
        sample.model_copy(
            update={"entities": [sample.entities[0].model_copy(update={"start": 1})]}
        ).model_validate(
            {**sample.model_dump(), "entities": [{**sample.entities[0].model_dump(), "start": 1}]}
        )


def test_mixed_tiers_are_rejected_and_restricted_results_are_aggregate_only(
    tmp_path: Path,
) -> None:
    public = CorpusSample(
        id="public-negative",
        language="en",
        domain="testing",
        text="A harmless public note.",
        source="public-source",
        tier="public",
        split="validation",
    )
    restricted = CorpusSample(
        id="restricted-positive",
        language="en",
        domain="testing",
        text="alex@example.test",
        source="restricted-source",
        tier="restricted",
        split="validation",
        entities=[
            Annotation(
                start=0,
                end=17,
                text="alex@example.test",
                entity_type=EntityType.EMAIL,
                provenance={"source": "restricted-test"},
            )
        ],
    )
    dataset = tmp_path / "mixed"
    _write_dataset(dataset, [public, restricted], tier="restricted")
    with pytest.raises(EvaluationConfigurationError, match="mixed_benchmark_tiers_forbidden"):
        run_quality_evaluation(dataset, engine=PrivacyEngine(detectors=[]))

    restricted_dataset = tmp_path / "restricted"
    _write_dataset(restricted_dataset, [restricted], tier="restricted")
    report = run_quality_evaluation(restricted_dataset, engine=PrivacyEngine(detectors=[]))
    assert set(report.per_tier) == {"restricted"}
    assert set(report.per_source) == {"restricted-source"}
    assert report.sample_results == []
    assert report.document_decisions is not None
    assert report.document_decisions.residual_sensitive_value_rate == 1.0
    assert report.document_decisions.approved_output_leak_rate == 1.0


def test_benchmark_package_imports_are_migration_compatible() -> None:
    from securedact_eval import benchmark

    assert benchmark.generate_profile is generate_profile
