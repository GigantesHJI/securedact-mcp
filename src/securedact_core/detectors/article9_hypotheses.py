# SPDX-License-Identifier: Apache-2.0
"""Frozen Article 9 semantic hypotheses and decomposition policy.

This module is the single source of truth for the FROZEN, research-validated
Article 9 semantic layer promoted into production for SecuRedact 0.4.0. The
hypothesis text, decomposition keys, thresholds, and confusion-guard policy are
the validated design from A9-Q3 .. A9-Q6 / A9-SOTA-001 (see the frozen
``HEAD_TO_HEAD_FREEZE.json`` and ``selected_genetic_policy.json`` artifacts from
the A9-quality-006 research run).

These values are PRODUCTION BEHAVIOUR, not benchmark tuning inputs. They MUST
NOT be changed, tuned, or "improved" against benchmark scores. Any change here
is a research change and must go through the experimental track first.
"""

from __future__ import annotations

from ..models import EntityType

# ---------------------------------------------------------------------------
# Generic Article 9 semantic hypotheses (BGE-M3 zero-shot proposer), EN/NL.
# ---------------------------------------------------------------------------
GEN_HYP_EN: dict[EntityType, str] = {
    EntityType.RACIAL_OR_ETHNIC_ORIGIN: "This text reveals a person's racial or ethnic origin.",
    EntityType.POLITICAL_OPINION: "This text reveals a person's political opinions.",
    EntityType.RELIGIOUS_OR_PHILOSOPHICAL_BELIEF: "This text reveals a person's religious or philosophical beliefs.",
    EntityType.TRADE_UNION_MEMBERSHIP: "This text reveals a person's trade-union membership.",
    EntityType.GENETIC_DATA: "This text reveals a person's genetic data.",
    EntityType.BIOMETRIC_DATA: "This text reveals a person's biometric data used for identification.",
    EntityType.HEALTH_DATA: "This text reveals information about a person's health.",
    EntityType.SEX_LIFE: "This text reveals a person's sex life.",
    EntityType.SEXUAL_ORIENTATION: "This text reveals a person's sexual orientation.",
}

GEN_HYP_NL: dict[EntityType, str] = {
    EntityType.RACIAL_OR_ETHNIC_ORIGIN: "Deze tekst onthult de raciale of etnische afkomst van een persoon.",
    EntityType.POLITICAL_OPINION: "Deze tekst onthult de politieke opvattingen van een persoon.",
    EntityType.RELIGIOUS_OR_PHILOSOPHICAL_BELIEF: "Deze tekst onthult de religieuze of filosofische overtuigingen van een persoon.",
    EntityType.TRADE_UNION_MEMBERSHIP: "Deze tekst onthult het vakbondslidmaatschap van een persoon.",
    EntityType.GENETIC_DATA: "Deze tekst onthult genetische gegevens van een persoon.",
    EntityType.BIOMETRIC_DATA: "Deze tekst onthult biometrische gegevens van een persoon die voor identificatie worden gebruikt.",
    EntityType.HEALTH_DATA: "Deze tekst onthult informatie over de gezondheid van een persoon.",
    EntityType.SEX_LIFE: "Deze tekst onthult het seksleven van een persoon.",
    EntityType.SEXUAL_ORIENTATION: "Deze tekst onthult de seksuele geaardheid van een persoon.",
}

# ---------------------------------------------------------------------------
# Political-opinion decomposition (internal sub-hypotheses; never new categories).
# ---------------------------------------------------------------------------
POL_DECOMP_EN: dict[str, str] = {
    "pol_voting_pref": "This text reveals which political party or candidate a person votes for, or their voting record.",
    "pol_party_support": "This text reveals that a person supports a political party.",
    "pol_party_oppose": "This text reveals that a person opposes a political party.",
    "pol_party_membership": "This text reveals a person's membership of or affiliation with a political party.",
    "pol_ideology": "This text reveals a person's political ideology.",
    "pol_policy_pos": "This text reveals a person's position on a political policy.",
    "pol_activism": "This text reveals that a person is politically active or engages in political activism.",
    "pol_campaigning": "This text reveals that a person campaigns for a political party or cause.",
    "pol_movement_support": "This text reveals that a person supports a political movement.",
    "pol_movement_oppose": "This text reveals that a person opposes a political movement.",
    "pol_candidate_endorse": "This text reveals that a person endorses a political candidate.",
    "pol_belief": "This text reveals a person's political belief.",
}

POL_DECOMP_NL: dict[str, str] = {
    "pol_voting_pref": "Deze tekst onthult op welke politieke partij of kandidaat een persoon stemt, of hun stemgedrag.",
    "pol_party_support": "Deze tekst onthult dat een persoon een politieke partij steunt.",
    "pol_party_oppose": "Deze tekst onthult dat een persoon een politieke partij tegenwerkt.",
    "pol_party_membership": "Deze tekst onthult het lidmaatschap van of de verbondenheid van een persoon met een politieke partij.",
    "pol_ideology": "Deze tekst onthult de politieke ideologie van een persoon.",
    "pol_policy_pos": "Deze tekst onthult het standpunt van een persoon over een politiek beleid.",
    "pol_activism": "Deze tekst onthult dat een persoon politiek actief is of politieke activisme bedrijft.",
    "pol_campaigning": "Deze tekst onthult dat een persoon campagne voert voor een politieke partij of zaak.",
    "pol_movement_support": "Deze tekst onthult dat een persoon een politieke beweging steunt.",
    "pol_movement_oppose": "Deze tekst onthult dat een persoon een politieke beweging tegenwerkt.",
    "pol_candidate_endorse": "Deze tekst onthult dat een persoon een politieke kandidaat onderschrijft.",
    "pol_belief": "Deze tekst onthult de politieke overtuiging van een persoon.",
}

# ---------------------------------------------------------------------------
# Sex-life decomposition (internal sub-hypotheses; never new categories).
# ---------------------------------------------------------------------------
SEX_DECOMP_EN: dict[str, str] = {
    "sex_activity": "This text reveals information about a person's sexual activity.",
    "sex_behaviour": "This text reveals information about a person's sexual behaviour.",
    "sex_practices": "This text reveals information about a person's sexual practices.",
    "sex_history": "This text reveals information about a person's sexual history.",
    "sex_relationships": "This text reveals information about a person's sexual relationships.",
    "sex_intimate": "This text reveals that a person engaged in intimate sexual activity.",
    "sex_partners": "This text reveals the number or history of a person's sexual partners.",
    "sex_abstinence": "This text reveals that a person abstains from sex or is sexually inactive.",
}

SEX_DECOMP_NL: dict[str, str] = {
    "sex_activity": "Deze tekst onthult informatie over de seksuele activiteit van een persoon.",
    "sex_behaviour": "Deze tekst onthult informatie over het seksuele gedrag van een persoon.",
    "sex_practices": "Deze tekst onthult informatie over de seksuele praktijken van een persoon.",
    "sex_history": "Deze tekst onthult informatie over de seksuele voorgeschiedenis van een persoon.",
    "sex_relationships": "Deze tekst onthult informatie over de seksuele relaties van een persoon.",
    "sex_intimate": "Deze tekst onthult dat een persoon intieme seksuele activiteit heeft ondergaan.",
    "sex_partners": "Deze tekst onthult het aantal of de geschiedenis van de seksuele partners van een persoon.",
    "sex_abstinence": "Deze tekst onthult dat een persoon zich onthoudt van seks of seksueel inactief is.",
}

# ---------------------------------------------------------------------------
# Genetic-data decomposition. Only the FOUR included hypotheses are scored;
# the other five are excluded by the frozen calibration policy.
# ---------------------------------------------------------------------------
GEN_DECOMP_EN: dict[str, str] = {
    "gen_gene_variant": "This text states that the person has a gene variant or mutation.",
    "gen_inherited_mutation": "This text states that the person has an inherited genetic mutation.",
    "gen_inherited_characteristic": "This text discloses an inherited or acquired genetic characteristic of the person.",
    "gen_chromosomal": "This text states a chromosomal or genomic finding about the person.",
}

GEN_DECOMP_NL: dict[str, str] = {
    "gen_gene_variant": "Deze tekst vermeldt dat de persoon een genvariant of mutatie heeft.",
    "gen_inherited_mutation": "Deze tekst vermeldt dat de persoon een erfelijke genetische mutatie heeft.",
    "gen_inherited_characteristic": "Deze tekst onthult een erfelijke of verworven genetische eigenschap van de persoon.",
    "gen_chromosomal": "Deze tekst vermeldt een chromosomale of genoombevinding over de persoon.",
}

# ---------------------------------------------------------------------------
# Frozen policy constants (mirror a9-quality-006/selected_genetic_policy.json).
# ---------------------------------------------------------------------------
FROZEN_G = 0.30  # generic BGE operating point for GEN4 categories
DECOMPOSED_POLITICAL_D = 0.30
DECOMPOSED_SEX_D = 0.30
DECOMPOSED_GENETIC_D = 0.50

GENETIC_GUARD = "hard"
GENETIC_MARGIN: float | None = None

# Categories whose generic BGE proposal may contribute (never the other five).
GEN4: tuple[EntityType, ...] = (
    EntityType.GENETIC_DATA,
    EntityType.HEALTH_DATA,
    EntityType.POLITICAL_OPINION,
    EntityType.SEX_LIFE,
)

# Frozen decomposition key sets.
POL_KEYS: frozenset[str] = frozenset(POL_DECOMP_EN)
SEX_KEYS: frozenset[str] = frozenset(SEX_DECOMP_EN)
GEN_KEYS: frozenset[str] = frozenset(GEN_DECOMP_EN)

# Confusion partners / hard-suppression sets used by the decomposition guards.
GENETIC_CONFUSION_PARTNERS: tuple[EntityType, ...] = (
    EntityType.RACIAL_OR_ETHNIC_ORIGIN,
    EntityType.BIOMETRIC_DATA,
)
POL_HARD_PARTNERS: tuple[EntityType, ...] = (
    EntityType.RELIGIOUS_OR_PHILOSOPHICAL_BELIEF,
    EntityType.TRADE_UNION_MEMBERSHIP,
    EntityType.RACIAL_OR_ETHNIC_ORIGIN,
    EntityType.BIOMETRIC_DATA,
)
SEX_HARD_PARTNERS: tuple[EntityType, ...] = (
    EntityType.HEALTH_DATA,
    EntityType.SEXUAL_ORIENTATION,
    EntityType.RACIAL_OR_ETHNIC_ORIGIN,
    EntityType.BIOMETRIC_DATA,
)

# Decomposition guard margin for political/sex-life (margin_hard).
DECOMP_MARGIN = 0.15

# The complete set of nine Article 9 categories in canonical evaluation order.
ARTICLE9_TYPES: tuple[EntityType, ...] = (
    EntityType.RACIAL_OR_ETHNIC_ORIGIN,
    EntityType.POLITICAL_OPINION,
    EntityType.RELIGIOUS_OR_PHILOSOPHICAL_BELIEF,
    EntityType.TRADE_UNION_MEMBERSHIP,
    EntityType.GENETIC_DATA,
    EntityType.BIOMETRIC_DATA,
    EntityType.HEALTH_DATA,
    EntityType.SEX_LIFE,
    EntityType.SEXUAL_ORIENTATION,
)

# Frozen hypotheses bundle hash recorded in HEAD_TO_HEAD_FREEZE.json. Documented
# here as a release-integrity anchor; the production tables above must match the
# frozen research bundle exactly (see the parity test).
FROZEN_HYPOTHESES_HASH_SHA256 = "043e0657dbe1e4961dc0b0e4d6569f5538910a0d8c45a8be0a72143ff9c6cc8e"


def hypothesis_for(entity_type: EntityType, language: str) -> str:
    """Return the frozen generic BGE hypothesis for ``entity_type`` in ``language``."""

    table = GEN_HYP_NL if language == "nl" else GEN_HYP_EN
    return table[entity_type]


def decomposition_for(entity_type: EntityType, language: str) -> dict[str, str]:
    """Return the frozen decomposition sub-hypotheses for ``entity_type``."""

    if entity_type == EntityType.POLITICAL_OPINION:
        return POL_DECOMP_NL if language == "nl" else POL_DECOMP_EN
    if entity_type == EntityType.SEX_LIFE:
        return SEX_DECOMP_NL if language == "nl" else SEX_DECOMP_EN
    if entity_type == EntityType.GENETIC_DATA:
        return GEN_DECOMP_NL if language == "nl" else GEN_DECOMP_EN
    return {}
