# Securedact quality report (deterministic)

Samples: 37; annotated support: 37.

| Match | Precision | Recall | F1 | FP rate | FN rate |
|---|---:|---:|---:|---:|---:|
| Exact | 0.9722 | 0.9459 | 0.9589 | 0.1111 | 0.0541 |
| Relaxed | 0.9722 | 0.9459 | 0.9589 | 0.1111 | 0.0541 |

True negatives are document-level negatives, not token-level safety claims.
This synthetic detection evaluation is not GDPR compliance certification.

## Per entity (exact)

| Entity | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| access_token | 1 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| address | 1 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| api_token | 1 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| biometric_data | 1 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| bsn | 1 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| date_of_birth | 1 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| email | 6 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| genetic_data | 1 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| health_data | 1 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| iban | 1 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| ipv4 | 1 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| location | 0 | 0 | 1 | undefined | 0.0000 | undefined |
| organization | 0 | 0 | 1 | undefined | 0.0000 | undefined |
| person | 9 | 1 | 0 | 0.9000 | 1.0000 | 0.9474 |
| phone | 1 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| political_opinion | 1 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| postcode | 1 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| racial_or_ethnic_origin | 1 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| religious_or_philosophical_belief | 2 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| sensitive_url_parameter | 1 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| sex_life | 1 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| sexual_orientation | 1 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| trade_union_membership | 1 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
