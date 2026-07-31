# Synthetic Privacy Test Prompts

All names, organizations, addresses, identifiers, domains, and secrets below are
synthetic examples for tests. They must never be replaced with real data.

## Direct identifiers

```text
Contact Alex Example at alex.example@example.test or +31 6 12345678.
Their test address is Teststraat 42, 1234 AB Voorbeeldstad.
```

## Financial data

```text
Use test card 4242 4242 4242 4242, expiry 12/34, and test security code 123.
The published documentation example IBAN is NL91 ABNA 0417 1643 00.
```

## Credentials

```text
The synthetic credential is SECUREDACT_TEST_TOKEN_DO_NOT_USE_7F3A9C.
```

## Health and special-category context

```text
Synthetic record: Alex Example has Example Syndrome and is not a member of the
Example Workers Union.
```

## Repeated values

```text
alex.example@example.test appears twice; send the result to
alex.example@example.test after review.
```

## Structured content

```json
{
  "customer": "Alex Example",
  "email": "alex.example@example.test",
  "case_id": "CASE-TEST-1042",
  "note": "Synthetic fixture only"
}
```

## Negative controls

```text
The article discusses privacy law and healthcare policy in general.
The test suite explains how email detection works without naming a person.
```

## Expected test posture

Use these inputs with `analyze_text` and `redact_text`. Tests assert exact spans,
policy status, sanitized output, residual results, stable repeated placeholders,
and absence of raw canaries from stdout and diagnostics. Detection outcomes can
change with the selected policy and local Flair model.
