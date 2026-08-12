# Fixtures vendoreados (EF tests)

Subconjunto mínimo de fixtures de conformance vendoreado para el gate. La
fuente de verdad del estado global es `docs/knowledge/CONFORMANCE.md`.

## Procedencia
- `GeneralStateTests/NonZeroValue_TransactionCALL_ToNonNonZeroBalance.json`
  - Origen: `ethereum/tests` (branch `develop`, `fixtures_general_state_tests.tgz`,
    2025-06), path original `GeneralStateTests/stNonZeroCallsTest/`.
  - Licencia: MIT (ethereum/tests). Sin modificaciones.
  - Por qué este: transferencia pura legacy (destino sin código, calldata
    vacía, tip 0, un solo index, mismo post-root en Cancun y Prague) — el
    test EF trivial del DoD de Fase 1, ejercitando validación de tx, gas
    intrínseco, transfer y post-state root real, sin arrastrar SSTORE/Host.

## Regla
El set completo (EEST v5.4.0 `--until=Prague`: **39 025 `state_test` + 42 017
`blockchain_test`**, el mismo de zeth) NO se vendorea: el runner lo consume
desde un release externo pineado por `sha256` (`scripts/fetch-eest.sh`, cache
gitignoreado). Acá solo viven los casos mínimos que gatean fases tempranas.
*(Las cifras "≈32999 + 8338" que figuraban acá eran del set legacy
`ethereum/tests`, que está incluido dentro de EEST como `state_tests/static/`;
corregidas en el slice 2.9a.)*
