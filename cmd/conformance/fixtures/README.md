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
El set completo (≈32999 GeneralStateTests + 8338 blockchain tests, el mismo de
zeth) NO se vendorea: en Fase 2 el runner los consume desde un checkout/release
externo. Acá solo viven los casos mínimos que gatean fases tempranas.
