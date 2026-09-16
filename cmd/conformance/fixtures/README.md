# Fixtures vendoreados (EF tests)

Subconjunto mínimo de fixtures de conformance vendoreado para el gate. El
estado global se mide contra el set completo de EEST (`--eest`).

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
El set completo NO se vendorea: el runner lo consume desde un release externo
pineado por `sha256` (`scripts/fetch-eest.sh`, cache gitignoreado). Acá solo
viven los casos mínimos que gatean fases tempranas.

El release es **`ethereum/execution-specs` `tests@v20.0.2`** (`fixtures.tar.gz`,
~515 MB). Sobre él, el scope Paris..Prague son **32 402 `state_test` + 37 459
`blockchain_test`**. Antes era `ethereum/execution-spec-tests` `v5.4.0`
(**39 025 + 42 017**), repo que quedó **archivado**; el scope baja porque la
suite estática se portó a Python y porque el release dejó de traer el
directorio de tests lentos — la cobertura por EIP, en cambio, creció. El tag y
el `sha256` están pineados en el script, en el código y en los baselines, y un
test exige que los cinco coincidan.

*(Las cifras "≈32999 + 8338" que figuraban acá eran del set legacy
`ethereum/tests`, que está incluido dentro de EEST como `ported_static/`.)*
