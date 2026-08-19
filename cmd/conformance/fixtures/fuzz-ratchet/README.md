# `fuzz-ratchet/` — el trinquete del red-team

Acá caen los **reproductores minimizados** de los hallazgos de una campaña de
fuzzing diferencial: un archivo por cluster, escrito por `--fuzz --out`.

**Hoy está vacío, y ésa es la razón correcta:** ninguna campaña encontró todavía
un bug real del motor. Las divergencias que sí aparecen (EIP-7610, invariantes
de encoding de los tipos 3 y 4) son **deliberadas**, están en el inventario de
`oracle.rs` y no son bugs.

El directorio existe igual, versionado, porque tiene que estar **antes** del
primer hallazgo: si no, el primero se pierde por no tener dónde caer.

## Cómo entra un caso acá

```sh
cargo run -p conformance --release --features diff-revm -- \
  --fuzz --mutate --cases 200000 --out cmd/conformance/fixtures/fuzz-ratchet
```

## Qué pasa cuando entra uno

Lo levanta el **loop de regresión** (`--fuzz --regression`), que corre en el gate
de merge. Desde ese momento el bug no puede volver: cada divergencia cazada una
vez pasa a ser defensa permanente.

Al sembrar el primero hay que **subir el piso** `MIN_REGRESSION_CASES` en
`src/fuzz/regression.rs`. El piso es lo que hace que "el corpus está sembrado"
sea una afirmación falsable.
