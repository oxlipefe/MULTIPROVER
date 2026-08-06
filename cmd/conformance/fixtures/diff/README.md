# `fixtures/diff/` — sets del **diferencial vs revm**

Estos fixtures NO son de la EF: los escribe este repo para ejercitar, caso por
caso, la superficie de consenso del slice en curso. Los de `GeneralStateTests/`
(vendoreados, procedencia en su README) son otra cosa y **no se tocan**.

## Quién es el juez acá

El oráculo es **`revm` =38.0.0 in-process**, no el `hash`/`logs` del fixture.
Por eso los campos `post[fork][].hash` y `.logs` están en cero: el formato del
runner los exige, pero el modo `--diff` **no los mira** — compara `OwnVm` vs
`revm` byte a byte (status, `gas_used`, refund, output y post-state completo).
Escribirlos a mano sería inventar el resultado esperado; calcularlos con
nuestro propio motor sería testear el código contra sí mismo.

Para correrlos:

```sh
cargo run -p conformance --features diff-revm -- --diff fixtures/diff/storage
```

## `storage/` — slice 2.2 (task 004)

Matriz de SSTORE (EIP-2200/2929/3529), transient storage (EIP-1153),
cold/warm, tope de refund, y qué sobrevive a un `REVERT` / a un halt.

Los casos con refunds altos corren en **Cancun** a propósito: bajo Prague el
floor de calldata de EIP-7623 puede morder el gas cobrado, y ese EIP es del
slice 2.7 (hasta entonces `OwnVm` lo rechaza explícito en vez de aproximarlo).
La semántica de storage es idéntica entre Cancun y Prague, así que la matriz
queda igual de cubierta.
