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

## `calls/` — slice 2.5 (task 007)

Calls anidadas: los 4 opcodes (CALL/CALLCODE/DELEGATECALL/STATICCALL), la
tabla de contexto (quién es `ADDRESS`/`CALLER`/`CALLVALUE` y de quién es el
storage), el gas (EIP-150 63/64, `G_callvalue` 9000, `G_newaccount` 25000,
stipend 2300, cold/warm del target), la semántica de revert del sub-árbol y
RETURNDATA\* (EIP-211, incluido el footgun de RETURNDATACOPY fuera de rango).

Dos convenciones que hacen legible el set:

- **El status se guarda como `status + 1`.** Un 0 no existe en el trie, así
  que un slot ausente no distinguiría "la call falló" de "el código ni
  corrió". Con `+1`, el slot SIEMPRE aparece: 1 = falló, 2 = éxito.
- **Varios casos reenvían gas ACOTADO (0xEA60) en vez de pedir todo.** Con el
  63/64, un halt del hijo le deja al caller 1/64 y el caller ni puede
  registrar el status — el caso dejaría de probar que el frame de arriba
  SOBREVIVE al halt de abajo, que es justamente el punto.

El set no es decorativo: al cerrar 2.5 se le corrieron 4 mutaciones
deliberadas al motor (63/64 → 63/63; commit en vez de revert del sub-frame;
sin stipend; `G_newaccount` sin gatear por kind/value) y las cazó todas.

**Fuera de scope acá** (fail-closed en el motor, no en el fixture): CREATE/
CREATE2/SELFDESTRUCT (2.6), precompiles `0x01..=0x11` (2.8) y los tipos de tx
2930/4844/7702 (2.7).
