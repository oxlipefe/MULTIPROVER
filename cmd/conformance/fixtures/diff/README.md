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

## `storage/`

Matriz de SSTORE (EIP-2200/2929/3529), transient storage (EIP-1153),
cold/warm, tope de refund, y qué sobrevive a un `REVERT` / a un halt.

Los casos con refunds altos corren en **Cancun** a propósito: bajo Prague el
floor de calldata de EIP-7623 puede morder el gas cobrado, y ese EIP es del
 (hasta entonces `OwnVm` lo rechaza explícito en vez de aproximarlo).
La semántica de storage es idéntica entre Cancun y Prague, así que la matriz
queda igual de cubierta.

## `calls/`

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

El set no es decorativo: al cerrar el slice se le corrieron 4 mutaciones
deliberadas al motor (63/64 → 63/63; commit en vez de revert del sub-frame;
sin stipend; `G_newaccount` sin gatear por kind/value) y las cazó todas.

**Fuera de scope acá** (fail-closed en el motor, no en el fixture): CREATE/
CREATE2/SELFDESTRUCT, precompiles `0x01..=0x11` y los
tipos de tx 2930/4844/7702.

## `create/`

Creación y destrucción de contratos: CREATE/CREATE2 (derivación EIP-1014, el
orden exacto de gas, colisión, value, initcode vacío), los tres límites del
código desplegado (EIP-3860 initcode, EIP-170 tamaño, EIP-3541 prefijo `0xEF`)
**con sus bordes exactos a un byte de distancia**, el depósito de código
(`G_codedeposit`, EIP-2 punto 3), el resultado del initcode (revert con
returndata / halt sin returndata / éxito sin returndata), SELFDESTRUCT bajo
EIP-6780 (creada-en-esta-tx vs preexistente, a sí misma, cold vs warm,
`G_newaccount` a cuenta muerta) y las **transacciones de creación** (`to: ""`).

Además de las convenciones de `calls/` (status/dirección `+1` en el slot, gas
acotado), este set tiene una propia que **no es opcional**:

- **El `gasLimit` de la tx está dimensionado para que el caller SOBREVIVA al
  sub-frame que se lleva todo el gas** (`GAS_ONE_SLOT_AFTER_BURN` /
  `GAS_TWO_SLOTS_AFTER_BURN` en `scripts/gen-create-fixtures.py`). Con el 63/64 de EIP-150, al
  caller le queda `remaining/64`; si eso no alcanza para los SSTORE que vienen
  después, el caller muere de OOG, la tx entera haltea y el caso pasa a
  comparar "los dos motores haltean" en vez de la regla de consenso que dice
  probar. Seis casos de este set nacieron así y se arreglaron recién en la
  auditoría de post-state.

El set no es decorativo: al cerrar el slice se le corrieron **18 mutaciones
deliberadas** al motor (orden bump-de-nonce/checkpoint, warm dentro vs fuera
del checkpoint, las tres variantes de la regla de colisión, off-by-one de
EIP-170 y EIP-3860, `G_newaccount` en CREATE, refund de SELFDESTRUCT,
`G_txcreate` ausente, …) y las cazó **todas**. Cinco de ellas las caza UN solo
caso cada una.

Los JSON de este set se generan con `scripts/gen-create-fixtures.py` (están
versionados igual; el script existe para que agregar un caso no sea copiar y
pegar bytecode a mano).

Direcciones fijas del set: `0xa0…` sender, `0xb0…` MAIN, `0xc0…` coinbase,
`0xd0…` beneficiary vivo, `0xe0…` cuenta muerta (inexistente), `0xf0…` proxy
(para STATICCALL), `0xc64cd893…` = `create(sender, 0)`, precomputada y fijada
por `evm/tests/creates.rs`.

## `set-code/`

EIP-7702: transacciones tipo 4 con `authorizationList`. El set cubre las tres
capas del EIP por separado — **aplicación** de las autorizaciones (el orden
exacto de los chequeos de skip, el bump del nonce del `authority`, undelegate
con la dirección cero, dos tuplas sobre la misma cuenta), **ejecución** (una
EOA delegada corre el código de la implementación sobre su PROPIO storage, en
sub-call por los cuatro opcodes y también en el frame RAÍZ, con la cadena de
dos hops halteando por EIP-3541) y **gas** (25000 por tupla declarada, refund
condicional de 12500, el acceso de EIP-2929 a la cuenta delegada, y el refund
sobreviviendo a un revert y a un halt).

Dos convenciones propias, además de las de `calls/`:

- **`authority` viene YA recuperado en el fixture** (`"authority": "0x…"`, o
  `null` para modelar una firma inválida). Acá no hay ECDSA de ningún lado: el
  harness le inyecta a revm el mismo valor vía `RecoveredAuthorization`, así
  que ningún motor tiene ventaja. Es el mismo contrato que `sender`.
- **`maxPriorityFeePerGas != 0` en todos los casos tipo 4.** El tip le deja al
  coinbase un balance proporcional al gas cobrado: un SEGUNDO observable del
  gas en el post-state, además del balance del sender.

Dos pares de casos valen por lo que miden **por diferencia** y no hay que
romperlos al agregar casos nuevos:

- `wrong_nonce_is_skipped` (la `authority` queda CALIENTE) vs
  `for_another_chain_is_skipped` (queda fría): **2500 de gas de diferencia**.
  Es la única evidencia observable de que el warm de EIP-2929 ocurre DESPUÉS
  de los chequeos de chain_id/nonce-máximo/firma y ANTES de los de código y
  nonce.
- `over_an_account_that_does_not_exist_gets_no_refund` vs
  `over_an_account_that_exists_but_is_empty_gets_the_refund`: **12500 exactos**
  de diferencia. Es el borde de la condición `!(vacía ∧ inexistente)`.

El set no es decorativo: al cerrar el slice se le corrieron **18 mutaciones
deliberadas** al motor y las cazó todas — pero **17 a la primera**: la que
permitía pisar el código real de una cuenta salió en 0 divergencias y destapó
que ese caso declaraba un nonce que no coincidía, así que el chequeo de nonce
enmascaraba al de código y el fixture no probaba su propia regla. Corregido
antes de cerrar. Es el mismo patrón que 008 it.3 en
otra variable.

Los JSON se generan con `scripts/gen-set-code-fixtures.py`.

Direcciones fijas del set: `0xa0…` sender, `0xb0…` MAIN (el que llama),
`0xb1…` cuenta con código REAL, `0xc0…` coinbase, `0xd0…` ALICE (authority que
existe), `0xd1…` GHOST (existe en el trie pero vacía), `0xe0…` FRESH (no
existe), `0xf0…`/`0xf1…` implementaciones delegadas, `0xf2…` cuenta ya
delegada (para la cadena de dos hops).
