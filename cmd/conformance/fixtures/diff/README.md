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

## `precompile-fork/`

Una dirección del rango reservado **no es precompile antes de su fork de
activación**: es una cuenta vacía normal. `0x0A` (KZG) entra en Cancun y
`0x0B..=0x11` (BLS12-381) en Prague.

**La forma de este set es distinta a la de los demás y es deliberada:** cada
caso lleva `post` con **dos claves de fork**, sobre el mismo bytecode y el mismo
pre-state. Si el motor resolviera precompiles por rango en vez de por fork, los
dos forks darían exactamente lo mismo y el caso no probaría nada — la
discriminación está construida en la estructura, no confiada al autor.

Cubre las **dos** dimensiones del bug, porque un fixture que solo mire el output
ve la mitad:

- **Existencia** (`existence.json`) — un `CALL` a `0x0A` con input vacío tiene
  ÉXITO en Shanghai (cuenta vacía) y FALLA en Cancun (KZG exige 192 bytes
  exactos). Se guardan status y `RETURNDATASIZE`.
- **Costo de acceso** (`access-cost.json`) — mide el gas con `GAS`/`SWAP1`/`SUB`
  alrededor de un `BALANCE`. La dirección que todavía no es precompile arranca
  **cold (2600)**, no warm: **Δ 2500**, y **cero** diferencia en el resultado de
  nada. Es la mitad que el post-state no muestra.
- **`selfdestruct.json`** — beneficiario `0x10`, el escenario de
  `create2collisionSelfdestructed`. Acá el Δ es **2600, no 2500**: el
  beneficiario warm de SELFDESTRUCT suma **0**, no 100, al revés de `BALANCE`.

Los controles (`0x01` activa en los cuatro forks, `0x12` en ninguno) no
discriminan solos a propósito: están para que una regresión que ensanche o
corra el set caiga en algún lado.

## `selfdestruct-fork/`

EIP-6780 —"SELFDESTRUCT solo destruye si la cuenta se creó en ESTA tx"— arranca
en **Cancun**. Antes, SELFDESTRUCT borra la cuenta entera: storage, código,
nonce y balance.

Misma forma que `precompile-fork/`: el mismo caso con `post` en **dos forks**.
Las víctimas llevan **storage no vacío** a propósito — es lo que hace observable
la destrucción **sin** depender de la ceguera de `diff.rs::normalize()` a
EIP-161. Acá el juez primario es EEST, que recomputa el root MPT real; un
`[SAME]` en este set vale menos que en cualquier otro.

- **`pre-existing.json`** — la víctima existe desde el pre-state. Pre-Cancun
  desaparece entera; desde Cancun sobrevive con su storage y solo se le mueve el
  balance. Incluye `beneficiary == addr` (el saldo se **quema** pre-Cancun) y una
  variante **sin balance**, que aísla el efecto de destrucción del de balance.
- **`created-in-tx.json`** — **el control**: una cuenta creada en la tx muere en
  todos los forks. Si empieza a divergir entre forks, el cambio borró el gate en
  vez de condicionarlo, y eso cuesta 533 casos de EEST. *Corre desde Shanghai:
  en Paris lo contamina un bug ajeno (EIP-3860 cobrado pre-Shanghai), anotado en
  el generador.*
- **`revert.json`** — un par. El que **revierte NO discrimina entre forks** y se
  deja igual sabiéndolo: su valor es de regresión (que un revert restaure una
  cuenta destruida), no de discriminación. El que **no** revierte es el que
  ejercita el gate. Está dicho en el fixture para que nadie lo lea al revés.

## `create-collision/`

EIP-7610 agrega la **tercera** condición de colisión de CREATE: una cuenta con
storage no vacío colisiona aunque tenga nonce 0 y no tenga código.

**Este set NO ejercita esa regla, y es a propósito.** `revm` =38.0.0 no
implementa EIP-7610 (mismo `if` de dos condiciones, `grep -rn 7610` sobre sus
crates da cero), así que un fixture que la ejercitara daría `[DIFF]`
**legítimo** y rompería el gate por hacer lo correcto. La regla la gatean los
unit tests de `evm/tests/journal.rs` y EEST, que recomputa el root MPT real.

Lo que este set cubre es la **vecindad** donde revm sigue siendo oráculo, y su
trabajo es probar que la condición nueva no se derramó a donde no va:

- **`collides.json`** — que las dos condiciones viejas sigan decidiendo solas.
  `create2_over_an_address_that_only_has_a_nonce_collides` aísla el nonce
  desplegando primero un initcode que retorna código **vacío**: la dirección
  queda con nonce 1, sin código y sin storage, así que ni la condición del
  código ni la de 7610 pueden taparlo.
  El segundo caso, el de la cuenta **creada y destruida en la misma tx**, **NO
  discrimina** el overlay `destroyed` y se deja igual sabiéndolo: colisiona por
  el nonce 1 que dejó la creación, que ninguna destrucción borra. Está dicho en
  el `_comment` para que nadie lo lea al revés.
- **`does-not-collide.json`** — el borde, que es donde vive el riesgo real. La
  tercera condición se contesta con el storage de **una** dirección; leerlo de
  otra, o barrer el overlay de la tx sin acotarlo por cuenta, hace colisionar
  creaciones perfectamente válidas. `a_second_create2_with_another_salt…`
  despliega un contrato que escribe storage y después crea en otra dirección
  virgen; `a_create_from_a_creator_with_storage_of_its_own…` le da storage al
  **creador** (uno en el pre-state y otro escrito en la tx) y crea por `CREATE`.
  El tercero entra por el frame **raíz** (tx de creación), que es el otro camino
  al mismo chokepoint.

El set no es decorativo. Se le corrieron 5 mutaciones y el reparto de señal es
el mapa de qué gatea qué:

- borrar la tercera condición: **−50 casos de EEST**, y el diferencial ni se
  entera (0 divergencias) — la ceguera de §"Quién es el juez" medida, no
  supuesta;
- barrer el overlay de storage **sin acotar por dirección**: **5 de las 8
  corridas de este set** en `[DIFF]` (las 4 de fork del primero, más el del
  creador con storage propio) y −440 en EEST. Es la mutación para la que el set
  existe;
- `MemoryState::storage_root` contestando siempre "sin storage": **el mismo
  número exacto** que borrar la condición, que es la evidencia de que el motor
  lee el storage por el seam y por ningún otro lado.

`a_second_create2_with_another_salt…` corre en los **cuatro** forks en scope
porque la regla no tiene gating por fork; la única diferencia entre ellos es el
gas de EIP-3860, que sí lo tiene.
