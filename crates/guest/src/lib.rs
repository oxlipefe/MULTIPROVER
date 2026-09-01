//! `repo-b-guest` — lo que corre **adentro** de la zkVM.
//!
//! Es el único crate del árbol que produce un **ELF**, y esa es toda su razón
//! de existir. Hasta acá el motor se verificaba sobre `rlib`s, y un `rlib` no
//! contesta la pregunta que importa: *¿qué código llega de verdad al binario?*
//! El código no-genérico de una dependencia vive en su propio `rlib` y el
//! linker lo descarta **solo si nadie lo llama** — o sea que sobre `rlib`s
//! "esto no llega al guest" es una **inferencia sobre el descarte del linker**,
//! y sobre un ELF es un **hecho**.
//!
//! **Agnóstico de backend, a propósito.** No hay macro de entrada de ninguna
//! zkVM acá: el punto de entrada es una función de Rust y `_start` es un
//! símbolo pelado. El día que entre un backend, lo que cambia es el arranque,
//! no esto. Casarse con uno ahora sería tomar en la Fase 3 una decisión que es
//! de la Fase 4, y contra el multiproof.
//!
//! **Qué NO hace todavía, dicho acá y no escondido:**
//!
//! 1. **No devuelve el post-state root.** El trie disperso que lo computa desde
//!    un witness ya existe (`repo_b_witness::WitnessState::post_state_root`),
//!    pero **qué publica el guest** es una decisión de backend —el techo de
//!    salida de OpenVM/ZisK— y tomarla antes de tener ese dato sería decidir a
//!    ciegas. Mientras tanto devuelve lo que el motor produce: el diff y los
//!    outputs de las system calls de cierre.
//! 2. **No computa el `requestsHash` de EIP-7685.** Devuelve los outputs
//!    **crudos** y el commitment se queda en el cliente: mezcla esos outputs con
//!    los logs de los receipts —que el guest no deriva— y es SHA-256, una
//!    primitiva que no está adentro del ELF y que entraría por una sola regla.
//! 3. ~~**Los senders vienen pre-recuperados.**~~ **Ya no.** El input lleva el
//!    **envelope canónico firmado** y el sender se **deriva** acá adentro
//!    (`signature.rs`), antes de llamar al motor. El seam `Vm` no cambia: el VM
//!    sigue sin llamar a `recover_signer`, y *dónde* se recupera es detalle de
//!    implementación. Lo que cambia es la afirmación que la prueba sostiene —
//!    deja de ser *"si aceptás que estos mensajes vienen de estos remitentes…"*
//!    y pasa a ser sobre el bloque.
//! 4. **No enforcea el *"must execute to completion"* de EIP-4788.** Las
//!    llamadas de arranque se corren *unchecked*, que es lo que
//!    `execution-specs` hace con 2935 y con el system call en general; el texto
//!    de EIP-4788 pide además que la suya no falle, y hoy esa regla vive en el
//!    cliente. Distinguirlas exigiría que el input dijera cuál es cuál, o sea
//!    reintroducir por la puerta de atrás el flag que `closing_system_calls`
//!    evita.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod codec;
pub mod journal;
pub mod kat;
pub mod signature;

use alloc::vec::Vec;

use repo_b_common::primitives::{Address, B256, Bytes};
use repo_b_common::transaction::Transaction;
use repo_b_common::withdrawal::Withdrawal;
use repo_b_common::witness::ExecutionWitness;
use repo_b_evm::result::ExecutionResult;
use repo_b_evm::types::BlockEnv;
use repo_b_evm::{OwnVm, StateChanges, Vm};
use repo_b_witness::WitnessState;

pub use ere_platform_core::Platform;

/// Lo que el guest necesita para ejecutar un bloque sin base de datos.
///
/// Tipado y no bytes: el codec es una pieza aparte. Cuando exista, decodifica a
/// esto — el punto de entrada no cambia.
pub struct GuestInput<'a> {
    /// Los pre-images: nodos de trie, códigos, claves y la cadena de headers.
    pub witness: &'a ExecutionWitness,
    /// El ancla. Toda lectura se verifica caminando el trie desde acá, así que
    /// un witness que no corresponda a este root no puede servir nada.
    pub pre_state_root: B256,
    /// El `parentHash` del bloque que se ejecuta: el ancla de la cadena de
    /// headers que prueba los `BLOCKHASH`.
    ///
    /// **Sin esto los headers del witness no se pueden verificar.** Están ahí,
    /// pero un header suelto no prueba nada: lo que lo prueba es encadenar cada
    /// uno con el `parent_hash` del anterior desde un ancla externa. Servir un
    /// `BLOCKHASH` sin esa cadena sería confiar en un dato del propio witness.
    pub parent_hash: B256,
    pub env: BlockEnv,
    /// **Los envelopes firmados**, sin sender: quién firmó sale de la firma.
    pub txs: &'a [signature::SignedTransaction],
    pub withdrawals: Vec<Withdrawal>,
    /// System calls del **arranque** del bloque (EIP-4788, EIP-2935), en orden.
    pub opening_system_calls: &'a [(Address, Bytes)],
    /// System calls del **cierre** del bloque (EIP-7002, EIP-7251), en orden.
    ///
    /// Campo aparte y no un flag adentro de la lista de arriba, y la razón es
    /// de hardening: el input del guest es input externo, y un flag se puede
    /// setear mal. Dos campos hacen el error irrepresentable — no hay forma de
    /// pedir que una llamada de cierre corra al arrancar el bloque.
    ///
    /// Corren **después** del settle de withdrawals y antes de cerrar, porque
    /// su output es la fuente de dos de los tres tipos de request de EIP-7685 y
    /// esos requests se derivan del estado que las withdrawals ya dejaron.
    pub closing_system_calls: &'a [(Address, Bytes)],
}

/// Lo que la ejecución de un bloque produce.
///
/// El diff **y** los outputs de las system calls de cierre: los requests de
/// EIP-7685 salen de ahí, así que un `run_block` que los tirara produciría el
/// estado correcto y un bloque sin identidad.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockOutput {
    pub changes: StateChanges,
    /// Los outputs crudos de `closing_system_calls`, **en el mismo orden**. Sin
    /// re-formatear: el commitment de EIP-7685 los mezcla con los logs de los
    /// receipts y es SHA-256, dos cosas que el guest no tiene.
    pub closing_outputs: Vec<Bytes>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestError {
    /// El motor rechazó el bloque. Se conserva el texto porque distinguir un
    /// rechazo de protocolo de un error interno es la diferencia entre un
    /// bloque inválido y un bug.
    Vm(alloc::string::String),
    /// La cadena de headers del witness no encadena desde el `parent_hash`.
    /// Fail-closed: sin cadena verificada no se sirve un `BLOCKHASH`.
    Chain(alloc::string::String),
    /// Una system call de **cierre** no terminó en éxito ⇒ el bloque es
    /// inválido (`execution-specs::process_checked_system_transaction`).
    ClosingSystemCall(alloc::string::String),
    /// La firma de una tx no produce un remitente. **Invalida el bloque**: un
    /// envelope que no recupera no es una tx del bloque, y ejecutarlo con
    /// cualquier otro sender sería exactamente la mentira que este camino
    /// existe para impedir.
    Signature(alloc::string::String),
}

/// Ejecuta un bloque **solo desde el witness** y devuelve lo que produjo.
///
/// Es el camino real y completo: apertura del bloque con sus withdrawals, las
/// system calls de arranque, las txs en orden, el settle de withdrawals, las
/// system calls de cierre —cuyo output es el dato— y el cierre. Ninguna de esas
/// llamadas se puede saltear ni reordenar sin producir otro bloque.
///
/// **La asimetría entre arranque y cierre la fija el texto de cada EIP**, no una
/// preferencia: 4788 y 2935 se corren *unchecked* (`execution-specs`), mientras
/// que 7002 y 7251 son *checked* y un revert, un halt o un OOG del predeploy
/// **invalida el bloque**. Tratarlas igual sería probar que un bloque inválido
/// es válido, que es soundness y no cosmética.
///
/// # Errors
/// Devuelve `GuestError::Vm` si el motor rechaza el bloque o si el witness no
/// alcanza para una lectura — que es fail-closed a propósito: servir un dato
/// sin prueba es la única forma de que un guest mienta. `GuestError::Chain` si
/// la cadena de headers no verifica, y `GuestError::ClosingSystemCall` si una
/// llamada de cierre no terminó en éxito.
pub fn run_block(input: &GuestInput<'_>) -> Result<BlockOutput, GuestError> {
    let state = build_state(input)?;
    let txs = recover_senders(input)?;
    run_on(&state, input, &txs, true)
}

/// **Deriva el remitente de cada tx del bloque.** Es el paso que convierte un
/// envelope firmado en una tx ejecutable, y el único lugar del guest donde
/// aparece una dirección de remitente.
///
/// Corre **antes** que el motor y no adentro: el seam `Vm` recibe el sender ya
/// resuelto, igual que en un cliente real. Es una pieza aparte porque además es
/// una pieza **medible** — el peldaño `Mode::Recover` de la escalera de ciclos
/// la aísla por diferencia.
///
/// # Errors
/// `GuestError::Signature` si alguna firma no recupera. Fail-closed: no hay
/// "sender por defecto".
pub fn recover_senders(input: &GuestInput<'_>) -> Result<Vec<Transaction>, GuestError> {
    let mut out = Vec::with_capacity(input.txs.len());
    for (i, tx) in input.txs.iter().enumerate() {
        out.push(
            tx.recover(input.env.chain_id)
                .map_err(|e| GuestError::Signature(alloc::format!("tx {i}: {}", e.0)))?,
        );
    }
    Ok(out)
}

/// Construye el `WitnessState` del bloque: indexa los nodos del witness por su
/// propio hash y verifica la cadena de headers contra el ancla.
///
/// **Es una pieza aparte porque es una pieza MEDIBLE.** El desglose de ciclos
/// se produce restando corridas con piezas ablacionadas, y la
/// verificación del witness es una de las que hay que poder aislar.
fn build_state(input: &GuestInput<'_>) -> Result<WitnessState, GuestError> {
    WitnessState::new(input.witness, input.pre_state_root)
        // El número del padre NO se lee de los headers: si la cadena encadena
        // desde el ancla, la posición `i` **es** el bloque `number - 1 - i`.
        .with_chain(
            input.witness,
            input.parent_hash,
            input.env.number.saturating_sub(1),
        )
        .map_err(|e| GuestError::Chain(alloc::format!("{e}")))
}

/// El lifecycle del bloque sobre un estado ya construido.
///
/// `run_txs` existe **solo** para la medición por diferencia: con `false` corre
/// el mismo lifecycle sin las transacciones, y la resta de ciclos contra la
/// corrida completa dice cuánto cuestan. El resultado de una corrida así **no
/// es el bloque** —produce otro diff— y por eso el modo viaja adentro del
/// journal público: ver `journal::Mode`.
fn run_on(
    state: &WitnessState,
    input: &GuestInput<'_>,
    txs: &[Transaction],
    run_txs: bool,
) -> Result<BlockOutput, GuestError> {
    let mut vm = OwnVm::new();

    let fail = |e: repo_b_evm::error::VmError| GuestError::Vm(alloc::format!("{e}"));

    vm.begin_block_with_withdrawals(&input.env, state, input.withdrawals.clone())
        .map_err(fail)?;
    for (to, data) in input.opening_system_calls {
        // *Unchecked*: el resultado no se mira. Ver el doc-comment de arriba.
        vm.system_call_in_block(*to, data.clone()).map_err(fail)?;
    }
    if run_txs {
        for tx in txs {
            vm.transact_in_block(tx, tx.sender).map_err(fail)?;
        }
    }
    // Antes de las de cierre: el protocolo acredita las withdrawals después de
    // las txs, y las system calls de EIP-7685 tienen que ver ese estado.
    vm.settle_withdrawals_in_block().map_err(fail)?;

    let mut closing_outputs = Vec::with_capacity(input.closing_system_calls.len());
    for (to, data) in input.closing_system_calls {
        let outcome = vm.system_call_in_block(*to, data.clone()).map_err(fail)?;
        match outcome.result {
            ExecutionResult::Success { output, .. } => closing_outputs.push(output),
            otro => {
                return Err(GuestError::ClosingSystemCall(alloc::format!(
                    "la system call de cierre a {to} no terminó en éxito: {otro:?}"
                )));
            }
        }
    }

    let changes = vm.finish_block().map_err(fail)?;
    Ok(BlockOutput {
        changes,
        closing_outputs,
    })
}

/// **La aritmética del bump allocator, fuera del `unsafe` y testeable.**
///
/// Vivía adentro del `unsafe impl GlobalAlloc`, que está detrás de
/// `cfg(target_os = "none")` — o sea que el único código `unsafe` del repo
/// tenía además cero tests y era imposible escribirlos. Acá es una función pura
/// que el host prueba, y del otro lado queda solo la entrega del puntero.
///
/// Devuelve `(offset, siguiente)` o `None` si no entra. `align` es potencia de
/// dos por contrato de `Layout`, pero el redondeo hacia arriba igual puede
/// desbordar con un tamaño hostil, así que va con `checked_*`.
#[must_use]
pub fn reservar(actual: usize, align: usize, size: usize, arena: usize) -> Option<(usize, usize)> {
    if align == 0 || !align.is_power_of_two() {
        return None;
    }
    let alineado = actual.checked_add(align.saturating_sub(1))? & !(align.saturating_sub(1));
    let fin = alineado.checked_add(size)?;
    if fin > arena {
        return None;
    }
    Some((alineado, fin))
}

/// Un digest de lo que el bloque produjo, para que el arranque bare-metal tenga
/// algo que devolver sin poder tirarlo por optimización.
///
/// **No es el post-state root** y no pretende serlo: es un resumen de lo que la
/// ejecución produjo. El root de verdad lo computa el trie disperso, y qué
/// publica el guest es una decisión de backend que todavía no está tomada.
///
/// Los outputs de las system calls de cierre entran acá **porque son parte de
/// lo que el bloque produjo**: si el digest solo mirara el diff, el output que
/// alimenta los requests de EIP-7685 no tendría ningún consumidor adentro del
/// ELF y el linker podría descartar su camino.
#[must_use]
pub fn digest_of(output: &BlockOutput) -> B256 {
    use repo_b_common::primitives::keccak256;
    let mut bytes = Vec::new();
    for update in &output.changes {
        bytes.extend_from_slice(update.address.as_slice());
        bytes.push(u8::from(update.destroyed));
        if let Some(nonce) = update.nonce {
            bytes.extend_from_slice(&nonce.to_be_bytes());
        }
        if let Some(balance) = update.balance {
            bytes.extend_from_slice(&balance.to_be_bytes::<32>());
        }
        for (key, value) in &update.storage {
            bytes.extend_from_slice(&key.to_be_bytes::<32>());
            bytes.extend_from_slice(&value.to_be_bytes::<32>());
        }
    }
    for output in &output.closing_outputs {
        // El largo entra al digest: sin él, dos outputs concatenados distintos
        // darían los mismos bytes.
        bytes.extend_from_slice(&(output.len() as u64).to_be_bytes());
        bytes.extend_from_slice(output.as_ref());
    }
    keccak256(&bytes)
}

/// El punto de entrada genérico: **lo que corre adentro de cualquier zkVM**.
///
/// # Por qué genérico sobre `Platform`
///
/// No hay un ELF para todos los backends: el guest concreto **nombra** el suyo
/// (`ere-platform-sp1` exige `sp1_zkvm::entrypoint!`). Lo agnóstico es la
/// lógica, y esta función es esa lógica. Cada backend es un crate hoja de tres
/// líneas que instancia esto con su `Platform`; el ELF sin backend —el del ABI
/// estándar de `zkvm-standards`, que sostiene la cadena de evidencia de floats
/// e ISA— es una plataforma más y no un camino aparte.
///
/// # El input entra por `Platform::read_input`, y su primer byte es el modo
///
/// El byte de modo va **afuera** del formato del bloque a propósito: el codec
/// describe un bloque de Ethereum y el modo describe qué hace el guest con él.
/// Mezclarlos obligaría a tocar el formato de consenso para poder medir.
///
/// # Fail-closed, y ruidoso
///
/// Cualquier error —input vacío, modo desconocido, witness insuficiente, el
/// motor rechazando el bloque— **panickea**. Adentro de una zkVM un panic es
/// una ejecución que no se puede probar, que es exactamente lo que corresponde:
/// lo peligroso sería publicar un journal en ceros, porque eso es una
/// afirmación bien formada sobre un bloque que nunca se ejecutó.
///
/// # Panics
///
/// Ver arriba: es el modo de falla elegido, no un descuido.
pub fn entry<P: Platform>() {
    let raw = P::read_input();
    let journal = run_bytes(&raw).unwrap_or_else(|e| panic!("{}", e.0));
    publish::<P>(&journal.encode());
}

/// Del buffer crudo al journal. Separado de `entry` porque **se testea en el
/// host**: `entry` necesita una `Platform` y esto no.
///
/// # Errors
/// Devuelve el motivo del rechazo. Nunca un journal a medio llenar.
pub fn run_bytes(raw: &[u8]) -> Result<journal::Journal, EntryError> {
    let Some((modo, cuerpo)) = raw.split_first() else {
        return Err(EntryError("el input está vacío: no hay ni byte de modo"));
    };
    let Some(mode) = journal::Mode::from_byte(*modo) else {
        return Err(EntryError("byte de modo desconocido"));
    };
    if mode == journal::Mode::Kat {
        // **Antes que nada, y sin tocar el cuerpo.** El KAT contesta si la
        // aritmética de este ELF es correcta; hacerlo depender de decodificar
        // un input lo ataría a una pieza que justamente puede estar rota.
        let r = kat::run();
        return Ok(journal::Journal {
            mode,
            pre_state_root: kat::KAT_MAGIC,
            post_state_root: B256::from(r.digest),
            output_digest: B256::new(r.fallas.to_be_bytes()),
        });
    }
    if mode == journal::Mode::Nop {
        // La línea de base de la medición: leer el input y publicar. El cuerpo
        // no se toca — es lo que hace que la resta atribuya el decode al
        // decoder y no al I/O.
        return Ok(journal::Journal::empty(mode));
    }
    let owned = codec::decode(cuerpo).map_err(|e| EntryError(e.0))?;
    if mode == journal::Mode::DecodeOnly {
        // El input decodificado se vuelve opaco: sin esto el optimizador puede
        // probar que nadie lo usa y borrar la decodificación entera, que es
        // justo la pieza que este modo mide.
        core::hint::black_box(&owned);
        return Ok(journal::Journal::empty(mode));
    }
    let input = owned.as_input();
    // **La recuperación va acá, antes de todo lo demás.** El peldaño propio la
    // aísla: `Recover − DecodeOnly` es lo que cuesta la criptografía de firma.
    let txs = recover_senders(&input).map_err(|_| EntryError("una firma no recupera"))?;
    if mode == journal::Mode::Recover {
        core::hint::black_box(&txs);
        return Ok(journal::Journal::empty(mode));
    }
    let state = build_state(&input).map_err(|_| EntryError("el witness no verifica"))?;
    if mode == journal::Mode::StateOnly {
        core::hint::black_box(&state);
        return Ok(journal::Journal::empty(mode));
    }
    let salida = run_on(&state, &input, &txs, mode.runs_txs())
        .map_err(|_| EntryError("el bloque no ejecuta"))?;
    let post_state_root = if mode == journal::Mode::Full {
        state
            .post_state_root(&salida.changes)
            .map_err(|_| EntryError("el post-state root no se puede computar desde el witness"))?
    } else {
        B256::ZERO
    };
    Ok(journal::Journal {
        mode,
        pre_state_root: input.pre_state_root,
        post_state_root,
        output_digest: digest_of(&salida),
    })
}

/// Por qué el guest no pudo producir un journal. Un solo camino de salida: no
/// hay a quién reportarle un error parcial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryError(pub &'static str);

/// Publica el output, **haciendo cumplir el techo de los tres backends**.
///
/// El techo no se chequea "por las dudas": OpenVM y ZisK truncan o rellenan a
/// 256 bytes, así que un guest que publicara de más produciría una prueba de
/// otra cosa **en silencio**. Acá es un halt.
///
/// # Panics
/// Si el output excede `journal::MAX_PUBLIC_OUTPUT_BYTES`.
pub fn publish<P: Platform>(bytes: &[u8]) {
    assert!(
        bytes.len() <= journal::MAX_PUBLIC_OUTPUT_BYTES,
        "el output del guest excede el techo de 256 bytes de OpenVM/ZisK"
    );
    P::write_output(bytes);
}

/// La plataforma del **ABI estándar sin backend**: la que produce el ELF cuya
/// ISA y ausencia de floats gatea `scripts/check-guest-isa.sh`.
///
/// **Sobrescribe los dos métodos en vez de usar el default de `ere`.** El
/// default llama a los símbolos `read_input`/`write_output` del ABI C de
/// `zkvm-standards`, que **exporta el runtime del zkVM** — y acá no hay
/// runtime: el ELF es un binario estático que arranca en `_start`. Usar el
/// default dejaría dos símbolos indefinidos y el link fallaría; definirlos
/// nosotros exigiría dos `#[unsafe(no_mangle)]` más, o sea agrandar la única
/// excepción de `unsafe` del repo para un binario que nadie ejecuta.
pub struct StdAbiPlatform;

/// El buffer del ELF sin backend. Vacío **porque no hay host que lo llene**:
/// este ELF existe para que la ISA y los símbolos se puedan auditar sin
/// instalar ningún backend. El input de verdad entra por la `Platform` del
/// backend, por `Platform::read_input`.
static ENTRADA: [u8; 0] = [];

impl Platform for StdAbiPlatform {
    fn read_input() -> impl core::ops::Deref<Target = [u8]> {
        // **Opaco al optimizador.** Sin esto el compilador sabe que el buffer
        // está vacío, pliega el rechazo y el motor entero deja de ser
        // alcanzable: el ELF quedaría en un cascarón que pasa todas las
        // aserciones de ISA sin contener nada.
        core::hint::black_box(&ENTRADA[..])
    }

    fn write_output(output: &[u8]) {
        core::hint::black_box(output);
    }
}

#[cfg(test)]
mod tests {
    use super::reservar;
    use super::{EntryError, StdAbiPlatform, journal, publish, run_bytes};

    /// **El techo de 256 bytes es un halt, no un comentario.** OpenVM y ZisK
    /// truncan o rellenan; un guest que publicara de más produciría una prueba
    /// de otra cosa en silencio.
    #[test]
    #[should_panic(expected = "excede el techo")]
    fn publishing_over_the_ceiling_halts() {
        publish::<StdAbiPlatform>(&[0u8; journal::MAX_PUBLIC_OUTPUT_BYTES + 1]);
    }

    /// El borde exacto SÍ entra: 256 es el techo, no el primer valor prohibido.
    #[test]
    fn publishing_exactly_at_the_ceiling_is_allowed() {
        publish::<StdAbiPlatform>(&[0u8; journal::MAX_PUBLIC_OUTPUT_BYTES]);
    }

    /// **Un input vacío es un rechazo, nunca un journal en ceros.** Es la
    /// diferencia entre "no pude ejecutar" y "ejecuté un bloque vacío", y la
    /// segunda es una afirmación bien formada sobre algo que no pasó.
    #[test]
    fn an_empty_input_is_refused_instead_of_producing_a_zero_journal() {
        assert_eq!(
            run_bytes(&[]),
            Err(EntryError("el input está vacío: no hay ni byte de modo"))
        );
    }

    /// Un byte de modo desconocido tampoco cae en `Full` por default.
    #[test]
    fn an_unknown_mode_byte_is_refused() {
        assert_eq!(
            run_bytes(&[99]),
            Err(EntryError("byte de modo desconocido"))
        );
    }

    /// El modo de línea de base no toca el cuerpo: es lo que hace que la resta
    /// de la escalera le atribuya el decode al decoder y no al I/O.
    #[test]
    fn the_baseline_mode_does_not_look_at_the_body() {
        assert_eq!(
            run_bytes(&[journal::Mode::Nop.as_byte(), 0xff, 0xff]),
            Ok(journal::Journal::empty(journal::Mode::Nop))
        );
    }

    const ARENA: usize = 1024;

    /// Lo básico: la primera reserva arranca en cero y avanza su tamaño.
    #[test]
    fn the_first_allocation_starts_at_zero() {
        assert_eq!(reservar(0, 8, 16, ARENA), Some((0, 16)));
    }

    /// **La alineación se redondea hacia arriba**, y el hueco queda perdido:
    /// un bump no lo reusa, y eso es exactamente lo que lo hace determinista.
    #[test]
    fn the_offset_is_rounded_up_to_the_alignment() {
        assert_eq!(reservar(1, 8, 4, ARENA), Some((8, 12)));
        assert_eq!(reservar(8, 8, 4, ARENA), Some((8, 12)));
        assert_eq!(reservar(9, 16, 1, ARENA), Some((16, 17)));
    }

    /// Que entre justo NO es que no entre: el borde exacto es válido.
    #[test]
    fn filling_the_arena_exactly_is_allowed() {
        assert_eq!(reservar(0, 1, ARENA, ARENA), Some((0, ARENA)));
    }

    /// Un byte más que la arena es `None`, no un puntero fuera de rango.
    #[test]
    fn one_byte_past_the_arena_is_refused() {
        assert_eq!(reservar(0, 1, ARENA + 1, ARENA), None);
        assert_eq!(reservar(ARENA, 1, 1, ARENA), None);
    }

    /// **Un `Layout` hostil no puede envolver la aritmética.** Es la razón por
    /// la que todo va con `checked_*`: sin eso, un tamaño cerca de `usize::MAX`
    /// daría un offset chico y un puntero adentro de la arena.
    #[test]
    fn a_hostile_layout_cannot_wrap_the_arithmetic() {
        assert_eq!(reservar(1, 1, usize::MAX, ARENA), None);
        assert_eq!(reservar(usize::MAX, 8, 1, ARENA), None);
        assert_eq!(reservar(usize::MAX - 1, 1, 1, ARENA), None);
    }

    /// Una alineación que no es potencia de dos viola el contrato de `Layout`:
    /// se rechaza en vez de producir una máscara sin sentido.
    #[test]
    fn a_non_power_of_two_alignment_is_refused() {
        assert_eq!(reservar(0, 0, 1, ARENA), None);
        assert_eq!(reservar(0, 3, 1, ARENA), None);
        assert_eq!(reservar(0, 6, 1, ARENA), None);
    }

    /// Dos reservas seguidas **nunca se solapan**: es la propiedad que hace
    /// sound al allocator, y la que el `unsafe impl` da por sentada.
    #[test]
    fn two_allocations_never_overlap() {
        let Some((o1, n1)) = reservar(0, 8, 20, ARENA) else {
            panic!("la primera reserva tiene que entrar");
        };
        let Some((o2, _)) = reservar(n1, 8, 20, ARENA) else {
            panic!("la segunda reserva tiene que entrar");
        };
        assert!(o2 >= o1 + 20, "se solapan: {o1}+20 > {o2}");
    }
}
