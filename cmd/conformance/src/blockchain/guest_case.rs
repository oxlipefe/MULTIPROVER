//! **El bloque real congelado, contra el guest y contra un input hostil.**
//!
//! El corpus le da al guest decenas de miles de bloques, y eso cubre el camino
//! feliz y los rechazos que un fixture sabe describir. Lo que no cubre es lo
//! que un prover haría con un bloque **válido**: cambiarle un byte al input y
//! ver si la prueba sigue saliendo. Acá se hace eso sobre el caso que corre
//! adentro del zkVM (`fixtures/guest`):
//!
//! - cada chequeo del guest tiene un test que lo dispara con su error exacto,
//!   así que borrar el chequeo cambia el error y el test cae;
//! - cada campo del header, alterado, hace fallar el bloque o cambia el hash;
//! - **todo** byte del input, invertido, da un error o un journal distinto.

use alloy_rlp::Encodable;
use repo_b_common::primitives::{Address, B256, Bytes, U256};
use repo_b_common::spec::Spec;
use repo_b_common::withdrawal::Withdrawal;
use repo_b_guest::block::{BlockError, Check, HeaderField, SystemCall, decode_block, encode_block};
use repo_b_guest::codec::{BlockInput, decode_block_input};
use repo_b_guest::journal::{Journal, Mode, fork_from_id};
use repo_b_guest::signature::{Signature, SignedTransaction, decode_2718};
use repo_b_guest::{GuestError, Header, check_block, run_block_input, run_bytes};

use super::dump::{CASE_INPUT, CASE_JOURNAL};

fn fixture(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/guest")
        .join(name)
}

/// Los bytes del caso, tal cual los consume `cmd/zkvm` (sin el byte de modo).
fn caso() -> Vec<u8> {
    match std::fs::read(fixture(CASE_INPUT)) {
        Ok(bytes) => bytes,
        Err(e) => panic!("no se pudo leer el caso congelado: {e}"),
    }
}

fn input() -> BlockInput {
    match decode_block_input(&caso()) {
        Ok(input) => input,
        Err(e) => panic!("el caso congelado tiene que decodificar: {e:?}"),
    }
}

/// El journal que el driver computó con el estado completo.
fn congelado() -> Journal {
    let texto = match std::fs::read_to_string(fixture(CASE_JOURNAL)) {
        Ok(t) => t,
        Err(e) => panic!("no se pudo leer el journal congelado: {e}"),
    };
    let valor = |campo: &str| -> String {
        let prefijo = format!("{campo} ");
        match texto
            .lines()
            .find_map(|l| l.strip_prefix(prefijo.as_str()))
            .and_then(|r| r.split_whitespace().next())
        {
            Some(v) => v.to_owned(),
            None => panic!("el journal congelado no declara `{campo}`"),
        }
    };
    let hash = |campo: &str| -> B256 {
        match valor(campo).parse() {
            Ok(h) => h,
            Err(e) => panic!("`{campo}` no es un hash: {e}"),
        }
    };
    let (Ok(chain_id), Ok(fork)) = (valor("chain_id").parse(), valor("fork").parse::<u8>()) else {
        panic!("chain_id y fork tienen que ser números");
    };
    Journal {
        mode: Mode::Full,
        chain_id,
        fork: fork_from_id(fork),
        block_hash: hash("block_hash"),
        parent_hash: hash("parent_hash"),
        pre_state_root: hash("pre_state_root"),
        post_state_root: hash("post_state_root"),
        output_digest: hash("output_digest"),
    }
}

/// El bloque del caso, en partes que se pueden alterar y volver a armar.
struct Partes {
    header: Header,
    txs: Vec<Vec<u8>>,
    withdrawals: Option<Vec<Withdrawal>>,
}

fn partes(input: &BlockInput) -> Partes {
    let block = match decode_block(&input.block) {
        Ok(b) => b,
        Err(e) => panic!("el bloque del caso tiene que decodificar: {e}"),
    };
    Partes {
        header: block.header.clone(),
        txs: block.transactions.iter().map(|t| t.to_vec()).collect(),
        withdrawals: block.withdrawals.clone(),
    }
}

/// El input con el bloque rearmado desde sus partes. El resto queda igual.
fn armar(partes: &Partes) -> BlockInput {
    BlockInput {
        block: encode_block(&partes.header, &partes.txs, partes.withdrawals.as_deref()).into(),
        ..input()
    }
}

fn correr(input: &BlockInput) -> Result<Journal, GuestError> {
    run_block_input(Mode::Full, input)
}

#[track_caller]
fn rechazo(input: &BlockInput) -> BlockError {
    match correr(input) {
        Err(GuestError::Block(e)) => e,
        otro => panic!("se esperaba un rechazo de validación y el guest dio {otro:?}"),
    }
}

/// La recíproca de todo lo de abajo, y sin ella nada de abajo prueba nada: el
/// caso **sin mutar** ejecuta y da el journal que el driver computó con el
/// estado completo, por el MISMO camino de bytes que corre el zkVM.
#[test]
fn the_frozen_case_executes_to_its_journal() {
    let mut buf = vec![Mode::Full.as_byte()];
    buf.extend_from_slice(&caso());
    assert_eq!(run_bytes(&buf), Ok(congelado()));
    // Y el rearmado desde las partes es byte a byte el original: los tests que
    // alteran una parte no alteran nada más.
    assert_eq!(armar(&partes(&input())), input());
}

/// El journal no es trivial: nombra el bloque bajo el fork declarado, sobre su
/// padre, y el pre-state es el `stateRoot` del padre.
#[test]
fn the_journal_names_the_block_and_its_parent() {
    let j = congelado();
    let input = input();
    let partes = partes(&input);
    let Some(padre) = input.witness.headers.first() else {
        panic!("el caso tiene que traer el padre");
    };
    let Ok(padre) = Header::decode_exact(padre) else {
        panic!("el padre tiene que decodificar");
    };
    assert_eq!(j.fork, Some(input.fork));
    assert!(
        input.fork.is_enabled(Spec::Prague),
        "el caso ejercita las system calls de cierre"
    );
    assert_eq!(j.block_hash, partes.header.hash());
    assert_eq!(j.parent_hash, padre.hash());
    assert_eq!(j.parent_hash, partes.header.parent_hash);
    assert_eq!(j.pre_state_root, padre.state_root);
    assert_eq!(j.post_state_root, partes.header.state_root);
    assert_ne!(j.output_digest, B256::ZERO);
}

/// **Las system calls salen del fork y del header**, y son exactamente estas:
/// 4788 con el `parentBeaconBlockRoot` y 2935 con el `parentHash`, *unchecked*,
/// y las dos de cierre sin calldata y *checked*. No hay byte del input que las nombre.
#[test]
fn the_system_calls_are_derived_from_the_header() {
    let Ok(checked) = check_block(&input()) else {
        panic!("el caso tiene que validar");
    };
    let Ok(calls) = checked.system_calls() else {
        panic!("un bloque de Prague tiene system calls");
    };
    let Some(beacon) = checked.header.parent_beacon_block_root else {
        panic!("un header de Prague trae parentBeaconBlockRoot");
    };
    let llamada = |address, calldata: &[u8], check| SystemCall {
        address,
        calldata: Bytes::copy_from_slice(calldata),
        check,
    };
    assert_eq!(
        calls.opening,
        vec![
            llamada(
                repo_b_evm::BEACON_ROOTS_ADDRESS,
                beacon.as_slice(),
                Check::Unchecked
            ),
            llamada(
                repo_b_evm::HISTORY_STORAGE_ADDRESS,
                checked.header.parent_hash.as_slice(),
                Check::Unchecked
            ),
        ]
    );
    assert_eq!(
        calls.closing,
        vec![
            llamada(repo_b_evm::WITHDRAWAL_REQUESTS_ADDRESS, &[], Check::Checked),
            llamada(
                repo_b_evm::CONSOLIDATION_REQUESTS_ADDRESS,
                &[],
                Check::Checked
            ),
        ]
    );
}

/// El `env` sale del header: lo que el motor ve como coinbase, timestamp,
/// gas limit, base fee y prevrandao es lo que el header declara.
#[test]
fn the_env_is_derived_from_the_header() {
    let Ok(checked) = check_block(&input()) else {
        panic!("el caso tiene que validar");
    };
    let Ok(env) = checked.env() else {
        panic!("un header validado tiene env");
    };
    let h = &checked.header;
    assert_eq!(env.spec, input().fork);
    assert_eq!(env.chain_id, congelado().chain_id);
    assert_eq!(env.number, h.number);
    assert_eq!(env.coinbase, h.beneficiary);
    assert_eq!(env.timestamp, h.timestamp);
    assert_eq!(env.gas_limit, h.gas_limit);
    assert_eq!(Some(env.base_fee), h.base_fee_per_gas);
    assert_eq!(env.prevrandao, h.mix_hash);
    assert_eq!(env.blob_excess_gas, h.excess_blob_gas);

    // El `mixHash` del caso es cero, así que la aserción de arriba no separa
    // "sale del header" de "es cero". Con otro `mixHash` el bloque sigue
    // pasando la validación previa, y el `prevrandao` tiene que seguirlo.
    let otro = B256::repeat_byte(0x42);
    let Ok(alterado) = check_block(&con_header(|h| h.mix_hash = B256::repeat_byte(0x42))) else {
        panic!("un mixHash distinto no invalida el header");
    };
    assert_eq!(alterado.env().map(|e| e.prevrandao), Ok(otro));
}

// ---------------------------------------------------------------------------
// El padre.
// ---------------------------------------------------------------------------

#[test]
fn a_missing_parent_is_refused() {
    let mut sin_padre = input();
    sin_padre.witness.headers.clear();
    assert_eq!(
        correr(&sin_padre),
        Err(GuestError::Input("el witness no trae el header del padre"))
    );
}

/// Un padre que no es el padre: otro header bien formado, con el mismo número,
/// otro `extraData`. El header del hijo no encadena con él.
#[test]
fn a_wrong_parent_is_refused() {
    let mut input = input();
    let Some(raw) = input.witness.headers.first() else {
        panic!("el caso tiene que traer el padre");
    };
    let Ok(mut otro) = Header::decode_exact(raw) else {
        panic!("el padre tiene que decodificar");
    };
    otro.extra_data = Bytes::from_static(b"otro padre");
    if let Some(h) = input.witness.headers.first_mut() {
        *h = Bytes::from(otro.rlp());
    }
    assert!(matches!(rechazo(&input), BlockError::ParentHash { .. }));
}

/// **El `pre_state_root` es el del padre.** Un padre con otro `stateRoot` es
/// otro padre: el hash no encadena, y no hay forma de arrancar desde otro
/// estado sin cambiar el `parent_hash` que el journal publica.
#[test]
fn a_parent_with_another_state_root_is_refused() {
    let mut input = input();
    let Some(raw) = input.witness.headers.first() else {
        panic!("el caso tiene que traer el padre");
    };
    let Ok(mut otro) = Header::decode_exact(raw) else {
        panic!("el padre tiene que decodificar");
    };
    otro.state_root = B256::repeat_byte(0x5a);
    if let Some(h) = input.witness.headers.first_mut() {
        *h = Bytes::from(otro.rlp());
    }
    assert!(matches!(rechazo(&input), BlockError::ParentHash { .. }));
}

// ---------------------------------------------------------------------------
// El fork.
// ---------------------------------------------------------------------------

/// **El fork declarado tiene que ser el de los campos del header.** Un header
/// de Prague declarado Cancun trae `requestsHash`, que Cancun no tiene; y
/// declarado Shanghai, los campos de blob.
#[test]
fn a_fork_that_does_not_match_the_header_is_refused() {
    for (fork, campo) in [
        (Spec::Cancun, HeaderField::RequestsHash),
        (Spec::Shanghai, HeaderField::BlobGasUsed),
        (Spec::Paris, HeaderField::WithdrawalsRoot),
    ] {
        let declarado = BlockInput { fork, ..input() };
        assert_eq!(
            rechazo(&declarado),
            BlockError::UnexpectedField {
                field: campo,
                spec: fork
            },
            "{fork:?}"
        );
    }
}

/// Prague y Osaka tienen los mismos campos de header, así que el mismo header
/// es de los dos forks. El guest no conoce el reloj de activación: lo que hace
/// es **publicar** el fork, y la prueba deja de ser la de este bloque bajo su
/// fork.
#[test]
fn a_fork_with_the_same_header_fields_is_published() {
    let input = input();
    let otro = if input.fork == Spec::Osaka {
        Spec::Prague
    } else {
        Spec::Osaka
    };
    let declarado = BlockInput {
        fork: otro,
        ..input
    };
    match correr(&declarado) {
        Err(_) => {}
        Ok(j) => {
            assert_eq!(j.fork, Some(otro));
            assert_ne!(j, congelado());
        }
    }
}

/// El `chain_id` viaja en el journal, y las firmas lo exigen.
#[test]
fn another_chain_id_is_refused_or_published() {
    let otra = BlockInput {
        chain_id: 7,
        ..input()
    };
    match correr(&otra) {
        Err(_) => {}
        Ok(j) => assert_eq!(j.chain_id, 7),
    }
}

// ---------------------------------------------------------------------------
// El cuerpo contra el header, y el tope de EIP-7934.
// ---------------------------------------------------------------------------

#[test]
fn an_extra_transaction_breaks_the_transactions_root() {
    let mut p = partes(&input());
    let Some(primera) = p.txs.first().cloned() else {
        panic!("el caso tiene txs");
    };
    p.txs.push(primera);
    assert!(matches!(
        rechazo(&armar(&p)),
        BlockError::TransactionsRoot { .. }
    ));
}

#[test]
fn an_extra_withdrawal_breaks_the_withdrawals_root() {
    let mut p = partes(&input());
    p.withdrawals.get_or_insert_with(Vec::new).push(Withdrawal {
        index: 0,
        validator_index: 0,
        address: Address::repeat_byte(0x99),
        amount: 1,
    });
    assert!(matches!(
        rechazo(&armar(&p)),
        BlockError::WithdrawalsRoot { .. }
    ));
}

#[test]
fn a_prague_body_without_the_withdrawals_list_is_refused() {
    let mut p = partes(&input());
    p.withdrawals = None;
    assert!(matches!(rechazo(&armar(&p)), BlockError::BodyShape { .. }));
}

/// Los ommers se cuentan del RLP recibido. El `ommersHash` del header sigue
/// siendo el de la lista vacía, así que lo que falla es el cuerpo.
#[test]
fn an_ommer_in_the_body_is_refused() {
    let input = input();
    let p = partes(&input);
    let mut items = p.header.rlp();
    let mut txs = Vec::new();
    for tx in &p.txs {
        if tx.first().is_some_and(|b| *b >= 0xc0) {
            txs.extend_from_slice(tx);
        } else {
            Bytes::copy_from_slice(tx).encode(&mut txs);
        }
    }
    let lista = |payload: &[u8], out: &mut Vec<u8>| {
        alloy_rlp::Header {
            list: true,
            payload_length: payload.len(),
        }
        .encode(out);
        out.extend_from_slice(payload);
    };
    lista(&txs, &mut items);
    lista(&p.header.rlp(), &mut items);
    let mut ws = Vec::new();
    for w in p.withdrawals.as_deref().unwrap_or_default() {
        w.encode(&mut ws);
    }
    lista(&ws, &mut items);
    let mut raw = Vec::new();
    lista(&items, &mut raw);
    let con_ommer = BlockInput {
        block: raw.into(),
        ..input
    };
    assert_eq!(rechazo(&con_ommer), BlockError::NonEmptyOmmers { count: 1 });
}

/// `blobGasUsed` del header contra lo que suman las txs.
#[test]
fn a_blob_gas_used_the_txs_do_not_add_up_to_is_refused() {
    let mut p = partes(&input());
    let usado = p.header.blob_gas_used.unwrap_or_default();
    p.header.blob_gas_used = Some(usado.saturating_add(repo_b_evm::blob::GAS_PER_BLOB));
    assert!(matches!(
        rechazo(&armar(&p)),
        BlockError::BlobGasUsed { .. }
    ));
}

/// **EIP-7934**: desde Osaka el RLP del bloque entero no pasa de 8 MiB. Se mide
/// sobre los bytes recibidos y antes que cualquier otra regla. En Prague el
/// mismo bloque no tiene tope y falla por otra cosa (la tx de relleno no es una
/// tx).
#[test]
fn the_block_rlp_size_is_capped_from_osaka() {
    let mut p = partes(&input());
    let mut relleno = vec![0x02u8];
    relleno.resize(repo_b_guest::block::validate::MAX_RLP_BLOCK_SIZE, 0);
    p.txs.push(relleno);
    let grande = armar(&p);
    assert!(grande.block.len() > repo_b_guest::block::validate::MAX_RLP_BLOCK_SIZE);
    let osaka = BlockInput {
        fork: Spec::Osaka,
        ..grande.clone()
    };
    assert!(matches!(
        rechazo(&osaka),
        BlockError::BlockRlpTooLarge { .. }
    ));
    let prague = BlockInput {
        fork: Spec::Prague,
        ..grande
    };
    assert!(!matches!(
        correr(&prague),
        Err(GuestError::Block(BlockError::BlockRlpTooLarge { .. }))
    ));
}

// ---------------------------------------------------------------------------
// Lo ejecutado contra el header.
// ---------------------------------------------------------------------------

#[track_caller]
fn con_header(cambio: impl Fn(&mut Header)) -> BlockInput {
    let mut p = partes(&input());
    cambio(&mut p.header);
    armar(&p)
}

#[test]
fn the_post_execution_fields_are_checked() {
    assert!(matches!(
        rechazo(&con_header(|h| h.state_root = B256::repeat_byte(1))),
        BlockError::StateRoot { .. }
    ));
    assert!(matches!(
        rechazo(&con_header(|h| h.gas_used = h.gas_used.saturating_sub(1))),
        BlockError::GasUsed { .. }
    ));
    assert!(matches!(
        rechazo(&con_header(|h| h.receipts_root = B256::repeat_byte(1))),
        BlockError::ReceiptsRoot { .. }
    ));
    assert_eq!(
        rechazo(&con_header(|h| h.logs_bloom.0[0] ^= 0x80)),
        BlockError::LogsBloom
    );
    assert!(matches!(
        rechazo(&con_header(|h| h.requests_hash = Some(B256::repeat_byte(1)))),
        BlockError::RequestsHash { .. }
    ));
}

/// El header contra el padre corre adentro del guest: un `timestamp` igual al
/// del padre es un rechazo de validación, no un bloque que ejecuta.
#[test]
fn the_header_is_validated_against_the_parent() {
    let Some(raw) = input().witness.headers.first().cloned() else {
        panic!("el caso tiene que traer el padre");
    };
    let Ok(padre) = Header::decode_exact(&raw) else {
        panic!("el padre tiene que decodificar");
    };
    assert!(matches!(
        rechazo(&con_header(|h| h.timestamp = padre.timestamp)),
        BlockError::TimestampNotAfterParent { .. }
    ));
}

/// **Cada campo del header, alterado, hace fallar el bloque o cambia el
/// hash.** Que cambie el hash es automático; lo que el test fija es CUÁLES
/// campos el guest acepta alterados, porque esos son los que el protocolo no
/// ata a nada más que al hash: un campo nuevo en esa lista es un chequeo que se
/// perdió.
#[test]
fn every_header_field_is_bound() {
    type Cambio = fn(&mut Header);
    let campos: [(&str, Cambio); 21] = [
        ("parentHash", |h| h.parent_hash.0[0] ^= 1),
        ("ommersHash", |h| h.ommers_hash.0[0] ^= 1),
        ("beneficiary", |h| h.beneficiary.0[0] ^= 1),
        ("stateRoot", |h| h.state_root.0[0] ^= 1),
        ("transactionsRoot", |h| h.transactions_root.0[0] ^= 1),
        ("receiptsRoot", |h| h.receipts_root.0[0] ^= 1),
        ("logsBloom", |h| h.logs_bloom.0[0] ^= 1),
        ("difficulty", |h| {
            h.difficulty = h.difficulty.saturating_add(U256::from(1u8));
        }),
        ("number", |h| h.number = h.number.saturating_add(1)),
        ("gasLimit", |h| h.gas_limit = h.gas_limit.saturating_add(1)),
        ("gasUsed", |h| h.gas_used ^= 1),
        ("timestamp", |h| h.timestamp = h.timestamp.saturating_add(1)),
        ("extraData", |h| {
            let mut e = h.extra_data.to_vec();
            e.push(0x42);
            h.extra_data = e.into();
        }),
        ("mixHash", |h| h.mix_hash.0[0] ^= 1),
        ("nonce", |h| h.nonce.0[0] ^= 1),
        ("baseFeePerGas", |h| {
            h.base_fee_per_gas = h.base_fee_per_gas.map(|v| v.saturating_add(1));
        }),
        ("withdrawalsRoot", |h| {
            h.withdrawals_root = h.withdrawals_root.map(|mut r| {
                r.0[0] ^= 1;
                r
            });
        }),
        ("blobGasUsed", |h| {
            h.blob_gas_used = h.blob_gas_used.map(|v| v.saturating_add(1));
        }),
        ("excessBlobGas", |h| {
            h.excess_blob_gas = h.excess_blob_gas.map(|v| v.saturating_add(1));
        }),
        ("parentBeaconBlockRoot", |h| {
            h.parent_beacon_block_root = h.parent_beacon_block_root.map(|mut r| {
                r.0[0] ^= 1;
                r
            });
        }),
        ("requestsHash", |h| {
            h.requests_hash = h.requests_hash.map(|mut r| {
                r.0[0] ^= 1;
                r
            });
        }),
    ];
    let original = congelado();
    let mut aceptados = Vec::new();
    for (nombre, cambio) in campos {
        match correr(&con_header(cambio)) {
            Err(_) => {}
            Ok(j) => {
                assert_ne!(j.block_hash, original.block_hash, "{nombre}");
                aceptados.push(nombre);
            }
        }
    }
    assert_eq!(aceptados, EXPECTED_FREE_HEADER_FIELDS);
}

/// Los campos que el protocolo deja libres en este bloque: el `gasLimit` (dentro
/// de `padre/1024`, y las txs del caso entran igual), el `extraData` (dentro de sus
/// 32 bytes) y el `mixHash` (el `prevrandao`, que las txs del caso
/// no lee). Alterarlos produce otro bloque válido —con otro hash—, no el mismo.
const EXPECTED_FREE_HEADER_FIELDS: [&str; 3] = ["gasLimit", "extraData", "mixHash"];

/// **M2 — un sender falsificado NO puede pasar.** El envelope se re-firma con
/// otra clave; el `transactionsRoot` se recomputa y el bloque se rearma, para
/// que lo único que lo invalide sea quién firmó. No hay campo `sender` que
/// tocar: el atacante tiene que cambiar la firma, y entonces el bloque que
/// ejecuta ya no es este.
#[test]
fn a_forged_sender_cannot_produce_the_block() {
    use k256::ecdsa::SigningKey;

    let input = input();
    let mut p = partes(&input);
    let Some(primera) = p.txs.first() else {
        panic!("el caso tiene txs");
    };
    let Ok(original) = decode_2718(primera) else {
        panic!("la tx del caso tiene que decodificar");
    };
    let Ok(key) = SigningKey::from_slice(B256::repeat_byte(0x11).as_slice()) else {
        panic!("la clave del atacante tiene que ser válida");
    };
    let tipada = original.chain_id().is_some();
    let chain = U256::from(input.chain_id);
    let legacy_v = |paridad: u8| {
        chain
            .saturating_mul(U256::from(2u8))
            .saturating_add(U256::from(35u8.saturating_add(paridad)))
    };
    let armar_tx = |sig: Signature| {
        SignedTransaction::new(
            original.payload().clone(),
            original.chain_id(),
            sig,
            original.authorization_signatures().to_vec(),
        )
    };
    let relleno = Signature {
        v: if tipada { U256::ZERO } else { legacy_v(0) },
        r: U256::from(1u8),
        s: U256::from(1u8),
    };
    let Ok(hash) = armar_tx(relleno).signing_hash(input.chain_id) else {
        panic!("el envelope del caso tiene que ser representable");
    };
    let Ok((firma, recid)) = key.sign_prehash_recoverable(hash.as_slice()) else {
        panic!("firmar no puede fallar");
    };
    let paridad = recid.to_byte() & 1;
    let forjada = armar_tx(Signature {
        v: if tipada {
            U256::from(paridad)
        } else {
            legacy_v(paridad)
        },
        r: U256::from_be_slice(&firma.r().to_bytes()),
        s: U256::from_be_slice(&firma.s().to_bytes()),
    });
    let Ok(envelope) = forjada.encode_2718() else {
        panic!("el envelope forjado tiene que encodear");
    };
    if let Some(t) = p.txs.first_mut() {
        *t = envelope;
    }
    p.header.transactions_root = repo_b_guest::block::roots::transactions_root(&p.txs);
    match correr(&armar(&p)) {
        Err(_) => {}
        Ok(j) => assert_ne!(
            j,
            congelado(),
            "un sender falsificado produjo EL MISMO journal"
        ),
    }
}

/// **El barrido completo: todo byte del input, invertido, da un error o un
/// journal distinto.** Es la pregunta que hace el prover deshonesto, en todas
/// las posiciones y no en una muestra. Un byte cuya inversión deja el journal
/// igual es un byte que la prueba no ata, y la lista de excepciones tiene que
/// decir por qué ese byte no se consulta.
#[test]
fn every_flipped_byte_of_the_input_is_caught() {
    let bytes = caso();
    let original = congelado();
    let mut silenciosos = Vec::new();
    let mut errores = 0usize;
    let mut otros = 0usize;
    for i in 0..bytes.len() {
        let mut buf = Vec::with_capacity(bytes.len().saturating_add(1));
        buf.push(Mode::Full.as_byte());
        buf.extend_from_slice(&bytes);
        if let Some(b) = buf.get_mut(i.saturating_add(1)) {
            *b ^= 0xff;
        }
        match run_bytes(&buf) {
            Err(_) => errores = errores.saturating_add(1),
            Ok(j) if j == original => silenciosos.push(i),
            Ok(_) => otros = otros.saturating_add(1),
        }
    }
    eprintln!(
        "barrido: {} offsets · {errores} error · {otros} journal distinto · {} silenciosos {silenciosos:?}",
        bytes.len(),
        silenciosos.len()
    );
    for i in &silenciosos {
        eprintln!("  silencioso {i}: {}", region(&bytes, *i));
    }
    let permitidos = empty_node_offsets(&bytes);
    let sin_justificar: Vec<usize> = silenciosos
        .iter()
        .copied()
        .filter(|i| !permitidos.contains(i))
        .collect();
    assert_eq!(sin_justificar, Vec::<usize>::new());
}

/// **La única excepción del barrido, con su prueba.** El witness puede traer el
/// nodo vacío (`0x80`, el RLP de la cadena vacía), cuyo hash es
/// `EMPTY_ROOT_HASH`. Ese nodo **nunca se consulta**: el walk del trie devuelve
/// "ausente" en cuanto el root es `EMPTY_ROOT_HASH`, sin buscar ningún nodo
/// (`WitnessState::walk`). Invertir la cabecera de su ítem (`0x81 → 0x7e`)
/// convierte `[0x80]` en dos ítems —`0x7e` y la cadena vacía—, que tampoco se
/// consultan. El journal no cambia porque la afirmación no cambia: un nodo que
/// nadie busca no es parte de lo que la prueba atesta.
///
/// Devuelve los offsets de la cabecera de esos ítems (el byte de contenido no
/// entra: `0x81 0x7f` no es RLP canónico y el decoder lo rechaza).
fn empty_node_offsets(bytes: &[u8]) -> Vec<usize> {
    assert_eq!(
        repo_b_common::primitives::keccak256([0x80u8]),
        repo_b_common::primitives::EMPTY_ROOT_HASH
    );
    let vacios: Vec<usize> = layout(bytes)
        .into_iter()
        .filter(|(nombre, item, _, _)| nombre.starts_with("state[") && item.as_ref() == [0x80])
        .map(|(_, _, at, _)| at.saturating_sub(1))
        .collect();
    assert!(
        vacios.len() <= 1,
        "más de un nodo vacío en el witness: la excepción dejaría de ser una"
    );
    vacios
}

/// Dónde está cada parte del input en sus bytes: el bloque, y cada ítem del
/// witness con su lista y su índice. Los ítems se buscan en orden, cada uno
/// después del anterior, que es el orden en el que el encoder los escribe.
fn layout(bytes: &[u8]) -> Vec<(String, Bytes, usize, usize)> {
    let input = input();
    let mut out = Vec::new();
    let mut cursor = 0usize;
    let mut partes = vec![("bloque".to_owned(), input.block.clone())];
    for (lista, items) in [
        ("state", &input.witness.state),
        ("codes", &input.witness.codes),
        ("headers", &input.witness.headers),
    ] {
        for (i, item) in items.iter().enumerate() {
            partes.push((format!("{lista}[{i}]"), item.clone()));
        }
    }
    for (nombre, item) in partes {
        let Some(at) = bytes.get(cursor..).and_then(|resto| {
            resto
                .windows(item.len().max(1))
                .position(|w| w == item.as_ref())
        }) else {
            panic!("{nombre} no aparece en el input");
        };
        let at = at.saturating_add(cursor);
        let end = at.saturating_add(item.len());
        cursor = end;
        out.push((nombre, item, at, end));
    }
    out
}

/// En qué parte del input cae un offset. Es lo que hace legible la tabla de
/// excepciones del barrido.
fn region(bytes: &[u8], offset: usize) -> String {
    layout(bytes)
        .into_iter()
        .find(|(_, _, a, b)| (*a..*b).contains(&offset))
        .map_or_else(
            || "cabeceras RLP del sobre o de un ítem".to_owned(),
            |(nombre, item, a, _)| {
                format!(
                    "{nombre} ({} B), byte {}",
                    item.len(),
                    offset.saturating_sub(a)
                )
            },
        )
}
