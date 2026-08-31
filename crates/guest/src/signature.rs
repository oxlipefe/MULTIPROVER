//! **El sender se DERIVA de la firma. Deja de ser un dato del input.**
//!
//! # Por qué esto es soundness y no plomería
//!
//! Hasta acá el guest recibía el sender ya recuperado adentro del input, y la
//! prueba que producía atestaba *"**si aceptás** que estos mensajes vienen de
//! estos remitentes, el root es este"* — no *"este bloque ejecuta a este
//! root"*. Un bloque real está comprometido por su `transactionsTrie`, que
//! commitea a los **envelopes firmados**: mientras el sender entre como dato, un
//! prover puede afirmar cualquier sender y la prueba sigue verificando.
//!
//! La forma de cerrarlo no es chequear el sender declarado contra el derivado:
//! es **no transportarlo**. Lo que no está en el formato no se puede falsificar,
//! y por eso `SignedTransaction` es dueño de su `Transaction` y le pone el
//! `sender` en cero al construirse — lo mismo con el `authority` de cada tupla
//! de EIP-7702. La única forma de que aparezca una dirección ahí es
//! `recover`.
//!
//! # Dónde se recupera, y por qué NO adentro del motor
//!
//! *"El sender es quien firmó"* es regla de consenso, pero **dónde** se deriva
//! es detalle de implementación. Un cliente real recupera fuera de la EVM y
//! `revm` tampoco lo hace adentro; el seam `Vm` de este repo lo dice explícito
//! y **no cambia**. Consecuencia estructural: el motor queda idéntico, así que
//! los ejes de conformance no pueden moverse por esto.
//!
//! # Tres reglas del bound de `s`, y son distintas
//!
//! 1. **ECRECOVER** (el precompile `0x01`): un `s` alto **NO** se rechaza —
//!    `normalize_s` lo reduce a `n − s`, flipea la paridad y recupera la MISMA
//!    dirección. Es malleability, no validación de tx.
//! 2. **La firma de una tx**: EIP-2 exige `s ≤ n/2`. Acá **sí** se rechaza, y
//!    una tx cuya firma no recupera **invalida el bloque**.
//! 3. **La tupla de EIP-7702**: mismo bound, pero el fallo **saltea esa tupla**
//!    sin invalidar la tx (`authority = None`).
//!
//! Heredar la conclusión de una para otra sería exactamente el error que este
//! módulo tiene que no cometer.

use alloc::vec::Vec;

use alloy_rlp::{Encodable, Header};
use repo_b_common::authorization::Authorization;
use repo_b_common::crypto::Crypto;
use repo_b_common::primitives::{Address, B256, U256, keccak256};
use repo_b_common::transaction::{Transaction, TxType};
use repo_b_evm::crypto::Active;

/// `secp256k1n / 2` — el bound de EIP-2 sobre `s`.
pub const SECP256K1N_HALF: U256 = U256::from_limbs([
    0xdfe9_2f46_681b_20a0,
    0x5d57_6e73_57a4_501d,
    0xffff_ffff_ffff_ffff,
    0x7fff_ffff_ffff_ffff,
]);

/// El byte de tipo que EIP-7702 antepone al hash de una tupla de autorización.
const AUTHORIZATION_MAGIC: u8 = 0x05;

/// Por qué una firma no produjo un remitente.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignatureError(pub &'static str);

/// Una firma ECDSA tal como viaja en el envelope.
///
/// **`v` crudo y no una paridad ya interpretada**: en una tx legacy el `v`
/// lleva el `chain_id` adentro (EIP-155) y eso **cambia el hash que se firma**.
/// Guardar solo la paridad perdería la diferencia entre una firma pre-155 y una
/// post-155, que son dos mensajes distintos.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature {
    pub v: U256,
    pub r: U256,
    pub s: U256,
}

/// La paridad y —si la firma la lleva— el `chain_id`, sacados del `v` de una
/// tx **legacy**.
///
/// `v ∈ {27, 28}` es pre-EIP-155 (sin `chain_id` en el mensaje);
/// `v = chain_id·2 + 35 + parity` es post-155. Cualquier otro `v` es una firma
/// que el protocolo no define, y se rechaza en vez de redondearse.
fn legacy_parity_and_chain(v: U256) -> Result<(bool, Option<u64>), SignatureError> {
    if v == U256::from(27u8) || v == U256::from(28u8) {
        return Ok((v == U256::from(28u8), None));
    }
    if v < U256::from(35u8) {
        return Err(SignatureError("v de una tx legacy fuera de {27,28} y < 35"));
    }
    let sin_offset = v - U256::from(35u8);
    let parity = (sin_offset & U256::from(1u8)) == U256::from(1u8);
    let chain: U256 = sin_offset >> 1usize;
    let chain: u64 = chain
        .try_into()
        .map_err(|_| SignatureError("el chain_id del v de una tx legacy no entra en 64 bits"))?;
    Ok((parity, Some(chain)))
}

/// La paridad de una tx **tipada**: el campo es `yParity` y solo vale 0 o 1.
fn typed_parity(v: U256) -> Result<bool, SignatureError> {
    if v == U256::ZERO {
        return Ok(false);
    }
    if v == U256::from(1u8) {
        return Ok(true);
    }
    Err(SignatureError("yParity fuera de {0,1}"))
}

/// La recuperación en crudo: hash + firma ⇒ dirección.
///
/// **Fail-closed en las cuatro puertas**: `r`/`s` fuera de `[1, n)` (lo enforcea
/// `from_slice`), `s > n/2` (EIP-2, acá **sí** se rechaza — ver el doc del
/// módulo), paridad fuera de `{0,1}`, y una recuperación que no da un punto de
/// la curva.
fn recover_address(hash: B256, sig: &Signature, parity: bool) -> Result<Address, SignatureError> {
    if sig.s > SECP256K1N_HALF {
        return Err(SignatureError("s por encima de secp256k1n/2 (EIP-2)"));
    }
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(&sig.r.to_be_bytes::<32>());
    bytes[32..].copy_from_slice(&sig.s.to_be_bytes::<32>());
    // La recuperación cruza el **seam `Crypto`**, igual que la del
    // precompile ECRECOVER: es la misma matemática, y tenerla dos veces sería
    // un guest donde dos reglas del mismo protocolo pueden discrepar. Lo que se
    // queda de este lado es lo que es de Ethereum — el rechazo de EIP-2 de acá
    // arriba y el keccak de acá abajo. El rango `[1, n)` de `r`/`s` lo enforcea
    // la recuperación misma, que es donde vive.
    //
    // La normalización de un `s` alto que el seam hace es un no-op acá: con
    // `s <= n/2` ya chequeado arriba, no hay nada que normalizar.
    let public_key = Active::secp256k1_ecrecover(&hash.0, &bytes, u8::from(parity))
        .map_err(|()| SignatureError("la firma no recupera un punto de la curva"))?;
    // Mismo layout que ECRECOVER: keccak de los 64 bytes del punto sin
    // comprimir, últimos 20 bytes.
    let hash = keccak256(public_key);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash.as_slice()[12..]);
    Ok(Address::new(addr))
}

/// Una transacción **con su firma**: lo que el `transactionsTrie` commitea.
///
/// El `Transaction` de adentro es privado a propósito. Su `sender` y los
/// `authority` de sus tuplas quedan en cero al construirse y **solo** `recover`
/// los llena: un input hostil no tiene dónde escribir una dirección.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTransaction {
    /// Con el `sender` y los `authority` en cero. Ver el doc del tipo.
    payload: Transaction,
    /// `chainId` del payload — obligatorio en las tipadas, ausente en la
    /// legacy (ahí viaja adentro del `v`).
    chain_id: Option<u64>,
    signature: Signature,
    /// Una firma por tupla de `authorization_list`, **en el mismo orden**.
    authorization_signatures: Vec<Signature>,
}

impl SignedTransaction {
    /// Construye el envelope. **Descarta el `sender` y los `authority` que
    /// venga trayendo el payload**: no es higiene, es lo que vuelve
    /// irrepresentable la falsificación.
    #[must_use]
    pub fn new(
        payload: Transaction,
        chain_id: Option<u64>,
        signature: Signature,
        authorization_signatures: Vec<Signature>,
    ) -> Self {
        let mut payload = payload;
        payload.sender = Address::ZERO;
        for auth in &mut payload.authorization_list {
            auth.authority = None;
        }
        Self {
            payload,
            chain_id,
            signature,
            authorization_signatures,
        }
    }

    /// El payload **sin remitente**. Sirve para encodear y para inspeccionar,
    /// nunca para ejecutar: su `sender` es cero.
    #[must_use]
    pub const fn payload(&self) -> &Transaction {
        &self.payload
    }

    #[must_use]
    pub const fn chain_id(&self) -> Option<u64> {
        self.chain_id
    }

    #[must_use]
    pub const fn signature(&self) -> &Signature {
        &self.signature
    }

    #[must_use]
    pub fn authorization_signatures(&self) -> &[Signature] {
        &self.authorization_signatures
    }

    /// El hash que se firmó.
    ///
    /// # Errors
    /// Si el envelope no es representable (una tipada sin `chainId`).
    pub fn signing_hash(&self, block_chain_id: u64) -> Result<B256, SignatureError> {
        let mut out = Vec::new();
        let chain = match self.payload.tx_type {
            TxType::Legacy => {
                let (_, chain) = legacy_parity_and_chain(self.signature.v)?;
                chain
            }
            _ => Some(self.require_chain_id(block_chain_id)?),
        };
        push_type_byte(self.payload.tx_type, &mut out);
        encode_payload(
            &self.payload,
            chain,
            &self.authorization_signatures,
            None,
            &mut out,
        )?;
        Ok(keccak256(&out))
    }

    /// El encoding de consenso EIP-2718 del envelope **firmado**: lo que entra
    /// al `transactionsTrie`.
    ///
    /// # Errors
    /// Si el envelope no es representable (una tipada sin `chainId`).
    pub fn encode_2718(&self) -> Result<Vec<u8>, SignatureError> {
        let mut out = Vec::new();
        let chain = match self.payload.tx_type {
            TxType::Legacy => None,
            _ => Some(
                self.chain_id
                    .ok_or(SignatureError("tx tipada sin chainId"))?,
            ),
        };
        push_type_byte(self.payload.tx_type, &mut out);
        encode_payload(
            &self.payload,
            chain,
            &self.authorization_signatures,
            Some(&self.signature),
            &mut out,
        )?;
        Ok(out)
    }

    /// El `chainId` del payload, exigiendo que sea el del bloque.
    ///
    /// **Es regla de consenso, no comodidad**: una tx firmada para otra cadena
    /// no es válida en esta, y sin el chequeo el mismo envelope valdría en
    /// todas — que es exactamente lo que EIP-155 existe para impedir.
    fn require_chain_id(&self, block_chain_id: u64) -> Result<u64, SignatureError> {
        let chain = self
            .chain_id
            .ok_or(SignatureError("tx tipada sin chainId"))?;
        if chain != block_chain_id {
            return Err(SignatureError("el chainId de la tx no es el del bloque"));
        }
        Ok(chain)
    }

    /// **Deriva el remitente y los `authority`, y devuelve la tx lista para el
    /// motor.**
    ///
    /// Devuelve una copia nueva y no muta: el envelope firmado se conserva tal
    /// cual entró.
    ///
    /// # Errors
    /// Si la firma de la **tx** no recupera. Una tupla de EIP-7702 que no
    /// recupera **no** es error: se saltea (`authority = None`), que es lo que
    /// dice la EIP.
    pub fn recover(&self, block_chain_id: u64) -> Result<Transaction, SignatureError> {
        let parity = match self.payload.tx_type {
            TxType::Legacy => {
                let (parity, chain) = legacy_parity_and_chain(self.signature.v)?;
                // EIP-155: si la firma lleva `chain_id`, tiene que ser el del
                // bloque. Una firma pre-155 (`v ∈ {27,28}`) no lo lleva y vale
                // en cualquier cadena — que es el agujero que EIP-155 cerró y
                // que el protocolo sigue aceptando para las viejas.
                if let Some(chain) = chain
                    && chain != block_chain_id
                {
                    return Err(SignatureError("el chainId del v no es el del bloque"));
                }
                parity
            }
            _ => {
                self.require_chain_id(block_chain_id)?;
                typed_parity(self.signature.v)?
            }
        };
        let hash = self.signing_hash(block_chain_id)?;
        let sender = recover_address(hash, &self.signature, parity)?;

        let mut tx = self.payload.clone();
        tx.sender = sender;
        if tx.authorization_list.len() != self.authorization_signatures.len() {
            return Err(SignatureError(
                "la tx trae otra cantidad de firmas que de tuplas de autorización",
            ));
        }
        for (auth, sig) in tx
            .authorization_list
            .iter_mut()
            .zip(&self.authorization_signatures)
        {
            auth.authority = recover_authority(auth, sig);
        }
        Ok(tx)
    }
}

/// El `authority` de una tupla de EIP-7702. `None` = firma inválida ⇒ la tupla
/// se saltea **sin invalidar la tx**, que es la asimetría que la EIP fija
/// contra el sender.
fn recover_authority(auth: &Authorization, sig: &Signature) -> Option<Address> {
    let parity = typed_parity(sig.v).ok()?;
    let mut inner = Vec::new();
    auth.chain_id.encode(&mut inner);
    auth.address.encode(&mut inner);
    auth.nonce.encode(&mut inner);
    let mut out = Vec::with_capacity(1 + inner.len() + 4);
    out.push(AUTHORIZATION_MAGIC);
    list_of(&inner, &mut out);
    recover_address(keccak256(&out), sig, parity).ok()
}

/// EIP-2718: la tx tipada se prefija con su byte de tipo; la legacy, no.
fn push_type_byte(tx_type: TxType, out: &mut Vec<u8>) {
    match tx_type {
        TxType::Legacy => {}
        TxType::Eip2930 => out.push(0x01),
        TxType::Eip1559 => out.push(0x02),
        TxType::Eip4844 => out.push(0x03),
        TxType::Eip7702 => out.push(0x04),
    }
}

fn list_of(payload: &[u8], out: &mut Vec<u8>) {
    Header {
        list: true,
        payload_length: payload.len(),
    }
    .encode(out);
    out.extend_from_slice(payload);
}

/// `to`: la dirección, o la **cadena vacía** si es un CREATE. RLP es
/// posicional y un hueco no es representable.
fn encode_to(to: Option<Address>, out: &mut Vec<u8>) {
    match to {
        Some(address) => address.encode(out),
        None => out.push(alloy_rlp::EMPTY_STRING_CODE),
    }
}

fn encode_access_list(list: &repo_b_common::access_list::AccessList, out: &mut Vec<u8>) {
    let mut items = Vec::new();
    for item in list {
        let mut e = Vec::new();
        item.address.encode(&mut e);
        let mut keys = Vec::new();
        for key in &item.storage_keys {
            key.encode(&mut keys);
        }
        list_of(&keys, &mut e);
        list_of(&e, &mut items);
    }
    list_of(&items, out);
}

/// **UN solo encoder para las dos preguntas**: con `sig = None` produce el
/// payload que se FIRMA, y con `sig = Some` el envelope de consenso que entra
/// al `transactionsTrie`.
///
/// Que sean el mismo código no es ahorro: es lo que hace que el trie —
/// contrastado contra el header de cada bloque del corpus— **gatee el encoding
/// del que sale el hash de firma**. Dos funciones separadas podrían discrepar
/// justo en el campo que el trie no mira.
fn encode_payload(
    tx: &Transaction,
    chain_id: Option<u64>,
    auth_sigs: &[Signature],
    sig: Option<&Signature>,
    out: &mut Vec<u8>,
) -> Result<(), SignatureError> {
    let mut i = Vec::new();
    let tipada = tx.tx_type != TxType::Legacy;
    if tipada {
        chain_id
            .ok_or(SignatureError("tx tipada sin chainId"))?
            .encode(&mut i);
    }
    tx.nonce.encode(&mut i);
    match tx.tx_type {
        TxType::Legacy | TxType::Eip2930 => {
            // Una legacy sin `gasPrice` no es representable; cero es lo que el
            // protocolo le daría a un campo ausente en RLP.
            tx.gas_price.unwrap_or_default().encode(&mut i);
        }
        _ => {
            tx.max_priority_fee_per_gas
                .ok_or(SignatureError("tx 1559+ sin maxPriorityFeePerGas"))?
                .encode(&mut i);
            tx.max_fee_per_gas
                .ok_or(SignatureError("tx 1559+ sin maxFeePerGas"))?
                .encode(&mut i);
        }
    }
    tx.gas_limit.encode(&mut i);
    encode_to(tx.to, &mut i);
    tx.value.encode(&mut i);
    tx.input.encode(&mut i);
    if tipada {
        encode_access_list(&tx.access_list, &mut i);
    }
    if tx.tx_type == TxType::Eip4844 {
        tx.max_fee_per_blob_gas
            .ok_or(SignatureError("tx tipo 3 sin maxFeePerBlobGas"))?
            .encode(&mut i);
        let mut blobs = Vec::new();
        for hash in &tx.blob_versioned_hashes {
            hash.encode(&mut blobs);
        }
        list_of(&blobs, &mut i);
    }
    if tx.tx_type == TxType::Eip7702 {
        if tx.authorization_list.len() != auth_sigs.len() {
            return Err(SignatureError(
                "la tx trae otra cantidad de firmas que de tuplas de autorización",
            ));
        }
        let mut auths = Vec::new();
        for (auth, firma) in tx.authorization_list.iter().zip(auth_sigs) {
            let mut e = Vec::new();
            auth.chain_id.encode(&mut e);
            auth.address.encode(&mut e);
            auth.nonce.encode(&mut e);
            firma.v.encode(&mut e);
            firma.r.encode(&mut e);
            firma.s.encode(&mut e);
            list_of(&e, &mut auths);
        }
        list_of(&auths, &mut i);
    }
    match sig {
        Some(s) => {
            s.v.encode(&mut i);
            s.r.encode(&mut i);
            s.s.encode(&mut i);
        }
        None => {
            // EIP-155: el payload que se firma en una legacy con `chain_id`
            // termina en `[chainId, 0, 0]`. Sin `chain_id` (pre-155) no lleva
            // sufijo, y son **dos mensajes distintos**.
            if !tipada && let Some(chain) = chain_id {
                chain.encode(&mut i);
                0u8.encode(&mut i);
                0u8.encode(&mut i);
            }
        }
    }
    list_of(&i, out);
    Ok(())
}

// ---------------------------------------------------------------------------
// El decoder del envelope canónico.
// ---------------------------------------------------------------------------

/// **Decodifica el envelope de consenso EIP-2718.** Es input externo: cada byte
/// es hostil hasta que se prueba lo contrario, y todo camino de error termina en
/// un rechazo y nunca en una tx a medio armar.
///
/// El formato NO es nuestro: es exactamente lo que el `transactionsTrie`
/// commitea. Que el guest lo lea de ahí es lo que hace que el bloque que
/// ejecuta sea *el* bloque y no una descripción nuestra de él.
///
/// # Errors
/// Cualquier byte que no encaje: tipo desconocido, lista mal formada, campos de
/// más o de menos, un `to` que no mide 0 ni 20 bytes.
pub fn decode_2718(raw: &[u8]) -> Result<SignedTransaction, SignatureError> {
    let Some(primero) = raw.first().copied() else {
        return Err(SignatureError("envelope vacío"));
    };
    // EIP-2718: un byte de tipo es `< 0x80`; una legacy arranca con la cabecera
    // de una lista RLP (`>= 0xc0`). El hueco entre medio no es representable.
    let (tx_type, cuerpo) = match primero {
        0xc0..=0xff => (TxType::Legacy, raw),
        0x01 => (TxType::Eip2930, &raw[1..]),
        0x02 => (TxType::Eip1559, &raw[1..]),
        0x03 => (TxType::Eip4844, &raw[1..]),
        0x04 => (TxType::Eip7702, &raw[1..]),
        _ => return Err(SignatureError("byte de tipo de tx desconocido")),
    };
    let mut cursor = cuerpo;
    let mut body = open_list(&mut cursor)?;
    if !cursor.is_empty() {
        return Err(SignatureError("hay bytes después del envelope"));
    }

    let mut tx = Transaction {
        tx_type,
        sender: Address::ZERO,
        nonce: 0,
        to: None,
        value: U256::ZERO,
        input: repo_b_common::primitives::Bytes::new(),
        gas_limit: 0,
        gas_price: None,
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
        access_list: repo_b_common::access_list::AccessList::new(),
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: Vec::new(),
        authorization_list: Vec::new(),
    };
    let tipada = tx_type != TxType::Legacy;
    let chain_id = if tipada {
        Some(decode::<u64>(&mut body)?)
    } else {
        None
    };
    tx.nonce = decode::<u64>(&mut body)?;
    match tx_type {
        TxType::Legacy | TxType::Eip2930 => tx.gas_price = Some(decode::<u128>(&mut body)?),
        _ => {
            tx.max_priority_fee_per_gas = Some(decode::<u128>(&mut body)?);
            tx.max_fee_per_gas = Some(decode::<u128>(&mut body)?);
        }
    }
    tx.gas_limit = decode::<u64>(&mut body)?;
    tx.to = decode_to(&mut body)?;
    tx.value = decode::<U256>(&mut body)?;
    tx.input = decode::<repo_b_common::primitives::Bytes>(&mut body)?;
    if tipada {
        tx.access_list = decode_access_list(&mut body)?;
    }
    if tx_type == TxType::Eip4844 {
        tx.max_fee_per_blob_gas = Some(decode::<u128>(&mut body)?);
        let mut blobs = open_list(&mut body)?;
        while !blobs.is_empty() {
            tx.blob_versioned_hashes.push(decode::<B256>(&mut blobs)?);
        }
    }
    let mut authorization_signatures = Vec::new();
    if tx_type == TxType::Eip7702 {
        let mut auths = open_list(&mut body)?;
        while !auths.is_empty() {
            let mut item = open_list(&mut auths)?;
            let auth = Authorization {
                chain_id: decode::<U256>(&mut item)?,
                address: decode::<Address>(&mut item)?,
                nonce: decode::<u64>(&mut item)?,
                authority: None,
            };
            let firma = decode_signature(&mut item)?;
            if !item.is_empty() {
                return Err(SignatureError(
                    "una tupla de autorización trae campos de más",
                ));
            }
            tx.authorization_list.push(auth);
            authorization_signatures.push(firma);
        }
    }
    let signature = decode_signature(&mut body)?;
    if !body.is_empty() {
        return Err(SignatureError("el envelope trae campos de más"));
    }
    Ok(SignedTransaction::new(
        tx,
        chain_id,
        signature,
        authorization_signatures,
    ))
}

fn decode<T: alloy_rlp::Decodable>(buf: &mut &[u8]) -> Result<T, SignatureError> {
    T::decode(buf).map_err(|_| SignatureError("campo RLP malformado en el envelope"))
}

fn decode_signature(buf: &mut &[u8]) -> Result<Signature, SignatureError> {
    Ok(Signature {
        v: decode::<U256>(buf)?,
        r: decode::<U256>(buf)?,
        s: decode::<U256>(buf)?,
    })
}

/// Abre una lista RLP acotada por **su largo declarado** y no por lo que quede
/// en el buffer: sin eso, una lista que dice medir más de lo que hay se comería
/// el resto del input en vez de ser rechazada.
fn open_list<'a>(buf: &mut &'a [u8]) -> Result<&'a [u8], SignatureError> {
    let header = Header::decode(buf).map_err(|_| SignatureError("cabecera RLP malformada"))?;
    if !header.list {
        return Err(SignatureError("se esperaba una lista RLP"));
    }
    if header.payload_length > buf.len() {
        return Err(SignatureError("una lista declara más bytes de los que hay"));
    }
    let (body, rest) = buf.split_at(header.payload_length);
    *buf = rest;
    Ok(body)
}

/// `to`: cadena vacía = CREATE, 20 bytes = dirección. **Cualquier otro largo se
/// rechaza**: un `to` de 19 bytes no es "casi una dirección", es un envelope
/// que no existe.
fn decode_to(buf: &mut &[u8]) -> Result<Option<Address>, SignatureError> {
    let raw = decode::<repo_b_common::primitives::Bytes>(buf)?;
    match raw.len() {
        0 => Ok(None),
        20 => {
            let mut bytes = [0u8; 20];
            bytes.copy_from_slice(raw.as_ref());
            Ok(Some(Address::new(bytes)))
        }
        _ => Err(SignatureError("el campo `to` no mide 0 ni 20 bytes")),
    }
}

fn decode_access_list(
    buf: &mut &[u8],
) -> Result<repo_b_common::access_list::AccessList, SignatureError> {
    let mut body = open_list(buf)?;
    let mut list = repo_b_common::access_list::AccessList::new();
    while !body.is_empty() {
        let mut item = open_list(&mut body)?;
        let address = decode::<Address>(&mut item)?;
        let mut keys_body = open_list(&mut item)?;
        let mut storage_keys = Vec::new();
        while !keys_body.is_empty() {
            storage_keys.push(decode::<B256>(&mut keys_body)?);
        }
        if !item.is_empty() {
            return Err(SignatureError("un ítem de access list trae campos de más"));
        }
        list.push(repo_b_common::access_list::AccessListItem {
            address,
            storage_keys,
        });
    }
    Ok(list)
}
