//! Las dos fuentes de traza EIP-3155 del diferencial, normalizadas al
//! `StepRecord` del comparador de 003.
//!
//! - **Nuestro lado:** `repo_b_evm::execution::trace_tx` (feature `tracer`),
//!   que reusa el MISMO `build_frame` que `execute_tx` — trazar no puede
//!   divergir de ejecutar.
//! - **Oráculo:** el inspector `TracerEip3155` de revm, que emite JSON-lines
//!   con el formato del EIP; acá se parsean, no se reinterpretan.
//!
//! Normalización única: EIP-3155 numera la profundidad desde 1 y nosotros
//! desde 0 (`depth` del `CallContext`); se resta 1 del lado del oráculo.

use std::cell::RefCell;
use std::io::Write;
use std::rc::Rc;

use repo_b_common::primitives::U256;
use repo_b_evm::types::Spec;
use repo_b_interpreter::tracer::{StepRecord as OurStep, StepSink};
use revm::inspector::inspectors::TracerEip3155;
use revm::{Context, InspectEvm, MainBuilder, MainContext};
use serde_json::Value;

use crate::fixture::{PostCase, StateTest};
use crate::runner::MemoryState;
use crate::trace_diff::StepRecord;

use super::{apply_block_env, revm_db, revm_tx, spec_id};

/// EIP-3155 numera los frames desde 1; el `CallContext` desde 0.
const EIP3155_DEPTH_BASE: usize = 1;

// Sin `Default`: un `max_steps` de 0 sería una traza vacía silenciosa, o sea
// el modo vacuo. El tope se pasa siempre, explícito.
struct Collector {
    steps: Vec<StepRecord>,
    /// Tope de pasos guardados. El corpus de EEST trae casos de 1 650 028
    /// pasos y una traza sin tope es memoria alimentada por input externo.
    max_steps: usize,
}

impl StepSink for Collector {
    fn step(&mut self, record: &OurStep) {
        if self.steps.len() >= self.max_steps {
            return;
        }
        self.steps.push(StepRecord {
            pc: record.pc,
            op: record.op,
            op_name: record.op_name.clone(),
            gas: record.gas,
            gas_cost: record.gas_cost,
            stack: record.stack.clone(),
            depth: record.depth,
            mem_size: record.mem_size,
            refund: record.refund,
            error: record.error.map(String::from),
        });
    }
}

/// Traza de `OwnVm` para la tx del caso.
pub fn ours(test: &StateTest, case: &PostCase, spec: Spec) -> Result<Vec<StepRecord>, String> {
    ours_capped(test, case, spec, usize::MAX)
}

/// La misma traza, acotada a `max_steps`. El modo humano imprime UN caso y no
/// necesita tope; el triage traza por cada divergencia de una campaña, y ahí
/// el tope es la diferencia entre acotar un recurso y confiar en el corpus.
pub fn ours_capped(
    test: &StateTest,
    case: &PostCase,
    spec: Spec,
    max_steps: usize,
) -> Result<Vec<StepRecord>, String> {
    let tx = test.transaction_for(case)?;
    let env = test.block_env(spec);
    let state = MemoryState::from_pre(&test.pre).with_block_hashes(test.env.block_hashes.clone());
    let mut collector = Collector {
        steps: Vec::new(),
        max_steps,
    };
    repo_b_evm::execution::trace_tx(&tx, &env, &state, &mut collector)
        .map_err(|e| e.to_string())?;
    Ok(collector.steps)
}

/// Buffer compartido: el inspector de revm escribe en un `Box<dyn Write>` y
/// nosotros necesitamos leer lo escrito después.
///
/// El tope se aplica **al escribir**, no al parsear: el inspector de revm
/// emite una línea JSON por paso, así que con el tope solo en el parseo la
/// memoria ya estaría gastada. Se declara `Ok(buf.len())` igual, porque un
/// `Err` acá abortaría la ejecución de revm y el punto es truncar la traza, no
/// la corrida.
// Sin `Default`, por la misma razón que `Collector`.
#[derive(Clone)]
struct SharedBuffer {
    bytes: Rc<RefCell<Vec<u8>>>,
    max_bytes: usize,
}

impl SharedBuffer {
    fn with_cap(max_bytes: usize) -> Self {
        Self {
            bytes: Rc::new(RefCell::new(Vec::new())),
            max_bytes,
        }
    }

    fn into_string(self) -> Result<String, String> {
        let bytes = self.bytes.borrow().clone();
        String::from_utf8(bytes).map_err(|e| format!("traza de revm no es UTF-8: {e}"))
    }
}

impl Write for SharedBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut bytes = self.bytes.borrow_mut();
        if bytes.len() < self.max_bytes {
            bytes.extend_from_slice(buf);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Traza de revm para la misma tx, vía su inspector EIP-3155.
pub fn revm(test: &StateTest, case: &PostCase, spec: Spec) -> Result<Vec<StepRecord>, String> {
    revm_capped(test, case, spec, usize::MAX)
}

/// La misma traza, acotada a `max_steps` (ver `ours_capped`).
pub fn revm_capped(
    test: &StateTest,
    case: &PostCase,
    spec: Spec,
    max_steps: usize,
) -> Result<Vec<StepRecord>, String> {
    let tx = test.transaction_for(case)?;
    let env = test.block_env(spec);
    let db = revm_db(&test.pre, &test.env.block_hashes)?;
    let buffer = SharedBuffer::with_cap(max_steps.saturating_mul(MAX_TRACE_LINE_BYTES));

    let mut evm = Context::mainnet()
        .with_db(db)
        .modify_cfg_chained(|cfg| {
            cfg.chain_id = env.chain_id;
            cfg.spec = spec_id(spec);
        })
        .modify_block_chained(|block| apply_block_env(block, &env))
        .build_mainnet_with_inspector(
            TracerEip3155::new(Box::new(buffer.clone())).without_summary(),
        );

    evm.inspect_tx(revm_tx(&tx, &env)?)
        .map_err(|e| format!("{e:?}"))?;
    drop(evm);

    let text = buffer.into_string()?;
    // La ÚLTIMA línea puede haber quedado cortada por el tope del buffer, y
    // una línea a medias no es un paso: se descarta antes de parsear.
    let lines: Vec<&str> = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    let keep = if text.ends_with('\n') {
        lines.len()
    } else {
        lines.len().saturating_sub(1)
    };
    lines
        .into_iter()
        .take(keep.min(max_steps))
        .map(parse_line)
        .collect()
}

/// Cuántos bytes se le reservan a una línea de traza para traducir un tope de
/// pasos a un tope de bytes. Generoso a propósito: si una línea real fuera más
/// larga, el efecto es truncar antes, nunca guardar de más.
const MAX_TRACE_LINE_BYTES: usize = 4_096;

/// Parsea una línea JSON del formato EIP-3155. Input hostil: todo campo se
/// valida, nada se asume presente.
fn parse_line(line: &str) -> Result<StepRecord, String> {
    let value: Value = serde_json::from_str(line).map_err(|e| format!("traza no-JSON: {e}"))?;
    // El tracer también emite líneas de resumen (sin `pc`); las filtramos
    // antes, pero si llega una, es un error explícito, no un cero silencioso.
    let pc =
        usize::try_from(number(&value, "pc")?).map_err(|_| "pc irrepresentable".to_string())?;
    let op = u8::try_from(number(&value, "op")?).map_err(|_| "op fuera de rango".to_string())?;
    let depth = usize::try_from(number(&value, "depth")?)
        .map_err(|_| "depth irrepresentable".to_string())?;
    Ok(StepRecord {
        pc,
        op,
        op_name: value
            .get("opName")
            .and_then(Value::as_str)
            .unwrap_or("UNKNOWN")
            .to_string(),
        gas: number(&value, "gas")?,
        gas_cost: number(&value, "gasCost")?,
        stack: stack(&value)?,
        depth: depth.saturating_sub(EIP3155_DEPTH_BASE),
        mem_size: usize::try_from(number(&value, "memSize")?)
            .map_err(|_| "memSize irrepresentable".to_string())?,
        refund: i64::try_from(number(&value, "refund").unwrap_or(0))
            .map_err(|_| "refund irrepresentable".to_string())?,
        error: normalize_error(value.get("error").and_then(Value::as_str)),
    })
}

/// El campo `error` de EIP-3155 lleva el `InstructionResult` de revm, que
/// incluye los finales **normales** (`Stop`, `Return`, `Revert`); nuestro
/// tracer solo lo llena en un `Halt` de verdad. Normalizamos a esa semántica.
///
/// Los nombres de halt son **diagnóstico, no consenso** (cada motor tiene su
/// vocabulario: revm parte el OOG en `MemoryOOG`, `PrecompileOOG`, …). Se
/// colapsan a `OutOfGas` para no reportar divergencias de ortografía; lo que
/// el gate compara de verdad es gas, stack, memoria y refund.
fn normalize_error(raw: Option<&str>) -> Option<String> {
    let name = raw?;
    match name {
        "Stop" | "Return" | "Revert" | "SelfDestruct" | "ReturnContract" => None,
        out_of_gas if out_of_gas.ends_with("OOG") => Some("OutOfGas".to_string()),
        other => Some(other.to_string()),
    }
}

/// EIP-3155 mezcla números JSON (`pc`, `op`, `depth`) con strings hex (`gas`,
/// `gasCost`, `refund`); aceptamos las dos formas.
fn number(value: &Value, field: &str) -> Result<u64, String> {
    let raw = value
        .get(field)
        .ok_or_else(|| format!("falta el campo {field} en la traza"))?;
    if let Some(n) = raw.as_u64() {
        return Ok(n);
    }
    let text = raw
        .as_str()
        .ok_or_else(|| format!("{field} no es número ni string: {raw}"))?;
    let stripped = text.strip_prefix("0x").unwrap_or(text);
    u64::from_str_radix(stripped, 16).map_err(|e| format!("{field} hex inválido ({text}): {e}"))
}

fn stack(value: &Value) -> Result<Vec<U256>, String> {
    let items = value
        .get("stack")
        .and_then(Value::as_array)
        .ok_or("falta el stack en la traza")?;
    items
        .iter()
        .map(|item| {
            let text = item.as_str().ok_or("entrada de stack no es string")?;
            let stripped = text.strip_prefix("0x").unwrap_or(text);
            if stripped.is_empty() {
                return Ok(U256::ZERO);
            }
            U256::from_str_radix(stripped, 16)
                .map_err(|e| format!("stack hex inválido ({text}): {e}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::parse_file;

    /// Fixture parametrizado por bytecode y gas limit: `{code}`/`{gas}` se
    /// sustituyen para cubrir el camino feliz Y los de halt.
    const FIXTURE_TEMPLATE: &str = r#"{
      "traced_case": {
        "env": {
          "currentCoinbase": "0xc0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0",
          "currentNumber": "0x01",
          "currentTimestamp": "0x03e8",
          "currentGasLimit": "0x01c9c380",
          "currentBaseFee": "0x0a",
          "currentRandom": "0x0000000000000000000000000000000000000000000000000000000000000000",
          "currentExcessBlobGas": "0x00"
        },
        "config": { "chainid": "0x01" },
        "pre": {
          "0xa0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0": {
            "nonce": "0x00", "balance": "0x3635c9adc5dea00000", "code": "0x", "storage": {}
          },
          "0xb0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0": {
            "nonce": "0x01", "balance": "0x00",
            "code": "{code}", "storage": {}
          }
        },
        "transaction": {
          "sender": "0xa0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0",
          "to": "0xb0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0",
          "nonce": "0x00", "gasPrice": "0x0a",
          "data": ["0x"], "gasLimit": ["{gas}"], "value": ["0x00"]
        },
        "post": {
          "Prague": [{
            "indexes": { "data": 0, "gas": 0, "value": 0 },
            "hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "logs": "0x0000000000000000000000000000000000000000000000000000000000000000"
          }]
        }
      }
    }"#;

    /// SSTORE (cold set) + SLOAD warm + RETURN: gas, stack, refund, memoria.
    const HAPPY_PATH: &str = "0x60016000556000545060206000f3";
    /// SSTORE + 0xFE: camino de halt (`InvalidFEOpcode`).
    const INVALID_OPCODE: &str = "0x6001600055fe";
    /// SSTORE con 23306 de gas: dispara el sentry EIP-2200 (`OutOfGas`).
    const SENTRY_OOG: &str = "0x600160005500";

    #[track_caller]
    fn traces(code: &str, gas: &str) -> (Vec<StepRecord>, Vec<StepRecord>) {
        let raw = FIXTURE_TEMPLATE
            .replace("{code}", code)
            .replace("{gas}", gas);
        let tests = parse_file(&raw).unwrap_or_else(|e| panic!("fixture inválido: {e}"));
        let test = tests.first().unwrap_or_else(|| panic!("sin tests"));
        let case = test.posts.first().unwrap_or_else(|| panic!("sin posts"));
        let ours = ours(test, case, Spec::Prague).unwrap_or_else(|e| panic!("traza propia: {e}"));
        let oracle = revm(test, case, Spec::Prague).unwrap_or_else(|e| panic!("traza revm: {e}"));
        (ours, oracle)
    }

    #[track_caller]
    fn assert_traces_match(code: &str, gas: &str) {
        let (ours, oracle) = traces(code, gas);
        assert!(!ours.is_empty(), "el tracer propio no emitió pasos");
        assert!(!oracle.is_empty(), "el tracer de revm no emitió pasos");
        assert_eq!(
            crate::trace_diff::first_divergence(&ours, &oracle),
            None,
            "ours={ours:#?}\noracle={oracle:#?}"
        );
    }

    /// Lo que hace útil al diagnóstico: si las dos trazas normalizadas
    /// coinciden en los casos verdes, entonces cuando NO coincidan el paso que
    /// reporta `first_divergence` es real y no ruido de normalización.
    #[test]
    fn the_two_traces_are_identical_on_a_matching_case() {
        assert_traces_match(HAPPY_PATH, "0x0f4240");
    }

    #[test]
    fn the_two_traces_are_identical_on_an_invalid_opcode_halt() {
        assert_traces_match(INVALID_OPCODE, "0x0f4240");
    }

    #[test]
    fn the_two_traces_are_identical_on_the_sstore_sentry_halt() {
        assert_traces_match(SENTRY_OOG, "0x5b0a");
    }

    #[test]
    fn normal_terminators_are_not_errors_but_halts_are() {
        assert_eq!(normalize_error(Some("Return")), None);
        assert_eq!(normalize_error(Some("Stop")), None);
        assert_eq!(normalize_error(Some("Revert")), None);
        assert_eq!(normalize_error(None), None);
        assert_eq!(
            normalize_error(Some("MemoryOOG")),
            Some("OutOfGas".to_string())
        );
        assert_eq!(
            normalize_error(Some("InvalidFEOpcode")),
            Some("InvalidFEOpcode".to_string())
        );
    }

    #[test]
    fn a_malformed_trace_line_is_an_explicit_error() {
        assert!(parse_line("{\"op\":96}").is_err());
        assert!(parse_line("no es json").is_err());
    }
}
