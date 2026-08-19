//! El presupuesto de la flota, con la semántica del **gas**.
//!
//! La regla es "presupuesto como acotador de recursos, **como el gas**", y
//! tomarla literal no es una metáfora bonita: es la especificación, y define
//! cuatro cosas que un contador de gasto común no tiene.
//!
//! 1. **Se cobra ANTES de gastar.** La EVM chequea que alcance el gas antes de
//!    ejecutar el paso, no después. Acá: antes de levantar un runner se
//!    descuenta su **costo máximo**; si no alcanza, el runner **no se levanta**.
//!    Un contador que suma lo gastado al terminar siempre se entera tarde, y
//!    "tarde" con una flota encendida es una factura.
//! 2. **Se devuelve lo no usado.** Igual que el gas sobrante de una tx: se cobra
//!    el límite, se liquida el consumo real, se acredita la diferencia. Sin la
//!    devolución, tarifar por el techo dejaría la mitad del presupuesto
//!    inmovilizada y la flota se apagaría a mitad de camino sin haber gastado.
//! 3. **El que se queda sin tiempo no recupera nada.** Un runner que llega al
//!    deadline de cosecha se mata y se liquida al techo: es el
//!    `OutOfGas` de la EVM, que consume todo el gas del frame. Perder una
//!    campaña es barato; una flota colgada que factura sola, no.
//! 4. **Fail-closed, sin default silencioso.** Sin presupuesto configurado la
//!    campaña **no arranca**. Es el patrón `Option<Spec>` de 2.9b-3c: un default
//!    contesta la pregunta equivocada en silencio, y acá la pregunta equivocada
//!    cuesta plata.
//!
//! ## Por qué micro-dólares enteros
//!
//! Nada de `f64`. El dinero en punto flotante acumula error y hace que "gasté
//! exactamente el tope" sea indecidible; y la regla de determinismo del
//! proyecto ya prohíbe floats donde se puede. Un `u64` de micro-dólares llega a
//! ~1.8 × 10^13 USD, que sobra por un margen que no vale la pena discutir.

/// El techo absoluto que puede configurarse, en micro-dólares.
///
/// Sale de la decisión del humano (2026-08-19): **flota chica con tope bajo**,
/// del orden de US$50–200/mes. No es el presupuesto: es el máximo que el
/// presupuesto puede declarar. Existe para que un dedo de más —`--fleet-budget
/// 20000` en vez de `200`— no compile un experimento de US$20 000.
pub const FLEET_BUDGET_CEILING_MICROS: u64 = 200_000_000;

/// El piso: un presupuesto de cero es "no arranques", no "arrancá gratis".
pub const FLEET_BUDGET_FLOOR_MICROS: u64 = 1_000;

/// Un micro-dólar por dólar.
const MICROS_PER_USD: u64 = 1_000_000;

/// El presupuesto vivo de una campaña de flota.
///
/// `spent` es **lo cobrado**, no lo consumido: entre el cobro y la liquidación
/// hay un runner corriendo cuyo costo real todavía no se sabe. Esa es
/// exactamente la diferencia entre cobrar antes y cobrar después.
#[derive(Debug, Clone)]
pub struct Budget {
    limit_micros: u64,
    spent_micros: u64,
    refunds_micros: u64,
}

/// El recibo de un cobro. **No es `Copy` y es `#[must_use]`** a propósito: un
/// cobro que nadie liquida deja el presupuesto tarifado al techo para siempre,
/// y el tipo lo hace visible en el punto donde pasaría.
#[derive(Debug)]
#[must_use = "un cobro sin liquidar deja el presupuesto tarifado al techo"]
pub struct Charge {
    reserved_micros: u64,
}

impl Charge {
    pub const fn reserved_micros(&self) -> u64 {
        self.reserved_micros
    }

    /// Liquida este cobro contra el consumo real y devuelve lo acreditado.
    ///
    /// El método vive en el **recibo** y no en el presupuesto porque el recibo
    /// es lo que se consume: `self` por valor significa que un cobro se liquida
    /// **una sola vez**, y que el tipo lo garantice es mejor que acordarse.
    ///
    /// Un consumo real por encima de lo reservado no puede pasar —el proveedor
    /// cobra por reloj y el reloj lo cortamos nosotros—, pero si pasara se
    /// clampea: el presupuesto no se puede exceder por una cuenta del
    /// proveedor, que es justamente lo que el §3.4 no acepta.
    pub fn settle(self, budget: &mut Budget, actual_micros: u64) -> u64 {
        let actual = actual_micros.min(self.reserved_micros);
        let refund = self.reserved_micros.saturating_sub(actual);
        budget.credit(refund);
        refund
    }
}

/// Por qué no se pudo cobrar. Un solo motivo, y con los dos números adentro:
/// un "no alcanza" sin el faltante obliga a ir a buscarlo al log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetExhausted {
    pub needed_micros: u64,
    pub remaining_micros: u64,
}

impl Budget {
    /// Construye el presupuesto. `Err` en las dos direcciones: por debajo del
    /// piso no arranca, por encima del techo tampoco.
    pub fn new(limit_micros: u64) -> Result<Self, String> {
        if limit_micros < FLEET_BUDGET_FLOOR_MICROS {
            return Err(format!(
                "presupuesto de {} micro-USD: por debajo del piso de {} \
                 (un presupuesto de cero es «no arranques», no «arrancá gratis»)",
                limit_micros, FLEET_BUDGET_FLOOR_MICROS
            ));
        }
        if limit_micros > FLEET_BUDGET_CEILING_MICROS {
            return Err(format!(
                "presupuesto de {} micro-USD: por encima del techo de {} \
                 (US$200; la decisión de 2026-08-19 es flota CHICA con tope BAJO)",
                limit_micros, FLEET_BUDGET_CEILING_MICROS
            ));
        }
        Ok(Self {
            limit_micros,
            spent_micros: 0,
            refunds_micros: 0,
        })
    }

    /// **Fail-closed (§3.2).** Sin presupuesto configurado no hay campaña. El
    /// `Option` es el patrón de `Option<Spec>` de 2.9b-3c: la ausencia se
    /// contesta con un error nombrado, nunca con un default.
    pub fn from_config(limit_micros: Option<u64>) -> Result<Self, String> {
        let Some(limit) = limit_micros else {
            return Err(
                "la flota no arranca sin presupuesto configurado: es el acotador de \
                 recursos de la campaña y no tiene default. \
                 Pasá `--fleet-budget <USD>`."
                    .to_owned(),
            );
        };
        Self::new(limit)
    }

    /// **Cobra ANTES de gastar.** `max_cost_micros` es el techo del runner, no
    /// su costo esperado: tarifar por el esperado es apostar, y está medido en
    /// 18.3× la dispersión de throughput entre shards del mismo tamaño.
    pub fn charge(&mut self, max_cost_micros: u64) -> Result<Charge, BudgetExhausted> {
        let remaining = self.remaining_micros();
        if max_cost_micros > remaining {
            return Err(BudgetExhausted {
                needed_micros: max_cost_micros,
                remaining_micros: remaining,
            });
        }
        self.spent_micros = self.spent_micros.saturating_add(max_cost_micros);
        Ok(Charge {
            reserved_micros: max_cost_micros,
        })
    }

    /// Acredita una devolución. Lo llama `Charge::settle`, que es donde vive la
    /// regla; acá solo se mueven los dos contadores.
    fn credit(&mut self, refund_micros: u64) {
        self.spent_micros = self.spent_micros.saturating_sub(refund_micros);
        self.refunds_micros = self.refunds_micros.saturating_add(refund_micros);
    }

    pub const fn limit_micros(&self) -> u64 {
        self.limit_micros
    }

    pub const fn spent_micros(&self) -> u64 {
        self.spent_micros
    }

    pub const fn refunded_micros(&self) -> u64 {
        self.refunds_micros
    }

    pub const fn remaining_micros(&self) -> u64 {
        self.limit_micros.saturating_sub(self.spent_micros)
    }
}

/// `"12.34"` → 12 340 000 micro-dólares. Sin floats: se parte por el punto y se
/// lee cada mitad como entero, y una parte decimal de más de 6 dígitos se
/// rechaza en vez de redondearse en silencio.
pub fn usd_to_micros(raw: &str) -> Result<u64, String> {
    let text = raw.trim().trim_start_matches("US$").trim_start_matches('$');
    if text.is_empty() {
        return Err("presupuesto vacío".to_owned());
    }
    let (whole, frac) = match text.split_once('.') {
        Some((whole, frac)) => (whole, frac),
        None => (text, ""),
    };
    let whole: u64 = whole
        .parse()
        .map_err(|_| format!("`{raw}` no es una cantidad de dólares"))?;
    if frac.len() > 6 {
        return Err(format!(
            "`{raw}` tiene más de 6 decimales: la unidad es el micro-dólar y \
             redondear en silencio un presupuesto es exactamente lo que no se hace"
        ));
    }
    let mut micros = if frac.is_empty() {
        0u64
    } else {
        frac.parse::<u64>()
            .map_err(|_| format!("`{raw}` no es una cantidad de dólares"))?
    };
    for _ in frac.len()..6 {
        micros = micros.saturating_mul(10);
    }
    whole
        .checked_mul(MICROS_PER_USD)
        .and_then(|whole| whole.checked_add(micros))
        .ok_or_else(|| format!("`{raw}` desborda la cuenta en micro-dólares"))
}

/// Micro-dólares → texto legible, para el reporte. Entero, sin floats.
pub fn micros_to_usd(micros: u64) -> String {
    format!(
        "US${}.{:06}",
        micros / MICROS_PER_USD,
        micros % MICROS_PER_USD
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **M6.** Sin presupuesto configurado la campaña no arranca. Es la mitad
    /// fail-closed del §3.2: el `Option` no tiene default.
    #[test]
    fn without_a_configured_budget_the_fleet_does_not_start() {
        let Err(message) = Budget::from_config(None) else {
            panic!("un presupuesto ausente arrancó la campaña");
        };
        assert!(message.contains("sin presupuesto"), "{message}");
    }

    /// El techo y el piso son las dos direcciones del mismo bound.
    #[test]
    fn the_budget_is_bounded_on_both_ends() {
        assert!(Budget::new(0).is_err(), "cero debería no arrancar");
        assert!(
            Budget::new(FLEET_BUDGET_CEILING_MICROS.saturating_add(1)).is_err(),
            "un presupuesto por encima del techo debería rechazarse"
        );
        assert!(Budget::new(FLEET_BUDGET_CEILING_MICROS).is_ok());
        assert!(Budget::new(FLEET_BUDGET_FLOOR_MICROS).is_ok());
    }

    /// **M1, la mitad del presupuesto que es de verdad gas.** Se cobra el techo
    /// ANTES: el cuarto runner no se levanta, y el gasto queda por debajo del
    /// tope aunque los tres anteriores hayan consumido menos de lo cobrado.
    #[test]
    fn charging_before_spending_is_what_keeps_the_cap() {
        let Ok(mut budget) = Budget::new(30_000_000) else {
            panic!("presupuesto inválido");
        };
        let mut launched = 0u32;
        for _ in 0..10 {
            let Ok(charge) = budget.charge(10_000_000) else {
                break;
            };
            launched += 1;
            // Consume la mitad del techo: la devolución es real.
            let _refund = charge.settle(&mut budget, 5_000_000);
        }
        assert_eq!(launched, 5, "la devolución tiene que dejar levantar más");
        assert!(
            budget.spent_micros() <= budget.limit_micros(),
            "el gasto excedió el tope: {} > {}",
            budget.spent_micros(),
            budget.limit_micros()
        );
    }

    /// El que llega al deadline se liquida **al techo**: es el `OutOfGas` del
    /// frame, que no devuelve nada.
    #[test]
    fn a_runner_that_burns_its_whole_clock_gets_no_refund() {
        let Ok(mut budget) = Budget::new(10_000_000) else {
            panic!("presupuesto inválido");
        };
        let Ok(charge) = budget.charge(10_000_000) else {
            panic!("el primer cobro tiene que entrar");
        };
        assert_eq!(charge.settle(&mut budget, 10_000_000), 0);
        assert_eq!(budget.remaining_micros(), 0);
        assert!(budget.charge(1).is_err(), "no queda nada para cobrar");
    }

    /// Un cobro que el proveedor liquida por ENCIMA de lo reservado no puede
    /// mover el tope. El §3.4 en una línea: la cuenta es nuestra.
    #[test]
    fn a_provider_overcharge_cannot_move_our_cap() {
        let Ok(mut budget) = Budget::new(10_000_000) else {
            panic!("presupuesto inválido");
        };
        let Ok(charge) = budget.charge(4_000_000) else {
            panic!("el cobro tiene que entrar");
        };
        assert_eq!(charge.settle(&mut budget, u64::MAX), 0);
        assert_eq!(budget.spent_micros(), 4_000_000);
    }

    #[test]
    fn dollars_parse_without_floats() {
        assert_eq!(usd_to_micros("150"), Ok(150_000_000));
        assert_eq!(usd_to_micros("US$0.5"), Ok(500_000));
        assert_eq!(usd_to_micros("0.000001"), Ok(1));
        assert!(usd_to_micros("0.0000001").is_err(), "7 decimales");
        assert!(usd_to_micros("").is_err());
        assert!(usd_to_micros("cien").is_err());
        assert_eq!(micros_to_usd(1_500_000), "US$1.500000");
    }
}
