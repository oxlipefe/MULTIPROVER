//! Los dos tipos que un triage produce: el **hallazgo** (un cluster con su
//! representante minimizado) y el **reporte** de la campaña.
//!
//! Viven aparte del lazo por tamaño —`campaign.rs` ya pasaba el máximo de 800
//! líneas de las reglas de estilo— y porque son datos, no control: el lazo los
//! llena, el reporte los imprime y el libro mayor los serializa, y ninguno de
//! los tres necesita a los otros dos.

use std::path::PathBuf;

use crate::fuzz::campaign::SeedSource;
use crate::fuzz::coverage::Coverage;
use crate::fuzz::shrink::ShrinkStats;
use crate::fuzz::themes::ThemeTally;

/// Un hallazgo, ya minimizado y con todo lo que hace falta para reproducirlo.
///
/// **Un `Finding` es un CLUSTER, no un caso**: el representante (el primer
/// caso que cayó ahí, minimizado) más lo que se aprendió del resto.
#[derive(Debug, Clone)]
pub struct Finding {
    /// La clave de cluster: `qué@dónde`. Es la unidad del veredicto.
    pub cluster: String,
    /// El **dónde** solo, para poder leerlo sin partir la clave.
    pub site: String,
    /// Cuántas divergencias crudas cayeron en este cluster. Es el numerador de
    /// la métrica señal/ruido.
    pub occurrences: u64,
    /// Todos los conjuntos de campos distintos que aparecieron en el cluster.
    ///
    /// **Es la evidencia contra la fusión**, y está acá por la lección de M4
    /// de 029: una regla que se traga a otra queda invisible si el reporte no
    /// tiene granularidad propia para mostrarlo. Si un cluster junta doce
    /// sub-firmas, se ve; si junta dos bugs, hay dónde mirarlo.
    pub sub_signatures: Vec<String>,
    /// Contra qué regla ya explicada cae, si cae contra alguna. `None` =
    /// **nuevo**, y lo nuevo es lo único que hace fallar la campaña.
    pub known: Option<&'static str>,
    /// La hipótesis del LLM sobre la causa raíz. **Anotación al costado**: no
    /// decide el cluster, no cambia el exit code, no filtra nada (§3.4). Se
    /// escribe DESPUÉS de que el veredicto está cerrado, y eso es estructura,
    /// no disciplina.
    pub llm_root_cause: Option<String>,
    /// La sub-firma del representante: el conjunto de campos que difieren.
    pub signature: String,
    pub seed: u64,
    pub index: u64,
    pub differences: Vec<String>,
    pub shrink: ShrinkStats,
    pub fixture: Option<PathBuf>,
    /// El fixture emitido se re-parsea y se re-corre: un trinquete que no
    /// reproduce es un trinquete mentiroso.
    pub fixture_reproduces: Option<bool>,
    /// **La identidad del fixture semilla** y los operadores aplicados, cuando
    /// el generador es de mutación. Sin la identidad, un hallazgo no se
    /// reproduce: el índice del caso depende del tamaño del corpus, que cambia
    /// con el release de EEST, mientras el nombre del fixture no.
    pub origin: Option<String>,
    pub seed_index: Option<usize>,
    /// ¿La semilla **sin mutar** ya divergía con la misma firma?
    ///
    /// **Clasificar, nunca excusar**: el hallazgo se reporta y se
    /// cuenta igual, pero el lector tiene que poder ver de un vistazo que la
    /// mutación no lo creó. Medido antes de escribir el generador: 55 de los
    /// 39 025 casos de EEST ya divergen sin tocarlos, y son las dos
    /// divergencias DELIBERADAS del inventario (EIP-7610 y los invariantes de
    /// encoding de los tipos 3 y 4). Sin este campo, las primeras decenas de
    /// "hallazgos" de este generador serían eso.
    pub seed_already_diverged: Option<bool>,
    /// El reproductor minimizado, embebido: el libro mayor no depende de que
    /// el directorio del trinquete siga existiendo.
    pub reproducer: Option<serde_json::Value>,
}

impl Finding {
    /// La línea que va al libro mayor. Función pura para poder exigir sus
    /// campos con un test en vez de con una lectura.
    pub fn to_ledger_value(&self) -> serde_json::Value {
        serde_json::json!({
            "cluster": self.cluster,
            "site": self.site,
            "signature": self.signature,
            "sub_signatures": self.sub_signatures,
            "occurrences": self.occurrences,
            "known": self.known,
            "seed": format!("{:#x}", self.seed),
            "case_index": self.index,
            "seed_fixture": self.origin,
            "seed_index": self.seed_index,
            "seed_already_diverged": self.seed_already_diverged,
            "differences": self.differences,
            "shrink": {
                "size_before": self.shrink.size_before,
                "size_after": self.shrink.size_after,
                "steps_tried": self.shrink.steps_tried,
                "steps_accepted": self.shrink.steps_accepted,
            },
            "reproducer": self.reproducer,
            "llm_root_cause": self.llm_root_cause,
        })
    }
}

#[derive(Debug, Default)]
pub struct CampaignReport {
    pub cases_run: u64,
    pub skipped_fork: u64,
    /// Casos donde los DOS motores rechazaron la tx. Se cuentan aparte porque
    /// no ejecutaron un solo opcode: sumarlos a `cases_run` haría que
    /// "0 divergencias en N casos" dijera más de lo que dice.
    pub both_rejected: u64,
    pub diverged: u64,
    pub findings: Vec<Finding>,
    pub coverage: Coverage,
    /// **Cobertura por tema**: qué territorio de consenso tocó la campaña.
    /// Va al lado de `coverage` y no adentro porque mide otra cosa: aquélla
    /// mide profundidad de ejecución, ésta mide *dónde* podía pegar el caso —
    /// el envelope de la tx y los cruces entre EIPs, que es lo que separa a
    /// los tres generadores.
    pub themes: ThemeTally,
    pub elapsed_secs: f64,
    /// Índice del PRIMER caso que divergió. Es el número de M4/M1.
    pub first_divergent_index: Option<u64>,
    /// **Todos** los índices que divergieron, acotados.
    ///
    /// No es telemetría: comparar DOS generadores sobre el mismo bug plantado
    /// exige saber en qué caso lo encontró cada uno, y "el primero que divergió"
    /// no sirve cuando el corpus ya trae divergencias deliberadas propias
    /// (medido: 55 de los 39 025 casos de EEST divergen sin tocarlos). El índice
    /// que aparece **solo** con el bug plantado es la respuesta.
    pub divergent_indices: Vec<u64>,
    pub corpus_programs: usize,
    /// Tamaño del corpus semilla (0 si el generador no siembra de casos).
    pub seed_cases: usize,
    /// De qué corpus salieron las semillas. `None` = la gramática.
    pub seed_source: Option<SeedSource>,
    /// **Métrica de vecindad**: cuántos casos quedaron estructuralmente
    /// distintos de su semilla. En el modo pass-through tiene que dar 0, y si
    /// no da 0 la métrica no está midiendo nada (§5, M2).
    pub mutated_cases: u64,
    /// Cuántos casos se construyeron sobre semillas (denominador de la
    /// vecindad).
    pub seeded_cases: u64,
    /// **Localidad**: instrucciones del stream que cambiaron / instrucciones
    /// totales, sumadas sobre todas las mutaciones de bytecode de la campaña.
    pub stream_touched: u64,
    pub stream_total: u64,
    pub code_mutations: u64,
    /// Saltos que aterrizaban en un `JUMPDEST` antes y después de la mutación.
    pub jumps_before: u64,
    pub jumps_after: u64,
    /// Cuánto costó el triage (trazar los dos motores por divergencia y
    /// minimizar los representantes). Va aparte del tiempo de la campaña
    /// porque el §6.4 pregunta exactamente esto: si el triage hunde el lazo,
    /// va fuera del lazo caliente.
    pub triage_secs: f64,
}

impl CampaignReport {
    /// Los clusters que **no** están explicados. Es el número del veredicto:
    /// una campaña falla por lo nuevo, no por lo que ya sabíamos.
    pub fn new_clusters(&self) -> usize {
        self.findings
            .iter()
            .filter(|finding| finding.known.is_none())
            .count()
    }

    pub fn known_clusters(&self) -> usize {
        self.findings.len().saturating_sub(self.new_clusters())
    }

    /// **Cada divergencia cruda cae en exactamente un cluster.**
    ///
    /// Es el auto-chequeo que hace imposible *suprimir* una divergencia
    /// conocida en vez de etiquetarla (§3.2): el que la suprima parte la
    /// cuenta, y la campaña lo dice. Un triage que se guarda hallazgos en el
    /// bolsillo produce exactamente el mismo reporte que uno que no encontró
    /// nada, y esa ambigüedad es la que este chequeo cierra.
    pub fn clusters_account_for_every_divergence(&self) -> bool {
        let clustered: u64 = self
            .findings
            .iter()
            .map(|finding| finding.occurrences)
            .sum();
        clustered == self.diverged
    }
}

impl CampaignReport {
    /// La fracción de casos que quedó distinta de su semilla. En el modo
    /// pass-through vale **0**, y ése es el punto del contraste.
    pub fn fraction_mutated(&self) -> f64 {
        if self.seeded_cases == 0 {
            return 0.0;
        }
        self.mutated_cases as f64 / self.seeded_cases as f64
    }

    /// La fracción del stream de instrucciones que una mutación de bytecode
    /// toca. Cerca de 0 = la mutación es LOCAL (la que se pidió); cerca de 1 =
    /// re-encuadró el programa entero.
    /// De los saltos que aterrizaban en un `JUMPDEST` antes de la mutación,
    /// cuántos siguen aterrizando después. **Es la trampa del §4.1 medida**:
    /// los saltos de la EVM son absolutos y mutar bytes corre los `JUMPDEST`.
    pub fn fraction_jumps_kept(&self) -> f64 {
        if self.jumps_before == 0 {
            return 1.0;
        }
        self.jumps_after as f64 / self.jumps_before as f64
    }

    pub fn stream_locality(&self) -> f64 {
        if self.stream_total == 0 {
            return 0.0;
        }
        self.stream_touched as f64 / self.stream_total as f64
    }
}
