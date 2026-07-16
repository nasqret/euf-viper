use super::{
    BOOL_SORT, BoolAtomKey, CnfProblem, FlatClauses, SymId, TermArena, TermId,
    finite_analysis::FiniteAnalysis, normalized_pair,
};
use rustc_hash::{FxHashMap as HashMap, FxHashSet as HashSet};
use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::env;
use std::io::Write;

pub(crate) const ENV: &str = "EUF_VIPER_T9_ACKERMANN";

const MAX_TERMS: usize = 16_384;
const MAX_BASE_CLAUSES: usize = 131_072;
const MAX_BASE_LITERAL_SLOTS: usize = 1_048_576;
const MAX_APPLICATIONS: usize = 256;
const MAX_ARITY: usize = 64;
const MAX_APPLICATION_ARGUMENT_SLOTS: usize = 16_384;
const MAX_ACKERMANN_CLAUSES: usize = 5_000;
const MAX_FILL_EDGES: usize = 20_000;
const MAX_FILL_PAIR_EXAMINATIONS: usize = 8_388_608;
const MAX_TRANSITIVITY_CLAUSES: usize = 2_000_000;
const MAX_TRIANGLE_VISITS: usize = 2_000_000;
const MAX_FINAL_VARIABLES: usize = 50_000;
const MAX_ADDED_LITERAL_SLOTS: usize = 6_000_000;

const MIN_ALL_DIFFERENT_CLIQUE: usize = 48;
const MAX_DISEQUALITY_CLIQUE_EXCESS: usize = 8;
const MIN_EQUALITY_GRAPH_VERTICES: usize = 2_500;
const MIN_EQUALITY_GRAPH_EDGES: usize = 10_000;
const ZERO_SHA256: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    Off,
    CliqueAuto,
}

impl Mode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::CliqueAuto => "clique-auto",
        }
    }
}

pub(crate) fn parse_mode(value: Option<&str>) -> Result<Mode, String> {
    match value {
        None | Some("off") => Ok(Mode::Off),
        Some("clique-auto") => Ok(Mode::CliqueAuto),
        Some(_) => Err(format!("{ENV} must be off or clique-auto")),
    }
}

pub(crate) fn selected_mode() -> Result<Mode, String> {
    match env::var(ENV) {
        Ok(value) => parse_mode(Some(&value)),
        Err(env::VarError::NotPresent) => parse_mode(None),
        Err(env::VarError::NotUnicode(_)) => Err(format!("{ENV} must be off or clique-auto")),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BackendRoute {
    Kissat,
    Cadical,
    CadicalRefine,
    Varisat,
    Dpll,
}

impl BackendRoute {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Kissat => "kissat",
            Self::Cadical => "cadical",
            Self::CadicalRefine => "cadical-refine",
            Self::Varisat => "varisat",
            Self::Dpll => "dpll",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SolvePrecheckRejection {
    FiniteAddedNonzero,
    ApplicationCountCap,
    BackendNotKissat,
}

impl SolvePrecheckRejection {
    fn as_str(self) -> &'static str {
        match self {
            Self::FiniteAddedNonzero => "finite_added_nonzero",
            Self::ApplicationCountCap => "application_count_cap",
            Self::BackendNotKissat => "backend_not_kissat",
        }
    }

    pub(crate) fn profile_if_enabled(self) {
        if env::var_os("EUF_VIPER_PROFILE").is_some() {
            eprintln!(
                "profile_t9_ackermann selected=0 reason={} precheck=1",
                self.as_str()
            );
        }
    }
}

pub(crate) fn solve_precheck(
    finite_added: usize,
    applications: usize,
    backend: BackendRoute,
) -> Result<(), SolvePrecheckRejection> {
    if finite_added != 0 {
        return Err(SolvePrecheckRejection::FiniteAddedNonzero);
    }
    if applications > MAX_APPLICATIONS {
        return Err(SolvePrecheckRejection::ApplicationCountCap);
    }
    if backend != BackendRoute::Kissat {
        return Err(SolvePrecheckRejection::BackendNotKissat);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CountState {
    NotComputed,
    Exact,
    LowerBound,
    Unavailable,
}

impl CountState {
    fn as_str(self) -> &'static str {
        match self {
            Self::NotComputed => "not_computed",
            Self::Exact => "exact",
            Self::LowerBound => "lower_bound",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Count {
    value: usize,
    state: CountState,
}

impl Count {
    const fn not_computed() -> Self {
        Self {
            value: 0,
            state: CountState::NotComputed,
        }
    }

    const fn exact(value: usize) -> Self {
        Self {
            value,
            state: CountState::Exact,
        }
    }

    const fn lower_bound(value: usize) -> Self {
        Self {
            value,
            state: CountState::LowerBound,
        }
    }

    const fn unavailable() -> Self {
        Self {
            value: 0,
            state: CountState::Unavailable,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rejection {
    Selected,
    ModeOff,
    FiniteAddedNonzero,
    CoveredFiniteTermsNonzero,
    ClosedTableFunctionsNonzero,
    AllDifferentCliqueBelowMinimum,
    DisequalityCliqueArithmeticOverflow,
    DisequalityCliqueExcessEdges,
    EqualityGraphVerticesBelowMinimum,
    EqualityGraphEdgesBelowMinimum,
    ApplicationCountCap,
    BackendNotKissat,
    RuntimeFactMismatch,
    FiniteStateMismatch,
    TermCountCap,
    BaseClauseCap,
    BaseLiteralSlotCap,
    ArityCap,
    ApplicationArgumentSlotCap,
    InvalidClauseStore,
    InvalidClauseLiteral,
    InvalidApplicationTerm,
    InvalidApplicationArgument,
    InvalidAtomTable,
    InvalidAtomTerm,
    InvalidEqualityEndpoint,
    UnsupportedSort,
    FootprintArithmeticOverflow,
    AckermannInvalidTerm,
    AckermannArithmeticOverflow,
    AckermannAllocationFailure,
    AckermannClauseCap,
    PlanningAllocationFailure,
    PlanningMismatch,
    FillInvalidTerm,
    FillArithmeticOverflow,
    FillEdgeCap,
    FillPairExaminationCap,
    FinalVariableCap,
    TransitivityArithmeticOverflow,
    TransitivityClauseCap,
    TriangleVisitCap,
    CandidateClauseOverflow,
    CandidateLiteralOverflow,
    AddedLiteralSlotCap,
    MaterializationVariableCapacity,
    MaterializationAllocationFailure,
    MaterializationArithmeticOverflow,
    MaterializationMismatch,
    BaselineStateChanged,
    SatDispatchObserved,
}

impl Rejection {
    fn as_str(self) -> &'static str {
        match self {
            Self::Selected => "selected",
            Self::ModeOff => "mode_off",
            Self::FiniteAddedNonzero => "finite_added_nonzero",
            Self::CoveredFiniteTermsNonzero => "covered_finite_terms_nonzero",
            Self::ClosedTableFunctionsNonzero => "closed_table_functions_nonzero",
            Self::AllDifferentCliqueBelowMinimum => "all_different_clique_below_minimum",
            Self::DisequalityCliqueArithmeticOverflow => "disequality_clique_arithmetic_overflow",
            Self::DisequalityCliqueExcessEdges => "disequality_clique_excess_edges",
            Self::EqualityGraphVerticesBelowMinimum => "equality_graph_vertices_below_minimum",
            Self::EqualityGraphEdgesBelowMinimum => "equality_graph_edges_below_minimum",
            Self::ApplicationCountCap => "application_count_cap",
            Self::BackendNotKissat => "backend_not_kissat",
            Self::RuntimeFactMismatch => "runtime_fact_mismatch",
            Self::FiniteStateMismatch => "finite_state_mismatch",
            Self::TermCountCap => "term_count_cap",
            Self::BaseClauseCap => "base_clause_cap",
            Self::BaseLiteralSlotCap => "base_literal_slot_cap",
            Self::ArityCap => "arity_cap",
            Self::ApplicationArgumentSlotCap => "application_argument_slot_cap",
            Self::InvalidClauseStore => "invalid_clause_store",
            Self::InvalidClauseLiteral => "invalid_clause_literal",
            Self::InvalidApplicationTerm => "invalid_application_term",
            Self::InvalidApplicationArgument => "invalid_application_argument",
            Self::InvalidAtomTable => "invalid_atom_table",
            Self::InvalidAtomTerm => "invalid_atom_term",
            Self::InvalidEqualityEndpoint => "invalid_equality_endpoint",
            Self::UnsupportedSort => "unsupported_sort",
            Self::FootprintArithmeticOverflow => "footprint_arithmetic_overflow",
            Self::AckermannInvalidTerm => "ackermann_invalid_term",
            Self::AckermannArithmeticOverflow => "ackermann_arithmetic_overflow",
            Self::AckermannAllocationFailure => "ackermann_allocation_failure",
            Self::AckermannClauseCap => "ackermann_clause_cap",
            Self::PlanningAllocationFailure => "planning_allocation_failure",
            Self::PlanningMismatch => "planning_mismatch",
            Self::FillInvalidTerm => "fill_invalid_term",
            Self::FillArithmeticOverflow => "fill_arithmetic_overflow",
            Self::FillEdgeCap => "fill_edge_cap",
            Self::FillPairExaminationCap => "fill_pair_examination_cap",
            Self::FinalVariableCap => "final_variable_cap",
            Self::TransitivityArithmeticOverflow => "transitivity_arithmetic_overflow",
            Self::TransitivityClauseCap => "transitivity_clause_cap",
            Self::TriangleVisitCap => "triangle_visit_cap",
            Self::CandidateClauseOverflow => "candidate_clause_overflow",
            Self::CandidateLiteralOverflow => "candidate_literal_overflow",
            Self::AddedLiteralSlotCap => "added_literal_slot_cap",
            Self::MaterializationVariableCapacity => "materialization_variable_capacity",
            Self::MaterializationAllocationFailure => "materialization_allocation_failure",
            Self::MaterializationArithmeticOverflow => "materialization_arithmetic_overflow",
            Self::MaterializationMismatch => "materialization_mismatch",
            Self::BaselineStateChanged => "baseline_state_changed",
            Self::SatDispatchObserved => "sat_dispatch_observed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StructuralFacts {
    finite_added: usize,
    covered_finite_terms: usize,
    closed_table_functions: usize,
    all_different_clique_lower_bound: usize,
    disequality_graph_edges: usize,
    equality_graph_vertices: usize,
    equality_graph_edges: usize,
    applications: usize,
    backend: BackendRoute,
}

impl StructuralFacts {
    pub(crate) fn from_analysis(
        analysis: &FiniteAnalysis,
        finite_added: usize,
        applications: usize,
        backend: BackendRoute,
    ) -> Self {
        Self {
            finite_added,
            covered_finite_terms: analysis.covered_finite_terms,
            closed_table_functions: analysis.closed_table_functions,
            all_different_clique_lower_bound: analysis.all_different_clique_lower_bound,
            disequality_graph_edges: analysis.disequality_graph_edges,
            equality_graph_vertices: analysis.equality_graph_vertices,
            equality_graph_edges: analysis.equality_graph_edges,
            applications,
            backend,
        }
    }

    pub(crate) fn dpll_route(applications: usize) -> Self {
        Self {
            finite_added: 0,
            covered_finite_terms: 0,
            closed_table_functions: 0,
            all_different_clique_lower_bound: 0,
            disequality_graph_edges: 0,
            equality_graph_vertices: 0,
            equality_graph_edges: 0,
            applications,
            backend: BackendRoute::Dpll,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Limits {
    max_terms: usize,
    max_base_clauses: usize,
    max_base_literal_slots: usize,
    max_applications: usize,
    max_arity: usize,
    max_application_argument_slots: usize,
    max_ackermann_clauses: usize,
    max_fill_edges: usize,
    max_fill_pair_examinations: usize,
    max_transitivity_clauses: usize,
    max_triangle_visits: usize,
    max_final_variables: usize,
    max_added_literal_slots: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_terms: MAX_TERMS,
            max_base_clauses: MAX_BASE_CLAUSES,
            max_base_literal_slots: MAX_BASE_LITERAL_SLOTS,
            max_applications: MAX_APPLICATIONS,
            max_arity: MAX_ARITY,
            max_application_argument_slots: MAX_APPLICATION_ARGUMENT_SLOTS,
            max_ackermann_clauses: MAX_ACKERMANN_CLAUSES,
            max_fill_edges: MAX_FILL_EDGES,
            max_fill_pair_examinations: MAX_FILL_PAIR_EXAMINATIONS,
            max_transitivity_clauses: MAX_TRANSITIVITY_CLAUSES,
            max_triangle_visits: MAX_TRIANGLE_VISITS,
            max_final_variables: MAX_FINAL_VARIABLES,
            max_added_literal_slots: MAX_ADDED_LITERAL_SLOTS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProjectionReport {
    mode: Mode,
    selector_selected: bool,
    selected: bool,
    reason: Rejection,
    facts: StructuralFacts,
    disequality_clique_excess_edges: Count,
    terms: usize,
    max_arity: Count,
    application_argument_slots: Count,
    ackermann_function_pairs: Count,
    ackermann_predicate_pairs: Count,
    candidate_pairs: Count,
    ackermann_function_differing_argument_pairs: Count,
    ackermann_predicate_differing_argument_pairs: Count,
    baseline_vars: usize,
    baseline_clauses: usize,
    baseline_literal_slots: usize,
    ackermann_clauses: Count,
    ackermann_literal_slots: Count,
    fill_edges: Count,
    fill_pair_examinations: Count,
    transitivity_clauses: Count,
    triangle_visits: Count,
    transitivity_literal_slots: Count,
    added_vars: Count,
    candidate_vars: Count,
    candidate_clauses: Count,
    candidate_literal_slots: Count,
    added_literal_slots: Count,
    materialized_ackermann_clauses: Count,
    materialized_ackermann_literal_slots: Count,
    materialized_fill_edges: Count,
    materialized_transitivity_clauses: Count,
    materialized_transitivity_literal_slots: Count,
    materialized_triangle_visits: Count,
    materialized_added_vars: Count,
    materialized_candidate_vars: Count,
    materialized_candidate_clauses: Count,
    materialized_candidate_literal_slots: Count,
    materialized_added_literal_slots: Count,
    baseline_before_sha256: String,
    baseline_after_sha256: String,
    materialized_candidate_sha256: String,
    materialization_match: bool,
    sat_calls: usize,
    off_path_unchanged: bool,
}

impl ProjectionReport {
    fn new(mode: Mode, cnf: &CnfProblem, arena: &TermArena, facts: StructuralFacts) -> Self {
        let baseline_sha256 = canonical_problem_sha256(cnf);
        let disequality_clique_excess_edges =
            checked_pair_count(facts.all_different_clique_lower_bound)
                .and_then(|minimum| facts.disequality_graph_edges.checked_sub(minimum))
                .map_or_else(Count::unavailable, Count::exact);
        Self {
            mode,
            selector_selected: false,
            selected: false,
            reason: Rejection::ModeOff,
            facts,
            disequality_clique_excess_edges,
            terms: arena.terms.len(),
            max_arity: Count::not_computed(),
            application_argument_slots: Count::not_computed(),
            ackermann_function_pairs: Count::not_computed(),
            ackermann_predicate_pairs: Count::not_computed(),
            candidate_pairs: Count::not_computed(),
            ackermann_function_differing_argument_pairs: Count::not_computed(),
            ackermann_predicate_differing_argument_pairs: Count::not_computed(),
            baseline_vars: cnf.var_count(),
            baseline_clauses: cnf.clauses.len(),
            baseline_literal_slots: cnf.clauses.literals.len(),
            ackermann_clauses: Count::not_computed(),
            ackermann_literal_slots: Count::not_computed(),
            fill_edges: Count::not_computed(),
            fill_pair_examinations: Count::not_computed(),
            transitivity_clauses: Count::not_computed(),
            triangle_visits: Count::not_computed(),
            transitivity_literal_slots: Count::not_computed(),
            added_vars: Count::not_computed(),
            candidate_vars: Count::not_computed(),
            candidate_clauses: Count::not_computed(),
            candidate_literal_slots: Count::not_computed(),
            added_literal_slots: Count::not_computed(),
            materialized_ackermann_clauses: Count::not_computed(),
            materialized_ackermann_literal_slots: Count::not_computed(),
            materialized_fill_edges: Count::not_computed(),
            materialized_transitivity_clauses: Count::not_computed(),
            materialized_transitivity_literal_slots: Count::not_computed(),
            materialized_triangle_visits: Count::not_computed(),
            materialized_added_vars: Count::not_computed(),
            materialized_candidate_vars: Count::not_computed(),
            materialized_candidate_clauses: Count::not_computed(),
            materialized_candidate_literal_slots: Count::not_computed(),
            materialized_added_literal_slots: Count::not_computed(),
            baseline_before_sha256: baseline_sha256.clone(),
            baseline_after_sha256: baseline_sha256,
            materialized_candidate_sha256: ZERO_SHA256.to_owned(),
            materialization_match: false,
            sat_calls: 0,
            off_path_unchanged: false,
        }
    }

    pub(crate) fn selected(&self) -> bool {
        self.selected
    }

    pub(crate) fn record_observed_sat_calls(&mut self, sat_calls: usize) {
        self.sat_calls = sat_calls;
        if sat_calls != 0 {
            self.selected = false;
            self.reason = Rejection::SatDispatchObserved;
        }
    }

    pub(crate) fn write_to(&self, output: &mut impl Write) -> std::io::Result<()> {
        writeln!(output, "t9_projection_version 1")?;
        writeln!(output, "mode {}", self.mode.as_str())?;
        writeln!(
            output,
            "selector_selected {}",
            usize::from(self.selector_selected)
        )?;
        writeln!(output, "selected {}", usize::from(self.selected))?;
        writeln!(output, "reason {}", self.reason.as_str())?;
        writeln!(output, "finite_added {}", self.facts.finite_added)?;
        writeln!(
            output,
            "covered_finite_terms {}",
            self.facts.covered_finite_terms
        )?;
        writeln!(
            output,
            "closed_table_functions {}",
            self.facts.closed_table_functions
        )?;
        writeln!(
            output,
            "all_different_clique_lb {}",
            self.facts.all_different_clique_lower_bound
        )?;
        writeln!(
            output,
            "disequality_graph_edges {}",
            self.facts.disequality_graph_edges
        )?;
        writeln!(
            output,
            "disequality_clique_excess_edges {}",
            self.disequality_clique_excess_edges.value
        )?;
        writeln!(
            output,
            "equality_graph_vertices {}",
            self.facts.equality_graph_vertices
        )?;
        writeln!(
            output,
            "equality_graph_edges {}",
            self.facts.equality_graph_edges
        )?;
        writeln!(output, "applications {}", self.facts.applications)?;
        writeln!(output, "backend {}", self.facts.backend.as_str())?;
        writeln!(output, "terms {}", self.terms)?;
        writeln!(output, "baseline_vars {}", self.baseline_vars)?;
        writeln!(output, "baseline_clauses {}", self.baseline_clauses)?;
        writeln!(
            output,
            "baseline_literal_slots {}",
            self.baseline_literal_slots
        )?;
        writeln!(
            output,
            "triangle_visits_definition eligible_third_vertex_probes"
        )?;
        writeln!(
            output,
            "baseline_before_sha256 {}",
            self.baseline_before_sha256
        )?;
        writeln!(
            output,
            "baseline_after_sha256 {}",
            self.baseline_after_sha256
        )?;
        writeln!(
            output,
            "materialized_candidate_sha256 {}",
            self.materialized_candidate_sha256
        )?;
        writeln!(output, "sat_calls {}", self.sat_calls)?;
        write_count(output, "planned_max_arity", self.max_arity)?;
        write_count(
            output,
            "planned_application_argument_slots",
            self.application_argument_slots,
        )?;
        write_count(
            output,
            "planned_ackermann_function_pairs",
            self.ackermann_function_pairs,
        )?;
        write_count(
            output,
            "planned_ackermann_predicate_pairs",
            self.ackermann_predicate_pairs,
        )?;
        write_count(
            output,
            "planned_ackermann_candidate_pairs",
            self.candidate_pairs,
        )?;
        write_count(
            output,
            "planned_ackermann_function_differing_argument_pairs",
            self.ackermann_function_differing_argument_pairs,
        )?;
        write_count(
            output,
            "planned_ackermann_predicate_differing_argument_pairs",
            self.ackermann_predicate_differing_argument_pairs,
        )?;
        write_count(output, "planned_ackermann_clauses", self.ackermann_clauses)?;
        write_count(
            output,
            "planned_ackermann_literal_slots",
            self.ackermann_literal_slots,
        )?;
        write_count(output, "planned_fill_edges", self.fill_edges)?;
        write_count(
            output,
            "planned_fill_pair_examinations",
            self.fill_pair_examinations,
        )?;
        write_count(output, "planned_added_vars", self.added_vars)?;
        write_count(
            output,
            "planned_transitivity_clauses",
            self.transitivity_clauses,
        )?;
        write_count(
            output,
            "planned_transitivity_literal_slots",
            self.transitivity_literal_slots,
        )?;
        write_count(output, "planned_triangle_visits", self.triangle_visits)?;
        write_count(output, "planned_candidate_vars", self.candidate_vars)?;
        write_count(output, "planned_candidate_clauses", self.candidate_clauses)?;
        write_count(
            output,
            "planned_candidate_literal_slots",
            self.candidate_literal_slots,
        )?;
        write_count(
            output,
            "planned_added_literal_slots",
            self.added_literal_slots,
        )?;
        write_count(
            output,
            "materialized_ackermann_clauses",
            self.materialized_ackermann_clauses,
        )?;
        write_count(
            output,
            "materialized_ackermann_literal_slots",
            self.materialized_ackermann_literal_slots,
        )?;
        write_count(
            output,
            "materialized_fill_edges",
            self.materialized_fill_edges,
        )?;
        write_count(
            output,
            "materialized_transitivity_clauses",
            self.materialized_transitivity_clauses,
        )?;
        write_count(
            output,
            "materialized_transitivity_literal_slots",
            self.materialized_transitivity_literal_slots,
        )?;
        write_count(
            output,
            "materialized_triangle_visits",
            self.materialized_triangle_visits,
        )?;
        write_count(
            output,
            "materialized_added_vars",
            self.materialized_added_vars,
        )?;
        write_count(
            output,
            "materialized_candidate_vars",
            self.materialized_candidate_vars,
        )?;
        write_count(
            output,
            "materialized_candidate_clauses",
            self.materialized_candidate_clauses,
        )?;
        write_count(
            output,
            "materialized_candidate_literal_slots",
            self.materialized_candidate_literal_slots,
        )?;
        write_count(
            output,
            "materialized_added_literal_slots",
            self.materialized_added_literal_slots,
        )
    }

    pub(crate) fn profile_if_enabled(&self) {
        if env::var_os("EUF_VIPER_PROFILE").is_none() {
            return;
        }
        let mut rendered = Vec::new();
        if self.write_to(&mut rendered).is_err() {
            return;
        }
        let Ok(rendered) = String::from_utf8(rendered) else {
            return;
        };
        let fields = rendered
            .lines()
            .skip(1)
            .filter_map(|line| line.split_once(' '))
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join(" ");
        eprintln!("profile_t9_ackermann {fields}");
    }
}

fn write_count(output: &mut impl Write, key: &str, count: Count) -> std::io::Result<()> {
    writeln!(output, "{key} {}", count.value)?;
    writeln!(output, "{key}_state {}", count.state.as_str())
}

const SHA256_ROUND_CONSTANTS: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    byte_len: u64,
}

impl Sha256 {
    fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buffer: [0; 64],
            buffer_len: 0,
            byte_len: 0,
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        self.byte_len = self.byte_len.wrapping_add(input.len() as u64);
        if self.buffer_len != 0 {
            let take = (64 - self.buffer_len).min(input.len());
            self.buffer[self.buffer_len..self.buffer_len + take].copy_from_slice(&input[..take]);
            self.buffer_len += take;
            input = &input[take..];
            if self.buffer_len == 64 {
                let block = self.buffer;
                self.compress(&block);
                self.buffer_len = 0;
            }
        }
        while input.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&input[..64]);
            self.compress(&block);
            input = &input[64..];
        }
        self.buffer[..input.len()].copy_from_slice(input);
        self.buffer_len = input.len();
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut words = [0u32; 64];
        for (index, chunk) in block.chunks_exact(4).enumerate() {
            words[index] = u32::from_be_bytes(chunk.try_into().unwrap());
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for index in 0..64 {
            let sigma1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(sigma1)
                .wrapping_add(choose)
                .wrapping_add(SHA256_ROUND_CONSTANTS[index])
                .wrapping_add(words[index]);
            let sigma0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = sigma0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        for (state, value) in self.state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *state = state.wrapping_add(value);
        }
    }

    fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.byte_len.wrapping_mul(8);
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;
        if self.buffer_len > 56 {
            self.buffer[self.buffer_len..].fill(0);
            let block = self.buffer;
            self.compress(&block);
            self.buffer = [0; 64];
            self.buffer_len = 0;
        }
        self.buffer[self.buffer_len..56].fill(0);
        self.buffer[56..].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.buffer;
        self.compress(&block);

        let mut output = [0u8; 32];
        for (chunk, word) in output.chunks_exact_mut(4).zip(self.state) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        output
    }
}

#[cfg(test)]
fn sha256_hex(input: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(input);
    hash.finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn hash_u8(hash: &mut Sha256, value: u8) {
    hash.update(&[value]);
}

fn hash_u32(hash: &mut Sha256, value: u32) {
    hash.update(&value.to_be_bytes());
}

fn hash_i32(hash: &mut Sha256, value: i32) {
    hash.update(&value.to_be_bytes());
}

fn hash_u64(hash: &mut Sha256, value: usize) {
    hash.update(&(value as u64).to_be_bytes());
}

fn hash_atom(hash: &mut Sha256, atom: &BoolAtomKey) {
    match atom {
        BoolAtomKey::Eq(left, right) => {
            hash_u8(hash, 1);
            hash_u64(hash, *left);
            hash_u64(hash, *right);
        }
        BoolAtomKey::BoolTerm(term) => {
            hash_u8(hash, 2);
            hash_u64(hash, *term);
        }
    }
}

fn digest_hex(hash: Sha256) -> String {
    hash.finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn hash_cnf_state(hash: &mut Sha256, cnf: &CnfProblem) {
    hash.update(b"euf-viper-t9-flat-clauses-v1\0");
    hash_u64(hash, cnf.clauses.end_offsets.len());
    for &offset in &cnf.clauses.end_offsets {
        hash_u32(hash, offset);
    }
    hash_u64(hash, cnf.clauses.literals.len());
    for &literal in &cnf.clauses.literals {
        hash_i32(hash, literal);
    }
}

fn hash_atom_state(hash: &mut Sha256, cnf: &CnfProblem) {
    hash.update(b"euf-viper-t9-atom-state-v1\0");
    hash_u64(hash, cnf.var_atoms.len());
    for atom in &cnf.var_atoms {
        match atom {
            None => hash_u8(hash, 0),
            Some(atom) => hash_atom(hash, atom),
        }
    }
    hash_u64(hash, cnf.atom_vars.len());
    for atom in cnf.var_atoms.iter().flatten() {
        hash_atom(hash, atom);
        match cnf.atom_vars.get(atom) {
            Some(variable) => {
                hash_u8(hash, 1);
                hash_i32(hash, *variable);
            }
            None => hash_u8(hash, 0),
        }
    }
    match cnf.true_lit {
        Some(literal) => {
            hash_u8(hash, 1);
            hash_i32(hash, literal);
        }
        None => hash_u8(hash, 0),
    }
    hash_u8(hash, u8::from(cnf.finite_equalities_complete));
    hash_u8(hash, u8::from(cnf.finite_predicate_congruence_complete));
}

fn canonical_problem_sha256(cnf: &CnfProblem) -> String {
    let mut hash = Sha256::new();
    hash.update(b"euf-viper-t9-cnf-atom-state-v1\0");
    hash_cnf_state(&mut hash, cnf);
    hash_atom_state(&mut hash, cnf);
    digest_hex(hash)
}

pub(crate) struct Attempt {
    pub(crate) candidate: Option<CnfProblem>,
    pub(crate) report: ProjectionReport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BaselineIdentity {
    first: u64,
    second: u64,
    clauses: usize,
    literals: usize,
    variables: usize,
    atoms: usize,
}

fn mix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn atom_hash(atom: &BoolAtomKey) -> u64 {
    match atom {
        BoolAtomKey::Eq(left, right) => {
            mix64(0x4551_u64 ^ (*left as u64)).rotate_left(17) ^ mix64(*right as u64)
        }
        BoolAtomKey::BoolTerm(term) => mix64(0x424f_4f4c_u64 ^ (*term as u64)),
    }
}

fn baseline_identity(cnf: &CnfProblem) -> BaselineIdentity {
    let mut first = mix64(cnf.clauses.end_offsets.len() as u64);
    let mut second = mix64(cnf.clauses.literals.len() as u64);
    for &offset in &cnf.clauses.end_offsets {
        first = mix64(first ^ u64::from(offset));
        second = second.wrapping_add(mix64(u64::from(offset)));
    }
    for &literal in &cnf.clauses.literals {
        let encoded = literal as i64 as u64;
        first = mix64(first ^ encoded);
        second = second.wrapping_add(mix64(encoded.rotate_left(11)));
    }
    for (variable, atom) in cnf.var_atoms.iter().enumerate() {
        let encoded = atom
            .as_ref()
            .map_or(0x4e4f_4e45_u64, |atom| atom_hash(atom) ^ variable as u64);
        first = mix64(first ^ encoded);
        second = second.wrapping_add(mix64(encoded.rotate_left(23)));
    }
    let mut map_first = 0u64;
    let mut map_second = 0u64;
    for (atom, variable) in &cnf.atom_vars {
        let encoded = atom_hash(atom) ^ (*variable as i64 as u64).rotate_left(29);
        map_first ^= mix64(encoded);
        map_second = map_second.wrapping_add(mix64(encoded.rotate_left(7)));
    }
    first = mix64(first ^ map_first);
    second = mix64(second ^ map_second);
    let state = (cnf.true_lit.unwrap_or_default() as i64 as u64)
        ^ ((cnf.finite_equalities_complete as u64) << 61)
        ^ ((cnf.finite_predicate_congruence_complete as u64) << 62);
    BaselineIdentity {
        first: mix64(first ^ state),
        second: mix64(second ^ state.rotate_left(13)),
        clauses: cnf.clauses.len(),
        literals: cnf.clauses.literals.len(),
        variables: cnf.var_count(),
        atoms: cnf.atom_vars.len(),
    }
}

fn selector_rejection(report: &ProjectionReport) -> Option<Rejection> {
    if report.mode == Mode::Off {
        return Some(Rejection::ModeOff);
    }
    if report.facts.finite_added != 0 {
        return Some(Rejection::FiniteAddedNonzero);
    }
    if report.facts.applications > MAX_APPLICATIONS {
        return Some(Rejection::ApplicationCountCap);
    }
    if report.facts.backend != BackendRoute::Kissat {
        return Some(Rejection::BackendNotKissat);
    }
    if report.facts.covered_finite_terms != 0 {
        return Some(Rejection::CoveredFiniteTermsNonzero);
    }
    if report.facts.closed_table_functions != 0 {
        return Some(Rejection::ClosedTableFunctionsNonzero);
    }
    if report.facts.all_different_clique_lower_bound < MIN_ALL_DIFFERENT_CLIQUE {
        return Some(Rejection::AllDifferentCliqueBelowMinimum);
    }
    match report.disequality_clique_excess_edges.state {
        CountState::Exact => {
            if report.disequality_clique_excess_edges.value > MAX_DISEQUALITY_CLIQUE_EXCESS {
                return Some(Rejection::DisequalityCliqueExcessEdges);
            }
        }
        _ => return Some(Rejection::DisequalityCliqueArithmeticOverflow),
    }
    if report.facts.equality_graph_vertices < MIN_EQUALITY_GRAPH_VERTICES {
        return Some(Rejection::EqualityGraphVerticesBelowMinimum);
    }
    if report.facts.equality_graph_edges < MIN_EQUALITY_GRAPH_EDGES {
        return Some(Rejection::EqualityGraphEdgesBelowMinimum);
    }
    None
}

pub(crate) fn attempt(
    mode: Mode,
    cnf: &CnfProblem,
    arena: &TermArena,
    facts: StructuralFacts,
) -> Attempt {
    attempt_with_limits(mode, cnf, arena, facts, Limits::default())
}

fn attempt_with_limits(
    mode: Mode,
    cnf: &CnfProblem,
    arena: &TermArena,
    facts: StructuralFacts,
    limits: Limits,
) -> Attempt {
    let before = baseline_identity(cnf);
    let mut report = ProjectionReport::new(mode, cnf, arena, facts);
    if let Some(rejection) = selector_rejection(&report) {
        report.reason = rejection;
        return finish_attempt(cnf, before, None, report);
    }
    report.selector_selected = true;

    let plan = match plan_completion(cnf, arena, limits, &mut report) {
        Ok(plan) => plan,
        Err(rejection) => {
            report.reason = rejection;
            return finish_attempt(cnf, before, None, report);
        }
    };
    match materialize_candidate(cnf, &plan) {
        Ok(materialized) => {
            set_materialized_counts(&mut report, materialized.facts);
            report.materialized_candidate_sha256 =
                canonical_problem_sha256(&materialized.candidate);
            report.selected = true;
            report.reason = Rejection::Selected;
            report.materialization_match = true;
            finish_attempt(cnf, before, Some(materialized.candidate), report)
        }
        Err(failure) => {
            if let Some(facts) = failure.facts {
                set_materialized_counts(&mut report, facts);
            }
            report.reason = failure.reason;
            finish_attempt(cnf, before, None, report)
        }
    }
}

fn set_materialized_counts(report: &mut ProjectionReport, facts: MaterializationFacts) {
    report.materialized_ackermann_clauses = Count::exact(facts.ackermann_clauses);
    report.materialized_ackermann_literal_slots = Count::exact(facts.ackermann_literal_slots);
    report.materialized_fill_edges = Count::exact(facts.fill_edges);
    report.materialized_transitivity_clauses = Count::exact(facts.transitivity_clauses);
    report.materialized_transitivity_literal_slots = Count::exact(facts.transitivity_literal_slots);
    report.materialized_triangle_visits = Count::exact(facts.triangle_visits);
    report.materialized_added_vars = Count::exact(facts.added_vars);
    report.materialized_candidate_vars = Count::exact(facts.candidate_vars);
    report.materialized_candidate_clauses = Count::exact(facts.candidate_clauses);
    report.materialized_candidate_literal_slots = Count::exact(facts.candidate_literal_slots);
    report.materialized_added_literal_slots = Count::exact(facts.added_literal_slots);
}

fn finish_attempt(
    cnf: &CnfProblem,
    before: BaselineIdentity,
    mut candidate: Option<CnfProblem>,
    mut report: ProjectionReport,
) -> Attempt {
    report.baseline_after_sha256 = canonical_problem_sha256(cnf);
    report.off_path_unchanged = baseline_identity(cnf) == before
        && report.baseline_before_sha256 == report.baseline_after_sha256;
    if !report.off_path_unchanged {
        candidate = None;
        report.materialized_candidate_sha256 = ZERO_SHA256.to_owned();
        report.selected = false;
        report.materialization_match = false;
        report.reason = Rejection::BaselineStateChanged;
    }
    Attempt { candidate, report }
}

fn checked_pair_count(count: usize) -> Option<usize> {
    if count < 2 {
        return Some(0);
    }
    if count % 2 == 0 {
        (count / 2).checked_mul(count - 1)
    } else {
        count.checked_mul((count - 1) / 2)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct AckermannEstimate {
    function_pairs: usize,
    predicate_pairs: usize,
    candidate_pairs: usize,
    function_differing_argument_pairs: usize,
    predicate_differing_argument_pairs: usize,
    clauses: usize,
    literal_slots: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AckermannEstimateFailure {
    InvalidTerm,
    ArithmeticOverflow,
    AllocationFailure,
}

#[derive(Debug, Default)]
struct AckermannGroupStats {
    application_count: usize,
    argument_frequencies: Vec<HashMap<TermId, usize>>,
}

fn checked_ackermann_group_estimate(
    pair_count: usize,
    differing_argument_pairs: usize,
    bool_result: bool,
) -> Option<AckermannEstimate> {
    if bool_result {
        Some(AckermannEstimate {
            function_pairs: 0,
            predicate_pairs: pair_count,
            candidate_pairs: pair_count,
            function_differing_argument_pairs: 0,
            predicate_differing_argument_pairs: differing_argument_pairs,
            clauses: pair_count.checked_mul(2)?,
            literal_slots: pair_count
                .checked_mul(4)?
                .checked_add(differing_argument_pairs.checked_mul(2)?)?,
        })
    } else {
        Some(AckermannEstimate {
            function_pairs: pair_count,
            predicate_pairs: 0,
            candidate_pairs: pair_count,
            function_differing_argument_pairs: differing_argument_pairs,
            predicate_differing_argument_pairs: 0,
            clauses: pair_count,
            literal_slots: pair_count.checked_add(differing_argument_pairs)?,
        })
    }
}

fn full_ackermann_estimate(
    cnf: &CnfProblem,
    arena: &TermArena,
) -> Result<AckermannEstimate, AckermannEstimateFailure> {
    let mut bool_functions = HashSet::default();
    bool_functions
        .try_reserve(cnf.var_atoms.len())
        .map_err(|_| AckermannEstimateFailure::AllocationFailure)?;
    for atom in cnf.var_atoms.iter().flatten() {
        let BoolAtomKey::BoolTerm(term) = atom else {
            continue;
        };
        let application = arena
            .terms
            .get(*term)
            .ok_or(AckermannEstimateFailure::InvalidTerm)?;
        bool_functions.insert((application.fun, application.args.len()));
    }

    let mut groups = HashMap::<(SymId, usize), AckermannGroupStats>::default();
    groups
        .try_reserve(arena.apps.len())
        .map_err(|_| AckermannEstimateFailure::AllocationFailure)?;
    for &term_id in &arena.apps {
        let application = arena
            .terms
            .get(term_id)
            .ok_or(AckermannEstimateFailure::InvalidTerm)?;
        let arity = application.args.len();
        if !groups.contains_key(&(application.fun, arity)) {
            let mut argument_frequencies = Vec::new();
            argument_frequencies
                .try_reserve_exact(arity)
                .map_err(|_| AckermannEstimateFailure::AllocationFailure)?;
            argument_frequencies.extend((0..arity).map(|_| HashMap::default()));
            groups.insert(
                (application.fun, arity),
                AckermannGroupStats {
                    application_count: 0,
                    argument_frequencies,
                },
            );
        }
        let group = groups.get_mut(&(application.fun, arity)).unwrap();
        group.application_count = group
            .application_count
            .checked_add(1)
            .ok_or(AckermannEstimateFailure::ArithmeticOverflow)?;
        for (position, &argument) in application.args.iter().enumerate() {
            let frequencies = &mut group.argument_frequencies[position];
            if !frequencies.contains_key(&argument) {
                frequencies
                    .try_reserve(1)
                    .map_err(|_| AckermannEstimateFailure::AllocationFailure)?;
            }
            let frequency = frequencies.entry(argument).or_insert(0);
            *frequency = frequency
                .checked_add(1)
                .ok_or(AckermannEstimateFailure::ArithmeticOverflow)?;
        }
    }

    let mut total = AckermannEstimate::default();
    for (&group, stats) in &groups {
        let pair_count = checked_pair_count(stats.application_count)
            .ok_or(AckermannEstimateFailure::ArithmeticOverflow)?;
        let mut differing_argument_pairs = 0usize;
        for frequencies in &stats.argument_frequencies {
            let mut equal_pairs = 0usize;
            for &frequency in frequencies.values() {
                equal_pairs = equal_pairs
                    .checked_add(
                        checked_pair_count(frequency)
                            .ok_or(AckermannEstimateFailure::ArithmeticOverflow)?,
                    )
                    .ok_or(AckermannEstimateFailure::ArithmeticOverflow)?;
            }
            let differing_pairs = pair_count
                .checked_sub(equal_pairs)
                .ok_or(AckermannEstimateFailure::ArithmeticOverflow)?;
            differing_argument_pairs = differing_argument_pairs
                .checked_add(differing_pairs)
                .ok_or(AckermannEstimateFailure::ArithmeticOverflow)?;
        }
        let estimate = checked_ackermann_group_estimate(
            pair_count,
            differing_argument_pairs,
            bool_functions.contains(&group),
        )
        .ok_or(AckermannEstimateFailure::ArithmeticOverflow)?;
        total.function_pairs = total
            .function_pairs
            .checked_add(estimate.function_pairs)
            .ok_or(AckermannEstimateFailure::ArithmeticOverflow)?;
        total.predicate_pairs = total
            .predicate_pairs
            .checked_add(estimate.predicate_pairs)
            .ok_or(AckermannEstimateFailure::ArithmeticOverflow)?;
        total.candidate_pairs = total
            .candidate_pairs
            .checked_add(estimate.candidate_pairs)
            .ok_or(AckermannEstimateFailure::ArithmeticOverflow)?;
        total.function_differing_argument_pairs = total
            .function_differing_argument_pairs
            .checked_add(estimate.function_differing_argument_pairs)
            .ok_or(AckermannEstimateFailure::ArithmeticOverflow)?;
        total.predicate_differing_argument_pairs = total
            .predicate_differing_argument_pairs
            .checked_add(estimate.predicate_differing_argument_pairs)
            .ok_or(AckermannEstimateFailure::ArithmeticOverflow)?;
        total.clauses = total
            .clauses
            .checked_add(estimate.clauses)
            .ok_or(AckermannEstimateFailure::ArithmeticOverflow)?;
        total.literal_slots = total
            .literal_slots
            .checked_add(estimate.literal_slots)
            .ok_or(AckermannEstimateFailure::ArithmeticOverflow)?;
    }
    Ok(total)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PlannedLiteral {
    atom: BoolAtomKey,
    positive: bool,
}

type PlannedClause = Vec<PlannedLiteral>;

#[derive(Debug, Clone, PartialEq, Eq)]
struct SparseTransitivityFillPlan {
    edges: Vec<(TermId, TermId)>,
    pair_examinations: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CompletionPlan {
    ackermann_clauses: Vec<PlannedClause>,
    ackermann_clause_count: usize,
    ackermann_literal_slots: usize,
    fill: SparseTransitivityFillPlan,
    fill_edge_count: usize,
    new_atoms: Vec<BoolAtomKey>,
    term_count: usize,
    added_vars: usize,
    candidate_vars: usize,
    candidate_clauses: usize,
    candidate_literal_slots: usize,
    transitivity_clauses: usize,
    triangle_visits: usize,
    transitivity_literal_slots: usize,
    added_literal_slots: usize,
}

fn validate_preplan(
    cnf: &CnfProblem,
    arena: &TermArena,
    limits: Limits,
    report: &mut ProjectionReport,
) -> Result<(), Rejection> {
    if report.facts.applications != arena.apps.len() {
        return Err(Rejection::RuntimeFactMismatch);
    }
    if cnf.finite_equalities_complete || cnf.finite_predicate_congruence_complete {
        return Err(Rejection::FiniteStateMismatch);
    }
    if arena.terms.len() > limits.max_terms {
        return Err(Rejection::TermCountCap);
    }
    if cnf.clauses.len() > limits.max_base_clauses {
        return Err(Rejection::BaseClauseCap);
    }
    if cnf.clauses.literals.len() > limits.max_base_literal_slots {
        return Err(Rejection::BaseLiteralSlotCap);
    }
    if cnf.var_count() > limits.max_final_variables {
        report.candidate_vars = Count::lower_bound(cnf.var_count());
        return Err(Rejection::FinalVariableCap);
    }
    if cnf.clauses.end_offsets.first() != Some(&0)
        || cnf.clauses.end_offsets.len() != cnf.clauses.len().saturating_add(1)
        || cnf
            .clauses
            .end_offsets
            .last()
            .copied()
            .map(|offset| offset as usize)
            != Some(cnf.clauses.literals.len())
        || cnf
            .clauses
            .end_offsets
            .windows(2)
            .any(|bounds| bounds[0] > bounds[1])
    {
        return Err(Rejection::InvalidClauseStore);
    }
    if cnf
        .clauses
        .literals
        .iter()
        .any(|literal| *literal == 0 || literal.unsigned_abs() as usize > cnf.var_count())
    {
        return Err(Rejection::InvalidClauseLiteral);
    }
    if arena.apps.len() > limits.max_applications {
        return Err(Rejection::ApplicationCountCap);
    }

    let mut seen_applications = HashSet::default();
    seen_applications
        .try_reserve(arena.apps.len())
        .map_err(|_| Rejection::PlanningAllocationFailure)?;
    let mut max_arity = 0usize;
    let mut argument_slots = 0usize;
    for &term_id in &arena.apps {
        let application = arena
            .terms
            .get(term_id)
            .ok_or(Rejection::InvalidApplicationTerm)?;
        if application.args.is_empty() || !seen_applications.insert(term_id) {
            return Err(Rejection::InvalidApplicationTerm);
        }
        max_arity = max_arity.max(application.args.len());
        if max_arity > limits.max_arity {
            report.max_arity = Count::lower_bound(max_arity);
            return Err(Rejection::ArityCap);
        }
        argument_slots = argument_slots
            .checked_add(application.args.len())
            .ok_or(Rejection::FootprintArithmeticOverflow)?;
        if argument_slots > limits.max_application_argument_slots {
            report.application_argument_slots = Count::lower_bound(argument_slots);
            return Err(Rejection::ApplicationArgumentSlotCap);
        }
        if application
            .args
            .iter()
            .any(|argument| *argument >= arena.terms.len())
        {
            return Err(Rejection::InvalidApplicationArgument);
        }
    }
    if arena.terms.iter().enumerate().any(|(term, application)| {
        !application.args.is_empty() && !seen_applications.contains(&term)
    }) {
        return Err(Rejection::InvalidApplicationTerm);
    }
    report.max_arity = Count::exact(max_arity);
    report.application_argument_slots = Count::exact(argument_slots);

    if cnf.var_atoms.is_empty()
        || cnf.var_atoms[0].is_some()
        || cnf.atom_vars.len() > cnf.var_count()
    {
        return Err(Rejection::InvalidAtomTable);
    }
    for (variable, atom) in cnf.var_atoms.iter().enumerate().skip(1) {
        let Some(atom) = atom else {
            continue;
        };
        if cnf.atom_vars.get(atom).copied() != Some(variable as i32) {
            return Err(Rejection::InvalidAtomTable);
        }
        match atom {
            BoolAtomKey::Eq(left, right) => {
                let (Some(left_term), Some(right_term)) =
                    (arena.terms.get(*left), arena.terms.get(*right))
                else {
                    return Err(Rejection::InvalidEqualityEndpoint);
                };
                if left_term.sort != right_term.sort {
                    return Err(Rejection::UnsupportedSort);
                }
            }
            BoolAtomKey::BoolTerm(term) => {
                let term = arena.terms.get(*term).ok_or(Rejection::InvalidAtomTerm)?;
                if term.sort != BOOL_SORT {
                    return Err(Rejection::UnsupportedSort);
                }
            }
        }
    }
    for (atom, &variable) in &cnf.atom_vars {
        if variable <= 0
            || variable as usize >= cnf.var_atoms.len()
            || cnf.var_atoms[variable as usize].as_ref() != Some(atom)
        {
            return Err(Rejection::InvalidAtomTable);
        }
    }
    if cnf
        .true_lit
        .is_some_and(|literal| literal <= 0 || literal as usize >= cnf.var_atoms.len())
    {
        return Err(Rejection::InvalidAtomTable);
    }
    Ok(())
}

fn ackermann_rejection(failure: AckermannEstimateFailure) -> Rejection {
    match failure {
        AckermannEstimateFailure::InvalidTerm => Rejection::AckermannInvalidTerm,
        AckermannEstimateFailure::ArithmeticOverflow => Rejection::AckermannArithmeticOverflow,
        AckermannEstimateFailure::AllocationFailure => Rejection::AckermannAllocationFailure,
    }
}

fn ordered_application_groups(
    arena: &TermArena,
) -> Result<Vec<((SymId, usize), Vec<TermId>)>, Rejection> {
    let mut groups = Vec::<((SymId, usize), Vec<TermId>)>::new();
    groups
        .try_reserve(arena.apps.len())
        .map_err(|_| Rejection::PlanningAllocationFailure)?;
    let mut indices = HashMap::<(SymId, usize), usize>::default();
    indices
        .try_reserve(arena.apps.len())
        .map_err(|_| Rejection::PlanningAllocationFailure)?;
    for &term_id in &arena.apps {
        let application = arena
            .terms
            .get(term_id)
            .ok_or(Rejection::AckermannInvalidTerm)?;
        let key = (application.fun, application.args.len());
        let index = if let Some(&index) = indices.get(&key) {
            index
        } else {
            let index = groups.len();
            indices.insert(key, index);
            groups.push((key, Vec::new()));
            index
        };
        groups[index]
            .1
            .try_reserve(1)
            .map_err(|_| Rejection::PlanningAllocationFailure)?;
        groups[index].1.push(term_id);
    }
    Ok(groups)
}

fn bool_function_keys(
    cnf: &CnfProblem,
    arena: &TermArena,
) -> Result<HashSet<(SymId, usize)>, Rejection> {
    let mut keys = HashSet::default();
    keys.try_reserve(cnf.var_atoms.len())
        .map_err(|_| Rejection::PlanningAllocationFailure)?;
    for atom in cnf.var_atoms.iter().flatten() {
        let BoolAtomKey::BoolTerm(term) = atom else {
            continue;
        };
        let application = arena
            .terms
            .get(*term)
            .ok_or(Rejection::AckermannInvalidTerm)?;
        keys.insert((application.fun, application.args.len()));
    }
    Ok(keys)
}

fn planned_literal(atom: BoolAtomKey, positive: bool) -> PlannedLiteral {
    PlannedLiteral { atom, positive }
}

fn build_ackermann_clause_plan(
    cnf: &CnfProblem,
    arena: &TermArena,
    estimate: AckermannEstimate,
) -> Result<Vec<PlannedClause>, Rejection> {
    let groups = ordered_application_groups(arena)?;
    let bool_functions = bool_function_keys(cnf, arena)?;
    let mut clauses = Vec::new();
    clauses
        .try_reserve_exact(estimate.clauses)
        .map_err(|_| Rejection::PlanningAllocationFailure)?;
    let mut literal_slots = 0usize;

    for (key, applications) in groups {
        let bool_result = bool_functions.contains(&key);
        for left_index in 0..applications.len() {
            let left_id = applications[left_index];
            let left = &arena.terms[left_id];
            for &right_id in &applications[(left_index + 1)..] {
                let right = &arena.terms[right_id];
                if left.sort != right.sort
                    || left.args.len() != right.args.len()
                    || left
                        .args
                        .iter()
                        .zip(&right.args)
                        .any(|(&left_arg, &right_arg)| {
                            arena.terms[left_arg].sort != arena.terms[right_arg].sort
                        })
                {
                    return Err(Rejection::UnsupportedSort);
                }
                let differing = left
                    .args
                    .iter()
                    .zip(&right.args)
                    .filter(|(left_arg, right_arg)| left_arg != right_arg)
                    .count();
                let clause_len = differing
                    .checked_add(if bool_result { 2 } else { 1 })
                    .ok_or(Rejection::AckermannArithmeticOverflow)?;
                let clause_count = if bool_result { 2 } else { 1 };
                for direction in 0..clause_count {
                    let mut clause = Vec::new();
                    clause
                        .try_reserve_exact(clause_len)
                        .map_err(|_| Rejection::PlanningAllocationFailure)?;
                    for (&left_arg, &right_arg) in left.args.iter().zip(&right.args) {
                        if left_arg != right_arg {
                            let (left_arg, right_arg) = normalized_pair(left_arg, right_arg);
                            clause
                                .push(planned_literal(BoolAtomKey::Eq(left_arg, right_arg), false));
                        }
                    }
                    if bool_result {
                        clause.push(planned_literal(
                            BoolAtomKey::BoolTerm(left_id),
                            direction != 0,
                        ));
                        clause.push(planned_literal(
                            BoolAtomKey::BoolTerm(right_id),
                            direction == 0,
                        ));
                    } else {
                        let (left_id, right_id) = normalized_pair(left_id, right_id);
                        clause.push(planned_literal(BoolAtomKey::Eq(left_id, right_id), true));
                    }
                    literal_slots = literal_slots
                        .checked_add(clause.len())
                        .ok_or(Rejection::AckermannArithmeticOverflow)?;
                    clauses.push(clause);
                }
            }
        }
    }
    if clauses.len() != estimate.clauses || literal_slots != estimate.literal_slots {
        return Err(Rejection::PlanningMismatch);
    }
    Ok(clauses)
}

fn empty_adjacency(term_count: usize) -> Result<Vec<HashSet<TermId>>, Rejection> {
    let mut adjacency = Vec::new();
    adjacency
        .try_reserve_exact(term_count)
        .map_err(|_| Rejection::PlanningAllocationFailure)?;
    adjacency.extend((0..term_count).map(|_| HashSet::default()));
    Ok(adjacency)
}

fn insert_graph_edge(
    adjacency: &mut [HashSet<TermId>],
    left: TermId,
    right: TermId,
) -> Result<bool, Rejection> {
    if left >= adjacency.len() || right >= adjacency.len() {
        return Err(Rejection::FillInvalidTerm);
    }
    if left == right {
        return Ok(false);
    }
    if adjacency[left].contains(&right) {
        return Ok(false);
    }
    adjacency[left]
        .try_reserve(1)
        .map_err(|_| Rejection::PlanningAllocationFailure)?;
    adjacency[right]
        .try_reserve(1)
        .map_err(|_| Rejection::PlanningAllocationFailure)?;
    adjacency[left].insert(right);
    adjacency[right].insert(left);
    Ok(true)
}

fn virtual_equality_graph(
    cnf: &CnfProblem,
    ackermann_clauses: &[PlannedClause],
    term_count: usize,
) -> Result<(Vec<HashSet<TermId>>, usize, Vec<BoolAtomKey>), Rejection> {
    let mut adjacency = empty_adjacency(term_count)?;
    let mut reflexive = HashSet::default();
    reflexive
        .try_reserve(cnf.var_atoms.len())
        .map_err(|_| Rejection::PlanningAllocationFailure)?;
    let mut atoms = HashSet::<BoolAtomKey>::default();
    atoms
        .try_reserve(cnf.atom_vars.len())
        .map_err(|_| Rejection::PlanningAllocationFailure)?;
    for atom in cnf.var_atoms.iter().flatten() {
        atoms.insert(atom.clone());
        if let BoolAtomKey::Eq(left, right) = atom {
            if left == right {
                reflexive.insert(*left);
            } else {
                insert_graph_edge(&mut adjacency, *left, *right)?;
            }
        }
    }

    let mut new_atoms = Vec::new();
    for clause in ackermann_clauses {
        for literal in clause {
            if atoms.insert(literal.atom.clone()) {
                new_atoms
                    .try_reserve(1)
                    .map_err(|_| Rejection::PlanningAllocationFailure)?;
                new_atoms.push(literal.atom.clone());
            }
            if let BoolAtomKey::Eq(left, right) = literal.atom {
                if left == right {
                    reflexive.insert(left);
                } else {
                    insert_graph_edge(&mut adjacency, left, right)?;
                }
            }
        }
    }
    Ok((adjacency, reflexive.len(), new_atoms))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SparseTransitivityFillFailure {
    ArithmeticOverflow,
    AllocationFailure,
    FillEdgeCap {
        at_least: usize,
        pair_examinations: usize,
    },
    PairExaminationCap {
        at_least: usize,
        fill_edges: usize,
    },
}

fn plan_sparse_transitivity_fill(
    adjacency: &mut [HashSet<TermId>],
    max_fill_edges: usize,
    max_pair_examinations: usize,
) -> Result<SparseTransitivityFillPlan, SparseTransitivityFillFailure> {
    let mut active = adjacency
        .iter()
        .map(|neighbors| !neighbors.is_empty())
        .collect::<Vec<_>>();
    let mut degree = adjacency.iter().map(HashSet::len).collect::<Vec<_>>();
    let mut queue = BinaryHeap::new();
    queue
        .try_reserve(active.iter().filter(|active| **active).count())
        .map_err(|_| SparseTransitivityFillFailure::AllocationFailure)?;
    for (vertex, &vertex_degree) in degree.iter().enumerate() {
        if active[vertex] {
            queue.push(Reverse((vertex_degree, vertex)));
        }
    }

    let mut fill_edges = Vec::new();
    fill_edges
        .try_reserve(max_fill_edges.min(adjacency.len()))
        .map_err(|_| SparseTransitivityFillFailure::AllocationFailure)?;
    let mut pair_examinations = 0usize;
    while let Some(Reverse((queued_degree, vertex))) = queue.pop() {
        if !active[vertex] || degree[vertex] != queued_degree {
            continue;
        }
        let mut neighbors = Vec::new();
        neighbors
            .try_reserve(degree[vertex])
            .map_err(|_| SparseTransitivityFillFailure::AllocationFailure)?;
        neighbors.extend(
            adjacency[vertex]
                .iter()
                .copied()
                .filter(|neighbor| active[*neighbor]),
        );
        neighbors.sort_unstable();
        for left_index in 0..neighbors.len() {
            let left = neighbors[left_index];
            for &right in &neighbors[(left_index + 1)..] {
                pair_examinations = pair_examinations
                    .checked_add(1)
                    .ok_or(SparseTransitivityFillFailure::ArithmeticOverflow)?;
                if pair_examinations > max_pair_examinations {
                    return Err(SparseTransitivityFillFailure::PairExaminationCap {
                        at_least: pair_examinations,
                        fill_edges: fill_edges.len(),
                    });
                }
                if adjacency[left].contains(&right) {
                    continue;
                }
                let next_fill_count = fill_edges
                    .len()
                    .checked_add(1)
                    .ok_or(SparseTransitivityFillFailure::ArithmeticOverflow)?;
                if next_fill_count > max_fill_edges {
                    return Err(SparseTransitivityFillFailure::FillEdgeCap {
                        at_least: next_fill_count,
                        pair_examinations,
                    });
                }
                adjacency[left]
                    .try_reserve(1)
                    .map_err(|_| SparseTransitivityFillFailure::AllocationFailure)?;
                adjacency[right]
                    .try_reserve(1)
                    .map_err(|_| SparseTransitivityFillFailure::AllocationFailure)?;
                adjacency[left].insert(right);
                adjacency[right].insert(left);
                degree[left] = degree[left]
                    .checked_add(1)
                    .ok_or(SparseTransitivityFillFailure::ArithmeticOverflow)?;
                degree[right] = degree[right]
                    .checked_add(1)
                    .ok_or(SparseTransitivityFillFailure::ArithmeticOverflow)?;
                queue.push(Reverse((degree[left], left)));
                queue.push(Reverse((degree[right], right)));
                fill_edges.push(normalized_pair(left, right));
            }
        }

        active[vertex] = false;
        for neighbor in neighbors {
            degree[neighbor] = degree[neighbor]
                .checked_sub(1)
                .ok_or(SparseTransitivityFillFailure::ArithmeticOverflow)?;
            queue.push(Reverse((degree[neighbor], neighbor)));
        }
    }

    fill_edges.sort_unstable();
    let before_dedup = fill_edges.len();
    fill_edges.dedup();
    if fill_edges.len() != before_dedup {
        return Err(SparseTransitivityFillFailure::ArithmeticOverflow);
    }
    Ok(SparseTransitivityFillPlan {
        edges: fill_edges,
        pair_examinations,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TransitivityCensus {
    clauses: usize,
    triangle_visits: usize,
    literal_slots: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransitivityCountFailure {
    ArithmeticOverflow,
    ClauseCap {
        at_least: usize,
        triangle_visits: usize,
    },
    TriangleVisitCap {
        at_least: usize,
        clauses: usize,
    },
}

fn bounded_transitivity_census(
    adjacency: &[HashSet<TermId>],
    reflexive_equalities: usize,
    max_clauses: usize,
    max_triangle_visits: usize,
) -> Result<TransitivityCensus, TransitivityCountFailure> {
    if reflexive_equalities > max_clauses {
        return Err(TransitivityCountFailure::ClauseCap {
            at_least: reflexive_equalities,
            triangle_visits: 0,
        });
    }
    let mut clauses = reflexive_equalities;
    let mut literal_slots = reflexive_equalities;
    let mut triangle_visits = 0usize;
    for left in 0..adjacency.len() {
        for &right in adjacency[left].iter().filter(|right| left < **right) {
            let incident = if adjacency[left].len() <= adjacency[right].len() {
                &adjacency[left]
            } else {
                &adjacency[right]
            };
            for &third in incident {
                if third <= right {
                    continue;
                }
                // A triangle visit is one eligible third-vertex probe, whether or not
                // that probe closes a triangle in the completed equality graph.
                triangle_visits = triangle_visits
                    .checked_add(1)
                    .ok_or(TransitivityCountFailure::ArithmeticOverflow)?;
                if triangle_visits > max_triangle_visits {
                    return Err(TransitivityCountFailure::TriangleVisitCap {
                        at_least: triangle_visits,
                        clauses,
                    });
                }
                if adjacency[left].contains(&third) && adjacency[right].contains(&third) {
                    let next = clauses
                        .checked_add(3)
                        .ok_or(TransitivityCountFailure::ArithmeticOverflow)?;
                    if next > max_clauses {
                        return Err(TransitivityCountFailure::ClauseCap {
                            at_least: next,
                            triangle_visits,
                        });
                    }
                    clauses = next;
                    literal_slots = literal_slots
                        .checked_add(9)
                        .ok_or(TransitivityCountFailure::ArithmeticOverflow)?;
                }
            }
        }
    }
    Ok(TransitivityCensus {
        clauses,
        triangle_visits,
        literal_slots,
    })
}

fn plan_completion(
    cnf: &CnfProblem,
    arena: &TermArena,
    limits: Limits,
    report: &mut ProjectionReport,
) -> Result<CompletionPlan, Rejection> {
    validate_preplan(cnf, arena, limits, report)?;

    let estimate = match full_ackermann_estimate(cnf, arena) {
        Ok(estimate) => estimate,
        Err(failure) => {
            report.ackermann_function_pairs = Count::unavailable();
            report.ackermann_predicate_pairs = Count::unavailable();
            report.candidate_pairs = Count::unavailable();
            report.ackermann_function_differing_argument_pairs = Count::unavailable();
            report.ackermann_predicate_differing_argument_pairs = Count::unavailable();
            report.ackermann_clauses = Count::unavailable();
            report.ackermann_literal_slots = Count::unavailable();
            return Err(ackermann_rejection(failure));
        }
    };
    report.ackermann_function_pairs = Count::exact(estimate.function_pairs);
    report.ackermann_predicate_pairs = Count::exact(estimate.predicate_pairs);
    report.candidate_pairs = Count::exact(estimate.candidate_pairs);
    report.ackermann_function_differing_argument_pairs =
        Count::exact(estimate.function_differing_argument_pairs);
    report.ackermann_predicate_differing_argument_pairs =
        Count::exact(estimate.predicate_differing_argument_pairs);
    report.ackermann_clauses = Count::exact(estimate.clauses);
    report.ackermann_literal_slots = Count::exact(estimate.literal_slots);
    if estimate.clauses > limits.max_ackermann_clauses {
        return Err(Rejection::AckermannClauseCap);
    }

    let ackermann_clauses = build_ackermann_clause_plan(cnf, arena, estimate)?;
    let (mut adjacency, reflexive_equalities, mut new_atoms) =
        virtual_equality_graph(cnf, &ackermann_clauses, arena.terms.len())?;
    let fill = match plan_sparse_transitivity_fill(
        &mut adjacency,
        limits.max_fill_edges,
        limits.max_fill_pair_examinations,
    ) {
        Ok(fill) => fill,
        Err(SparseTransitivityFillFailure::ArithmeticOverflow) => {
            return Err(Rejection::FillArithmeticOverflow);
        }
        Err(SparseTransitivityFillFailure::AllocationFailure) => {
            return Err(Rejection::PlanningAllocationFailure);
        }
        Err(SparseTransitivityFillFailure::FillEdgeCap {
            at_least,
            pair_examinations,
        }) => {
            report.fill_edges = Count::lower_bound(at_least);
            report.fill_pair_examinations = Count::lower_bound(pair_examinations);
            return Err(Rejection::FillEdgeCap);
        }
        Err(SparseTransitivityFillFailure::PairExaminationCap {
            at_least,
            fill_edges,
        }) => {
            report.fill_edges = Count::exact(fill_edges);
            report.fill_pair_examinations = Count::lower_bound(at_least);
            return Err(Rejection::FillPairExaminationCap);
        }
    };
    report.fill_edges = Count::exact(fill.edges.len());
    report.fill_pair_examinations = Count::exact(fill.pair_examinations);
    new_atoms
        .try_reserve(fill.edges.len())
        .map_err(|_| Rejection::PlanningAllocationFailure)?;
    new_atoms.extend(
        fill.edges
            .iter()
            .map(|&(left, right)| BoolAtomKey::Eq(left, right)),
    );

    let added_vars = new_atoms.len();
    let candidate_vars = cnf
        .var_count()
        .checked_add(added_vars)
        .ok_or(Rejection::MaterializationVariableCapacity)?;
    report.added_vars = Count::exact(added_vars);
    report.candidate_vars = Count::exact(candidate_vars);
    if candidate_vars > limits.max_final_variables || candidate_vars > i32::MAX as usize {
        return Err(Rejection::FinalVariableCap);
    }

    let transitivity = match bounded_transitivity_census(
        &adjacency,
        reflexive_equalities,
        limits.max_transitivity_clauses,
        limits.max_triangle_visits,
    ) {
        Ok(census) => census,
        Err(TransitivityCountFailure::ArithmeticOverflow) => {
            report.transitivity_clauses = Count::unavailable();
            report.triangle_visits = Count::unavailable();
            report.transitivity_literal_slots = Count::unavailable();
            return Err(Rejection::TransitivityArithmeticOverflow);
        }
        Err(TransitivityCountFailure::ClauseCap {
            at_least,
            triangle_visits,
        }) => {
            report.transitivity_clauses = Count::lower_bound(at_least);
            report.triangle_visits = Count::exact(triangle_visits);
            return Err(Rejection::TransitivityClauseCap);
        }
        Err(TransitivityCountFailure::TriangleVisitCap { at_least, clauses }) => {
            report.transitivity_clauses = Count::exact(clauses);
            report.triangle_visits = Count::lower_bound(at_least);
            return Err(Rejection::TriangleVisitCap);
        }
    };
    report.transitivity_clauses = Count::exact(transitivity.clauses);
    report.triangle_visits = Count::exact(transitivity.triangle_visits);
    report.transitivity_literal_slots = Count::exact(transitivity.literal_slots);

    let candidate_clauses = cnf
        .clauses
        .len()
        .checked_add(estimate.clauses)
        .ok_or(Rejection::CandidateClauseOverflow)?;
    let candidate_literal_slots = cnf
        .clauses
        .literals
        .len()
        .checked_add(estimate.literal_slots)
        .ok_or(Rejection::CandidateLiteralOverflow)?;
    let added_literal_slots = estimate
        .literal_slots
        .checked_add(transitivity.literal_slots)
        .ok_or(Rejection::TransitivityArithmeticOverflow)?;
    report.candidate_clauses = Count::exact(candidate_clauses);
    report.candidate_literal_slots = Count::exact(candidate_literal_slots);
    report.added_literal_slots = Count::exact(added_literal_slots);
    if added_literal_slots > limits.max_added_literal_slots {
        return Err(Rejection::AddedLiteralSlotCap);
    }
    if candidate_literal_slots > u32::MAX as usize {
        return Err(Rejection::MaterializationVariableCapacity);
    }

    Ok(CompletionPlan {
        ackermann_clauses,
        ackermann_clause_count: estimate.clauses,
        ackermann_literal_slots: estimate.literal_slots,
        fill_edge_count: fill.edges.len(),
        fill,
        new_atoms,
        term_count: arena.terms.len(),
        added_vars,
        candidate_vars,
        candidate_clauses,
        candidate_literal_slots,
        transitivity_clauses: transitivity.clauses,
        triangle_visits: transitivity.triangle_visits,
        transitivity_literal_slots: transitivity.literal_slots,
        added_literal_slots,
    })
}

fn try_clone_flat_clauses(source: &FlatClauses) -> Result<FlatClauses, Rejection> {
    let mut literals = Vec::new();
    literals
        .try_reserve_exact(source.literals.len())
        .map_err(|_| Rejection::MaterializationAllocationFailure)?;
    literals.extend_from_slice(&source.literals);
    let mut end_offsets = Vec::new();
    end_offsets
        .try_reserve_exact(source.end_offsets.len())
        .map_err(|_| Rejection::MaterializationAllocationFailure)?;
    end_offsets.extend_from_slice(&source.end_offsets);
    Ok(FlatClauses {
        literals,
        end_offsets,
    })
}

fn try_clone_cnf(source: &CnfProblem) -> Result<CnfProblem, Rejection> {
    let clauses = try_clone_flat_clauses(&source.clauses)?;
    let mut var_atoms = Vec::new();
    var_atoms
        .try_reserve_exact(source.var_atoms.len())
        .map_err(|_| Rejection::MaterializationAllocationFailure)?;
    var_atoms.extend(source.var_atoms.iter().cloned());
    let mut atom_vars = HashMap::default();
    atom_vars
        .try_reserve(source.atom_vars.len())
        .map_err(|_| Rejection::MaterializationAllocationFailure)?;
    atom_vars.extend(
        source
            .atom_vars
            .iter()
            .map(|(atom, variable)| (atom.clone(), *variable)),
    );
    Ok(CnfProblem {
        clauses,
        var_atoms,
        atom_vars,
        true_lit: source.true_lit,
        finite_equalities_complete: source.finite_equalities_complete,
        finite_predicate_congruence_complete: source.finite_predicate_congruence_complete,
    })
}

fn try_atom_lit(cnf: &mut CnfProblem, atom: BoolAtomKey) -> Result<i32, Rejection> {
    if let Some(&literal) = cnf.atom_vars.get(&atom) {
        return Ok(literal);
    }
    let variable = i32::try_from(cnf.var_atoms.len())
        .map_err(|_| Rejection::MaterializationVariableCapacity)?;
    cnf.var_atoms
        .try_reserve(1)
        .map_err(|_| Rejection::MaterializationAllocationFailure)?;
    cnf.atom_vars
        .try_reserve(1)
        .map_err(|_| Rejection::MaterializationAllocationFailure)?;
    cnf.var_atoms.push(Some(atom.clone()));
    cnf.atom_vars.insert(atom, variable);
    Ok(variable)
}

fn baseline_prefix_matches(baseline: &CnfProblem, candidate: &CnfProblem) -> bool {
    candidate
        .clauses
        .literals
        .starts_with(&baseline.clauses.literals)
        && candidate
            .clauses
            .end_offsets
            .starts_with(&baseline.clauses.end_offsets)
        && candidate.var_atoms.starts_with(&baseline.var_atoms)
        && baseline
            .atom_vars
            .iter()
            .all(|(atom, variable)| candidate.atom_vars.get(atom) == Some(variable))
        && candidate.true_lit == baseline.true_lit
        && candidate.finite_equalities_complete == baseline.finite_equalities_complete
        && candidate.finite_predicate_congruence_complete
            == baseline.finite_predicate_congruence_complete
}

fn materialized_equality_graph(
    cnf: &CnfProblem,
    term_count: usize,
) -> Result<(Vec<HashSet<TermId>>, usize), Rejection> {
    let mut adjacency =
        empty_adjacency(term_count).map_err(|_| Rejection::MaterializationAllocationFailure)?;
    let mut reflexive = HashSet::default();
    reflexive
        .try_reserve(cnf.atom_vars.len())
        .map_err(|_| Rejection::MaterializationAllocationFailure)?;
    for atom in cnf.var_atoms.iter().flatten() {
        let BoolAtomKey::Eq(left, right) = atom else {
            continue;
        };
        if *left >= term_count || *right >= term_count {
            return Err(Rejection::MaterializationMismatch);
        }
        if left == right {
            reflexive.insert(*left);
        } else {
            insert_graph_edge(&mut adjacency, *left, *right)
                .map_err(|_| Rejection::MaterializationAllocationFailure)?;
        }
    }
    Ok((adjacency, reflexive.len()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MaterializationFacts {
    ackermann_clauses: usize,
    ackermann_literal_slots: usize,
    fill_edges: usize,
    transitivity_clauses: usize,
    triangle_visits: usize,
    transitivity_literal_slots: usize,
    added_vars: usize,
    candidate_vars: usize,
    candidate_clauses: usize,
    candidate_literal_slots: usize,
    added_literal_slots: usize,
}

struct MaterializedCandidate {
    candidate: CnfProblem,
    facts: MaterializationFacts,
}

struct MaterializationFailure {
    reason: Rejection,
    facts: Option<MaterializationFacts>,
}

impl From<Rejection> for MaterializationFailure {
    fn from(reason: Rejection) -> Self {
        Self {
            reason,
            facts: None,
        }
    }
}

fn materialize_candidate(
    baseline: &CnfProblem,
    plan: &CompletionPlan,
) -> Result<MaterializedCandidate, MaterializationFailure> {
    let mut candidate = try_clone_cnf(baseline)?;
    for planned_clause in &plan.ackermann_clauses {
        let mut clause = Vec::new();
        clause
            .try_reserve_exact(planned_clause.len())
            .map_err(|_| Rejection::MaterializationAllocationFailure)?;
        for planned in planned_clause {
            let literal = try_atom_lit(&mut candidate, planned.atom.clone())?;
            clause.push(if planned.positive { literal } else { -literal });
        }
        candidate
            .clauses
            .try_push(clause)
            .map_err(|error| match error {
                super::FlatClauseStoreError::LiteralCapacityExceeded => {
                    Rejection::MaterializationArithmeticOverflow
                }
                super::FlatClauseStoreError::AllocationFailed => {
                    Rejection::MaterializationAllocationFailure
                }
            })?;
    }
    let ackermann_clauses = candidate
        .clauses
        .len()
        .checked_sub(baseline.clauses.len())
        .ok_or(Rejection::MaterializationArithmeticOverflow)?;
    let ackermann_literal_slots = candidate
        .clauses
        .literals
        .len()
        .checked_sub(baseline.clauses.literals.len())
        .ok_or(Rejection::MaterializationArithmeticOverflow)?;
    let variables_after_ackermann = candidate.var_count();
    for &(left, right) in &plan.fill.edges {
        try_atom_lit(&mut candidate, BoolAtomKey::Eq(left, right))?;
    }
    let fill_edges = candidate
        .var_count()
        .checked_sub(variables_after_ackermann)
        .ok_or(Rejection::MaterializationArithmeticOverflow)?;

    let mut expected_new_atoms = Vec::new();
    expected_new_atoms
        .try_reserve_exact(plan.new_atoms.len())
        .map_err(|_| Rejection::MaterializationAllocationFailure)?;
    expected_new_atoms.extend(plan.new_atoms.iter().cloned().map(Some));
    let new_atom_slice = &candidate.var_atoms[baseline.var_atoms.len()..];
    let (adjacency, reflexive_equalities) =
        materialized_equality_graph(&candidate, plan.term_count)?;
    let materialized_transitivity =
        bounded_transitivity_census(&adjacency, reflexive_equalities, usize::MAX, usize::MAX)
            .map_err(|_| Rejection::MaterializationMismatch)?;
    let added_literal_slots = ackermann_literal_slots
        .checked_add(materialized_transitivity.literal_slots)
        .ok_or(Rejection::MaterializationArithmeticOverflow)?;
    let facts = MaterializationFacts {
        ackermann_clauses,
        ackermann_literal_slots,
        fill_edges,
        transitivity_clauses: materialized_transitivity.clauses,
        triangle_visits: materialized_transitivity.triangle_visits,
        transitivity_literal_slots: materialized_transitivity.literal_slots,
        added_vars: candidate
            .var_count()
            .checked_sub(baseline.var_count())
            .ok_or(Rejection::MaterializationArithmeticOverflow)?,
        candidate_vars: candidate.var_count(),
        candidate_clauses: candidate.clauses.len(),
        candidate_literal_slots: candidate.clauses.literals.len(),
        added_literal_slots,
    };
    if !baseline_prefix_matches(baseline, &candidate)
        || new_atom_slice != expected_new_atoms.as_slice()
        || facts.ackermann_clauses != plan.ackermann_clause_count
        || facts.ackermann_literal_slots != plan.ackermann_literal_slots
        || facts.fill_edges != plan.fill_edge_count
        || facts.candidate_vars != plan.candidate_vars
        || facts.candidate_clauses != plan.candidate_clauses
        || facts.candidate_literal_slots != plan.candidate_literal_slots
        || facts.transitivity_clauses != plan.transitivity_clauses
        || facts.triangle_visits != plan.triangle_visits
        || facts.transitivity_literal_slots != plan.transitivity_literal_slots
        || facts.added_vars != plan.added_vars
        || facts.added_literal_slots != plan.added_literal_slots
    {
        return Err(MaterializationFailure {
            reason: Rejection::MaterializationMismatch,
            facts: Some(facts),
        });
    }
    Ok(MaterializedCandidate { candidate, facts })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ScopedLetMode, add_full_ackermann_axioms, atomize_bool_data_terms,
        equality_transitivity_clauses, parse_problem_with_scoped_let_mode,
    };

    fn eligible_facts(applications: usize) -> StructuralFacts {
        StructuralFacts {
            finite_added: 0,
            covered_finite_terms: 0,
            closed_table_functions: 0,
            all_different_clique_lower_bound: 48,
            disequality_graph_edges: checked_pair_count(48).unwrap(),
            equality_graph_vertices: 2_500,
            equality_graph_edges: 10_000,
            applications,
            backend: BackendRoute::Kissat,
        }
    }

    fn direct_cnf(problem: &crate::Problem) -> CnfProblem {
        let bool_problem = problem.bool_problem.as_ref().unwrap();
        let mut cnf = CnfProblem::new();
        atomize_bool_data_terms(&mut cnf, bool_problem);
        for assertion in &bool_problem.assertions {
            cnf.add_direct_assertion_with_negated_root(assertion, false);
        }
        cnf
    }

    fn parsed_problem_and_cnf(input: &str) -> (crate::Problem, CnfProblem) {
        let problem = parse_problem_with_scoped_let_mode(input, ScopedLetMode::Auto).unwrap();
        let cnf = direct_cnf(&problem);
        (problem, cnf)
    }

    fn mixed_ackermann_problem() -> (crate::Problem, CnfProblem) {
        parsed_problem_and_cnf(
            "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun a () U)
            (declare-fun b () U)
            (declare-fun c () U)
            (declare-fun f (U U) U)
            (declare-fun p (U U) Bool)
            (assert (= (f a b) (f a c)))
            (assert (distinct (f a c) (f b c)))
            (assert (or (p a b) (p a c) (p b c)))
            (check-sat)
            ",
        )
    }

    fn four_cycle() -> (TermArena, CnfProblem) {
        let mut arena = TermArena::default();
        for function in 0..4 {
            arena.intern(function, Vec::new());
        }
        let mut cnf = CnfProblem::new();
        for (left, right) in [(0, 1), (1, 2), (2, 3), (0, 3)] {
            cnf.atom_lit(BoolAtomKey::Eq(left, right));
        }
        (arena, cnf)
    }

    fn assert_reason(facts: StructuralFacts, expected: Rejection) {
        let cnf = CnfProblem::new();
        let arena = TermArena::default();
        let report = ProjectionReport::new(Mode::CliqueAuto, &cnf, &arena, facts);
        assert_eq!(selector_rejection(&report), Some(expected));
    }

    #[test]
    fn strict_mode_accepts_only_off_and_clique_auto() {
        assert_eq!(parse_mode(None), Ok(Mode::Off));
        assert_eq!(parse_mode(Some("off")), Ok(Mode::Off));
        assert_eq!(parse_mode(Some("clique-auto")), Ok(Mode::CliqueAuto));
        assert_eq!(
            parse_mode(Some("auto")),
            Err("EUF_VIPER_T9_ACKERMANN must be off or clique-auto".to_owned())
        );
        assert!(parse_mode(Some("ON")).is_err());
        assert!(parse_mode(Some("")).is_err());
    }

    #[test]
    fn selector_accepts_exact_positive_boundary() {
        let cnf = CnfProblem::new();
        let arena = TermArena::default();
        let report = ProjectionReport::new(Mode::CliqueAuto, &cnf, &arena, eligible_facts(0));
        assert_eq!(selector_rejection(&report), None);
        assert_eq!(report.disequality_clique_excess_edges, Count::exact(0));
    }

    #[test]
    fn selector_rejects_each_forbidden_runtime_fact() {
        let positive = eligible_facts(0);

        let mut facts = positive;
        facts.finite_added = 1;
        assert_reason(facts, Rejection::FiniteAddedNonzero);

        let mut facts = positive;
        facts.covered_finite_terms = 1;
        assert_reason(facts, Rejection::CoveredFiniteTermsNonzero);

        let mut facts = positive;
        facts.closed_table_functions = 1;
        assert_reason(facts, Rejection::ClosedTableFunctionsNonzero);

        let mut facts = positive;
        facts.all_different_clique_lower_bound = 47;
        facts.disequality_graph_edges = checked_pair_count(47).unwrap();
        assert_reason(facts, Rejection::AllDifferentCliqueBelowMinimum);

        let mut facts = positive;
        facts.disequality_graph_edges = checked_pair_count(48).unwrap() + 9;
        assert_reason(facts, Rejection::DisequalityCliqueExcessEdges);

        let mut facts = positive;
        facts.equality_graph_vertices = 2_499;
        assert_reason(facts, Rejection::EqualityGraphVerticesBelowMinimum);

        let mut facts = positive;
        facts.equality_graph_edges = 9_999;
        assert_reason(facts, Rejection::EqualityGraphEdgesBelowMinimum);

        let mut facts = positive;
        facts.applications = 257;
        assert_reason(facts, Rejection::ApplicationCountCap);

        let mut facts = positive;
        facts.backend = BackendRoute::Cadical;
        assert_reason(facts, Rejection::BackendNotKissat);
    }

    #[test]
    fn selector_checked_arithmetic_fails_closed() {
        assert_eq!(checked_pair_count(usize::MAX), None);
        let mut facts = eligible_facts(0);
        facts.all_different_clique_lower_bound = usize::MAX;
        facts.disequality_graph_edges = usize::MAX;
        let report = ProjectionReport::new(
            Mode::CliqueAuto,
            &CnfProblem::new(),
            &TermArena::default(),
            facts,
        );
        assert_eq!(report.disequality_clique_excess_edges, Count::unavailable());
        assert_eq!(
            selector_rejection(&report),
            Some(Rejection::DisequalityCliqueArithmeticOverflow)
        );
    }

    #[test]
    fn solve_precheck_has_frozen_cheap_rejection_order() {
        assert_eq!(
            solve_precheck(1, MAX_APPLICATIONS + 1, BackendRoute::Cadical),
            Err(SolvePrecheckRejection::FiniteAddedNonzero)
        );
        assert_eq!(
            solve_precheck(0, MAX_APPLICATIONS + 1, BackendRoute::Cadical),
            Err(SolvePrecheckRejection::ApplicationCountCap)
        );
        assert_eq!(
            solve_precheck(0, MAX_APPLICATIONS, BackendRoute::Cadical),
            Err(SolvePrecheckRejection::BackendNotKissat)
        );
        assert_eq!(
            solve_precheck(0, MAX_APPLICATIONS, BackendRoute::Kissat),
            Ok(())
        );
    }

    #[test]
    fn observed_sat_dispatch_forces_projection_rejection() {
        let cnf = CnfProblem::new();
        let arena = TermArena::default();
        let mut report = ProjectionReport::new(Mode::CliqueAuto, &cnf, &arena, eligible_facts(0));
        report.selected = true;
        report.reason = Rejection::Selected;
        report.record_observed_sat_calls(1);
        assert!(!report.selected);
        assert_eq!(report.reason, Rejection::SatDispatchObserved);
        assert_eq!(report.sat_calls, 1);
    }

    #[test]
    fn frozen_caps_match_the_preregistered_contract() {
        let limits = Limits::default();
        assert_eq!(limits.max_terms, 16_384);
        assert_eq!(limits.max_base_clauses, 131_072);
        assert_eq!(limits.max_base_literal_slots, 1_048_576);
        assert_eq!(limits.max_applications, 256);
        assert_eq!(limits.max_arity, 64);
        assert_eq!(limits.max_application_argument_slots, 16_384);
        assert_eq!(limits.max_ackermann_clauses, 5_000);
        assert_eq!(limits.max_fill_edges, 20_000);
        assert_eq!(limits.max_fill_pair_examinations, 8_388_608);
        assert_eq!(limits.max_transitivity_clauses, 2_000_000);
        assert_eq!(limits.max_triangle_visits, 2_000_000);
        assert_eq!(limits.max_final_variables, 50_000);
        assert_eq!(limits.max_added_literal_slots, 6_000_000);
    }

    #[test]
    fn full_ackermann_estimate_matches_mixed_materialization() {
        let (problem, mut cnf) = mixed_ackermann_problem();
        let estimate = full_ackermann_estimate(&cnf, &problem.arena).unwrap();
        assert_eq!(
            estimate,
            AckermannEstimate {
                function_pairs: 3,
                predicate_pairs: 3,
                candidate_pairs: 6,
                function_differing_argument_pairs: 4,
                predicate_differing_argument_pairs: 4,
                clauses: 9,
                literal_slots: 27,
            }
        );
        let clause_start = cnf.clauses.len();
        let literal_start = cnf.clauses.literals.len();
        assert_eq!(
            add_full_ackermann_axioms(&mut cnf, &problem.arena),
            estimate.clauses
        );
        assert_eq!(cnf.clauses.len() - clause_start, estimate.clauses);
        assert_eq!(
            cnf.clauses.literals.len() - literal_start,
            estimate.literal_slots
        );
    }

    #[test]
    fn exact_plan_and_materialization_match_without_touching_baseline() {
        let (problem, cnf) = mixed_ackermann_problem();
        let before = baseline_identity(&cnf);
        let attempt = attempt(
            Mode::CliqueAuto,
            &cnf,
            &problem.arena,
            eligible_facts(problem.arena.apps.len()),
        );
        assert!(attempt.report.selected);
        assert!(attempt.report.materialization_match);
        assert!(attempt.report.off_path_unchanged);
        assert_eq!(
            attempt.report.baseline_before_sha256,
            attempt.report.baseline_after_sha256
        );
        assert_ne!(attempt.report.materialized_candidate_sha256, ZERO_SHA256);
        assert_eq!(baseline_identity(&cnf), before);
        assert_eq!(attempt.report.ackermann_clauses, Count::exact(9));
        assert_eq!(attempt.report.ackermann_literal_slots, Count::exact(27));
        assert_eq!(
            attempt.report.materialized_ackermann_clauses,
            attempt.report.ackermann_clauses
        );
        assert_eq!(
            attempt.report.materialized_ackermann_literal_slots,
            attempt.report.ackermann_literal_slots
        );
        assert_eq!(
            attempt.report.materialized_fill_edges,
            attempt.report.fill_edges
        );
        assert_eq!(
            attempt.report.materialized_transitivity_clauses,
            attempt.report.transitivity_clauses
        );
        assert_eq!(
            attempt.report.materialized_transitivity_literal_slots,
            attempt.report.transitivity_literal_slots
        );
        assert_eq!(
            attempt.report.materialized_triangle_visits,
            attempt.report.triangle_visits
        );
        assert_eq!(
            attempt.report.materialized_added_vars,
            attempt.report.added_vars
        );
        assert_eq!(
            attempt.report.materialized_added_literal_slots.value,
            attempt.report.materialized_ackermann_literal_slots.value
                + attempt.report.materialized_transitivity_literal_slots.value
        );

        let candidate = attempt.candidate.unwrap();
        assert_eq!(candidate.var_count(), attempt.report.candidate_vars.value);
        assert_eq!(
            candidate.clauses.len(),
            attempt.report.candidate_clauses.value
        );
        assert_eq!(
            candidate.clauses.literals.len(),
            attempt.report.candidate_literal_slots.value
        );
        let transitivity = equality_transitivity_clauses(&candidate, problem.arena.terms.len());
        assert_eq!(
            transitivity.len(),
            attempt.report.transitivity_clauses.value
        );
        let transitivity_literals = transitivity.iter().map(Vec::len).sum::<usize>();
        assert_eq!(
            transitivity_literals,
            attempt.report.transitivity_literal_slots.value
        );
    }

    #[test]
    fn feature_off_is_an_exact_identity_transaction() {
        let (problem, cnf) = mixed_ackermann_problem();
        let clauses = cnf.clauses.clone();
        let var_atoms = cnf.var_atoms.clone();
        let atom_vars = cnf.atom_vars.clone();
        let attempt = attempt(
            Mode::Off,
            &cnf,
            &problem.arena,
            eligible_facts(problem.arena.apps.len()),
        );
        assert!(attempt.candidate.is_none());
        assert_eq!(attempt.report.reason, Rejection::ModeOff);
        assert_eq!(attempt.report.ackermann_clauses, Count::not_computed());
        assert!(attempt.report.off_path_unchanged);
        assert_eq!(cnf.clauses, clauses);
        assert_eq!(cnf.var_atoms, var_atoms);
        assert_eq!(cnf.atom_vars, atom_vars);
    }

    #[test]
    fn finite_added_rejection_is_pre_materialization_and_unchanged() {
        let (problem, cnf) = mixed_ackermann_problem();
        let mut facts = eligible_facts(problem.arena.apps.len());
        facts.finite_added = 1;
        let before = baseline_identity(&cnf);
        let attempt = attempt(Mode::CliqueAuto, &cnf, &problem.arena, facts);
        assert!(attempt.candidate.is_none());
        assert_eq!(attempt.report.reason, Rejection::FiniteAddedNonzero);
        assert_eq!(attempt.report.ackermann_clauses, Count::not_computed());
        assert!(attempt.report.off_path_unchanged);
        assert_eq!(baseline_identity(&cnf), before);
    }

    #[test]
    fn ackermann_cap_rejection_keeps_exact_counts_and_byte_identity() {
        let (problem, cnf) = mixed_ackermann_problem();
        let clauses = cnf.clauses.clone();
        let var_atoms = cnf.var_atoms.clone();
        let atom_vars = cnf.atom_vars.clone();
        let attempt = attempt_with_limits(
            Mode::CliqueAuto,
            &cnf,
            &problem.arena,
            eligible_facts(problem.arena.apps.len()),
            Limits {
                max_ackermann_clauses: 8,
                ..Limits::default()
            },
        );
        assert!(attempt.candidate.is_none());
        assert_eq!(attempt.report.reason, Rejection::AckermannClauseCap);
        assert_eq!(attempt.report.ackermann_clauses, Count::exact(9));
        assert_eq!(attempt.report.ackermann_literal_slots, Count::exact(27));
        assert!(attempt.report.off_path_unchanged);
        assert_eq!(cnf.clauses, clauses);
        assert_eq!(cnf.var_atoms, var_atoms);
        assert_eq!(cnf.atom_vars, atom_vars);
    }

    #[test]
    fn invalid_endpoints_and_sorts_reject_without_state_changes() {
        let mut arena = TermArena::default();
        arena.intern(0, Vec::new());
        let mut invalid_endpoint = CnfProblem::new();
        invalid_endpoint.atom_lit(BoolAtomKey::Eq(0, 1));
        let before = baseline_identity(&invalid_endpoint);
        let invalid_endpoint_attempt = attempt(
            Mode::CliqueAuto,
            &invalid_endpoint,
            &arena,
            eligible_facts(0),
        );
        assert_eq!(
            invalid_endpoint_attempt.report.reason,
            Rejection::InvalidEqualityEndpoint
        );
        assert!(invalid_endpoint_attempt.report.off_path_unchanged);
        assert_eq!(baseline_identity(&invalid_endpoint), before);

        let mut mixed_sorts = TermArena::default();
        mixed_sorts.intern_typed(0, Vec::new(), crate::SortId(1));
        mixed_sorts.intern_typed(1, Vec::new(), crate::SortId(2));
        let mut invalid_sort = CnfProblem::new();
        invalid_sort.atom_lit(BoolAtomKey::Eq(0, 1));
        let invalid_sort_attempt = attempt(
            Mode::CliqueAuto,
            &invalid_sort,
            &mixed_sorts,
            eligible_facts(0),
        );
        assert_eq!(
            invalid_sort_attempt.report.reason,
            Rejection::UnsupportedSort
        );
        assert!(invalid_sort_attempt.report.off_path_unchanged);
    }

    #[test]
    fn high_arity_and_argument_slot_caps_fail_before_ackermann_planning() {
        let mut arena = TermArena::default();
        let args = (0..=MAX_ARITY)
            .map(|function| arena.intern(function as SymId, Vec::new()))
            .collect::<Vec<_>>();
        arena.intern(10_000, args);
        let cnf = CnfProblem::new();
        let attempt = attempt(
            Mode::CliqueAuto,
            &cnf,
            &arena,
            eligible_facts(arena.apps.len()),
        );
        assert_eq!(attempt.report.reason, Rejection::ArityCap);
        assert_eq!(attempt.report.max_arity, Count::lower_bound(MAX_ARITY + 1));
        assert_eq!(attempt.report.ackermann_clauses, Count::not_computed());

        let mut limits = Limits::default();
        limits.max_arity = MAX_ARITY + 1;
        limits.max_application_argument_slots = MAX_ARITY;
        let attempt = attempt_with_limits(
            Mode::CliqueAuto,
            &cnf,
            &arena,
            eligible_facts(arena.apps.len()),
            limits,
        );
        assert_eq!(attempt.report.reason, Rejection::ApplicationArgumentSlotCap);
    }

    #[test]
    fn fill_plan_and_all_post_ackermann_caps_have_exact_boundaries() {
        let (arena, cnf) = four_cycle();
        let admitted = attempt(Mode::CliqueAuto, &cnf, &arena, eligible_facts(0));
        assert!(admitted.report.selected);
        assert_eq!(admitted.report.fill_edges, Count::exact(1));
        assert_eq!(admitted.report.transitivity_clauses, Count::exact(6));
        assert!(admitted.report.triangle_visits.value >= 2);

        let fill_rejected = attempt_with_limits(
            Mode::CliqueAuto,
            &cnf,
            &arena,
            eligible_facts(0),
            Limits {
                max_fill_edges: 0,
                ..Limits::default()
            },
        );
        assert_eq!(fill_rejected.report.reason, Rejection::FillEdgeCap);
        assert_eq!(fill_rejected.report.fill_edges, Count::lower_bound(1));

        let pair_rejected = attempt_with_limits(
            Mode::CliqueAuto,
            &cnf,
            &arena,
            eligible_facts(0),
            Limits {
                max_fill_pair_examinations: 0,
                ..Limits::default()
            },
        );
        assert_eq!(
            pair_rejected.report.reason,
            Rejection::FillPairExaminationCap
        );
        assert_eq!(
            pair_rejected.report.fill_pair_examinations,
            Count::lower_bound(1)
        );

        let variable_rejected = attempt_with_limits(
            Mode::CliqueAuto,
            &cnf,
            &arena,
            eligible_facts(0),
            Limits {
                max_final_variables: admitted.report.candidate_vars.value - 1,
                ..Limits::default()
            },
        );
        assert_eq!(variable_rejected.report.reason, Rejection::FinalVariableCap);
        assert_eq!(
            variable_rejected.report.candidate_vars,
            admitted.report.candidate_vars
        );

        let transitivity_rejected = attempt_with_limits(
            Mode::CliqueAuto,
            &cnf,
            &arena,
            eligible_facts(0),
            Limits {
                max_transitivity_clauses: 5,
                ..Limits::default()
            },
        );
        assert_eq!(
            transitivity_rejected.report.reason,
            Rejection::TransitivityClauseCap
        );
        assert_eq!(
            transitivity_rejected.report.transitivity_clauses,
            Count::lower_bound(6)
        );

        let visit_rejected = attempt_with_limits(
            Mode::CliqueAuto,
            &cnf,
            &arena,
            eligible_facts(0),
            Limits {
                max_triangle_visits: 0,
                ..Limits::default()
            },
        );
        assert_eq!(visit_rejected.report.reason, Rejection::TriangleVisitCap);
        assert_eq!(visit_rejected.report.triangle_visits, Count::lower_bound(1));

        let literal_rejected = attempt_with_limits(
            Mode::CliqueAuto,
            &cnf,
            &arena,
            eligible_facts(0),
            Limits {
                max_added_literal_slots: admitted.report.added_literal_slots.value - 1,
                ..Limits::default()
            },
        );
        assert_eq!(
            literal_rejected.report.reason,
            Rejection::AddedLiteralSlotCap
        );
        assert_eq!(
            literal_rejected.report.added_literal_slots,
            admitted.report.added_literal_slots
        );
    }

    #[test]
    fn exact_base_literal_cap_is_enforced_from_flat_storage() {
        let (arena, mut cnf) = four_cycle();
        let literals = (1..=cnf.var_count()).map(|var| var as i32).collect();
        cnf.add_clause(literals);
        let exact = cnf.clauses.literals.len();
        let admitted = attempt_with_limits(
            Mode::CliqueAuto,
            &cnf,
            &arena,
            eligible_facts(0),
            Limits {
                max_base_literal_slots: exact,
                ..Limits::default()
            },
        );
        assert!(admitted.report.selected);
        let rejected = attempt_with_limits(
            Mode::CliqueAuto,
            &cnf,
            &arena,
            eligible_facts(0),
            Limits {
                max_base_literal_slots: exact - 1,
                ..Limits::default()
            },
        );
        assert_eq!(rejected.report.reason, Rejection::BaseLiteralSlotCap);
        assert_eq!(rejected.report.baseline_literal_slots, exact);
        assert!(rejected.report.off_path_unchanged);
    }

    #[test]
    fn materialization_mismatch_discards_candidate_and_preserves_baseline() {
        let (problem, cnf) = mixed_ackermann_problem();
        let facts = eligible_facts(problem.arena.apps.len());
        let before = baseline_identity(&cnf);
        let mut report = ProjectionReport::new(Mode::CliqueAuto, &cnf, &problem.arena, facts);
        let plan = plan_completion(&cnf, &problem.arena, Limits::default(), &mut report).unwrap();
        let expected_facts = match materialize_candidate(&cnf, &plan) {
            Ok(materialized) => materialized.facts,
            Err(_) => panic!("untampered plan must materialize"),
        };

        for component in 0..11 {
            let mut tampered = plan.clone();
            match component {
                0 => tampered.ackermann_clause_count += 1,
                1 => tampered.ackermann_literal_slots += 1,
                2 => tampered.fill_edge_count += 1,
                3 => tampered.transitivity_clauses += 1,
                4 => tampered.transitivity_literal_slots += 1,
                5 => tampered.triangle_visits += 1,
                6 => tampered.added_vars += 1,
                7 => tampered.candidate_vars += 1,
                8 => tampered.candidate_clauses += 1,
                9 => tampered.candidate_literal_slots += 1,
                10 => tampered.added_literal_slots += 1,
                _ => unreachable!(),
            }
            let failure = match materialize_candidate(&cnf, &tampered) {
                Ok(_) => panic!("tampered materialization component {component} was accepted"),
                Err(failure) => failure,
            };
            assert_eq!(failure.reason, Rejection::MaterializationMismatch);
            assert_eq!(failure.facts, Some(expected_facts));
        }
        assert_eq!(baseline_identity(&cnf), before);
    }

    #[test]
    fn custom_sha256_matches_standard_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn finish_attempt_rehashes_and_detects_mutated_baseline_state() {
        let mut arena = TermArena::default();
        arena.intern(0, Vec::new());
        arena.intern(1, Vec::new());

        let mut atom_cnf = CnfProblem::new();
        atom_cnf.atom_lit(BoolAtomKey::Eq(0, 1));
        let atom_before = baseline_identity(&atom_cnf);
        let atom_report =
            ProjectionReport::new(Mode::CliqueAuto, &atom_cnf, &arena, eligible_facts(0));
        let atom_hash = atom_report.baseline_before_sha256.clone();
        atom_cnf.atom_lit(BoolAtomKey::Eq(0, 0));
        let atom_attempt = finish_attempt(&atom_cnf, atom_before, None, atom_report);
        assert_eq!(atom_attempt.report.reason, Rejection::BaselineStateChanged);
        assert!(!atom_attempt.report.off_path_unchanged);
        assert_ne!(atom_attempt.report.baseline_after_sha256, atom_hash);

        let mut clause_cnf = CnfProblem::new();
        let equality = clause_cnf.atom_lit(BoolAtomKey::Eq(0, 1));
        let clause_before = baseline_identity(&clause_cnf);
        let clause_report =
            ProjectionReport::new(Mode::CliqueAuto, &clause_cnf, &arena, eligible_facts(0));
        let clause_hash = clause_report.baseline_before_sha256.clone();
        clause_cnf.add_clause(vec![equality]);
        let clause_attempt = finish_attempt(&clause_cnf, clause_before, None, clause_report);
        assert_eq!(
            clause_attempt.report.reason,
            Rejection::BaselineStateChanged
        );
        assert!(!clause_attempt.report.off_path_unchanged);
        assert_ne!(clause_attempt.report.baseline_after_sha256, clause_hash);
    }

    #[test]
    fn projection_schema_is_deterministic_and_machine_readable() {
        let (problem, cnf) = mixed_ackermann_problem();
        let report = attempt(
            Mode::CliqueAuto,
            &cnf,
            &problem.arena,
            eligible_facts(problem.arena.apps.len()),
        )
        .report;
        let mut first = Vec::new();
        let mut second = Vec::new();
        report.write_to(&mut first).unwrap();
        report.write_to(&mut second).unwrap();
        assert_eq!(first, second);
        let rendered = String::from_utf8(first).unwrap();
        let fields = rendered
            .lines()
            .map(|line| {
                let (key, value) = line
                    .split_once(' ')
                    .unwrap_or_else(|| panic!("invalid projection line: {line}"));
                assert!(!key.is_empty());
                assert!(!value.is_empty());
                assert!(!value.contains(char::is_whitespace));
                (key, value)
            })
            .collect::<Vec<_>>();
        let keys = fields.iter().map(|(key, _)| *key).collect::<Vec<_>>();
        assert_eq!(
            keys,
            [
                "t9_projection_version",
                "mode",
                "selector_selected",
                "selected",
                "reason",
                "finite_added",
                "covered_finite_terms",
                "closed_table_functions",
                "all_different_clique_lb",
                "disequality_graph_edges",
                "disequality_clique_excess_edges",
                "equality_graph_vertices",
                "equality_graph_edges",
                "applications",
                "backend",
                "terms",
                "baseline_vars",
                "baseline_clauses",
                "baseline_literal_slots",
                "triangle_visits_definition",
                "baseline_before_sha256",
                "baseline_after_sha256",
                "materialized_candidate_sha256",
                "sat_calls",
                "planned_max_arity",
                "planned_max_arity_state",
                "planned_application_argument_slots",
                "planned_application_argument_slots_state",
                "planned_ackermann_function_pairs",
                "planned_ackermann_function_pairs_state",
                "planned_ackermann_predicate_pairs",
                "planned_ackermann_predicate_pairs_state",
                "planned_ackermann_candidate_pairs",
                "planned_ackermann_candidate_pairs_state",
                "planned_ackermann_function_differing_argument_pairs",
                "planned_ackermann_function_differing_argument_pairs_state",
                "planned_ackermann_predicate_differing_argument_pairs",
                "planned_ackermann_predicate_differing_argument_pairs_state",
                "planned_ackermann_clauses",
                "planned_ackermann_clauses_state",
                "planned_ackermann_literal_slots",
                "planned_ackermann_literal_slots_state",
                "planned_fill_edges",
                "planned_fill_edges_state",
                "planned_fill_pair_examinations",
                "planned_fill_pair_examinations_state",
                "planned_added_vars",
                "planned_added_vars_state",
                "planned_transitivity_clauses",
                "planned_transitivity_clauses_state",
                "planned_transitivity_literal_slots",
                "planned_transitivity_literal_slots_state",
                "planned_triangle_visits",
                "planned_triangle_visits_state",
                "planned_candidate_vars",
                "planned_candidate_vars_state",
                "planned_candidate_clauses",
                "planned_candidate_clauses_state",
                "planned_candidate_literal_slots",
                "planned_candidate_literal_slots_state",
                "planned_added_literal_slots",
                "planned_added_literal_slots_state",
                "materialized_ackermann_clauses",
                "materialized_ackermann_clauses_state",
                "materialized_ackermann_literal_slots",
                "materialized_ackermann_literal_slots_state",
                "materialized_fill_edges",
                "materialized_fill_edges_state",
                "materialized_transitivity_clauses",
                "materialized_transitivity_clauses_state",
                "materialized_transitivity_literal_slots",
                "materialized_transitivity_literal_slots_state",
                "materialized_triangle_visits",
                "materialized_triangle_visits_state",
                "materialized_added_vars",
                "materialized_added_vars_state",
                "materialized_candidate_vars",
                "materialized_candidate_vars_state",
                "materialized_candidate_clauses",
                "materialized_candidate_clauses_state",
                "materialized_candidate_literal_slots",
                "materialized_candidate_literal_slots_state",
                "materialized_added_literal_slots",
                "materialized_added_literal_slots_state",
            ]
        );
        let unique_keys = keys.iter().copied().collect::<HashSet<_>>();
        assert_eq!(unique_keys.len(), keys.len());
        assert_eq!(fields[0], ("t9_projection_version", "1"));
        assert!(fields.contains(&("mode", "clique-auto")));
        assert!(fields.contains(&("selector_selected", "1")));
        assert!(fields.contains(&("selected", "1")));
        assert!(fields.contains(&("sat_calls", "0")));
        assert!(fields.contains(&("triangle_visits_definition", "eligible_third_vertex_probes")));
    }

    #[test]
    fn rejected_projection_uses_numeric_counts_with_explicit_states() {
        let (problem, cnf) = mixed_ackermann_problem();
        let mut facts = eligible_facts(problem.arena.apps.len());
        facts.backend = BackendRoute::Varisat;
        let report = attempt(Mode::CliqueAuto, &cnf, &problem.arena, facts).report;
        let mut output = Vec::new();
        report.write_to(&mut output).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("selector_selected 0\n"));
        assert!(output.contains("selected 0\n"));
        assert!(output.contains("reason backend_not_kissat\n"));
        assert!(output.contains("planned_ackermann_clauses 0\n"));
        assert!(output.contains("planned_ackermann_clauses_state not_computed\n"));
        assert!(output.contains(&format!("materialized_candidate_sha256 {ZERO_SHA256}\n")));
        assert!(output.contains("sat_calls 0\n"));
        assert!(output.ends_with("materialized_added_literal_slots_state not_computed\n"));
    }

    #[test]
    fn project_t9_pins_direct_root_encoding_and_never_dispatches_sat() {
        let input = "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun a () U)
            (declare-fun b () U)
            (assert (or (= a b) (distinct a b)))
            (check-sat)
        ";
        let problem = parse_problem_with_scoped_let_mode(input, ScopedLetMode::Auto).unwrap();
        let baseline = direct_cnf(&problem);
        let first = crate::project_t9_problem(&problem).unwrap();
        let second = crate::project_t9_problem(&problem).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.baseline_vars, baseline.var_count());
        assert_eq!(first.baseline_clauses, baseline.clauses.len());
        assert_eq!(
            first.baseline_literal_slots,
            baseline.clauses.literals.len()
        );
        let mut rendered = Vec::new();
        first.write_to(&mut rendered).unwrap();
        let rendered = String::from_utf8(rendered).unwrap();
        assert!(rendered.contains("sat_calls 0\n"));
        assert_eq!(first.baseline_before_sha256, first.baseline_after_sha256);
        assert!(rendered.ends_with("materialized_added_literal_slots_state not_computed\n"));
    }

    #[test]
    fn project_t9_reports_actual_finite_axioms_before_selector_rejection() {
        let input = "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun a () U)
            (declare-fun b () U)
            (declare-fun c () U)
            (declare-fun f (U) U)
            (assert (distinct a b c))
            (assert (or (= (f a) a) (= (f a) b) (= (f a) c)))
            (assert (or (= (f b) a) (= (f b) b) (= (f b) c)))
            (assert (or (= (f c) a) (= (f c) b) (= (f c) c)))
            (check-sat)
        ";
        let problem = parse_problem_with_scoped_let_mode(input, ScopedLetMode::Auto).unwrap();
        let report = crate::project_t9_problem(&problem).unwrap();
        assert!(report.facts.finite_added > 0);
        assert!(report.facts.covered_finite_terms > 0);
        assert!(report.facts.closed_table_functions > 0);
        assert_eq!(report.reason, Rejection::FiniteAddedNonzero);
        assert!(!report.selected);
        assert!(!report.materialization_match);
        assert!(report.off_path_unchanged);
    }
}
