use super::{
    BOOL_SORT, BoolAtomKey, CnfProblem, FlatClauses, SymId, TermArena, TermId,
    finite_analysis::FiniteAnalysis, normalized_pair,
};
use std::collections::BTreeMap;
use std::env;
use std::io::Write;

pub(crate) const ENV: &str = "EUF_VIPER_T10_ACKERMANN";

const MAX_APPLICATIONS: usize = 256;
const MAX_CLOSED_CLAUSES: usize = 4_096;
const MAX_CLOSED_LITERAL_SLOTS: usize = 16_384;
const MAX_CLOSED_WIDTH: usize = 4;

const MIN_ALL_DIFFERENT_CLIQUE: usize = 48;
const MAX_DISEQUALITY_CLIQUE_EXCESS: usize = 8;
const MIN_EQUALITY_GRAPH_VERTICES: usize = 2_500;
const MIN_EQUALITY_GRAPH_EDGES: usize = 10_000;
const ZERO_SHA256: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    Off,
    ClosedAtomAuto,
}

impl Mode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::ClosedAtomAuto => "closed-atom-auto",
        }
    }
}

pub(crate) fn parse_mode(value: Option<&str>) -> Result<Mode, String> {
    match value {
        None | Some("off") => Ok(Mode::Off),
        Some("closed-atom-auto") => Ok(Mode::ClosedAtomAuto),
        Some(_) => Err(format!("{ENV} must be off or closed-atom-auto")),
    }
}

pub(crate) fn selected_mode() -> Result<Mode, String> {
    match env::var(ENV) {
        Ok(value) => parse_mode(Some(&value)),
        Err(env::VarError::NotPresent) => parse_mode(None),
        Err(env::VarError::NotUnicode(_)) => Err(format!("{ENV} must be off or closed-atom-auto")),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BackendRoute {
    Kissat,
    Cadical,
    CadicalRefine,
    Varisat,
    Fallback,
    Dpll,
}

impl BackendRoute {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Kissat => "kissat",
            Self::Cadical => "cadical",
            Self::CadicalRefine => "cadical-refine",
            Self::Varisat => "varisat",
            Self::Fallback => "fallback",
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
                "profile_t10_ackermann {{\"t10_projection_version\":1,\"mode\":\"closed-atom-auto\",\"selector_selected\":false,\"selected\":false,\"reason\":\"{}\",\"precheck\":true,\"sat_calls\":0}}",
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
    InvalidClauseLiteral,
    InvalidApplicationTerm,
    InvalidApplicationArgument,
    InvalidApplicationList,
    InvalidApplicationSort,
    InvalidAtomTable,
    PlanningArithmeticOverflow,
    PlanningAllocationFailure,
    TypedReplayMismatch,
    NoClosedAtomClauses,
    ClosedClauseCap,
    ClosedLiteralSlotCap,
    ClosedWidthCap,
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
            Self::InvalidClauseLiteral => "invalid_clause_literal",
            Self::InvalidApplicationTerm => "invalid_application_term",
            Self::InvalidApplicationArgument => "invalid_application_argument",
            Self::InvalidApplicationList => "invalid_application_list",
            Self::InvalidApplicationSort => "invalid_application_sort",
            Self::InvalidAtomTable => "invalid_atom_table",
            Self::PlanningArithmeticOverflow => "planning_arithmetic_overflow",
            Self::PlanningAllocationFailure => "planning_allocation_failure",
            Self::TypedReplayMismatch => "typed_replay_mismatch",
            Self::NoClosedAtomClauses => "no_closed_atom_clauses",
            Self::ClosedClauseCap => "closed_clause_cap",
            Self::ClosedLiteralSlotCap => "closed_literal_slot_cap",
            Self::ClosedWidthCap => "closed_width_cap",
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

    pub(crate) fn fallback_route(applications: usize) -> Self {
        Self {
            finite_added: 0,
            covered_finite_terms: 0,
            closed_table_functions: 0,
            all_different_clique_lower_bound: 0,
            disequality_graph_edges: 0,
            equality_graph_vertices: 0,
            equality_graph_edges: 0,
            applications,
            backend: BackendRoute::Fallback,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Limits {
    max_closed_clauses: usize,
    max_closed_literal_slots: usize,
    max_closed_width: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_closed_clauses: MAX_CLOSED_CLAUSES,
            max_closed_literal_slots: MAX_CLOSED_LITERAL_SLOTS,
            max_closed_width: MAX_CLOSED_WIDTH,
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
    disequality_clique_excess_edges: usize,
    disequality_clique_excess_edges_exact: bool,
    terms: usize,
    baseline_vars: usize,
    baseline_atoms: usize,
    baseline_clauses: usize,
    baseline_literal_slots: usize,
    full_clause_count: usize,
    full_literal_slots: usize,
    full_max_width: usize,
    closed_clause_count: usize,
    closed_literal_slots: usize,
    closed_max_width: usize,
    ackermann_replay_clauses: usize,
    ackermann_replay_failures: usize,
    added_vars: usize,
    new_atoms: usize,
    fill_edges: usize,
    transitivity_clauses: usize,
    materialized_clause_count: usize,
    materialized_literal_slots: usize,
    materialized_max_width: usize,
    candidate_vars: usize,
    candidate_atoms: usize,
    candidate_clauses: usize,
    candidate_literal_slots: usize,
    source_sha256: String,
    baseline_cnf_before_sha256: String,
    baseline_cnf_after_sha256: String,
    baseline_atom_map_before_sha256: String,
    baseline_atom_map_after_sha256: String,
    baseline_problem_before_sha256: String,
    baseline_problem_after_sha256: String,
    clause_plan_sha256: String,
    materialized_clause_sha256: String,
    materialized_candidate_sha256: String,
    materialization_equal: bool,
    off_path_unchanged: bool,
    sat_calls: usize,
}

impl ProjectionReport {
    fn new(mode: Mode, cnf: &CnfProblem, arena: &TermArena, facts: StructuralFacts) -> Self {
        let clique_excess = checked_pair_count(facts.all_different_clique_lower_bound)
            .and_then(|minimum| facts.disequality_graph_edges.checked_sub(minimum));
        let baseline_cnf_sha256 = canonical_cnf_sha256(cnf);
        let baseline_atom_map_sha256 = canonical_atom_map_sha256(cnf);
        let baseline_problem_sha256 = canonical_problem_sha256(cnf);
        Self {
            mode,
            selector_selected: false,
            selected: false,
            reason: Rejection::ModeOff,
            facts,
            disequality_clique_excess_edges: clique_excess.unwrap_or_default(),
            disequality_clique_excess_edges_exact: clique_excess.is_some(),
            terms: arena.terms.len(),
            baseline_vars: cnf.var_count(),
            baseline_atoms: cnf.atom_vars.len(),
            baseline_clauses: cnf.clauses.len(),
            baseline_literal_slots: cnf.clauses.literals.len(),
            full_clause_count: 0,
            full_literal_slots: 0,
            full_max_width: 0,
            closed_clause_count: 0,
            closed_literal_slots: 0,
            closed_max_width: 0,
            ackermann_replay_clauses: 0,
            ackermann_replay_failures: 0,
            added_vars: 0,
            new_atoms: 0,
            fill_edges: 0,
            transitivity_clauses: 0,
            materialized_clause_count: 0,
            materialized_literal_slots: 0,
            materialized_max_width: 0,
            candidate_vars: cnf.var_count(),
            candidate_atoms: cnf.atom_vars.len(),
            candidate_clauses: cnf.clauses.len(),
            candidate_literal_slots: cnf.clauses.literals.len(),
            source_sha256: ZERO_SHA256.to_owned(),
            baseline_cnf_before_sha256: baseline_cnf_sha256.clone(),
            baseline_cnf_after_sha256: baseline_cnf_sha256,
            baseline_atom_map_before_sha256: baseline_atom_map_sha256.clone(),
            baseline_atom_map_after_sha256: baseline_atom_map_sha256,
            baseline_problem_before_sha256: baseline_problem_sha256.clone(),
            baseline_problem_after_sha256: baseline_problem_sha256,
            clause_plan_sha256: ZERO_SHA256.to_owned(),
            materialized_clause_sha256: ZERO_SHA256.to_owned(),
            materialized_candidate_sha256: ZERO_SHA256.to_owned(),
            materialization_equal: false,
            off_path_unchanged: false,
            sat_calls: 0,
        }
    }

    pub(crate) fn selected(&self) -> bool {
        self.selected
    }

    pub(crate) fn record_source(&mut self, source: &[u8]) {
        self.source_sha256 = sha256_hex(source);
    }

    pub(crate) fn record_observed_sat_calls(&mut self, sat_calls: usize) {
        self.sat_calls = sat_calls;
        if sat_calls != 0 {
            self.selected = false;
            self.reason = Rejection::SatDispatchObserved;
        }
    }

    pub(crate) fn write_to(&self, output: &mut impl Write) -> std::io::Result<()> {
        write!(output, "{{\"t10_projection_version\":1")?;
        write!(output, ",\"mode\":\"{}\"", self.mode.as_str())?;
        write!(
            output,
            ",\"selector_selected\":{},\"selected\":{}",
            self.selector_selected, self.selected
        )?;
        write!(output, ",\"reason\":\"{}\"", self.reason.as_str())?;
        write!(
            output,
            ",\"finite_added\":{},\"covered_finite_terms\":{},\"closed_table_functions\":{}",
            self.facts.finite_added,
            self.facts.covered_finite_terms,
            self.facts.closed_table_functions
        )?;
        write!(
            output,
            ",\"all_different_clique_lb\":{},\"disequality_graph_edges\":{}",
            self.facts.all_different_clique_lower_bound, self.facts.disequality_graph_edges
        )?;
        write!(
            output,
            ",\"disequality_clique_excess_edges\":{},\"disequality_clique_excess_edges_exact\":{}",
            self.disequality_clique_excess_edges, self.disequality_clique_excess_edges_exact
        )?;
        write!(
            output,
            ",\"equality_graph_vertices\":{},\"equality_graph_edges\":{}",
            self.facts.equality_graph_vertices, self.facts.equality_graph_edges
        )?;
        write!(
            output,
            ",\"applications\":{},\"backend\":\"{}\",\"terms\":{}",
            self.facts.applications,
            self.facts.backend.as_str(),
            self.terms
        )?;
        write!(
            output,
            ",\"baseline_vars\":{},\"baseline_atoms\":{},\"baseline_clauses\":{},\"baseline_literal_slots\":{}",
            self.baseline_vars,
            self.baseline_atoms,
            self.baseline_clauses,
            self.baseline_literal_slots
        )?;
        write!(
            output,
            ",\"full_clause_count\":{},\"full_literal_slots\":{},\"full_max_width\":{}",
            self.full_clause_count, self.full_literal_slots, self.full_max_width
        )?;
        write!(
            output,
            ",\"closed_clause_count\":{},\"closed_literal_slots\":{},\"closed_max_width\":{}",
            self.closed_clause_count, self.closed_literal_slots, self.closed_max_width
        )?;
        write!(
            output,
            ",\"ackermann_replay_clauses\":{},\"ackermann_replay_failures\":{}",
            self.ackermann_replay_clauses, self.ackermann_replay_failures
        )?;
        write!(
            output,
            ",\"added_vars\":{},\"new_atoms\":{},\"fill_edges\":{},\"transitivity_clauses\":{}",
            self.added_vars, self.new_atoms, self.fill_edges, self.transitivity_clauses
        )?;
        write!(
            output,
            ",\"materialized_clause_count\":{},\"materialized_literal_slots\":{},\"materialized_max_width\":{}",
            self.materialized_clause_count,
            self.materialized_literal_slots,
            self.materialized_max_width
        )?;
        write!(
            output,
            ",\"candidate_vars\":{},\"candidate_atoms\":{},\"candidate_clauses\":{},\"candidate_literal_slots\":{}",
            self.candidate_vars,
            self.candidate_atoms,
            self.candidate_clauses,
            self.candidate_literal_slots
        )?;
        write!(output, ",\"source_sha256\":\"{}\"", self.source_sha256)?;
        write!(
            output,
            ",\"baseline_cnf_before_sha256\":\"{}\",\"baseline_cnf_after_sha256\":\"{}\"",
            self.baseline_cnf_before_sha256, self.baseline_cnf_after_sha256
        )?;
        write!(
            output,
            ",\"baseline_atom_map_before_sha256\":\"{}\",\"baseline_atom_map_after_sha256\":\"{}\"",
            self.baseline_atom_map_before_sha256, self.baseline_atom_map_after_sha256
        )?;
        write!(
            output,
            ",\"baseline_problem_before_sha256\":\"{}\",\"baseline_problem_after_sha256\":\"{}\"",
            self.baseline_problem_before_sha256, self.baseline_problem_after_sha256
        )?;
        write!(
            output,
            ",\"clause_plan_sha256\":\"{}\",\"materialized_clause_sha256\":\"{}\"",
            self.clause_plan_sha256, self.materialized_clause_sha256
        )?;
        write!(
            output,
            ",\"materialized_candidate_sha256\":\"{}\"",
            self.materialized_candidate_sha256
        )?;
        writeln!(
            output,
            ",\"materialization_equal\":{},\"off_path_unchanged\":{},\"sat_calls\":{}}}",
            self.materialization_equal, self.off_path_unchanged, self.sat_calls
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
        if rendered.last() == Some(&b'\n') {
            rendered.pop();
        }
        if let Ok(rendered) = String::from_utf8(rendered) {
            eprintln!("profile_t10_ackermann {rendered}");
        }
    }
}

#[derive(Debug)]
pub(crate) struct Attempt {
    pub(crate) clauses: Option<Vec<Vec<i32>>>,
    pub(crate) report: ProjectionReport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BaselineIdentity {
    clauses: usize,
    literals: usize,
    variables: usize,
    atoms: usize,
}

fn baseline_identity(cnf: &CnfProblem) -> BaselineIdentity {
    BaselineIdentity {
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
    if !report.disequality_clique_excess_edges_exact {
        return Some(Rejection::DisequalityCliqueArithmeticOverflow);
    }
    if report.disequality_clique_excess_edges > MAX_DISEQUALITY_CLIQUE_EXCESS {
        return Some(Rejection::DisequalityCliqueExcessEdges);
    }
    if report.facts.equality_graph_vertices < MIN_EQUALITY_GRAPH_VERTICES {
        return Some(Rejection::EqualityGraphVerticesBelowMinimum);
    }
    if report.facts.equality_graph_edges < MIN_EQUALITY_GRAPH_EDGES {
        return Some(Rejection::EqualityGraphEdgesBelowMinimum);
    }
    None
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

fn validate_baseline(cnf: &CnfProblem) -> Result<(), Rejection> {
    for &literal in &cnf.clauses.literals {
        let variable = literal.unsigned_abs() as usize;
        if literal == 0 || variable == 0 || variable > cnf.var_count() {
            return Err(Rejection::InvalidClauseLiteral);
        }
    }
    if cnf.var_atoms.first() != Some(&None) {
        return Err(Rejection::InvalidAtomTable);
    }
    for (variable, atom) in cnf.var_atoms.iter().enumerate().skip(1) {
        if let Some(atom) = atom {
            let normalized = normalized_atom(atom.clone());
            if normalized != *atom || cnf.atom_vars.get(atom) != Some(&(variable as i32)) {
                return Err(Rejection::InvalidAtomTable);
            }
        }
    }
    for (atom, &variable) in &cnf.atom_vars {
        let index = usize::try_from(variable).map_err(|_| Rejection::InvalidAtomTable)?;
        if variable <= 0
            || normalized_atom(atom.clone()) != *atom
            || cnf.var_atoms.get(index).and_then(Option::as_ref) != Some(atom)
        {
            return Err(Rejection::InvalidAtomTable);
        }
    }
    Ok(())
}

fn normalized_atom(atom: BoolAtomKey) -> BoolAtomKey {
    match atom {
        BoolAtomKey::Eq(left, right) => {
            let (left, right) = normalized_pair(left, right);
            BoolAtomKey::Eq(left, right)
        }
        atom => atom,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum SymbolicAtom {
    Equality(TermId, TermId),
    BoolTerm(TermId),
}

impl SymbolicAtom {
    fn equality(left: TermId, right: TermId) -> Self {
        let (left, right) = normalized_pair(left, right);
        Self::Equality(left, right)
    }

    fn as_bool_atom(&self) -> BoolAtomKey {
        match *self {
            Self::Equality(left, right) => BoolAtomKey::Eq(left, right),
            Self::BoolTerm(term) => BoolAtomKey::BoolTerm(term),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SymbolicLiteral {
    atom: SymbolicAtom,
    positive: bool,
}

impl SymbolicLiteral {
    fn negative_equality(left: TermId, right: TermId) -> Self {
        Self {
            atom: SymbolicAtom::equality(left, right),
            positive: false,
        }
    }

    fn positive_equality(left: TermId, right: TermId) -> Self {
        Self {
            atom: SymbolicAtom::equality(left, right),
            positive: true,
        }
    }

    fn bool_term(term: TermId, positive: bool) -> Self {
        Self {
            atom: SymbolicAtom::BoolTerm(term),
            positive,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum AckermannKind {
    Function,
    BoolForward,
    BoolBackward,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct AckermannProvenance {
    left: TermId,
    right: TermId,
    kind: AckermannKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SymbolicClause {
    literals: Vec<SymbolicLiteral>,
    provenance: AckermannProvenance,
}

fn canonicalize_symbolic_clause(
    mut literals: Vec<SymbolicLiteral>,
) -> Option<Vec<SymbolicLiteral>> {
    literals.sort_unstable();
    literals.dedup();
    if literals
        .windows(2)
        .any(|pair| pair[0].atom == pair[1].atom && pair[0].positive != pair[1].positive)
    {
        return None;
    }
    Some(literals)
}

fn build_symbolic_clause(
    arena: &TermArena,
    provenance: AckermannProvenance,
) -> Option<Vec<SymbolicLiteral>> {
    let left = arena.terms.get(provenance.left)?;
    let right = arena.terms.get(provenance.right)?;
    if provenance.left == provenance.right
        || left.fun != right.fun
        || left.args.len() != right.args.len()
        || left.sort != right.sort
    {
        return None;
    }
    let mut literals = Vec::new();
    literals
        .try_reserve(left.args.len().saturating_add(2))
        .ok()?;
    for (&left_arg, &right_arg) in left.args.iter().zip(&right.args) {
        let left_sort = arena.terms.get(left_arg)?.sort;
        let right_sort = arena.terms.get(right_arg)?.sort;
        if left_sort != right_sort {
            return None;
        }
        if left_arg != right_arg {
            literals.push(SymbolicLiteral::negative_equality(left_arg, right_arg));
        }
    }
    match provenance.kind {
        AckermannKind::Function if left.sort != BOOL_SORT => {
            literals.push(SymbolicLiteral::positive_equality(
                provenance.left,
                provenance.right,
            ));
        }
        AckermannKind::BoolForward if left.sort == BOOL_SORT => {
            literals.push(SymbolicLiteral::bool_term(provenance.left, false));
            literals.push(SymbolicLiteral::bool_term(provenance.right, true));
        }
        AckermannKind::BoolBackward if left.sort == BOOL_SORT => {
            literals.push(SymbolicLiteral::bool_term(provenance.left, true));
            literals.push(SymbolicLiteral::bool_term(provenance.right, false));
        }
        _ => return None,
    }
    canonicalize_symbolic_clause(literals)
}

fn enumerate_full_ackermann(arena: &TermArena) -> Result<Vec<SymbolicClause>, Rejection> {
    let mut groups = BTreeMap::<(SymId, usize), Vec<TermId>>::new();
    for &term_id in &arena.apps {
        let term = arena
            .terms
            .get(term_id)
            .ok_or(Rejection::InvalidApplicationTerm)?;
        if term.args.is_empty() {
            return Err(Rejection::InvalidApplicationList);
        }
        if term.args.iter().any(|&arg| arg >= arena.terms.len()) {
            return Err(Rejection::InvalidApplicationArgument);
        }
        groups
            .entry((term.fun, term.args.len()))
            .or_default()
            .push(term_id);
    }

    let mut clause_capacity = 0usize;
    for applications in groups.values_mut() {
        applications.sort_unstable();
        let before = applications.len();
        applications.dedup();
        if applications.len() != before {
            return Err(Rejection::InvalidApplicationList);
        }
        let pairs =
            checked_pair_count(applications.len()).ok_or(Rejection::PlanningArithmeticOverflow)?;
        let bool_result = applications
            .first()
            .and_then(|&term| arena.terms.get(term))
            .is_some_and(|term| term.sort == BOOL_SORT);
        let clauses = if bool_result {
            pairs
                .checked_mul(2)
                .ok_or(Rejection::PlanningArithmeticOverflow)?
        } else {
            pairs
        };
        clause_capacity = clause_capacity
            .checked_add(clauses)
            .ok_or(Rejection::PlanningArithmeticOverflow)?;
    }

    let mut clauses = Vec::new();
    clauses
        .try_reserve(clause_capacity)
        .map_err(|_| Rejection::PlanningAllocationFailure)?;
    for applications in groups.values() {
        for left_index in 0..applications.len() {
            let left_id = applications[left_index];
            let left = &arena.terms[left_id];
            for &right_id in &applications[(left_index + 1)..] {
                let right = &arena.terms[right_id];
                if left.sort != right.sort
                    || left
                        .args
                        .iter()
                        .zip(&right.args)
                        .any(|(&left_arg, &right_arg)| {
                            arena.terms[left_arg].sort != arena.terms[right_arg].sort
                        })
                {
                    return Err(Rejection::InvalidApplicationSort);
                }
                let kinds: &[AckermannKind] = if left.sort == BOOL_SORT {
                    &[AckermannKind::BoolForward, AckermannKind::BoolBackward]
                } else {
                    &[AckermannKind::Function]
                };
                for &kind in kinds {
                    let provenance = AckermannProvenance {
                        left: left_id,
                        right: right_id,
                        kind,
                    };
                    let literals = build_symbolic_clause(arena, provenance)
                        .ok_or(Rejection::TypedReplayMismatch)?;
                    clauses.push(SymbolicClause {
                        literals,
                        provenance,
                    });
                }
            }
        }
    }
    clauses.sort_unstable_by(|left, right| {
        left.literals
            .cmp(&right.literals)
            .then_with(|| left.provenance.cmp(&right.provenance))
    });
    clauses.dedup_by(|left, right| left.literals == right.literals);
    Ok(clauses)
}

fn lookup_existing_atom(cnf: &CnfProblem, atom: &SymbolicAtom) -> Result<Option<i32>, Rejection> {
    let key = atom.as_bool_atom();
    let Some(&variable) = cnf.atom_vars.get(&key) else {
        return Ok(None);
    };
    let index = usize::try_from(variable).map_err(|_| Rejection::InvalidAtomTable)?;
    if variable <= 0 || cnf.var_atoms.get(index).and_then(Option::as_ref) != Some(&key) {
        return Err(Rejection::InvalidAtomTable);
    }
    Ok(Some(variable))
}

fn canonicalize_integer_clause(mut clause: Vec<i32>) -> Option<Vec<i32>> {
    clause.sort_unstable();
    clause.dedup();
    if clause
        .iter()
        .any(|literal| clause.binary_search(&-*literal).is_ok())
    {
        return None;
    }
    Some(clause)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RetainedClause {
    literals: Vec<i32>,
    provenance: AckermannProvenance,
}

fn retain_closed_clauses(
    cnf: &CnfProblem,
    full: &[SymbolicClause],
) -> Result<Vec<RetainedClause>, Rejection> {
    let mut closed = Vec::new();
    closed
        .try_reserve(full.len())
        .map_err(|_| Rejection::PlanningAllocationFailure)?;
    for symbolic in full {
        let mut clause = Vec::new();
        clause
            .try_reserve(symbolic.literals.len())
            .map_err(|_| Rejection::PlanningAllocationFailure)?;
        let mut complete = true;
        for literal in &symbolic.literals {
            let Some(variable) = lookup_existing_atom(cnf, &literal.atom)? else {
                complete = false;
                break;
            };
            clause.push(if literal.positive {
                variable
            } else {
                -variable
            });
        }
        if complete && let Some(literals) = canonicalize_integer_clause(clause) {
            closed.push(RetainedClause {
                literals,
                provenance: symbolic.provenance,
            });
        }
    }
    closed.sort_unstable_by(|left, right| {
        left.literals
            .cmp(&right.literals)
            .then_with(|| left.provenance.cmp(&right.provenance))
    });
    closed.dedup_by(|left, right| left.literals == right.literals);
    Ok(closed)
}

fn verifier_existing_atom_variable(
    cnf: &CnfProblem,
    key: &BoolAtomKey,
) -> Result<Option<i32>, Rejection> {
    let Some(&variable) = cnf.atom_vars.get(key) else {
        return Ok(None);
    };
    let index = usize::try_from(variable).map_err(|_| Rejection::InvalidAtomTable)?;
    if variable <= 0 || cnf.var_atoms.get(index).and_then(Option::as_ref) != Some(key) {
        return Err(Rejection::InvalidAtomTable);
    }
    Ok(Some(variable))
}

fn verifier_literal(
    cnf: &CnfProblem,
    key: BoolAtomKey,
    positive: bool,
) -> Result<Option<i32>, Rejection> {
    Ok(verifier_existing_atom_variable(cnf, &key)?
        .map(|variable| if positive { variable } else { -variable }))
}

fn verify_retained_ackermann_clause(
    cnf: &CnfProblem,
    arena: &TermArena,
    retained: &RetainedClause,
) -> Result<bool, Rejection> {
    let provenance = retained.provenance;
    let Some(left) = arena.terms.get(provenance.left) else {
        return Ok(false);
    };
    let Some(right) = arena.terms.get(provenance.right) else {
        return Ok(false);
    };
    if provenance.left == provenance.right
        || left.args.is_empty()
        || right.args.is_empty()
        || left.fun != right.fun
        || left.args.len() != right.args.len()
        || left.sort != right.sort
        || !arena.apps.contains(&provenance.left)
        || !arena.apps.contains(&provenance.right)
    {
        return Ok(false);
    }

    let Some(capacity) = left.args.len().checked_add(2) else {
        return Err(Rejection::PlanningArithmeticOverflow);
    };
    let mut expected = Vec::new();
    expected
        .try_reserve(capacity)
        .map_err(|_| Rejection::PlanningAllocationFailure)?;
    for (&left_arg, &right_arg) in left.args.iter().zip(&right.args) {
        let Some(left_arg_term) = arena.terms.get(left_arg) else {
            return Ok(false);
        };
        let Some(right_arg_term) = arena.terms.get(right_arg) else {
            return Ok(false);
        };
        if left_arg_term.sort != right_arg_term.sort {
            return Ok(false);
        }
        if left_arg != right_arg {
            let (left_arg, right_arg) = normalized_pair(left_arg, right_arg);
            let Some(literal) = verifier_literal(cnf, BoolAtomKey::Eq(left_arg, right_arg), false)?
            else {
                return Ok(false);
            };
            expected.push(literal);
        }
    }

    match provenance.kind {
        AckermannKind::Function if left.sort != BOOL_SORT => {
            let (left, right) = normalized_pair(provenance.left, provenance.right);
            let Some(literal) = verifier_literal(cnf, BoolAtomKey::Eq(left, right), true)? else {
                return Ok(false);
            };
            expected.push(literal);
        }
        AckermannKind::BoolForward if left.sort == BOOL_SORT => {
            let Some(left_literal) =
                verifier_literal(cnf, BoolAtomKey::BoolTerm(provenance.left), false)?
            else {
                return Ok(false);
            };
            let Some(right_literal) =
                verifier_literal(cnf, BoolAtomKey::BoolTerm(provenance.right), true)?
            else {
                return Ok(false);
            };
            expected.push(left_literal);
            expected.push(right_literal);
        }
        AckermannKind::BoolBackward if left.sort == BOOL_SORT => {
            let Some(left_literal) =
                verifier_literal(cnf, BoolAtomKey::BoolTerm(provenance.left), true)?
            else {
                return Ok(false);
            };
            let Some(right_literal) =
                verifier_literal(cnf, BoolAtomKey::BoolTerm(provenance.right), false)?
            else {
                return Ok(false);
            };
            expected.push(left_literal);
            expected.push(right_literal);
        }
        _ => return Ok(false),
    }

    expected.sort_unstable();
    expected.dedup();
    if expected
        .iter()
        .any(|literal| expected.binary_search(&-*literal).is_ok())
    {
        return Ok(false);
    }
    Ok(expected == retained.literals)
}

fn replay_retained_ackermann_clauses(
    cnf: &CnfProblem,
    arena: &TermArena,
    retained: &[RetainedClause],
) -> Result<(usize, usize), Rejection> {
    let mut failures = 0usize;
    for clause in retained {
        if !verify_retained_ackermann_clause(cnf, arena, clause)? {
            failures = failures
                .checked_add(1)
                .ok_or(Rejection::PlanningArithmeticOverflow)?;
        }
    }
    Ok((retained.len(), failures))
}

fn checked_literal_slots_symbolic(clauses: &[SymbolicClause]) -> Option<usize> {
    clauses.iter().try_fold(0usize, |total, clause| {
        total.checked_add(clause.literals.len())
    })
}

fn checked_literal_slots(clauses: &[RetainedClause]) -> Option<usize> {
    clauses.iter().try_fold(0usize, |total, clause| {
        total.checked_add(clause.literals.len())
    })
}

fn materialize_clauses(
    clauses: &[RetainedClause],
    literal_slots: usize,
) -> Result<FlatClauses, Rejection> {
    let mut materialized = FlatClauses::new();
    materialized
        .literals
        .try_reserve(literal_slots)
        .map_err(|_| Rejection::MaterializationAllocationFailure)?;
    materialized
        .end_offsets
        .try_reserve(clauses.len())
        .map_err(|_| Rejection::MaterializationAllocationFailure)?;
    for retained in clauses {
        let clause = &retained.literals;
        let end = materialized
            .literals
            .len()
            .checked_add(clause.len())
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(Rejection::MaterializationArithmeticOverflow)?;
        materialized.literals.extend_from_slice(clause);
        materialized.end_offsets.push(end);
    }
    Ok(materialized)
}

fn materialized_matches_plan(materialized: &FlatClauses, clauses: &[RetainedClause]) -> bool {
    materialized.len() == clauses.len()
        && materialized
            .iter()
            .zip(clauses)
            .all(|(materialized, planned)| materialized == planned.literals)
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

    if facts.applications != arena.apps.len() {
        report.reason = Rejection::RuntimeFactMismatch;
        return finish_attempt(cnf, before, None, report);
    }
    if let Err(rejection) = validate_baseline(cnf) {
        report.reason = rejection;
        return finish_attempt(cnf, before, None, report);
    }

    let full = match enumerate_full_ackermann(arena) {
        Ok(full) => full,
        Err(rejection) => {
            report.reason = rejection;
            return finish_attempt(cnf, before, None, report);
        }
    };
    let Some(full_literal_slots) = checked_literal_slots_symbolic(&full) else {
        report.reason = Rejection::PlanningArithmeticOverflow;
        return finish_attempt(cnf, before, None, report);
    };
    report.full_clause_count = full.len();
    report.full_literal_slots = full_literal_slots;
    report.full_max_width = full
        .iter()
        .map(|clause| clause.literals.len())
        .max()
        .unwrap_or_default();

    let closed = match retain_closed_clauses(cnf, &full) {
        Ok(clauses) => clauses,
        Err(rejection) => {
            report.reason = rejection;
            return finish_attempt(cnf, before, None, report);
        }
    };
    let Some(closed_literal_slots) = checked_literal_slots(&closed) else {
        report.reason = Rejection::PlanningArithmeticOverflow;
        return finish_attempt(cnf, before, None, report);
    };
    report.closed_clause_count = closed.len();
    report.closed_literal_slots = closed_literal_slots;
    report.closed_max_width = closed
        .iter()
        .map(|clause| clause.literals.len())
        .max()
        .unwrap_or_default();

    let (replay_clauses, replay_failures) =
        match replay_retained_ackermann_clauses(cnf, arena, &closed) {
            Ok(counts) => counts,
            Err(rejection) => {
                report.reason = rejection;
                return finish_attempt(cnf, before, None, report);
            }
        };
    report.ackermann_replay_clauses = replay_clauses;
    report.ackermann_replay_failures = replay_failures;
    if replay_clauses != closed.len() || replay_failures != 0 {
        report.reason = Rejection::TypedReplayMismatch;
        return finish_attempt(cnf, before, None, report);
    }

    let rejection = if closed.is_empty() {
        Some(Rejection::NoClosedAtomClauses)
    } else if closed.len() > limits.max_closed_clauses {
        Some(Rejection::ClosedClauseCap)
    } else if closed_literal_slots > limits.max_closed_literal_slots {
        Some(Rejection::ClosedLiteralSlotCap)
    } else if report.closed_max_width > limits.max_closed_width {
        Some(Rejection::ClosedWidthCap)
    } else {
        None
    };
    if let Some(rejection) = rejection {
        report.reason = rejection;
        return finish_attempt(cnf, before, None, report);
    }

    report.clause_plan_sha256 = canonical_retained_clause_sequence_sha256(&closed);
    let materialized = match materialize_clauses(&closed, closed_literal_slots) {
        Ok(materialized) => materialized,
        Err(rejection) => {
            report.reason = rejection;
            return finish_attempt(cnf, before, None, report);
        }
    };
    report.materialized_clause_count = materialized.len();
    report.materialized_literal_slots = materialized.literals.len();
    report.materialized_max_width = materialized
        .iter()
        .map(<[i32]>::len)
        .max()
        .unwrap_or_default();
    report.materialized_clause_sha256 = canonical_flat_clause_sequence_sha256(&materialized);
    report.candidate_clauses = match cnf.clauses.len().checked_add(materialized.len()) {
        Some(value) => value,
        None => {
            report.reason = Rejection::MaterializationArithmeticOverflow;
            return finish_attempt(cnf, before, None, report);
        }
    };
    report.candidate_literal_slots = match cnf
        .clauses
        .literals
        .len()
        .checked_add(materialized.literals.len())
    {
        Some(value) => value,
        None => {
            report.reason = Rejection::MaterializationArithmeticOverflow;
            return finish_attempt(cnf, before, None, report);
        }
    };
    report.materialized_candidate_sha256 = canonical_candidate_sha256(cnf, &materialized);
    report.materialization_equal = materialized_matches_plan(&materialized, &closed)
        && report.clause_plan_sha256 == report.materialized_clause_sha256
        && report.materialized_clause_count == report.closed_clause_count
        && report.materialized_literal_slots == report.closed_literal_slots
        && report.materialized_max_width == report.closed_max_width
        && report.ackermann_replay_clauses == report.closed_clause_count
        && report.ackermann_replay_failures == 0
        && report.candidate_vars == report.baseline_vars
        && report.candidate_atoms == report.baseline_atoms
        && report.added_vars == 0
        && report.new_atoms == 0
        && report.fill_edges == 0
        && report.transitivity_clauses == 0;
    if !report.materialization_equal {
        report.reason = Rejection::MaterializationMismatch;
        return finish_attempt(cnf, before, None, report);
    }

    let mut planned_clauses = Vec::new();
    if planned_clauses.try_reserve(closed.len()).is_err() {
        report.reason = Rejection::PlanningAllocationFailure;
        return finish_attempt(cnf, before, None, report);
    }
    planned_clauses.extend(closed.into_iter().map(|clause| clause.literals));

    report.selected = true;
    report.reason = Rejection::Selected;
    finish_attempt(cnf, before, Some(planned_clauses), report)
}

fn finish_attempt(
    cnf: &CnfProblem,
    before: BaselineIdentity,
    mut clauses: Option<Vec<Vec<i32>>>,
    mut report: ProjectionReport,
) -> Attempt {
    report.baseline_cnf_after_sha256 = canonical_cnf_sha256(cnf);
    report.baseline_atom_map_after_sha256 = canonical_atom_map_sha256(cnf);
    report.baseline_problem_after_sha256 = canonical_problem_sha256(cnf);
    report.off_path_unchanged = baseline_identity(cnf) == before
        && report.baseline_cnf_before_sha256 == report.baseline_cnf_after_sha256
        && report.baseline_atom_map_before_sha256 == report.baseline_atom_map_after_sha256
        && report.baseline_problem_before_sha256 == report.baseline_problem_after_sha256;
    if !report.off_path_unchanged {
        clauses = None;
        report.selected = false;
        report.materialization_equal = false;
        report.materialized_candidate_sha256 = ZERO_SHA256.to_owned();
        report.reason = Rejection::BaselineStateChanged;
    }
    Attempt { clauses, report }
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
            if self.buffer_len < 64 {
                return;
            }
            let block = self.buffer;
            self.compress(&block);
            self.buffer_len = 0;
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

fn digest_hex(hash: Sha256) -> String {
    hash.finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn sha256_hex(input: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(input);
    digest_hex(hash)
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

fn hash_usize(hash: &mut Sha256, value: usize) {
    hash.update(&(value as u64).to_be_bytes());
}

fn hash_atom(hash: &mut Sha256, atom: &BoolAtomKey) {
    match atom {
        BoolAtomKey::Eq(left, right) => {
            hash_u8(hash, 1);
            hash_usize(hash, *left);
            hash_usize(hash, *right);
        }
        BoolAtomKey::BoolTerm(term) => {
            hash_u8(hash, 2);
            hash_usize(hash, *term);
        }
    }
}

fn hash_flat_clauses(hash: &mut Sha256, clauses: &FlatClauses) {
    hash_usize(hash, clauses.end_offsets.len());
    for &offset in &clauses.end_offsets {
        hash_u32(hash, offset);
    }
    hash_usize(hash, clauses.literals.len());
    for &literal in &clauses.literals {
        hash_i32(hash, literal);
    }
}

fn hash_atom_map(hash: &mut Sha256, cnf: &CnfProblem) {
    hash_usize(hash, cnf.var_atoms.len());
    for atom in &cnf.var_atoms {
        match atom {
            None => hash_u8(hash, 0),
            Some(atom) => {
                hash_u8(hash, 1);
                hash_atom(hash, atom);
                match cnf.atom_vars.get(atom) {
                    Some(variable) => {
                        hash_u8(hash, 1);
                        hash_i32(hash, *variable);
                    }
                    None => hash_u8(hash, 0),
                }
            }
        }
    }
    hash_usize(hash, cnf.atom_vars.len());
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

fn canonical_cnf_sha256(cnf: &CnfProblem) -> String {
    let mut hash = Sha256::new();
    hash.update(b"euf-viper-t10-baseline-cnf-v1\0");
    hash_flat_clauses(&mut hash, &cnf.clauses);
    digest_hex(hash)
}

fn canonical_atom_map_sha256(cnf: &CnfProblem) -> String {
    let mut hash = Sha256::new();
    hash.update(b"euf-viper-t10-baseline-atom-map-v1\0");
    hash_atom_map(&mut hash, cnf);
    digest_hex(hash)
}

fn canonical_problem_sha256(cnf: &CnfProblem) -> String {
    let mut hash = Sha256::new();
    hash.update(b"euf-viper-t10-baseline-problem-v1\0");
    hash_flat_clauses(&mut hash, &cnf.clauses);
    hash_atom_map(&mut hash, cnf);
    digest_hex(hash)
}

fn hash_clause_sequence<'a>(
    hash: &mut Sha256,
    count: usize,
    clauses: impl IntoIterator<Item = &'a [i32]>,
) {
    hash_usize(hash, count);
    for clause in clauses {
        hash_usize(hash, clause.len());
        for &literal in clause {
            hash_i32(hash, literal);
        }
    }
}

fn canonical_retained_clause_sequence_sha256(clauses: &[RetainedClause]) -> String {
    let mut hash = Sha256::new();
    hash.update(b"euf-viper-t10-closed-clause-sequence-v1\0");
    hash_clause_sequence(
        &mut hash,
        clauses.len(),
        clauses.iter().map(|clause| clause.literals.as_slice()),
    );
    digest_hex(hash)
}

fn canonical_flat_clause_sequence_sha256(clauses: &FlatClauses) -> String {
    let mut hash = Sha256::new();
    hash.update(b"euf-viper-t10-closed-clause-sequence-v1\0");
    hash_clause_sequence(&mut hash, clauses.len(), clauses.iter());
    digest_hex(hash)
}

fn canonical_candidate_sha256(cnf: &CnfProblem, added: &FlatClauses) -> String {
    let mut hash = Sha256::new();
    hash.update(b"euf-viper-t10-materialized-candidate-v1\0");
    hash_flat_clauses(&mut hash, &cnf.clauses);
    hash_clause_sequence(&mut hash, added.len(), added.iter());
    hash_atom_map(&mut hash, cnf);
    digest_hex(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ScopedLetMode, SortId, atomize_bool_data_terms, parse_problem_with_scoped_let_mode,
    };

    const DATA_SORT: SortId = SortId(1);

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

    fn function_pair(arity: usize) -> (TermArena, CnfProblem, Vec<BoolAtomKey>) {
        let mut arena = TermArena::default();
        let mut left_args = Vec::new();
        let mut right_args = Vec::new();
        let mut atoms = Vec::new();
        for index in 0..arity {
            let left = arena.intern_typed(index as SymId, Vec::new(), DATA_SORT);
            let right = arena.intern_typed((arity + index) as SymId, Vec::new(), DATA_SORT);
            left_args.push(left);
            right_args.push(right);
            atoms.push(BoolAtomKey::Eq(
                normalized_pair(left, right).0,
                normalized_pair(left, right).1,
            ));
        }
        let left = arena.intern_typed(10_000, left_args, DATA_SORT);
        let right = arena.intern_typed(10_000, right_args, DATA_SORT);
        let (left, right) = normalized_pair(left, right);
        atoms.push(BoolAtomKey::Eq(left, right));
        (arena, CnfProblem::new(), atoms)
    }

    fn bool_pair() -> (TermArena, CnfProblem, Vec<BoolAtomKey>) {
        let mut arena = TermArena::default();
        let left_arg = arena.intern_typed(0, Vec::new(), DATA_SORT);
        let right_arg = arena.intern_typed(1, Vec::new(), DATA_SORT);
        let left = arena.intern_typed(10_000, vec![left_arg], BOOL_SORT);
        let right = arena.intern_typed(10_000, vec![right_arg], BOOL_SORT);
        let (arg_left, arg_right) = normalized_pair(left_arg, right_arg);
        (
            arena,
            CnfProblem::new(),
            vec![
                BoolAtomKey::Eq(arg_left, arg_right),
                BoolAtomKey::BoolTerm(left),
                BoolAtomKey::BoolTerm(right),
            ],
        )
    }

    fn intern_atoms(cnf: &mut CnfProblem, atoms: &[BoolAtomKey], mask: usize) {
        for (index, atom) in atoms.iter().enumerate() {
            if mask & (1 << index) != 0 {
                cnf.atom_lit(atom.clone());
            }
        }
    }

    fn assert_selector_reason(facts: StructuralFacts, expected: Rejection) {
        let cnf = CnfProblem::new();
        let arena = TermArena::default();
        let report = ProjectionReport::new(Mode::ClosedAtomAuto, &cnf, &arena, facts);
        assert_eq!(selector_rejection(&report), Some(expected));
    }

    #[test]
    fn strict_mode_accepts_only_the_preregistered_values() {
        assert_eq!(parse_mode(None), Ok(Mode::Off));
        assert_eq!(parse_mode(Some("off")), Ok(Mode::Off));
        assert_eq!(
            parse_mode(Some("closed-atom-auto")),
            Ok(Mode::ClosedAtomAuto)
        );
        assert_eq!(
            parse_mode(Some("auto")),
            Err("EUF_VIPER_T10_ACKERMANN must be off or closed-atom-auto".to_owned())
        );
        assert!(parse_mode(Some("closed-atom-auto ")).is_err());
        assert!(parse_mode(Some("ON")).is_err());
        assert!(parse_mode(Some("")).is_err());
    }

    #[test]
    fn selector_duplicates_the_t9_boundary_and_rejection_order() {
        let cnf = CnfProblem::new();
        let arena = TermArena::default();
        let positive = ProjectionReport::new(Mode::ClosedAtomAuto, &cnf, &arena, eligible_facts(0));
        assert_eq!(selector_rejection(&positive), None);

        let base = eligible_facts(0);
        let mut facts = base;
        facts.finite_added = 1;
        assert_selector_reason(facts, Rejection::FiniteAddedNonzero);
        let mut facts = base;
        facts.covered_finite_terms = 1;
        assert_selector_reason(facts, Rejection::CoveredFiniteTermsNonzero);
        let mut facts = base;
        facts.closed_table_functions = 1;
        assert_selector_reason(facts, Rejection::ClosedTableFunctionsNonzero);
        let mut facts = base;
        facts.all_different_clique_lower_bound = 47;
        facts.disequality_graph_edges = checked_pair_count(47).unwrap();
        assert_selector_reason(facts, Rejection::AllDifferentCliqueBelowMinimum);
        let mut facts = base;
        facts.disequality_graph_edges = checked_pair_count(48).unwrap() + 9;
        assert_selector_reason(facts, Rejection::DisequalityCliqueExcessEdges);
        let mut facts = base;
        facts.equality_graph_vertices = 2_499;
        assert_selector_reason(facts, Rejection::EqualityGraphVerticesBelowMinimum);
        let mut facts = base;
        facts.equality_graph_edges = 9_999;
        assert_selector_reason(facts, Rejection::EqualityGraphEdgesBelowMinimum);
        let mut facts = base;
        facts.applications = MAX_APPLICATIONS + 1;
        assert_selector_reason(facts, Rejection::ApplicationCountCap);
        let mut facts = base;
        facts.backend = BackendRoute::Cadical;
        assert_selector_reason(facts, Rejection::BackendNotKissat);
    }

    #[test]
    fn selector_arithmetic_and_kissat_precheck_fail_closed() {
        let mut facts = eligible_facts(0);
        facts.all_different_clique_lower_bound = usize::MAX;
        facts.disequality_graph_edges = usize::MAX;
        assert_selector_reason(facts, Rejection::DisequalityCliqueArithmeticOverflow);

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
    fn retained_clauses_replay_independently_and_mutations_are_rejected() {
        let (function_arena, mut function_cnf, function_atoms) = function_pair(3);
        for atom in function_atoms {
            function_cnf.atom_lit(atom);
        }
        let function = enumerate_full_ackermann(&function_arena).unwrap();
        assert_eq!(function.len(), 1);
        assert_eq!(function[0].provenance.kind, AckermannKind::Function);
        assert_eq!(function[0].literals.len(), 4);
        let retained = retain_closed_clauses(&function_cnf, &function).unwrap();
        assert_eq!(
            replay_retained_ackermann_clauses(&function_cnf, &function_arena, &retained).unwrap(),
            (1, 0)
        );

        let mut literal_mutation = retained.clone();
        literal_mutation[0].literals[0] = -literal_mutation[0].literals[0];
        assert_eq!(
            replay_retained_ackermann_clauses(&function_cnf, &function_arena, &literal_mutation,)
                .unwrap(),
            (1, 1)
        );

        let mut provenance_mutation = retained.clone();
        provenance_mutation[0].provenance.right = provenance_mutation[0].provenance.left;
        assert_eq!(
            replay_retained_ackermann_clauses(
                &function_cnf,
                &function_arena,
                &provenance_mutation,
            )
            .unwrap(),
            (1, 1)
        );

        let (bool_arena, mut bool_cnf, bool_atoms) = bool_pair();
        for atom in bool_atoms {
            bool_cnf.atom_lit(atom);
        }
        let predicates = enumerate_full_ackermann(&bool_arena).unwrap();
        assert_eq!(predicates.len(), 2);
        assert_eq!(
            predicates
                .iter()
                .map(|clause| clause.provenance.kind)
                .collect::<Vec<_>>(),
            [AckermannKind::BoolForward, AckermannKind::BoolBackward]
        );
        assert!(predicates.iter().all(|clause| clause.literals.len() == 3));
        let retained = retain_closed_clauses(&bool_cnf, &predicates).unwrap();
        assert_eq!(
            replay_retained_ackermann_clauses(&bool_cnf, &bool_arena, &retained).unwrap(),
            (2, 0)
        );
    }

    #[test]
    fn exhaustive_atom_subsets_retain_if_and_only_if_every_atom_exists() {
        let (arena, _, atoms) = function_pair(1);
        let full = enumerate_full_ackermann(&arena).unwrap();
        for mask in 0..(1usize << atoms.len()) {
            let mut cnf = CnfProblem::new();
            intern_atoms(&mut cnf, &atoms, mask);
            let before_vars = cnf.var_count();
            let before_atoms = cnf.atom_vars.clone();
            let closed = retain_closed_clauses(&cnf, &full).unwrap();
            assert_eq!(closed.len(), usize::from(mask == 0b11), "mask={mask:b}");
            assert_eq!(cnf.var_count(), before_vars);
            assert_eq!(cnf.atom_vars, before_atoms);
        }

        let (arena, _, atoms) = bool_pair();
        let full = enumerate_full_ackermann(&arena).unwrap();
        for mask in 0..(1usize << atoms.len()) {
            let mut cnf = CnfProblem::new();
            intern_atoms(&mut cnf, &atoms, mask);
            let before_vars = cnf.var_count();
            let before_atoms = cnf.atom_vars.clone();
            let closed = retain_closed_clauses(&cnf, &full).unwrap();
            assert_eq!(closed.len(), if mask == 0b111 { 2 } else { 0 });
            assert_eq!(cnf.var_count(), before_vars);
            assert_eq!(cnf.atom_vars, before_atoms);
        }
    }

    #[test]
    fn missing_atoms_never_create_variables_or_change_hashes() {
        let (arena, cnf, atoms) = function_pair(1);
        assert_eq!(atoms.len(), 2);
        let before = baseline_identity(&cnf);
        let before_problem_hash = canonical_problem_sha256(&cnf);
        let attempt = attempt(
            Mode::ClosedAtomAuto,
            &cnf,
            &arena,
            eligible_facts(arena.apps.len()),
        );
        assert_eq!(attempt.report.reason, Rejection::NoClosedAtomClauses);
        assert!(attempt.clauses.is_none());
        assert_eq!(baseline_identity(&cnf), before);
        assert_eq!(canonical_problem_sha256(&cnf), before_problem_hash);
        assert!(attempt.report.off_path_unchanged);
        assert_eq!(attempt.report.added_vars, 0);
        assert_eq!(attempt.report.new_atoms, 0);
    }

    #[test]
    fn exact_plan_materialization_and_hashes_are_deterministic() {
        let (arena, mut cnf, atoms) = function_pair(3);
        for atom in atoms {
            cnf.atom_lit(atom);
        }
        let before = baseline_identity(&cnf);
        let first = attempt(
            Mode::ClosedAtomAuto,
            &cnf,
            &arena,
            eligible_facts(arena.apps.len()),
        );
        let second = attempt(
            Mode::ClosedAtomAuto,
            &cnf,
            &arena,
            eligible_facts(arena.apps.len()),
        );
        assert!(first.report.selected);
        assert!(first.report.materialization_equal);
        assert!(first.report.off_path_unchanged);
        assert_eq!(first.report, second.report);
        assert_eq!(first.clauses, second.clauses);
        assert_eq!(first.report.full_clause_count, 1);
        assert_eq!(first.report.closed_clause_count, 1);
        assert_eq!(first.report.closed_literal_slots, 4);
        assert_eq!(first.report.closed_max_width, 4);
        assert_eq!(first.report.ackermann_replay_clauses, 1);
        assert_eq!(first.report.ackermann_replay_failures, 0);
        assert_eq!(first.clauses, Some(vec![vec![-3, -2, -1, 4]]));
        assert_eq!(
            first.report.clause_plan_sha256,
            first.report.materialized_clause_sha256
        );
        assert_eq!(
            first.report.clause_plan_sha256,
            "c272e737958b7c3b1c17511cab0fa6e2abb9869037c36aa185fd530e6b13662a"
        );
        assert_ne!(first.report.clause_plan_sha256, ZERO_SHA256);
        assert_ne!(first.report.materialized_candidate_sha256, ZERO_SHA256);
        assert_eq!(baseline_identity(&cnf), before);
    }

    #[test]
    fn frozen_caps_have_exact_boundaries_and_fail_closed() {
        let limits = Limits::default();
        assert_eq!(limits.max_closed_clauses, 4_096);
        assert_eq!(limits.max_closed_literal_slots, 16_384);
        assert_eq!(limits.max_closed_width, 4);

        let (arena, mut cnf, atoms) = function_pair(3);
        for atom in atoms {
            cnf.atom_lit(atom);
        }
        let facts = eligible_facts(arena.apps.len());
        assert!(
            attempt_with_limits(Mode::ClosedAtomAuto, &cnf, &arena, facts, limits)
                .report
                .selected
        );

        let clause_cap = Limits {
            max_closed_clauses: 0,
            ..limits
        };
        assert_eq!(
            attempt_with_limits(Mode::ClosedAtomAuto, &cnf, &arena, facts, clause_cap)
                .report
                .reason,
            Rejection::ClosedClauseCap
        );
        let literal_cap = Limits {
            max_closed_literal_slots: 3,
            ..limits
        };
        assert_eq!(
            attempt_with_limits(Mode::ClosedAtomAuto, &cnf, &arena, facts, literal_cap)
                .report
                .reason,
            Rejection::ClosedLiteralSlotCap
        );
        let width_cap = Limits {
            max_closed_width: 3,
            ..limits
        };
        assert_eq!(
            attempt_with_limits(Mode::ClosedAtomAuto, &cnf, &arena, facts, width_cap)
                .report
                .reason,
            Rejection::ClosedWidthCap
        );

        let (wide_arena, mut wide_cnf, wide_atoms) = function_pair(4);
        for atom in wide_atoms {
            wide_cnf.atom_lit(atom);
        }
        let wide = attempt(
            Mode::ClosedAtomAuto,
            &wide_cnf,
            &wide_arena,
            eligible_facts(wide_arena.apps.len()),
        );
        assert_eq!(wide.report.closed_max_width, 5);
        assert_eq!(wide.report.reason, Rejection::ClosedWidthCap);
        assert!(wide.clauses.is_none());
    }

    #[test]
    fn default_clause_and_literal_slot_caps_reject_exact_overflows() {
        let mut arena = TermArena::default();
        let mut arguments = Vec::new();
        let mut applications = Vec::new();
        for index in 0..92 {
            let argument = arena.intern_typed(index, Vec::new(), DATA_SORT);
            arguments.push(argument);
            applications.push(arena.intern_typed(10_000, vec![argument], DATA_SORT));
        }
        let mut cnf = CnfProblem::new();
        for left in 0..applications.len() {
            for right in (left + 1)..applications.len() {
                cnf.atom_lit(BoolAtomKey::Eq(arguments[left], arguments[right]));
                cnf.atom_lit(BoolAtomKey::Eq(applications[left], applications[right]));
            }
        }
        let over_clause_cap = attempt(
            Mode::ClosedAtomAuto,
            &cnf,
            &arena,
            eligible_facts(arena.apps.len()),
        );
        assert_eq!(over_clause_cap.report.closed_clause_count, 4_186);
        assert_eq!(over_clause_cap.report.ackermann_replay_clauses, 4_186);
        assert_eq!(over_clause_cap.report.ackermann_replay_failures, 0);
        assert_eq!(over_clause_cap.report.reason, Rejection::ClosedClauseCap);
        assert!(over_clause_cap.clauses.is_none());

        let (wide_arena, mut wide_cnf, atoms) = function_pair(MAX_CLOSED_LITERAL_SLOTS);
        for atom in atoms {
            wide_cnf.atom_lit(atom);
        }
        let over_literal_cap = attempt(
            Mode::ClosedAtomAuto,
            &wide_cnf,
            &wide_arena,
            eligible_facts(wide_arena.apps.len()),
        );
        assert_eq!(
            over_literal_cap.report.closed_literal_slots,
            MAX_CLOSED_LITERAL_SLOTS + 1
        );
        assert_eq!(over_literal_cap.report.ackermann_replay_clauses, 1);
        assert_eq!(over_literal_cap.report.ackermann_replay_failures, 0);
        assert_eq!(
            over_literal_cap.report.reason,
            Rejection::ClosedLiteralSlotCap
        );
        assert!(over_literal_cap.clauses.is_none());
    }

    #[test]
    fn selected_kernel_trusts_only_an_unsat_result() {
        let (arena, mut cnf, atoms) = function_pair(1);
        let argument_equality = cnf.atom_lit(atoms[0].clone());
        let result_equality = cnf.atom_lit(atoms[1].clone());
        cnf.add_clause(vec![argument_equality]);
        cnf.add_clause(vec![-result_equality]);
        let attempt = attempt(
            Mode::ClosedAtomAuto,
            &cnf,
            &arena,
            eligible_facts(arena.apps.len()),
        );
        assert!(attempt.report.selected);
        let closed = attempt.clauses.unwrap();
        let baseline_before = baseline_identity(&cnf);

        let (kernel, sat_calls) =
            crate::measure_sat_dispatches(|| crate::solve_t10_kissat_kernel(&cnf, &closed));
        assert_eq!(kernel, crate::T10KernelOutcome::Unsat);
        assert_eq!(kernel.sat_calls(), 1);
        assert_eq!(sat_calls, 1);
        assert_eq!(baseline_identity(&cnf), baseline_before);
    }

    #[test]
    fn selected_kernel_sat_is_never_a_solver_result_and_leaves_baseline_unchanged() {
        let (mut arena, mut cnf, atoms) = function_pair(1);
        for atom in atoms {
            cnf.atom_lit(atom);
        }
        let true_term = arena.intern_typed(20_000, Vec::new(), BOOL_SORT);
        let false_term = arena.intern_typed(20_001, Vec::new(), BOOL_SORT);
        let attempt = attempt(
            Mode::ClosedAtomAuto,
            &cnf,
            &arena,
            eligible_facts(arena.apps.len()),
        );
        assert!(attempt.report.selected);
        let closed = attempt.clauses.unwrap();
        let baseline_before = baseline_identity(&cnf);
        let baseline_hash = canonical_problem_sha256(&cnf);

        let ((kernel, fallback), sat_calls) = crate::measure_sat_dispatches(|| {
            let kernel = crate::solve_t10_kissat_kernel(&cnf, &closed);
            assert_eq!(kernel, crate::T10KernelOutcome::Sat);
            let fallback = crate::solve_kissat_euf_once(&cnf, &arena, true_term, false_term, false);
            (kernel, fallback)
        });
        assert_eq!(kernel.sat_calls(), 1);
        assert_eq!(
            fallback,
            crate::EagerSolveOutcome::Solved(crate::SolveResult::Sat)
        );
        assert_eq!(sat_calls, 2);
        assert_eq!(baseline_identity(&cnf), baseline_before);
        assert_eq!(canonical_problem_sha256(&cnf), baseline_hash);
    }

    #[test]
    fn off_and_selector_rejections_are_exact_identity_transactions() {
        let (problem, cnf) = parsed_problem_and_cnf(
            "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun a () U)
            (declare-fun b () U)
            (declare-fun f (U) U)
            (assert (= (f a) (f b)))
            (assert (= a b))
            (check-sat)
            ",
        );
        let clauses = cnf.clauses.clone();
        let var_atoms = cnf.var_atoms.clone();
        let atom_vars = cnf.atom_vars.clone();
        let off = attempt(
            Mode::Off,
            &cnf,
            &problem.arena,
            eligible_facts(problem.arena.apps.len()),
        );
        assert_eq!(off.report.reason, Rejection::ModeOff);
        assert!(off.report.off_path_unchanged);
        assert!(off.clauses.is_none());

        let mut facts = eligible_facts(problem.arena.apps.len());
        facts.backend = BackendRoute::Varisat;
        let rejected = attempt(Mode::ClosedAtomAuto, &cnf, &problem.arena, facts);
        assert_eq!(rejected.report.reason, Rejection::BackendNotKissat);
        assert!(rejected.report.off_path_unchanged);
        assert_eq!(cnf.clauses, clauses);
        assert_eq!(cnf.var_atoms, var_atoms);
        assert_eq!(cnf.atom_vars, atom_vars);
    }

    #[test]
    fn projection_json_is_strict_deterministic_and_no_sat() {
        let (arena, mut cnf, atoms) = function_pair(1);
        for atom in atoms {
            cnf.atom_lit(atom);
        }
        let mut report = attempt(
            Mode::ClosedAtomAuto,
            &cnf,
            &arena,
            eligible_facts(arena.apps.len()),
        )
        .report;
        report.record_source(b"source bytes");
        let mut first = Vec::new();
        let mut second = Vec::new();
        report.write_to(&mut first).unwrap();
        report.write_to(&mut second).unwrap();
        assert_eq!(first, second);
        let rendered = String::from_utf8(first).unwrap();
        assert!(rendered.starts_with("{\"t10_projection_version\":1,"));
        assert!(rendered.ends_with("\"sat_calls\":0}\n"));
        assert_eq!(rendered.lines().count(), 1);
        assert!(rendered.contains("\"selected\":true"));
        assert!(rendered.contains("\"materialization_equal\":true"));
        assert!(
            rendered.contains("\"ackermann_replay_clauses\":1,\"ackermann_replay_failures\":0")
        );
        assert!(rendered.contains("\"added_vars\":0,\"new_atoms\":0"));
        assert!(rendered.contains(&format!(
            "\"source_sha256\":\"{}\"",
            sha256_hex(b"source bytes")
        )));

        report.record_observed_sat_calls(1);
        assert!(!report.selected);
        assert_eq!(report.reason, Rejection::SatDispatchObserved);
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
        assert_eq!(
            sha256_hex(&[b'a'; 100]),
            "2816597888e4a0d3a36b82b83316ab32680eb8f00f8cd3b904d681246d285a0e"
        );
        let mut incremental = Sha256::new();
        incremental.update(b"abc");
        incremental.update(b"def");
        assert_eq!(
            digest_hex(incremental),
            "bef57ec7f53a6d40beb640a780a639c83bc29ac8a9816f1fc6c5c6dcd93c4721"
        );
    }
}
