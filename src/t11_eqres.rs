//! T11 routing and integration glue.
//!
//! Proof construction and replay live in separate modules. This layer owns
//! only option parsing, the exact T9-selector adapter, and immutable input
//! assembly.

use super::{
    BOOL_SORT, CnfProblem, Problem, TermArena,
    finite_analysis::FiniteAnalysis,
    t9_ackermann, t10_ackermann, t11_eqres_checker, t11_eqres_compiler,
    t11_eqres_types::{
        CheckerCounters, CheckerResult, CheckerStatus, CompilerFailure, CompilerResult,
        CompilerStatus, CompilerVariant, DeterministicCounters, EQRES_ENV, EQRES_SCHEMA_VERSION,
        EqresBundle, EqresInput, EqresMode, EqresOutput, EqresReport, ForbiddenGrowthCounters,
        HashBindings, IntegrityReport, MaterializedClauseStore, ReportOutcome, SelectorDecision,
        SelectorFacts, SelectorRejection, SelectorReport, SolverBackend,
    },
};
#[cfg(feature = "certificates")]
use std::io::{self, Write};
use std::{collections::BTreeMap, env};

pub(crate) const ROOT_CNF_MODE: &[u8] = b"direct-root;negated-root=false;v1";

pub(crate) fn parse_mode(value: Option<&str>) -> Result<EqresMode, String> {
    match value {
        None | Some("off") => Ok(EqresMode::Off),
        Some("clique-er-auto") => Ok(EqresMode::CliqueErAuto),
        Some(_) => Err(format!("{EQRES_ENV} must be off or clique-er-auto")),
    }
}

pub(crate) fn selected_mode() -> Result<EqresMode, String> {
    match env::var(EQRES_ENV) {
        Ok(value) => parse_mode(Some(&value)),
        Err(env::VarError::NotPresent) => parse_mode(None),
        Err(env::VarError::NotUnicode(_)) => {
            Err(format!("{EQRES_ENV} must be off or clique-er-auto"))
        }
    }
}

pub(crate) fn validate_experimental_mode_exclusivity(
    t9: t9_ackermann::Mode,
    t10: t10_ackermann::Mode,
    t11: EqresMode,
) -> Result<(), String> {
    let enabled = usize::from(t9 != t9_ackermann::Mode::Off)
        + usize::from(t10 != t10_ackermann::Mode::Off)
        + usize::from(t11 != EqresMode::Off);
    if enabled > 1 {
        return Err(format!(
            "{}, {}, and {} are mutually exclusive experimental modes",
            t9_ackermann::ENV,
            t10_ackermann::ENV,
            EQRES_ENV
        ));
    }
    Ok(())
}

fn solver_backend(backend: t9_ackermann::BackendRoute) -> SolverBackend {
    match backend {
        t9_ackermann::BackendRoute::Kissat => SolverBackend::Kissat,
        t9_ackermann::BackendRoute::Cadical => SolverBackend::Cadical,
        t9_ackermann::BackendRoute::CadicalRefine => SolverBackend::CadicalRefine,
        t9_ackermann::BackendRoute::Varisat => SolverBackend::Varisat,
        t9_ackermann::BackendRoute::Fallback => SolverBackend::Fallback,
        t9_ackermann::BackendRoute::Dpll => SolverBackend::Dpll,
    }
}

fn map_t9_rejection(reason: &str) -> SelectorRejection {
    match reason {
        "mode_off" => SelectorRejection::ModeOff,
        "finite_added_nonzero" => SelectorRejection::FiniteAddedNonzero,
        "covered_finite_terms_nonzero" => SelectorRejection::CoveredFiniteTermsNonzero,
        "closed_table_functions_nonzero" => SelectorRejection::ClosedTableFunctionsNonzero,
        "all_different_clique_below_minimum" => SelectorRejection::AllDifferentCliqueBelowMinimum,
        "disequality_clique_arithmetic_overflow" => {
            SelectorRejection::DisequalityCliqueArithmeticOverflow
        }
        "disequality_clique_excess_edges" => SelectorRejection::DisequalityCliqueExcessEdges,
        "equality_graph_vertices_below_minimum" => {
            SelectorRejection::EqualityGraphVerticesBelowMinimum
        }
        "equality_graph_edges_below_minimum" => SelectorRejection::EqualityGraphEdgesBelowMinimum,
        "application_count_cap" => SelectorRejection::ApplicationCountCap,
        "backend_not_kissat" => SelectorRejection::BackendNotKissat,
        _ => SelectorRejection::RuntimeFactMismatch,
    }
}

fn boolean_valued_application_pairs(arena: &TermArena) -> Option<u64> {
    let mut per_function = BTreeMap::<u32, u64>::new();
    for &application in &arena.apps {
        let term = arena.terms.get(application)?;
        if term.args.is_empty() {
            return None;
        }
        if term.sort == BOOL_SORT {
            let count = per_function.entry(term.fun).or_default();
            *count = count.checked_add(1)?;
        }
    }
    per_function.values().try_fold(0u64, |total, &count| {
        let pairs = count.checked_mul(count.saturating_sub(1))?.checked_div(2)?;
        total.checked_add(pairs)
    })
}

pub(crate) fn selector_report(
    mode: EqresMode,
    cnf: &CnfProblem,
    arena: &TermArena,
    analysis: &FiniteAnalysis,
    finite_added: usize,
    backend: t9_ackermann::BackendRoute,
) -> SelectorReport {
    let boolean_pairs = boolean_valued_application_pairs(arena);
    let facts = SelectorFacts {
        finite_added_clauses: finite_added as u64,
        covered_finite_terms: analysis.covered_finite_terms as u64,
        closed_table_functions: analysis.closed_table_functions as u64,
        all_different_clique_lower_bound: analysis.all_different_clique_lower_bound as u64,
        disequality_graph_edges: analysis.disequality_graph_edges as u64,
        equality_graph_vertices: analysis.equality_graph_vertices as u64,
        equality_graph_edges: analysis.equality_graph_edges as u64,
        applications: arena.apps.len() as u64,
        boolean_valued_application_pairs: boolean_pairs.unwrap_or(u64::MAX),
        backend: solver_backend(backend),
    };

    let t9_mode = match mode {
        EqresMode::Off => t9_ackermann::Mode::Off,
        EqresMode::CliqueErAuto => t9_ackermann::Mode::CliqueAuto,
    };
    let t9_facts = t9_ackermann::StructuralFacts::from_analysis(
        analysis,
        finite_added,
        arena.apps.len(),
        backend,
    );
    let t9_decision = t9_ackermann::structural_selector_decision(t9_mode, cnf, arena, t9_facts);
    let decision = if !t9_decision.selected() {
        SelectorDecision::Rejected(map_t9_rejection(t9_decision.reason()))
    } else if boolean_pairs.is_none() {
        SelectorDecision::Rejected(SelectorRejection::RuntimeFactMismatch)
    } else if boolean_pairs != Some(0) {
        SelectorDecision::Rejected(SelectorRejection::BooleanValuedApplicationPair)
    } else {
        SelectorDecision::Selected
    };
    SelectorReport {
        mode,
        facts,
        decision,
    }
}

pub(crate) fn fallback_selector_report(
    mode: EqresMode,
    cnf: &CnfProblem,
    arena: &TermArena,
) -> SelectorReport {
    let backend = t9_ackermann::BackendRoute::Fallback;
    let t9_mode = match mode {
        EqresMode::Off => t9_ackermann::Mode::Off,
        EqresMode::CliqueErAuto => t9_ackermann::Mode::CliqueAuto,
    };
    let t9_decision = t9_ackermann::structural_selector_decision(
        t9_mode,
        cnf,
        arena,
        t9_ackermann::StructuralFacts::fallback_route(arena.apps.len()),
    );
    SelectorReport {
        mode,
        facts: SelectorFacts {
            finite_added_clauses: 0,
            covered_finite_terms: 0,
            closed_table_functions: 0,
            all_different_clique_lower_bound: 0,
            disequality_graph_edges: 0,
            equality_graph_vertices: 0,
            equality_graph_edges: 0,
            applications: u64::try_from(arena.apps.len()).unwrap_or(u64::MAX),
            boolean_valued_application_pairs: boolean_valued_application_pairs(arena)
                .unwrap_or(u64::MAX),
            backend: SolverBackend::Fallback,
        },
        decision: SelectorDecision::Rejected(map_t9_rejection(t9_decision.reason())),
    }
}

pub(crate) fn input_view<'a>(
    source: &'a [u8],
    problem: &'a Problem,
    cnf: &'a CnfProblem,
) -> EqresInput<'a> {
    EqresInput {
        source_bytes: source,
        root_cnf_mode: ROOT_CNF_MODE,
        sorts: &problem.sorts,
        declarations: &problem.fun_decls,
        term_dag: &problem.arena.terms,
        ordered_applications: &problem.arena.apps,
        baseline_clauses: &cnf.clauses,
        variable_atoms: &cnf.var_atoms,
        atom_variables: &cnf.atom_vars,
        true_literal: cnf.true_lit,
        finite_equalities_complete: cnf.finite_equalities_complete,
        finite_predicate_congruence_complete: cnf.finite_predicate_congruence_complete,
    }
}

fn report_outcome(
    selector: SelectorReport,
    compiler: &CompilerResult,
    checker: &CheckerResult,
) -> ReportOutcome {
    if selector.mode == EqresMode::Off {
        return ReportOutcome::Off;
    }
    if selector.decision != SelectorDecision::Selected
        || !matches!(checker.status, CheckerStatus::Accepted)
    {
        return ReportOutcome::Rejected;
    }
    match &compiler.status {
        CompilerStatus::Completed(EqresOutput::Lemmas(_)) => ReportOutcome::Lemmas,
        CompilerStatus::Completed(EqresOutput::TheoryEmpty { .. }) => ReportOutcome::TheoryEmpty,
        CompilerStatus::Completed(EqresOutput::NoLemmas) => ReportOutcome::NoLemmas,
        CompilerStatus::NotRun | CompilerStatus::Rejected(_) => ReportOutcome::Rejected,
    }
}

fn checked_integrity(compiler: &CompilerResult, checker: &CheckerResult) -> IntegrityReport {
    let checker_accepted = matches!(checker.status, CheckerStatus::Accepted);
    let hashes_agree = compiler.hashes == checker.recomputed_hashes;
    let baseline_hashes_bound = compiler.hashes.baseline_cnf_sha256 != Default::default()
        && compiler.hashes.atom_map_sha256 != Default::default()
        && compiler.hashes.baseline_problem_sha256 != Default::default();
    IntegrityReport {
        baseline_unchanged: checker_accepted && hashes_agree && baseline_hashes_bound,
        trace_materialization_equal: checker_accepted
            && hashes_agree
            && compiler.hashes.lemma_sequence_sha256 == compiler.hashes.materialized_lemmas_sha256,
        compiler_checker_agree: checker_accepted && hashes_agree,
        output_canonical: checker_accepted,
        external_audit_accepted: false,
        off_path_unchanged: false,
    }
}

fn assemble_bundle(
    selector: SelectorReport,
    compiler: CompilerResult,
    materialized_lemmas: MaterializedClauseStore,
    checker: CheckerResult,
) -> EqresBundle {
    let outcome = report_outcome(selector, &compiler, &checker);
    let cap_attempt = match &compiler.status {
        CompilerStatus::Rejected(CompilerFailure::Cap(attempt)) => Some(attempt.clone()),
        _ => None,
    };
    let report = EqresReport {
        schema_version: EQRES_SCHEMA_VERSION,
        selector,
        compiler_variant: compiler.variant,
        outcome,
        counters: compiler.counters,
        checker_counters: checker.counters,
        cap_attempt,
        forbidden_growth: ForbiddenGrowthCounters::default(),
        integrity: checked_integrity(&compiler, &checker),
        sat_calls: 0,
        hashes: compiler.hashes,
    };
    EqresBundle::new(selector, compiler, materialized_lemmas, checker, report)
}

pub(crate) fn unexecuted_bundle(selector: SelectorReport) -> EqresBundle {
    let compiler = CompilerResult {
        variant: CompilerVariant::Ordinary,
        status: CompilerStatus::NotRun,
        trace: Box::new([]),
        counters: DeterministicCounters::default(),
        hashes: HashBindings::default(),
    };
    let checker = CheckerResult {
        status: CheckerStatus::NotRun,
        counters: CheckerCounters::default(),
        recomputed_hashes: HashBindings::default(),
    };
    let mut bundle = assemble_bundle(
        selector,
        compiler,
        MaterializedClauseStore::empty(),
        checker,
    );
    bundle.report.integrity.off_path_unchanged = true;
    bundle
}

pub(crate) fn execute_projection(
    selector: SelectorReport,
    input: EqresInput<'_>,
    variant: CompilerVariant,
) -> Result<EqresBundle, String> {
    if selector.decision != SelectorDecision::Selected {
        return Ok(unexecuted_bundle(selector));
    }
    let compiler = t11_eqres_compiler::compile(input, variant);
    let materialized_lemmas = materialize_lemmas(&compiler)?;
    let checker = t11_eqres_checker::check(input, &compiler, &materialized_lemmas);
    Ok(assemble_bundle(
        selector,
        compiler,
        materialized_lemmas,
        checker,
    ))
}

fn materialize_lemmas(compiler: &CompilerResult) -> Result<MaterializedClauseStore, String> {
    let (clause_count, literal_capacity) = match &compiler.status {
        CompilerStatus::Completed(EqresOutput::Lemmas(lemmas)) => {
            let slots = lemmas
                .iter()
                .try_fold(0usize, |total, lemma| total.checked_add(lemma.clause.len()));
            (
                lemmas.len(),
                slots.ok_or_else(|| "T11 materialized literal-count overflow".to_owned())?,
            )
        }
        CompilerStatus::Completed(EqresOutput::TheoryEmpty { lemma, .. }) => {
            (1, lemma.clause.len())
        }
        CompilerStatus::NotRun
        | CompilerStatus::Rejected(_)
        | CompilerStatus::Completed(EqresOutput::NoLemmas) => (0, 0),
    };
    let offset_capacity = clause_count
        .checked_add(1)
        .ok_or_else(|| "T11 materialized clause-count overflow".to_owned())?;
    let mut end_offsets = Vec::new();
    end_offsets
        .try_reserve_exact(offset_capacity)
        .map_err(|_| "T11 materialized offset allocation failed".to_owned())?;
    let mut literals = Vec::new();
    literals
        .try_reserve_exact(literal_capacity)
        .map_err(|_| "T11 materialized literal allocation failed".to_owned())?;
    end_offsets.push(0);
    let mut append = |clause: &[i32]| -> Result<(), String> {
        literals.extend_from_slice(clause);
        let end = u32::try_from(literals.len())
            .map_err(|_| "T11 materialized literal offset exceeds u32".to_owned())?;
        end_offsets.push(end);
        Ok(())
    };
    match &compiler.status {
        CompilerStatus::Completed(EqresOutput::Lemmas(lemmas)) => {
            for lemma in lemmas {
                append(lemma.clause.as_slice())?;
            }
        }
        CompilerStatus::Completed(EqresOutput::TheoryEmpty { lemma, .. }) => {
            append(lemma.clause.as_slice())?;
        }
        CompilerStatus::NotRun
        | CompilerStatus::Rejected(_)
        | CompilerStatus::Completed(EqresOutput::NoLemmas) => {}
    }
    drop(append);
    MaterializedClauseStore::from_parts(end_offsets, literals)
        .map_err(|error| format!("invalid T11 materialized clause store: {error:?}"))
}

pub(crate) fn record_observed_sat_calls(bundle: &mut EqresBundle, sat_calls: usize) {
    bundle.report.sat_calls = u64::try_from(sat_calls).unwrap_or(u64::MAX);
    if sat_calls != 0 {
        bundle.report.outcome = ReportOutcome::Rejected;
        bundle.report.integrity.compiler_checker_agree = false;
    }
}

/// This is only the in-process projection gate. Exact target identity,
/// baseline receipts, and the external scheduling audit remain mandatory
/// before a bundle can count as a Stage 0A pass.
pub(crate) fn internally_accepted_projection(bundle: &EqresBundle) -> bool {
    let expected_integrity = checked_integrity(&bundle.compiler, &bundle.checker);
    if bundle.selector.decision != SelectorDecision::Selected
        || bundle.report.schema_version != EQRES_SCHEMA_VERSION
        || bundle.report.selector != bundle.selector
        || bundle.report.compiler_variant != bundle.compiler.variant
        || bundle.report.counters != bundle.compiler.counters
        || bundle.report.checker_counters != bundle.checker.counters
        || bundle.report.hashes != bundle.compiler.hashes
        || bundle.compiler.hashes != bundle.checker.recomputed_hashes
        || bundle.report.sat_calls != 0
        || bundle.report.cap_attempt.is_some()
        || bundle.report.forbidden_growth != Default::default()
        || bundle.report.integrity != expected_integrity
        || bundle.report.integrity.external_audit_accepted
        || !matches!(bundle.checker.status, CheckerStatus::Accepted)
        || !materialized_matches_output(bundle)
        || bundle
            .report
            .counters
            .output
            .emitted_with_missing_equality_congruence
            == 0
    {
        return false;
    }

    match (&bundle.compiler.status, bundle.report.outcome) {
        (CompilerStatus::Completed(EqresOutput::Lemmas(lemmas)), ReportOutcome::Lemmas) => {
            !lemmas.is_empty()
        }
        (
            CompilerStatus::Completed(EqresOutput::TheoryEmpty { .. }),
            ReportOutcome::TheoryEmpty,
        ) => true,
        _ => false,
    }
}

fn materialized_matches_output(bundle: &EqresBundle) -> bool {
    let materialized = bundle.materialized_lemmas();
    match &bundle.compiler.status {
        CompilerStatus::Completed(EqresOutput::Lemmas(lemmas)) => {
            lemmas.len() == materialized.len()
                && lemmas.iter().enumerate().all(|(index, lemma)| {
                    materialized.clause(index) == Some(lemma.clause.as_slice())
                })
        }
        CompilerStatus::Completed(EqresOutput::TheoryEmpty { lemma, .. }) => {
            materialized.len() == 1
                && materialized.clause(0) == Some(lemma.clause.as_slice())
                && lemma.clause.is_empty()
        }
        CompilerStatus::Completed(EqresOutput::NoLemmas)
        | CompilerStatus::NotRun
        | CompilerStatus::Rejected(_) => materialized.len() == 0,
    }
}

#[cfg(feature = "certificates")]
pub(crate) fn write_bundle(bundle: &EqresBundle, output: &mut impl Write) -> io::Result<()> {
    serde_json::to_writer(&mut *output, bundle).map_err(io::Error::other)?;
    output.write_all(b"\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn selector(mode: EqresMode, decision: SelectorDecision) -> SelectorReport {
        SelectorReport {
            mode,
            facts: SelectorFacts {
                finite_added_clauses: 0,
                covered_finite_terms: 0,
                closed_table_functions: 0,
                all_different_clique_lower_bound: 0,
                disequality_graph_edges: 0,
                equality_graph_vertices: 0,
                equality_graph_edges: 0,
                applications: 0,
                boolean_valued_application_pairs: 0,
                backend: SolverBackend::Fallback,
            },
            decision,
        }
    }

    #[test]
    fn mode_parser_fails_closed() {
        assert_eq!(parse_mode(None), Ok(EqresMode::Off));
        assert_eq!(parse_mode(Some("off")), Ok(EqresMode::Off));
        assert_eq!(
            parse_mode(Some("clique-er-auto")),
            Ok(EqresMode::CliqueErAuto)
        );
        assert!(parse_mode(Some("auto")).is_err());
    }

    #[test]
    fn experimental_modes_are_mutually_exclusive() {
        assert!(
            validate_experimental_mode_exclusivity(
                t9_ackermann::Mode::Off,
                t10_ackermann::Mode::Off,
                EqresMode::CliqueErAuto,
            )
            .is_ok()
        );
        assert!(
            validate_experimental_mode_exclusivity(
                t9_ackermann::Mode::CliqueAuto,
                t10_ackermann::Mode::Off,
                EqresMode::CliqueErAuto,
            )
            .is_err()
        );
        assert!(
            validate_experimental_mode_exclusivity(
                t9_ackermann::Mode::Off,
                t10_ackermann::Mode::ClosedAtomAuto,
                EqresMode::CliqueErAuto,
            )
            .is_err()
        );
    }

    #[test]
    fn rejected_selector_is_explicitly_unexecuted() {
        let mut bundle = unexecuted_bundle(selector(
            EqresMode::CliqueErAuto,
            SelectorDecision::Rejected(SelectorRejection::BackendNotKissat),
        ));
        assert!(matches!(bundle.compiler.status, CompilerStatus::NotRun));
        assert!(matches!(bundle.checker.status, CheckerStatus::NotRun));
        assert_eq!(bundle.report.outcome, ReportOutcome::Rejected);
        assert!(bundle.report.integrity.off_path_unchanged);
        assert!(!internally_accepted_projection(&bundle));

        record_observed_sat_calls(&mut bundle, 1);
        assert_eq!(bundle.report.sat_calls, 1);
        assert_eq!(bundle.report.outcome, ReportOutcome::Rejected);
    }

    #[test]
    fn off_mode_has_a_distinct_report_outcome() {
        let bundle = unexecuted_bundle(selector(
            EqresMode::Off,
            SelectorDecision::Rejected(SelectorRejection::ModeOff),
        ));
        assert_eq!(bundle.report.outcome, ReportOutcome::Off);
    }

    #[test]
    fn boolean_application_guard_counts_same_function_pairs() {
        let mut arena = TermArena::default();
        let data_sort = super::super::SortId(1);
        let left = arena.intern_typed(1, Vec::new(), data_sort);
        let right = arena.intern_typed(2, Vec::new(), data_sort);
        arena.intern_typed(3, vec![left], BOOL_SORT);
        arena.intern_typed(3, vec![right], BOOL_SORT);
        arena.intern_typed(4, vec![left], BOOL_SORT);
        assert_eq!(boolean_valued_application_pairs(&arena), Some(1));
    }

    #[test]
    fn compiler_and_checker_agree_on_missing_equality_congruence() {
        let source = r#"
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun a () U)
            (declare-fun b () U)
            (declare-fun c () U)
            (declare-fun f (U) U)
            (assert (= a b))
            (assert (= b c))
            (assert (distinct (f a) (f c)))
            (check-sat)
        "#;
        let problem =
            crate::parse_problem_with_scoped_let_mode(source, crate::ScopedLetMode::Auto).unwrap();
        let bool_problem = problem.bool_problem.as_ref().unwrap();
        let (cnf, _, _, _) = crate::build_pinned_projection_baseline(&problem, bool_problem);
        let mut selected = selector(EqresMode::CliqueErAuto, SelectorDecision::Selected);
        selected.facts.backend = SolverBackend::Kissat;

        let bundle = execute_projection(
            selected,
            input_view(source.as_bytes(), &problem, &cnf),
            CompilerVariant::Ordinary,
        )
        .unwrap();
        let (expected_atom_map, expected_cnf, expected_problem) =
            crate::t10_ackermann::canonical_baseline_hashes_for_test(&cnf);
        assert_eq!(
            bundle.compiler.hashes.source_sha256.to_string(),
            crate::t10_ackermann::raw_sha256_for_test(source.as_bytes())
        );
        assert_eq!(
            bundle.compiler.hashes.root_cnf_mode_sha256.to_string(),
            crate::t10_ackermann::raw_sha256_for_test(ROOT_CNF_MODE)
        );
        assert_eq!(
            bundle.compiler.hashes.atom_map_sha256.to_string(),
            expected_atom_map
        );
        assert_eq!(
            bundle.compiler.hashes.baseline_cnf_sha256.to_string(),
            expected_cnf
        );
        assert_eq!(
            bundle.compiler.hashes.baseline_problem_sha256.to_string(),
            expected_problem
        );
        assert_eq!(
            bundle.compiler.hashes.lemma_sequence_sha256,
            bundle.compiler.hashes.materialized_lemmas_sha256
        );
        assert!(matches!(
            bundle.compiler.status,
            CompilerStatus::Completed(EqresOutput::TheoryEmpty { .. })
        ));
        assert!(
            matches!(bundle.checker.status, CheckerStatus::Accepted),
            "checker rejected compiler trace\ncompiler hashes: {:#?}\nchecker: {:#?}",
            bundle.compiler.hashes,
            bundle.checker,
        );
        assert!(bundle.report.integrity.compiler_checker_agree);
        assert!(
            bundle
                .report
                .counters
                .output
                .emitted_with_missing_equality_congruence
                > 0
        );
        assert!(internally_accepted_projection(&bundle));

        let mut forged_external_acceptance = bundle.clone();
        forged_external_acceptance
            .report
            .integrity
            .external_audit_accepted = true;
        assert!(!internally_accepted_projection(&forged_external_acceptance));

        let mut stale_report = bundle.clone();
        stale_report.report.counters.search.events_popped += 1;
        assert!(!internally_accepted_projection(&stale_report));
    }
}
