use super::{BOOL_SORT, BoolAtomKey, BoolExpr, FunDecl, Problem, SortId, SymId, TermId};
use rustc_hash::FxHashMap as HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScoutQuotient {
    MaximallyDiverse,
    SingleClass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScoutBoolFill {
    AllFalse,
    AllTrue,
}

impl ScoutBoolFill {
    fn value(self) -> bool {
        matches!(self, Self::AllTrue)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ScoutSelection {
    pub(crate) quotient: ScoutQuotient,
    pub(crate) bool_fill: ScoutBoolFill,
}

const SCOUT_SUITE: [ScoutSelection; 4] = [
    ScoutSelection {
        quotient: ScoutQuotient::MaximallyDiverse,
        bool_fill: ScoutBoolFill::AllFalse,
    },
    ScoutSelection {
        quotient: ScoutQuotient::MaximallyDiverse,
        bool_fill: ScoutBoolFill::AllTrue,
    },
    ScoutSelection {
        quotient: ScoutQuotient::SingleClass,
        bool_fill: ScoutBoolFill::AllFalse,
    },
    ScoutSelection {
        quotient: ScoutQuotient::SingleClass,
        bool_fill: ScoutBoolFill::AllTrue,
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct ScoutValue {
    pub(crate) sort: SortId,
    pub(crate) element: usize,
}

impl ScoutValue {
    const FALSE: Self = Self {
        sort: BOOL_SORT,
        element: 0,
    };
    const TRUE: Self = Self {
        sort: BOOL_SORT,
        element: 1,
    };

    fn as_bool(self) -> Option<bool> {
        if self.sort != BOOL_SORT {
            return None;
        }
        match self.element {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScoutFunctionEntry {
    pub(crate) arguments: Vec<ScoutValue>,
    pub(crate) result: ScoutValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScoutFunction {
    pub(crate) fun: SymId,
    pub(crate) argument_sorts: Vec<SortId>,
    pub(crate) result_sort: SortId,
    pub(crate) default_result: ScoutValue,
    pub(crate) entries: Vec<ScoutFunctionEntry>,
}

impl ScoutFunction {
    fn apply(&self, arguments: &[ScoutValue]) -> Option<ScoutValue> {
        if arguments.len() != self.argument_sorts.len()
            || arguments
                .iter()
                .zip(&self.argument_sorts)
                .any(|(value, expected)| value.sort != *expected)
        {
            return None;
        }
        Some(
            self.entries
                .iter()
                .find(|entry| entry.arguments == arguments)
                .map_or(self.default_result, |entry| entry.result),
        )
    }
}

/// A finite, total interpretation. Function entries override a typed default,
/// so even tuples not represented by ground terms have a defined result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScoutModel {
    pub(crate) selection: ScoutSelection,
    pub(crate) domain_sizes: Vec<usize>,
    pub(crate) term_values: Vec<ScoutValue>,
    pub(crate) functions: Vec<Option<ScoutFunction>>,
}

impl ScoutModel {
    pub(crate) fn value_of(&self, term: TermId) -> Option<ScoutValue> {
        self.term_values.get(term).copied()
    }

    pub(crate) fn function_value(
        &self,
        fun: SymId,
        arguments: &[ScoutValue],
    ) -> Option<ScoutValue> {
        for value in arguments {
            let domain_size = *self.domain_sizes.get(value.sort.0 as usize)?;
            if value.element >= domain_size {
                return None;
            }
        }
        self.functions.get(fun as usize)?.as_ref()?.apply(arguments)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScoutIneligibleReason {
    Contradiction,
    UnsupportedSource,
    IllSortedTerms,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ScoutTelemetry {
    pub(crate) ineligible: Option<ScoutIneligibleReason>,
    pub(crate) candidates_attempted: usize,
    pub(crate) candidates_built: usize,
    pub(crate) candidate_build_failures: usize,
    pub(crate) models_validated: usize,
    pub(crate) model_validation_failures: usize,
    pub(crate) source_rejections: usize,
    pub(crate) source_evaluation_failures: usize,
    pub(crate) initial_quotient_merges: usize,
    pub(crate) congruence_merges: usize,
    pub(crate) congruence_rounds: usize,
    pub(crate) hit: Option<ScoutSelection>,
    pub(crate) hit_function_entries: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScoutOutcome {
    pub(crate) model: Option<ScoutModel>,
    pub(crate) telemetry: ScoutTelemetry,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ScoutModelError {
    DomainCount,
    BooleanDomainSize,
    EmptyDomain(SortId),
    TermCount,
    TermValue(TermId),
    FunctionSlotCount,
    UnexpectedFunction(SymId),
    MissingFunction(SymId),
    FunctionShape(SymId),
    FunctionDefault(SymId),
    FunctionEntry(SymId, usize),
    DuplicateFunctionInput(SymId, usize),
    GroundTermMismatch(TermId),
    CongruenceViolation(TermId, TermId),
    BooleanAnchor(TermId),
    TrueFalseNotSeparated,
    BooleanDataTerm(TermId),
}

#[derive(Debug, Clone, Copy, Default)]
struct CandidateBuildStats {
    initial_merges: usize,
    congruence_merges: usize,
    congruence_rounds: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CandidateBuildError {
    BooleanAnchor,
    CongruenceCollapsedBooleans,
    MissingDeclaration,
    InconsistentFunctionGraph,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CongruenceKey {
    fun: SymId,
    arguments: Vec<TermId>,
}

#[derive(Debug, Clone)]
struct TermPartition {
    parent: Vec<TermId>,
    rank: Vec<u8>,
}

impl TermPartition {
    fn new(size: usize) -> Self {
        Self {
            parent: (0..size).collect(),
            rank: vec![0; size],
        }
    }

    fn find(&mut self, term: TermId) -> TermId {
        let parent = self.parent[term];
        if parent != term {
            self.parent[term] = self.find(parent);
        }
        self.parent[term]
    }

    fn union(&mut self, left: TermId, right: TermId) -> bool {
        let mut left = self.find(left);
        let mut right = self.find(right);
        if left == right {
            return false;
        }
        if self.rank[left] < self.rank[right] {
            std::mem::swap(&mut left, &mut right);
        }
        self.parent[right] = left;
        if self.rank[left] == self.rank[right] {
            self.rank[left] = self.rank[left].saturating_add(1);
        }
        true
    }
}

pub(crate) fn scout_sat_model(problem: &Problem) -> ScoutOutcome {
    let mut telemetry = ScoutTelemetry::default();
    telemetry.ineligible = scout_ineligibility(problem);
    if telemetry.ineligible.is_some() {
        return ScoutOutcome {
            model: None,
            telemetry,
        };
    }

    for selection in SCOUT_SUITE {
        telemetry.candidates_attempted += 1;
        let (model, stats) = match build_candidate(problem, selection) {
            Ok(candidate) => candidate,
            Err(_) => {
                telemetry.candidate_build_failures += 1;
                continue;
            }
        };
        telemetry.candidates_built += 1;
        telemetry.initial_quotient_merges += stats.initial_merges;
        telemetry.congruence_merges += stats.congruence_merges;
        telemetry.congruence_rounds += stats.congruence_rounds;

        if validate_scout_model(problem, &model).is_err() {
            telemetry.model_validation_failures += 1;
            continue;
        }
        telemetry.models_validated += 1;

        match model_satisfies_source(problem, &model) {
            Some(true) => {
                telemetry.hit = Some(selection);
                telemetry.hit_function_entries = model
                    .functions
                    .iter()
                    .flatten()
                    .map(|function| function.entries.len())
                    .sum();
                return ScoutOutcome {
                    model: Some(model),
                    telemetry,
                };
            }
            Some(false) => telemetry.source_rejections += 1,
            None => telemetry.source_evaluation_failures += 1,
        }
    }

    ScoutOutcome {
        model: None,
        telemetry,
    }
}

fn scout_ineligibility(problem: &Problem) -> Option<ScoutIneligibleReason> {
    if problem.contradiction {
        return Some(ScoutIneligibleReason::Contradiction);
    }
    if !problem.unsupported.is_empty()
        || problem
            .bool_problem
            .as_ref()
            .is_some_and(|bool_problem| !bool_problem.unsupported.is_empty())
    {
        return Some(ScoutIneligibleReason::UnsupportedSource);
    }
    if !problem.terms_are_well_sorted() {
        return Some(ScoutIneligibleReason::IllSortedTerms);
    }
    None
}

fn build_candidate(
    problem: &Problem,
    selection: ScoutSelection,
) -> Result<(ScoutModel, CandidateBuildStats), CandidateBuildError> {
    let term_count = problem.arena.terms.len();
    let sort_count = problem.sorts.names.len();
    let mut partition = TermPartition::new(term_count);
    let mut stats = CandidateBuildStats::default();

    let bool_anchors = problem
        .bool_problem
        .as_ref()
        .map(|bool_problem| (bool_problem.false_term, bool_problem.true_term));
    if let Some((false_term, true_term)) = bool_anchors {
        if false_term >= term_count
            || true_term >= term_count
            || problem.arena.terms[false_term].sort != BOOL_SORT
            || problem.arena.terms[true_term].sort != BOOL_SORT
            || false_term == true_term
        {
            return Err(CandidateBuildError::BooleanAnchor);
        }
        let target = if selection.bool_fill.value() {
            true_term
        } else {
            false_term
        };
        for (term_id, term) in problem.arena.terms.iter().enumerate() {
            if term.sort == BOOL_SORT
                && term_id != false_term
                && term_id != true_term
                && partition.union(target, term_id)
            {
                stats.initial_merges += 1;
            }
        }
    } else {
        let mut first_bool = None;
        for (term_id, term) in problem.arena.terms.iter().enumerate() {
            if term.sort != BOOL_SORT {
                continue;
            }
            if let Some(first) = first_bool {
                if partition.union(first, term_id) {
                    stats.initial_merges += 1;
                }
            } else {
                first_bool = Some(term_id);
            }
        }
    }

    if selection.quotient == ScoutQuotient::SingleClass {
        let mut first_by_sort = vec![None; sort_count];
        for (term_id, term) in problem.arena.terms.iter().enumerate() {
            if term.sort == BOOL_SORT {
                continue;
            }
            let slot = &mut first_by_sort[term.sort.0 as usize];
            if let Some(first) = *slot {
                if partition.union(first, term_id) {
                    stats.initial_merges += 1;
                }
            } else {
                *slot = Some(term_id);
            }
        }
    }

    loop {
        stats.congruence_rounds += 1;
        let mut signatures: HashMap<CongruenceKey, TermId> = HashMap::default();
        let mut changed = false;
        for (term_id, term) in problem.arena.terms.iter().enumerate() {
            let arguments = term
                .args
                .iter()
                .map(|&argument| partition.find(argument))
                .collect();
            let key = CongruenceKey {
                fun: term.fun,
                arguments,
            };
            if let Some(&prior) = signatures.get(&key) {
                if partition.union(prior, term_id) {
                    stats.congruence_merges += 1;
                    changed = true;
                }
            } else {
                signatures.insert(key, term_id);
            }
        }
        if !changed {
            break;
        }
    }

    let bool_roots = if let Some((false_term, true_term)) = bool_anchors {
        let false_root = partition.find(false_term);
        let true_root = partition.find(true_term);
        if false_root == true_root {
            return Err(CandidateBuildError::CongruenceCollapsedBooleans);
        }
        Some((false_root, true_root))
    } else {
        None
    };

    let mut domain_sizes = vec![1; sort_count];
    domain_sizes[BOOL_SORT.0 as usize] = 2;
    let mut next_element = vec![0; sort_count];
    let mut class_values: HashMap<(SortId, TermId), usize> = HashMap::default();
    let mut term_values = Vec::with_capacity(term_count);
    for (term_id, term) in problem.arena.terms.iter().enumerate() {
        let value = if term.sort == BOOL_SORT {
            if let Some((false_root, true_root)) = bool_roots {
                let root = partition.find(term_id);
                if root == false_root {
                    ScoutValue::FALSE
                } else if root == true_root {
                    ScoutValue::TRUE
                } else {
                    return Err(CandidateBuildError::BooleanAnchor);
                }
            } else if selection.bool_fill.value() {
                ScoutValue::TRUE
            } else {
                ScoutValue::FALSE
            }
        } else {
            let root = partition.find(term_id);
            let element = *class_values.entry((term.sort, root)).or_insert_with(|| {
                let slot = &mut next_element[term.sort.0 as usize];
                let element = *slot;
                *slot += 1;
                element
            });
            ScoutValue {
                sort: term.sort,
                element,
            }
        };
        term_values.push(value);
    }
    for sort in 1..sort_count {
        domain_sizes[sort] = next_element[sort].max(1);
    }

    let mut functions = problem
        .fun_decls
        .slots
        .iter()
        .enumerate()
        .map(|(fun, declaration)| {
            declaration.as_ref().map(|declaration| ScoutFunction {
                fun: fun as SymId,
                argument_sorts: declaration.arg_sorts.clone(),
                result_sort: declaration.result_sort,
                default_result: ScoutValue {
                    sort: declaration.result_sort,
                    element: 0,
                },
                entries: Vec::new(),
            })
        })
        .collect::<Vec<_>>();

    for (term_id, term) in problem.arena.terms.iter().enumerate() {
        let function = functions
            .get_mut(term.fun as usize)
            .and_then(Option::as_mut)
            .ok_or(CandidateBuildError::MissingDeclaration)?;
        let arguments = term
            .args
            .iter()
            .map(|&argument| term_values[argument])
            .collect::<Vec<_>>();
        let result = term_values[term_id];
        if let Some(entry) = function
            .entries
            .iter()
            .find(|entry| entry.arguments == arguments)
        {
            if entry.result != result {
                return Err(CandidateBuildError::InconsistentFunctionGraph);
            }
        } else {
            function
                .entries
                .push(ScoutFunctionEntry { arguments, result });
        }
    }

    Ok((
        ScoutModel {
            selection,
            domain_sizes,
            term_values,
            functions,
        },
        stats,
    ))
}

pub(crate) fn validate_scout_model(
    problem: &Problem,
    model: &ScoutModel,
) -> Result<(), ScoutModelError> {
    if model.domain_sizes.len() != problem.sorts.names.len() {
        return Err(ScoutModelError::DomainCount);
    }
    if model.domain_sizes.get(BOOL_SORT.0 as usize) != Some(&2) {
        return Err(ScoutModelError::BooleanDomainSize);
    }
    for (sort, &size) in model.domain_sizes.iter().enumerate() {
        if size == 0 {
            return Err(ScoutModelError::EmptyDomain(SortId(sort as u32)));
        }
    }
    if model.term_values.len() != problem.arena.terms.len() {
        return Err(ScoutModelError::TermCount);
    }
    for (term_id, (term, value)) in problem
        .arena
        .terms
        .iter()
        .zip(&model.term_values)
        .enumerate()
    {
        if !value_is_in_model(model, *value) || value.sort != term.sort {
            return Err(ScoutModelError::TermValue(term_id));
        }
    }

    if let Some(bool_problem) = &problem.bool_problem {
        let Some(false_value) = model.value_of(bool_problem.false_term) else {
            return Err(ScoutModelError::BooleanAnchor(bool_problem.false_term));
        };
        let Some(true_value) = model.value_of(bool_problem.true_term) else {
            return Err(ScoutModelError::BooleanAnchor(bool_problem.true_term));
        };
        if false_value == true_value {
            return Err(ScoutModelError::TrueFalseNotSeparated);
        }
        if false_value != ScoutValue::FALSE {
            return Err(ScoutModelError::BooleanAnchor(bool_problem.false_term));
        }
        if true_value != ScoutValue::TRUE {
            return Err(ScoutModelError::BooleanAnchor(bool_problem.true_term));
        }
        for &term in &bool_problem.data_terms {
            if problem.arena.terms.get(term).map(|term| term.sort) != Some(BOOL_SORT) {
                return Err(ScoutModelError::BooleanDataTerm(term));
            }
        }
    }

    if model.functions.len() != problem.fun_decls.slots.len() {
        return Err(ScoutModelError::FunctionSlotCount);
    }
    for (index, (declaration, function)) in problem
        .fun_decls
        .slots
        .iter()
        .zip(&model.functions)
        .enumerate()
    {
        let fun = index as SymId;
        match (declaration, function) {
            (None, None) => {}
            (None, Some(_)) => return Err(ScoutModelError::UnexpectedFunction(fun)),
            (Some(_), None) => return Err(ScoutModelError::MissingFunction(fun)),
            (Some(declaration), Some(function)) => {
                validate_function(model, fun, declaration, function)?;
            }
        }
    }

    let mut ground_signatures: HashMap<(SymId, Vec<ScoutValue>), (TermId, ScoutValue)> =
        HashMap::default();
    for (term_id, term) in problem.arena.terms.iter().enumerate() {
        let arguments = term
            .args
            .iter()
            .map(|&argument| model.term_values[argument])
            .collect::<Vec<_>>();
        let result = model.term_values[term_id];
        let Some(interpreted) = model.function_value(term.fun, &arguments) else {
            return Err(ScoutModelError::GroundTermMismatch(term_id));
        };
        if interpreted != result {
            return Err(ScoutModelError::GroundTermMismatch(term_id));
        }
        if let Some(&(prior_term, prior_result)) =
            ground_signatures.get(&(term.fun, arguments.clone()))
        {
            if prior_result != result {
                return Err(ScoutModelError::CongruenceViolation(prior_term, term_id));
            }
        } else {
            ground_signatures.insert((term.fun, arguments), (term_id, result));
        }
    }
    Ok(())
}

fn validate_function(
    model: &ScoutModel,
    fun: SymId,
    declaration: &FunDecl,
    function: &ScoutFunction,
) -> Result<(), ScoutModelError> {
    if function.fun != fun
        || function.argument_sorts != declaration.arg_sorts
        || function.result_sort != declaration.result_sort
    {
        return Err(ScoutModelError::FunctionShape(fun));
    }
    if !value_is_in_model(model, function.default_result)
        || function.default_result.sort != declaration.result_sort
    {
        return Err(ScoutModelError::FunctionDefault(fun));
    }
    let mut inputs: HashMap<Vec<ScoutValue>, usize> = HashMap::default();
    for (entry_index, entry) in function.entries.iter().enumerate() {
        let arguments_valid = entry.arguments.len() == declaration.arg_sorts.len()
            && entry
                .arguments
                .iter()
                .zip(&declaration.arg_sorts)
                .all(|(value, sort)| value.sort == *sort && value_is_in_model(model, *value));
        if !arguments_valid
            || entry.result.sort != declaration.result_sort
            || !value_is_in_model(model, entry.result)
        {
            return Err(ScoutModelError::FunctionEntry(fun, entry_index));
        }
        if let Some(&prior) = inputs.get(&entry.arguments) {
            return Err(ScoutModelError::DuplicateFunctionInput(fun, prior));
        }
        inputs.insert(entry.arguments.clone(), entry_index);
    }
    Ok(())
}

fn value_is_in_model(model: &ScoutModel, value: ScoutValue) -> bool {
    model
        .domain_sizes
        .get(value.sort.0 as usize)
        .is_some_and(|&size| value.element < size)
}

pub(crate) fn evaluate_source_bool(model: &ScoutModel, expression: &BoolExpr) -> Option<bool> {
    match expression {
        BoolExpr::Const(value) => Some(*value),
        BoolExpr::Atom(BoolAtomKey::Eq(left, right)) => {
            let left = model.value_of(*left)?;
            let right = model.value_of(*right)?;
            (left.sort == right.sort).then_some(left == right)
        }
        BoolExpr::Atom(BoolAtomKey::BoolTerm(term)) => model.value_of(*term)?.as_bool(),
        BoolExpr::Not(child) => Some(!evaluate_source_bool(model, child)?),
        BoolExpr::And(children) => {
            let mut result = true;
            for child in children {
                result &= evaluate_source_bool(model, child)?;
            }
            Some(result)
        }
        BoolExpr::Or(children) => {
            let mut result = false;
            for child in children {
                result |= evaluate_source_bool(model, child)?;
            }
            Some(result)
        }
        BoolExpr::Iff(children) => {
            let Some((first, rest)) = children.split_first() else {
                return Some(true);
            };
            let first = evaluate_source_bool(model, first)?;
            let mut result = true;
            for child in rest {
                result &= evaluate_source_bool(model, child)? == first;
            }
            Some(result)
        }
        BoolExpr::Ite(condition, then_expression, else_expression) => {
            let condition = evaluate_source_bool(model, condition)?;
            let then_value = evaluate_source_bool(model, then_expression)?;
            let else_value = evaluate_source_bool(model, else_expression)?;
            Some(if condition { then_value } else { else_value })
        }
    }
}

fn model_satisfies_source(problem: &Problem, model: &ScoutModel) -> Option<bool> {
    let mut result = true;
    for &(left, right) in &problem.eqs {
        result &= terms_equal(model, left, right)?;
    }
    for &(left, right) in &problem.diseqs {
        result &= !terms_equal(model, left, right)?;
    }
    if let Some(bool_problem) = &problem.bool_problem {
        for assertion in &bool_problem.assertions {
            result &= evaluate_source_bool(model, assertion)?;
        }
    }
    Some(result)
}

fn terms_equal(model: &ScoutModel, left: TermId, right: TermId) -> Option<bool> {
    let left = model.value_of(left)?;
    let right = model.value_of(right)?;
    (left.sort == right.sort).then_some(left == right)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ScopedLetMode, parse_problem_with_scoped_let_mode};

    fn parse(input: &str) -> Problem {
        parse_problem_with_scoped_let_mode(input, ScopedLetMode::Off).unwrap()
    }

    fn only_model(input: &str) -> ScoutOutcome {
        let problem = parse(input);
        let outcome = scout_sat_model(&problem);
        if let Some(model) = &outcome.model {
            validate_scout_model(&problem, model).unwrap();
        }
        outcome
    }

    #[test]
    fn maximally_diverse_quotient_hits_disequality() {
        let outcome = only_model(
            "(set-logic QF_UF)
             (declare-sort U 0)
             (declare-fun a () U)
             (declare-fun b () U)
             (assert (distinct a b))
             (check-sat)",
        );

        assert_eq!(
            outcome.telemetry.hit,
            Some(ScoutSelection {
                quotient: ScoutQuotient::MaximallyDiverse,
                bool_fill: ScoutBoolFill::AllFalse,
            })
        );
        assert_eq!(outcome.telemetry.candidates_attempted, 1);
        assert_eq!(outcome.telemetry.models_validated, 1);
        assert!(outcome.model.is_some());
    }

    #[test]
    fn single_class_quotient_hits_positive_equality() {
        let outcome = only_model(
            "(set-logic QF_UF)
             (declare-sort U 0)
             (declare-fun a () U)
             (declare-fun b () U)
             (assert (= a b))
             (check-sat)",
        );

        assert_eq!(
            outcome.telemetry.hit,
            Some(ScoutSelection {
                quotient: ScoutQuotient::SingleClass,
                bool_fill: ScoutBoolFill::AllFalse,
            })
        );
        assert_eq!(outcome.telemetry.candidates_attempted, 3);
        assert_eq!(outcome.telemetry.source_rejections, 2);
    }

    #[test]
    fn mixed_quotient_sat_formula_is_a_required_miss() {
        let outcome = only_model(
            "(set-logic QF_UF)
             (declare-sort U 0)
             (declare-fun a () U)
             (declare-fun b () U)
             (declare-fun c () U)
             (assert (and (= a b) (distinct b c)))
             (check-sat)",
        );

        assert!(outcome.model.is_none());
        assert_eq!(outcome.telemetry.candidates_attempted, 4);
        assert_eq!(outcome.telemetry.models_validated, 4);
        assert_eq!(outcome.telemetry.source_rejections, 4);
    }

    #[test]
    fn contradictory_formula_can_only_miss() {
        let outcome = only_model(
            "(set-logic QF_UF)
             (declare-sort U 0)
             (declare-fun a () U)
             (declare-fun b () U)
             (assert (= a b))
             (assert (distinct a b))
             (check-sat)",
        );

        assert!(outcome.model.is_none());
        assert_eq!(outcome.telemetry.candidates_attempted, 4);
        assert_eq!(outcome.telemetry.source_rejections, 4);
    }

    #[test]
    fn bool_as_data_closes_non_boolean_function_results() {
        let problem = parse(
            "(set-logic QF_UF)
             (declare-sort U 0)
             (declare-fun p () Bool)
             (declare-fun q () Bool)
             (declare-fun f (Bool) U)
             (assert (= (f p) (f q)))
             (check-sat)",
        );
        let outcome = scout_sat_model(&problem);
        let model = outcome.model.as_ref().unwrap();

        validate_scout_model(&problem, model).unwrap();
        assert_eq!(
            outcome.telemetry.hit.unwrap().bool_fill,
            ScoutBoolFill::AllFalse
        );
        let applications = problem
            .arena
            .terms
            .iter()
            .enumerate()
            .filter(|(_, term)| term.args.len() == 1 && term.sort != BOOL_SORT)
            .map(|(term, _)| term)
            .collect::<Vec<_>>();
        assert_eq!(applications.len(), 2);
        assert_eq!(
            model.value_of(applications[0]),
            model.value_of(applications[1])
        );
        assert!(outcome.telemetry.congruence_merges > 0);
    }

    #[test]
    fn bool_as_data_split_required_by_sat_formula_is_a_miss() {
        let outcome = only_model(
            "(set-logic QF_UF)
             (declare-sort U 0)
             (declare-fun p () Bool)
             (declare-fun q () Bool)
             (declare-fun f (Bool) U)
             (assert (distinct (f p) (f q)))
             (check-sat)",
        );

        assert!(outcome.model.is_none());
        assert_eq!(outcome.telemetry.models_validated, 4);
    }

    #[test]
    fn bool_data_pigeonhole_unsat_is_never_a_hit() {
        let outcome = only_model(
            "(set-logic QF_UF)
             (declare-sort U 0)
             (declare-fun p () Bool)
             (declare-fun q () Bool)
             (declare-fun r () Bool)
             (declare-fun f (Bool) U)
             (assert (distinct (f p) (f q) (f r)))
             (check-sat)",
        );

        assert!(outcome.model.is_none());
        assert_eq!(outcome.telemetry.candidates_attempted, 4);
        assert_eq!(outcome.telemetry.model_validation_failures, 0);
    }

    #[test]
    fn nested_boolean_ufs_use_the_all_true_cross_product_arm() {
        let problem = parse(
            "(set-logic QF_UF)
             (declare-fun p () Bool)
             (declare-fun g (Bool) Bool)
             (declare-fun h (Bool) Bool)
             (assert (h (g p)))
             (check-sat)",
        );
        let outcome = scout_sat_model(&problem);
        let model = outcome.model.as_ref().unwrap();

        assert_eq!(
            outcome.telemetry.hit,
            Some(ScoutSelection {
                quotient: ScoutQuotient::MaximallyDiverse,
                bool_fill: ScoutBoolFill::AllTrue,
            })
        );
        assert_eq!(outcome.telemetry.candidates_attempted, 2);
        assert!(
            problem
                .arena
                .terms
                .iter()
                .enumerate()
                .filter(|(term, node)| {
                    node.sort == BOOL_SORT
                        && Some(*term) != problem.bool_problem.as_ref().map(|p| p.true_term)
                        && Some(*term) != problem.bool_problem.as_ref().map(|p| p.false_term)
                })
                .all(|(term, _)| model.value_of(term) == Some(ScoutValue::TRUE))
        );
    }

    #[test]
    fn source_evaluator_covers_all_boolean_connectives() {
        let problem = parse(
            "(set-logic QF_UF)
             (declare-fun p () Bool)
             (assert (and (or p (not p)) (= p p) (ite p true true)))
             (check-sat)",
        );
        let outcome = scout_sat_model(&problem);
        let model = outcome.model.as_ref().unwrap();
        let bool_problem = problem.bool_problem.as_ref().unwrap();

        assert!(
            bool_problem
                .assertions
                .iter()
                .all(|assertion| evaluate_source_bool(model, assertion) == Some(true))
        );
    }

    #[test]
    fn congruence_contradiction_is_a_required_miss() {
        let outcome = only_model(
            "(set-logic QF_UF)
             (declare-sort U 0)
             (declare-fun a () U)
             (declare-fun b () U)
             (declare-fun f (U) U)
             (assert (and (= a b) (distinct (f a) (f b))))
             (check-sat)",
        );

        assert!(outcome.model.is_none());
        assert_eq!(outcome.telemetry.model_validation_failures, 0);
        assert!(outcome.telemetry.initial_quotient_merges > 0);
    }

    #[test]
    fn model_is_typed_and_total_across_multiple_sorts() {
        let problem = parse(
            "(set-logic QF_UF)
             (declare-sort U 0)
             (declare-sort V 0)
             (declare-sort W 0)
             (declare-fun a () U)
             (declare-fun b () U)
             (declare-fun x () V)
             (declare-fun y () V)
             (declare-fun unused (U W) U)
             (assert (and (distinct a b) (distinct x y)))
             (check-sat)",
        );
        let outcome = scout_sat_model(&problem);
        let model = outcome.model.as_ref().unwrap();

        validate_scout_model(&problem, model).unwrap();
        assert_eq!(model.domain_sizes.len(), 4);
        assert_eq!(model.domain_sizes[0], 2);
        assert!(model.domain_sizes[1] >= 2);
        assert!(model.domain_sizes[2] >= 2);
        assert_eq!(model.domain_sizes[3], 1);
        let unused = model
            .functions
            .iter()
            .flatten()
            .find(|function| function.argument_sorts.len() == 2)
            .unwrap();
        assert!(unused.entries.is_empty());
        let arguments = [
            ScoutValue {
                sort: unused.argument_sorts[0],
                element: model.domain_sizes[unused.argument_sorts[0].0 as usize] - 1,
            },
            ScoutValue {
                sort: unused.argument_sorts[1],
                element: model.domain_sizes[unused.argument_sorts[1].0 as usize] - 1,
            },
        ];
        assert_eq!(
            model.function_value(unused.fun, &arguments),
            Some(unused.default_result)
        );
    }

    #[test]
    fn validator_is_independent_from_source_acceptance() {
        let problem = parse(
            "(set-logic QF_UF)
             (declare-sort U 0)
             (declare-fun a () U)
             (declare-fun b () U)
             (assert (= a b))
             (check-sat)",
        );
        let selection = ScoutSelection {
            quotient: ScoutQuotient::MaximallyDiverse,
            bool_fill: ScoutBoolFill::AllFalse,
        };
        let (model, _) = build_candidate(&problem, selection).unwrap();

        validate_scout_model(&problem, &model).unwrap();
        assert_eq!(model_satisfies_source(&problem, &model), Some(false));
    }

    #[test]
    fn validator_rejects_true_false_collapse_and_function_corruption() {
        let problem = parse(
            "(set-logic QF_UF)
             (declare-sort U 0)
             (declare-fun a () U)
             (declare-fun b () U)
             (assert (distinct a b))
             (check-sat)",
        );
        let outcome = scout_sat_model(&problem);
        let model = outcome.model.unwrap();
        let bool_problem = problem.bool_problem.as_ref().unwrap();

        let mut collapsed = model.clone();
        collapsed.term_values[bool_problem.true_term] = ScoutValue::FALSE;
        assert_eq!(
            validate_scout_model(&problem, &collapsed),
            Err(ScoutModelError::TrueFalseNotSeparated)
        );

        let mut corrupted = model;
        let (term_id, term) = problem
            .arena
            .terms
            .iter()
            .enumerate()
            .find(|(_, term)| term.sort != BOOL_SORT)
            .unwrap();
        let function = corrupted.functions[term.fun as usize].as_mut().unwrap();
        let entry = function.entries.first_mut().unwrap();
        entry.result.element =
            (entry.result.element + 1) % corrupted.domain_sizes[entry.result.sort.0 as usize];
        assert_eq!(
            validate_scout_model(&problem, &corrupted),
            Err(ScoutModelError::GroundTermMismatch(term_id))
        );
    }

    #[test]
    fn scout_order_and_models_are_deterministic() {
        let problem = parse(
            "(set-logic QF_UF)
             (declare-sort U 0)
             (declare-sort V 0)
             (declare-fun p () Bool)
             (declare-fun a () U)
             (declare-fun b () U)
             (declare-fun f (Bool U) V)
             (assert (and (distinct a b) (= (f p a) (f p a))))
             (check-sat)",
        );

        let first = scout_sat_model(&problem);
        let second = scout_sat_model(&problem);
        assert_eq!(first, second);
    }

    #[test]
    fn contradiction_flag_is_ineligible_not_unsat() {
        let mut problem = parse("(set-logic QF_UF) (check-sat)");
        problem.contradiction = true;
        let outcome = scout_sat_model(&problem);

        assert!(outcome.model.is_none());
        assert_eq!(
            outcome.telemetry.ineligible,
            Some(ScoutIneligibleReason::Contradiction)
        );
        assert_eq!(outcome.telemetry.candidates_attempted, 0);
    }
}
