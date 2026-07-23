#![forbid(unsafe_code)]

//! Deterministic generated differentials for the Fabric research engines.
//!
//! Cases are random-access: a generator version, campaign seed, and case ID
//! identify one problem without replaying the campaign prefix. The runner owns
//! no corpus-sized collection and stops at the first disagreement.

use super::component::{ComponentBuilder, ComponentError, ComponentId};
use super::engine::{
    EngineCaps, ReferenceOutcome, solve_incremental_action_nogood_reference,
    solve_incremental_learned_reference, solve_incremental_reference,
    solve_incremental_watched_reference, solve_reference,
};
use super::finite_oracle::{
    self, MAX_ASSERTIONS as ORACLE_MAX_ASSERTIONS, MAX_ATOMS as ORACLE_MAX_ATOMS,
    MAX_EXPRESSION_DEPTH as ORACLE_MAX_EXPRESSION_DEPTH,
    MAX_EXPRESSION_NODES as ORACLE_MAX_EXPRESSION_NODES,
    MAX_GROUND_TERMS as ORACLE_MAX_GROUND_TERMS, MAX_ROOT_LITERALS as ORACLE_MAX_ROOT_LITERALS,
    MAX_SEMANTIC_TERMS as ORACLE_MAX_SEMANTIC_TERMS,
    MAX_TERM_ARGUMENTS as ORACLE_MAX_TERM_ARGUMENTS, OracleOutcome,
};
use super::native_clause::AtomId;
use super::partition::TermId;
use super::semantic::{
    RootLiteral, SemanticAtom, SemanticExpr, SemanticProblem, SemanticStats, SemanticTerm,
};
use std::error::Error;
use std::fmt;

pub(crate) const GENERATOR_VERSION: u32 = 1;
pub(crate) const ONE_MILLION_CASES: u64 = 1_000_000;
pub(crate) const DEFAULT_CAMPAIGN_SEED: u64 = 0x6a09_e667_f3bc_c909;

const FAMILY_COUNT: u64 = 4;
const MAX_GENERATED_TERMS: usize = 6;
const FINGERPRINT_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FINGERPRINT_PRIME: u64 = 0x0000_0100_0000_01b3;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct CaseId(u64);

impl CaseId {
    pub(crate) const fn new(raw: u64) -> Self {
        Self(raw)
    }

    pub(crate) const fn raw(self) -> u64 {
        self.0
    }
}

impl fmt::Display for CaseId {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(output)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GeneratorFamily {
    Equality,
    Congruence,
    BooleanData,
    ManySorted,
}

impl GeneratorFamily {
    const fn from_index(index: u64) -> Self {
        match index {
            0 => Self::Equality,
            1 => Self::Congruence,
            2 => Self::BooleanData,
            _ => Self::ManySorted,
        }
    }

    const fn tag(self) -> &'static str {
        match self {
            Self::Equality => "equality",
            Self::Congruence => "congruence",
            Self::BooleanData => "boolean-data",
            Self::ManySorted => "many-sorted",
        }
    }
}

impl fmt::Display for GeneratorFamily {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str(self.tag())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GenerationCaps {
    pub(crate) max_terms: usize,
    pub(crate) max_argument_cells: usize,
    pub(crate) max_atoms: usize,
    pub(crate) max_assertions: usize,
    pub(crate) max_root_literals: usize,
    pub(crate) max_expression_nodes: usize,
    pub(crate) max_expression_depth: usize,
}

impl GenerationCaps {
    pub(crate) const fn finite_oracle() -> Self {
        Self {
            max_terms: ORACLE_MAX_SEMANTIC_TERMS,
            max_argument_cells: ORACLE_MAX_TERM_ARGUMENTS,
            max_atoms: ORACLE_MAX_ATOMS,
            max_assertions: ORACLE_MAX_ASSERTIONS,
            max_root_literals: ORACLE_MAX_ROOT_LITERALS,
            max_expression_nodes: ORACLE_MAX_EXPRESSION_NODES,
            max_expression_depth: ORACLE_MAX_EXPRESSION_DEPTH,
        }
    }
}

impl Default for GenerationCaps {
    fn default() -> Self {
        Self {
            max_terms: MAX_GENERATED_TERMS,
            max_argument_cells: 2,
            max_atoms: 8,
            max_assertions: 3,
            max_root_literals: 2,
            max_expression_nodes: 64,
            max_expression_depth: 4,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GenerationResource {
    Terms,
    TermIdentifiers,
    ArgumentCells,
    Atoms,
    Assertions,
    RootLiterals,
    ExpressionNodes,
    ExpressionDepth,
}

impl fmt::Display for GenerationResource {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str(match self {
            Self::Terms => "terms",
            Self::TermIdentifiers => "term identifiers",
            Self::ArgumentCells => "term argument cells",
            Self::Atoms => "atoms",
            Self::Assertions => "assertions",
            Self::RootLiterals => "root literals",
            Self::ExpressionNodes => "expression nodes",
            Self::ExpressionDepth => "expression depth",
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum GenerationError {
    CapExceeded {
        resource: GenerationResource,
        attempted: usize,
        limit: usize,
    },
    ArithmeticOverflow {
        resource: GenerationResource,
    },
    AllocationFailed {
        context: &'static str,
    },
    UnknownTerm {
        term: TermId,
        term_count: usize,
    },
    InconsistentFunctionSignature {
        function: u32,
    },
    IllSortedEquality {
        left: TermId,
        right: TermId,
    },
    MissingBooleanValues {
        term: TermId,
    },
    IllSortedBooleanTerm {
        term: TermId,
    },
    AtomOutOfRange {
        atom: AtomId,
        atom_count: usize,
    },
    Component(ComponentError),
    GeneratorVersionMismatch {
        witness: u32,
        current: u32,
    },
    GeneratorDrift {
        expected_case_seed: u64,
        actual_case_seed: u64,
        expected_fingerprint: u64,
        actual_fingerprint: u64,
    },
    Invariant(&'static str),
}

impl fmt::Display for GenerationError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapExceeded {
                resource,
                attempted,
                limit,
            } => write!(
                output,
                "generated Fabric {resource} cap exceeded: attempted {attempted}, limit {limit}"
            ),
            Self::ArithmeticOverflow { resource } => {
                write!(output, "generated Fabric {resource} count overflowed")
            }
            Self::AllocationFailed { context } => {
                write!(
                    output,
                    "allocation failed while building generated {context}"
                )
            }
            Self::UnknownTerm { term, term_count } => write!(
                output,
                "generated term {term} is outside the term range 0..{term_count}"
            ),
            Self::InconsistentFunctionSignature { function } => {
                write!(
                    output,
                    "generated function {function} has inconsistent signatures"
                )
            }
            Self::IllSortedEquality { left, right } => {
                write!(output, "generated equality {left} = {right} is ill-sorted")
            }
            Self::MissingBooleanValues { term } => {
                write!(
                    output,
                    "generated Boolean term {term} has no Boolean universe"
                )
            }
            Self::IllSortedBooleanTerm { term } => {
                write!(output, "generated Boolean term {term} has the wrong sort")
            }
            Self::AtomOutOfRange { atom, atom_count } => write!(
                output,
                "generated atom {} is outside the atom range 0..{atom_count}",
                atom.index()
            ),
            Self::Component(error) => error.fmt(output),
            Self::GeneratorVersionMismatch { witness, current } => write!(
                output,
                "witness uses generator version {witness}, current version is {current}"
            ),
            Self::GeneratorDrift {
                expected_case_seed,
                actual_case_seed,
                expected_fingerprint,
                actual_fingerprint,
            } => write!(
                output,
                "generated witness drifted: case seed {expected_case_seed:#018x}/{actual_case_seed:#018x}, fingerprint {expected_fingerprint:#018x}/{actual_fingerprint:#018x}"
            ),
            Self::Invariant(message) => output.write_str(message),
        }
    }
}

impl Error for GenerationError {}

impl From<ComponentError> for GenerationError {
    fn from(error: ComponentError) -> Self {
        Self::Component(error)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct GeneratedMetrics {
    pub(crate) terms: usize,
    pub(crate) argument_cells: usize,
    pub(crate) atoms: usize,
    pub(crate) assertions: usize,
    pub(crate) root_literals: usize,
    pub(crate) expression_nodes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GeneratedCase {
    pub(crate) generator_version: u32,
    pub(crate) campaign_seed: u64,
    pub(crate) case_id: CaseId,
    pub(crate) case_seed: u64,
    pub(crate) family: GeneratorFamily,
    pub(crate) problem_fingerprint: u64,
    pub(crate) oracle_applicable: bool,
    pub(crate) metrics: GeneratedMetrics,
    pub(crate) problem: SemanticProblem,
}

pub(crate) fn generate_case(
    campaign_seed: u64,
    case_id: CaseId,
    caps: GenerationCaps,
) -> Result<GeneratedCase, GenerationError> {
    let case_seed = derive_case_seed(campaign_seed, case_id);
    let family_offset = campaign_seed.rotate_left(17) % FAMILY_COUNT;
    let family =
        GeneratorFamily::from_index(case_id.raw().wrapping_add(family_offset) % FAMILY_COUNT);
    let mut random = SplitMix64::new(case_seed);
    let mut builder = ProblemBuilder::new(caps);

    match family {
        GeneratorFamily::Equality => generate_equality(&mut builder, &mut random)?,
        GeneratorFamily::Congruence => generate_congruence(&mut builder, &mut random)?,
        GeneratorFamily::BooleanData => generate_boolean_data(&mut builder, &mut random)?,
        GeneratorFamily::ManySorted => generate_many_sorted(&mut builder, &mut random)?,
    }
    populate_constraints(&mut builder, &mut random)?;
    let problem = builder.finish()?;
    let metrics = measure_problem(&problem)?;
    let problem_fingerprint = fingerprint_problem(family, &problem);
    let oracle_applicable = finite_oracle_applicable(&problem);

    Ok(GeneratedCase {
        generator_version: GENERATOR_VERSION,
        campaign_seed,
        case_id,
        case_seed,
        family,
        problem_fingerprint,
        oracle_applicable,
        metrics,
        problem,
    })
}

fn derive_case_seed(campaign_seed: u64, case_id: CaseId) -> u64 {
    let value = campaign_seed
        ^ case_id.raw().wrapping_mul(0x9e37_79b9_7f4a_7c15)
        ^ u64::from(GENERATOR_VERSION).wrapping_mul(0xd6e8_feb8_6659_fd93);
    mix64(value)
}

fn mix64(mut value: u64) -> u64 {
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        mix64(self.state)
    }

    fn bounded(&mut self, upper: usize) -> usize {
        debug_assert!(upper > 0);
        (self.next() % upper as u64) as usize
    }

    fn boolean(&mut self) -> bool {
        self.next() & 1 != 0
    }
}

struct ProblemBuilder {
    caps: GenerationCaps,
    terms: Vec<SemanticTerm>,
    argument_cells: usize,
    atoms: Vec<SemanticAtom>,
    assertions: Vec<SemanticExpr>,
    expression_nodes: usize,
    root_literals: Vec<RootLiteral>,
    boolean_values: Option<(TermId, TermId)>,
    contradiction: bool,
}

impl ProblemBuilder {
    fn new(caps: GenerationCaps) -> Self {
        Self {
            caps,
            terms: Vec::new(),
            argument_cells: 0,
            atoms: Vec::new(),
            assertions: Vec::new(),
            expression_nodes: 0,
            root_literals: Vec::new(),
            boolean_values: None,
            contradiction: false,
        }
    }

    fn add_term(
        &mut self,
        function: u32,
        sort: u32,
        arguments: &[TermId],
    ) -> Result<TermId, GenerationError> {
        let attempted_terms = checked_increment(self.terms.len(), GenerationResource::Terms)?;
        enforce_generation_cap(
            GenerationResource::Terms,
            attempted_terms,
            self.caps.max_terms,
        )?;
        if attempted_terms > MAX_GENERATED_TERMS {
            return Err(GenerationError::CapExceeded {
                resource: GenerationResource::Terms,
                attempted: attempted_terms,
                limit: MAX_GENERATED_TERMS,
            });
        }
        let attempted_arguments = self.argument_cells.checked_add(arguments.len()).ok_or(
            GenerationError::ArithmeticOverflow {
                resource: GenerationResource::ArgumentCells,
            },
        )?;
        enforce_generation_cap(
            GenerationResource::ArgumentCells,
            attempted_arguments,
            self.caps.max_argument_cells,
        )?;

        for &argument in arguments {
            self.validate_term(argument)?;
        }
        for previous in &self.terms {
            if previous.function != function {
                continue;
            }
            let signature_matches = previous.sort == sort
                && previous.arguments.len() == arguments.len()
                && previous
                    .arguments
                    .iter()
                    .zip(arguments)
                    .all(|(&left, &right)| {
                        self.terms[left.index()].sort == self.terms[right.index()].sort
                    });
            if !signature_matches {
                return Err(GenerationError::InconsistentFunctionSignature { function });
            }
        }

        let raw =
            u32::try_from(self.terms.len()).map_err(|_| GenerationError::ArithmeticOverflow {
                resource: GenerationResource::TermIdentifiers,
            })?;
        let mut owned_arguments = try_vec(arguments.len(), "term arguments")?;
        owned_arguments.extend_from_slice(arguments);
        try_push(
            &mut self.terms,
            SemanticTerm {
                function,
                sort,
                arguments: owned_arguments.into_boxed_slice(),
            },
            "semantic terms",
        )?;
        self.argument_cells = attempted_arguments;
        Ok(TermId::new(raw))
    }

    fn set_boolean_values(
        &mut self,
        true_term: TermId,
        false_term: TermId,
    ) -> Result<(), GenerationError> {
        self.validate_term(true_term)?;
        self.validate_term(false_term)?;
        if true_term == false_term {
            return Err(GenerationError::Invariant(
                "generated Boolean values must be distinct",
            ));
        }
        if self.terms[true_term.index()].sort != self.terms[false_term.index()].sort {
            return Err(GenerationError::Invariant(
                "generated Boolean values must have one sort",
            ));
        }
        if self
            .boolean_values
            .replace((true_term, false_term))
            .is_some()
        {
            return Err(GenerationError::Invariant(
                "generated Boolean values were assigned twice",
            ));
        }
        Ok(())
    }

    fn add_equality(&mut self, left: TermId, right: TermId) -> Result<AtomId, GenerationError> {
        self.validate_term(left)?;
        self.validate_term(right)?;
        if self.terms[left.index()].sort != self.terms[right.index()].sort {
            return Err(GenerationError::IllSortedEquality { left, right });
        }
        let atom = if left <= right {
            SemanticAtom::Equality(left, right)
        } else {
            SemanticAtom::Equality(right, left)
        };
        self.add_atom(atom)
    }

    fn add_boolean_term(&mut self, term: TermId) -> Result<AtomId, GenerationError> {
        self.validate_term(term)?;
        let Some((true_term, _)) = self.boolean_values else {
            return Err(GenerationError::MissingBooleanValues { term });
        };
        if self.terms[term.index()].sort != self.terms[true_term.index()].sort {
            return Err(GenerationError::IllSortedBooleanTerm { term });
        }
        self.add_atom(SemanticAtom::BoolTerm(term))
    }

    fn add_atom(&mut self, atom: SemanticAtom) -> Result<AtomId, GenerationError> {
        if let Some(index) = self.atoms.iter().position(|registered| *registered == atom) {
            return atom_id(index);
        }
        let attempted = checked_increment(self.atoms.len(), GenerationResource::Atoms)?;
        enforce_generation_cap(GenerationResource::Atoms, attempted, self.caps.max_atoms)?;
        let id = atom_id(self.atoms.len())?;
        try_push(&mut self.atoms, atom, "semantic atoms")?;
        Ok(id)
    }

    fn add_root_literal(&mut self, atom: AtomId, positive: bool) -> Result<(), GenerationError> {
        self.validate_atom(atom)?;
        let attempted =
            checked_increment(self.root_literals.len(), GenerationResource::RootLiterals)?;
        enforce_generation_cap(
            GenerationResource::RootLiterals,
            attempted,
            self.caps.max_root_literals,
        )?;
        try_push(
            &mut self.root_literals,
            RootLiteral { atom, positive },
            "root literals",
        )
    }

    fn add_assertion(&mut self, expression: SemanticExpr) -> Result<(), GenerationError> {
        validate_expression_atoms(&expression, self.atoms.len())?;
        let (nodes, depth) = expression_shape(&expression)?;
        enforce_generation_cap(
            GenerationResource::ExpressionDepth,
            depth,
            self.caps.max_expression_depth,
        )?;
        let attempted_nodes = self.expression_nodes.checked_add(nodes).ok_or(
            GenerationError::ArithmeticOverflow {
                resource: GenerationResource::ExpressionNodes,
            },
        )?;
        enforce_generation_cap(
            GenerationResource::ExpressionNodes,
            attempted_nodes,
            self.caps.max_expression_nodes,
        )?;
        let attempted_assertions =
            checked_increment(self.assertions.len(), GenerationResource::Assertions)?;
        enforce_generation_cap(
            GenerationResource::Assertions,
            attempted_assertions,
            self.caps.max_assertions,
        )?;
        try_push(&mut self.assertions, expression, "semantic assertions")?;
        self.expression_nodes = attempted_nodes;
        Ok(())
    }

    fn validate_term(&self, term: TermId) -> Result<(), GenerationError> {
        if term.index() < self.terms.len() {
            Ok(())
        } else {
            Err(GenerationError::UnknownTerm {
                term,
                term_count: self.terms.len(),
            })
        }
    }

    fn validate_atom(&self, atom: AtomId) -> Result<(), GenerationError> {
        if atom.index() < self.atoms.len() {
            Ok(())
        } else {
            Err(GenerationError::AtomOutOfRange {
                atom,
                atom_count: self.atoms.len(),
            })
        }
    }

    fn finish(self) -> Result<SemanticProblem, GenerationError> {
        let mut component_builder = ComponentBuilder::new(self.terms.len())?;
        for (index, term) in self.terms.iter().enumerate() {
            let id = TermId::new(index as u32);
            component_builder.connect_all(id, term.arguments.iter().copied())?;
        }
        if let Some((true_term, false_term)) = self.boolean_values {
            component_builder.connect(true_term, false_term)?;
            for atom in &self.atoms {
                match atom {
                    SemanticAtom::Equality(left, right) => {
                        component_builder.connect(*left, *right)?;
                    }
                    SemanticAtom::BoolTerm(term) => {
                        component_builder.connect(*term, true_term)?;
                        component_builder.connect(*term, false_term)?;
                    }
                }
            }
        } else {
            for atom in &self.atoms {
                if let SemanticAtom::Equality(left, right) = atom {
                    component_builder.connect(*left, *right)?;
                }
            }
        }
        let components = component_builder.finish();
        let mut atom_components = try_vec(self.atoms.len(), "atom component owners")?;
        for atom in &self.atoms {
            let anchor = match atom {
                SemanticAtom::Equality(left, _) => *left,
                SemanticAtom::BoolTerm(term) => *term,
            };
            atom_components.push(components.owner(anchor).ok_or(GenerationError::Invariant(
                "generated atom lost its component owner",
            ))?);
        }

        let mut cross_component_boolean_nodes = 0usize;
        for assertion in &self.assertions {
            let (nested, _) = expression_components(assertion, &atom_components)?;
            cross_component_boolean_nodes = cross_component_boolean_nodes
                .checked_add(nested)
                .ok_or(GenerationError::ArithmeticOverflow {
                    resource: GenerationResource::ExpressionNodes,
                })?;
        }
        let applications = self
            .terms
            .iter()
            .filter(|term| !term.arguments.is_empty())
            .count();
        let stats = SemanticStats {
            terms: self.terms.len(),
            applications,
            atoms: self.atoms.len(),
            assertions: self.assertions.len(),
            root_literals: self.root_literals.len(),
            components: components.component_count(),
            max_component_terms: components.max_component_size(),
            cross_component_boolean_nodes,
            unsupported_fragments: 0,
            contradiction: self.contradiction,
        };

        Ok(SemanticProblem {
            terms: self.terms.into_boxed_slice(),
            atoms: self.atoms.into_boxed_slice(),
            assertions: self.assertions.into_boxed_slice(),
            root_literals: self.root_literals.into_boxed_slice(),
            boolean_values: self.boolean_values,
            atom_components: atom_components.into_boxed_slice(),
            components,
            stats,
        })
    }
}

fn generate_equality(
    builder: &mut ProblemBuilder,
    random: &mut SplitMix64,
) -> Result<(), GenerationError> {
    let first = builder.add_term(0, 0, &[])?;
    let second = builder.add_term(1, 0, &[])?;
    let third = builder.add_term(2, 0, &[])?;
    let fourth_sort = u32::from(random.boolean());
    let fourth = builder.add_term(3, fourth_sort, &[])?;
    let terms = [first, second, third, fourth];
    for right in 1..terms.len() {
        for left in 0..right {
            if builder.terms[terms[left].index()].sort == builder.terms[terms[right].index()].sort {
                builder.add_equality(terms[left], terms[right])?;
            }
        }
    }
    Ok(())
}

fn generate_congruence(
    builder: &mut ProblemBuilder,
    random: &mut SplitMix64,
) -> Result<(), GenerationError> {
    let first = builder.add_term(0, 0, &[])?;
    let second = builder.add_term(1, 0, &[])?;
    let result_sort = u32::from(random.boolean());
    let first_application = builder.add_term(2, result_sort, &[first])?;
    let second_application = builder.add_term(2, result_sort, &[second])?;
    builder.add_equality(first, second)?;
    builder.add_equality(first_application, second_application)?;
    Ok(())
}

fn generate_boolean_data(
    builder: &mut ProblemBuilder,
    _random: &mut SplitMix64,
) -> Result<(), GenerationError> {
    let true_term = builder.add_term(0, 0, &[])?;
    let false_term = builder.add_term(1, 0, &[])?;
    let first_boolean = builder.add_term(2, 0, &[])?;
    let second_boolean = builder.add_term(3, 0, &[])?;
    let first_application = builder.add_term(4, 1, &[first_boolean])?;
    let second_application = builder.add_term(4, 1, &[second_boolean])?;
    builder.set_boolean_values(true_term, false_term)?;

    builder.add_equality(true_term, first_boolean)?;
    builder.add_equality(false_term, second_boolean)?;
    builder.add_equality(first_boolean, second_boolean)?;
    builder.add_equality(first_application, second_application)?;
    builder.add_boolean_term(first_boolean)?;
    builder.add_boolean_term(second_boolean)?;
    Ok(())
}

fn generate_many_sorted(
    builder: &mut ProblemBuilder,
    _random: &mut SplitMix64,
) -> Result<(), GenerationError> {
    let first_left = builder.add_term(0, 0, &[])?;
    let first_right = builder.add_term(1, 0, &[])?;
    let second_left = builder.add_term(2, 1, &[])?;
    let second_right = builder.add_term(3, 1, &[])?;
    builder.add_equality(first_left, first_right)?;
    builder.add_equality(second_left, second_right)?;
    Ok(())
}

fn populate_constraints(
    builder: &mut ProblemBuilder,
    random: &mut SplitMix64,
) -> Result<(), GenerationError> {
    if builder.atoms.is_empty() {
        return Err(GenerationError::Invariant(
            "generated family did not register any atoms",
        ));
    }
    let atom_count = builder.atoms.len();
    for _ in 0..random.bounded(3) {
        let atom = atom_id(random.bounded(atom_count))?;
        builder.add_root_literal(atom, random.boolean())?;
    }
    let assertion_count = 1 + random.bounded(3);
    for _ in 0..assertion_count {
        let expression = random_expression(random, atom_count)?;
        builder.add_assertion(expression)?;
    }
    builder.contradiction = random.next() & 0x7f == 0;
    Ok(())
}

fn random_expression(
    random: &mut SplitMix64,
    atom_count: usize,
) -> Result<SemanticExpr, GenerationError> {
    match random.bounded(6) {
        0 => random_literal(random, atom_count),
        1 => {
            let width = 2 + random.bounded(2);
            random_nary(random, atom_count, Nary::And, width)
        }
        2 => {
            let width = 2 + random.bounded(2);
            random_nary(random, atom_count, Nary::Or, width)
        }
        3 => random_nary(random, atom_count, Nary::Iff, 2),
        4 => {
            let first = random_literal(random, atom_count)?;
            let inner = random_nary(random, atom_count, Nary::And, 2)?;
            Ok(SemanticExpr::Or(boxed_pair(
                first,
                inner,
                "nested expression children",
            )?))
        }
        _ => Ok(SemanticExpr::Const(random.boolean())),
    }
}

#[derive(Clone, Copy)]
enum Nary {
    And,
    Or,
    Iff,
}

fn random_nary(
    random: &mut SplitMix64,
    atom_count: usize,
    kind: Nary,
    width: usize,
) -> Result<SemanticExpr, GenerationError> {
    let mut children = try_vec(width, "Boolean expression children")?;
    for _ in 0..width {
        children.push(random_literal(random, atom_count)?);
    }
    let children = children.into_boxed_slice();
    Ok(match kind {
        Nary::And => SemanticExpr::And(children),
        Nary::Or => SemanticExpr::Or(children),
        Nary::Iff => SemanticExpr::Iff(children),
    })
}

fn random_literal(
    random: &mut SplitMix64,
    atom_count: usize,
) -> Result<SemanticExpr, GenerationError> {
    let atom = atom_id(random.bounded(atom_count))?;
    if random.boolean() {
        Ok(SemanticExpr::Atom(atom))
    } else {
        Ok(SemanticExpr::Iff(boxed_pair(
            SemanticExpr::Atom(atom),
            SemanticExpr::Const(false),
            "negated literal children",
        )?))
    }
}

fn boxed_pair(
    first: SemanticExpr,
    second: SemanticExpr,
    context: &'static str,
) -> Result<Box<[SemanticExpr]>, GenerationError> {
    let mut children = try_vec(2, context)?;
    children.push(first);
    children.push(second);
    Ok(children.into_boxed_slice())
}

fn atom_id(index: usize) -> Result<AtomId, GenerationError> {
    let raw = u32::try_from(index).map_err(|_| GenerationError::ArithmeticOverflow {
        resource: GenerationResource::Atoms,
    })?;
    Ok(AtomId::new(raw))
}

fn checked_increment(value: usize, resource: GenerationResource) -> Result<usize, GenerationError> {
    value
        .checked_add(1)
        .ok_or(GenerationError::ArithmeticOverflow { resource })
}

fn enforce_generation_cap(
    resource: GenerationResource,
    attempted: usize,
    limit: usize,
) -> Result<(), GenerationError> {
    if attempted <= limit {
        Ok(())
    } else {
        Err(GenerationError::CapExceeded {
            resource,
            attempted,
            limit,
        })
    }
}

fn try_vec<T>(capacity: usize, context: &'static str) -> Result<Vec<T>, GenerationError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(capacity)
        .map_err(|_| GenerationError::AllocationFailed { context })?;
    Ok(values)
}

fn try_push<T>(
    values: &mut Vec<T>,
    value: T,
    context: &'static str,
) -> Result<(), GenerationError> {
    if values.len() == values.capacity() {
        values
            .try_reserve(1)
            .map_err(|_| GenerationError::AllocationFailed { context })?;
    }
    values.push(value);
    Ok(())
}

fn validate_expression_atoms(
    expression: &SemanticExpr,
    atom_count: usize,
) -> Result<(), GenerationError> {
    match expression {
        SemanticExpr::Const(_) => Ok(()),
        SemanticExpr::Atom(atom) => {
            if atom.index() < atom_count {
                Ok(())
            } else {
                Err(GenerationError::AtomOutOfRange {
                    atom: *atom,
                    atom_count,
                })
            }
        }
        SemanticExpr::Not(child) => validate_expression_atoms(child, atom_count),
        SemanticExpr::And(children) | SemanticExpr::Or(children) | SemanticExpr::Iff(children) => {
            for child in children {
                validate_expression_atoms(child, atom_count)?;
            }
            Ok(())
        }
        SemanticExpr::Ite(condition, then_expression, else_expression) => {
            for child in [condition, then_expression, else_expression] {
                validate_expression_atoms(child, atom_count)?;
            }
            Ok(())
        }
    }
}

fn expression_shape(expression: &SemanticExpr) -> Result<(usize, usize), GenerationError> {
    let (children_nodes, children_depth) = match expression {
        SemanticExpr::Const(_) | SemanticExpr::Atom(_) => (0, 0),
        SemanticExpr::Not(child) => expression_shape(child)?,
        SemanticExpr::And(children) | SemanticExpr::Or(children) | SemanticExpr::Iff(children) => {
            expression_children_shape(children.iter())?
        }
        SemanticExpr::Ite(condition, then_expression, else_expression) => {
            expression_children_shape(
                [
                    condition.as_ref(),
                    then_expression.as_ref(),
                    else_expression.as_ref(),
                ]
                .into_iter(),
            )?
        }
    };
    let nodes = children_nodes
        .checked_add(1)
        .ok_or(GenerationError::ArithmeticOverflow {
            resource: GenerationResource::ExpressionNodes,
        })?;
    let depth = children_depth
        .checked_add(1)
        .ok_or(GenerationError::ArithmeticOverflow {
            resource: GenerationResource::ExpressionDepth,
        })?;
    Ok((nodes, depth))
}

fn expression_children_shape<'a>(
    children: impl Iterator<Item = &'a SemanticExpr>,
) -> Result<(usize, usize), GenerationError> {
    let mut nodes = 0usize;
    let mut depth = 0usize;
    for child in children {
        let (child_nodes, child_depth) = expression_shape(child)?;
        nodes = nodes
            .checked_add(child_nodes)
            .ok_or(GenerationError::ArithmeticOverflow {
                resource: GenerationResource::ExpressionNodes,
            })?;
        depth = depth.max(child_depth);
    }
    Ok((nodes, depth))
}

fn expression_components(
    expression: &SemanticExpr,
    atom_components: &[ComponentId],
) -> Result<(usize, u64), GenerationError> {
    match expression {
        SemanticExpr::Const(_) => Ok((0, 0)),
        SemanticExpr::Atom(atom) => {
            let component =
                atom_components
                    .get(atom.index())
                    .ok_or(GenerationError::AtomOutOfRange {
                        atom: *atom,
                        atom_count: atom_components.len(),
                    })?;
            let bit =
                1u64.checked_shl(component.index() as u32)
                    .ok_or(GenerationError::Invariant(
                        "generated component bitset overflowed",
                    ))?;
            Ok((0, bit))
        }
        SemanticExpr::Not(child) => expression_components(child, atom_components),
        SemanticExpr::And(children) | SemanticExpr::Or(children) | SemanticExpr::Iff(children) => {
            expression_child_components(children.iter(), atom_components)
        }
        SemanticExpr::Ite(condition, then_expression, else_expression) => {
            expression_child_components(
                [
                    condition.as_ref(),
                    then_expression.as_ref(),
                    else_expression.as_ref(),
                ]
                .into_iter(),
                atom_components,
            )
        }
    }
}

fn expression_child_components<'a>(
    children: impl Iterator<Item = &'a SemanticExpr>,
    atom_components: &[ComponentId],
) -> Result<(usize, u64), GenerationError> {
    let mut count = 0usize;
    let mut mask = 0u64;
    for child in children {
        let (child_count, child_mask) = expression_components(child, atom_components)?;
        count = count
            .checked_add(child_count)
            .ok_or(GenerationError::ArithmeticOverflow {
                resource: GenerationResource::ExpressionNodes,
            })?;
        mask |= child_mask;
    }
    if mask.count_ones() > 1 {
        count = checked_increment(count, GenerationResource::ExpressionNodes)?;
    }
    Ok((count, mask))
}

fn measure_problem(problem: &SemanticProblem) -> Result<GeneratedMetrics, GenerationError> {
    let mut argument_cells = 0usize;
    for term in &problem.terms {
        argument_cells = argument_cells.checked_add(term.arguments.len()).ok_or(
            GenerationError::ArithmeticOverflow {
                resource: GenerationResource::ArgumentCells,
            },
        )?;
    }
    let mut expression_nodes = 0usize;
    for assertion in &problem.assertions {
        expression_nodes = expression_nodes
            .checked_add(expression_shape(assertion)?.0)
            .ok_or(GenerationError::ArithmeticOverflow {
                resource: GenerationResource::ExpressionNodes,
            })?;
    }
    Ok(GeneratedMetrics {
        terms: problem.terms.len(),
        argument_cells,
        atoms: problem.atoms.len(),
        assertions: problem.assertions.len(),
        root_literals: problem.root_literals.len(),
        expression_nodes,
    })
}

pub(crate) fn finite_oracle_applicable(problem: &SemanticProblem) -> bool {
    if problem.stats.unsupported_fragments != 0
        || problem.terms.len() > ORACLE_MAX_SEMANTIC_TERMS
        || problem.atoms.len() > ORACLE_MAX_ATOMS
        || problem.assertions.len() > ORACLE_MAX_ASSERTIONS
        || problem.root_literals.len() > ORACLE_MAX_ROOT_LITERALS
    {
        return false;
    }

    let mut argument_cells = 0usize;
    for term in &problem.terms {
        let Some(next) = argument_cells.checked_add(term.arguments.len()) else {
            return false;
        };
        argument_cells = next;
    }
    if argument_cells > ORACLE_MAX_TERM_ARGUMENTS {
        return false;
    }

    let distinguished = match problem.boolean_values {
        Some((true_term, false_term))
            if true_term != false_term
                && true_term.index() < problem.terms.len()
                && false_term.index() < problem.terms.len() =>
        {
            2
        }
        _ => 0,
    };
    if problem.terms.len().saturating_sub(distinguished) > ORACLE_MAX_GROUND_TERMS {
        return false;
    }

    let mut nodes = 0usize;
    for assertion in &problem.assertions {
        let Ok((assertion_nodes, depth)) = expression_shape(assertion) else {
            return false;
        };
        let Some(next) = nodes.checked_add(assertion_nodes) else {
            return false;
        };
        nodes = next;
        if depth > ORACLE_MAX_EXPRESSION_DEPTH {
            return false;
        }
    }
    nodes <= ORACLE_MAX_EXPRESSION_NODES
}

struct Fingerprint(u64);

impl Fingerprint {
    const fn new() -> Self {
        Self(FINGERPRINT_OFFSET)
    }

    fn byte(&mut self, value: u8) {
        self.0 ^= u64::from(value);
        self.0 = self.0.wrapping_mul(FINGERPRINT_PRIME);
    }

    fn word(&mut self, value: u64) {
        for byte in value.to_le_bytes() {
            self.byte(byte);
        }
    }

    const fn finish(self) -> u64 {
        self.0
    }
}

fn fingerprint_problem(family: GeneratorFamily, problem: &SemanticProblem) -> u64 {
    let mut fingerprint = Fingerprint::new();
    fingerprint.word(u64::from(GENERATOR_VERSION));
    fingerprint.word(match family {
        GeneratorFamily::Equality => 0,
        GeneratorFamily::Congruence => 1,
        GeneratorFamily::BooleanData => 2,
        GeneratorFamily::ManySorted => 3,
    });
    fingerprint.word(problem.terms.len() as u64);
    for term in &problem.terms {
        fingerprint.word(u64::from(term.function));
        fingerprint.word(u64::from(term.sort));
        fingerprint.word(term.arguments.len() as u64);
        for argument in &term.arguments {
            fingerprint.word(u64::from(argument.raw()));
        }
    }
    fingerprint.word(problem.atoms.len() as u64);
    for atom in &problem.atoms {
        match atom {
            SemanticAtom::Equality(left, right) => {
                fingerprint.word(0);
                fingerprint.word(u64::from(left.raw()));
                fingerprint.word(u64::from(right.raw()));
            }
            SemanticAtom::BoolTerm(term) => {
                fingerprint.word(1);
                fingerprint.word(u64::from(term.raw()));
            }
        }
    }
    fingerprint.word(problem.assertions.len() as u64);
    for assertion in &problem.assertions {
        fingerprint_expression(&mut fingerprint, assertion);
    }
    fingerprint.word(problem.root_literals.len() as u64);
    for literal in &problem.root_literals {
        fingerprint.word(literal.atom.index() as u64);
        fingerprint.word(u64::from(literal.positive));
    }
    match problem.boolean_values {
        Some((true_term, false_term)) => {
            fingerprint.word(1);
            fingerprint.word(u64::from(true_term.raw()));
            fingerprint.word(u64::from(false_term.raw()));
        }
        None => fingerprint.word(0),
    }
    fingerprint.word(u64::from(problem.stats.contradiction));
    fingerprint.finish()
}

fn fingerprint_expression(fingerprint: &mut Fingerprint, expression: &SemanticExpr) {
    match expression {
        SemanticExpr::Const(value) => {
            fingerprint.word(0);
            fingerprint.word(u64::from(*value));
        }
        SemanticExpr::Atom(atom) => {
            fingerprint.word(1);
            fingerprint.word(atom.index() as u64);
        }
        SemanticExpr::Not(child) => {
            fingerprint.word(2);
            fingerprint_expression(fingerprint, child);
        }
        SemanticExpr::And(children) => {
            fingerprint.word(3);
            fingerprint_children(fingerprint, children);
        }
        SemanticExpr::Or(children) => {
            fingerprint.word(4);
            fingerprint_children(fingerprint, children);
        }
        SemanticExpr::Iff(children) => {
            fingerprint.word(5);
            fingerprint_children(fingerprint, children);
        }
        SemanticExpr::Ite(condition, then_expression, else_expression) => {
            fingerprint.word(6);
            fingerprint_expression(fingerprint, condition);
            fingerprint_expression(fingerprint, then_expression);
            fingerprint_expression(fingerprint, else_expression);
        }
    }
}

fn fingerprint_children(fingerprint: &mut Fingerprint, children: &[SemanticExpr]) {
    fingerprint.word(children.len() as u64);
    for child in children {
        fingerprint_expression(fingerprint, child);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OutcomeClass {
    Sat,
    Unsat,
    Abstained,
    Error,
}

impl fmt::Display for OutcomeClass {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str(match self {
            Self::Sat => "sat",
            Self::Unsat => "unsat",
            Self::Abstained => "abstained",
            Self::Error => "error",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DifferentialObservations {
    pub(crate) reference: OutcomeClass,
    pub(crate) incremental: OutcomeClass,
    pub(crate) watched: OutcomeClass,
    pub(crate) learned: OutcomeClass,
    pub(crate) action_nogood: OutcomeClass,
    pub(crate) oracle: Option<OutcomeClass>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WitnessKind {
    EngineDisagreement,
    OracleDisagreement,
    ExecutionError,
}

impl fmt::Display for WitnessKind {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str(match self {
            Self::EngineDisagreement => "engine-disagreement",
            Self::OracleDisagreement => "oracle-disagreement",
            Self::ExecutionError => "execution-error",
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DifferentialWitness {
    pub(crate) generator_version: u32,
    pub(crate) campaign_seed: u64,
    pub(crate) case_id: CaseId,
    pub(crate) case_seed: u64,
    pub(crate) family: GeneratorFamily,
    pub(crate) problem_fingerprint: u64,
    pub(crate) kind: WitnessKind,
    pub(crate) observations: DifferentialObservations,
    pub(crate) engine_caps: EngineCaps,
}

impl fmt::Display for DifferentialWitness {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        let caps = if self.engine_caps == EngineCaps::default() {
            "default"
        } else {
            "custom-embedded"
        };
        write!(
            output,
            "fabric-generated-v{} seed={:#018x} case={} case-seed={:#018x} family={} fingerprint={:#018x} kind={} reference={} incremental={} watched={} learned={} action-nogood={} oracle=",
            self.generator_version,
            self.campaign_seed,
            self.case_id,
            self.case_seed,
            self.family,
            self.problem_fingerprint,
            self.kind,
            self.observations.reference,
            self.observations.incremental,
            self.observations.watched,
            self.observations.learned,
            self.observations.action_nogood,
        )?;
        match self.observations.oracle {
            Some(outcome) => outcome.fmt(output)?,
            None => output.write_str("n/a")?,
        }
        write!(output, " caps={caps}")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CaseAgreement {
    pub(crate) outcome: OutcomeClass,
    pub(crate) oracle_checked: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DifferentialCaseOutcome {
    Agreement(CaseAgreement),
    Disagreement(DifferentialWitness),
}

pub(crate) fn compare_generated_case(
    case: &GeneratedCase,
    engine_caps: EngineCaps,
) -> DifferentialCaseOutcome {
    let observations = DifferentialObservations {
        reference: classify_reference(solve_reference(&case.problem, engine_caps)),
        incremental: classify_reference(solve_incremental_reference(&case.problem, engine_caps)),
        watched: classify_reference(solve_incremental_watched_reference(
            &case.problem,
            engine_caps,
        )),
        learned: classify_reference(solve_incremental_learned_reference(
            &case.problem,
            engine_caps,
        )),
        action_nogood: classify_reference(solve_incremental_action_nogood_reference(
            &case.problem,
            engine_caps,
        )),
        oracle: case
            .oracle_applicable
            .then(|| classify_oracle(finite_oracle::solve(&case.problem))),
    };

    let has_error = observations.reference == OutcomeClass::Error
        || observations.incremental == OutcomeClass::Error
        || observations.watched == OutcomeClass::Error
        || observations.learned == OutcomeClass::Error
        || observations.action_nogood == OutcomeClass::Error
        || observations.oracle == Some(OutcomeClass::Error);
    let engines_agree = observations.incremental == observations.reference
        && observations.watched == observations.reference
        && observations.learned == observations.reference
        && observations.action_nogood == observations.reference;
    let oracle_agrees = observations
        .oracle
        .is_none_or(|oracle| oracle == observations.reference);

    if has_error || !engines_agree || !oracle_agrees {
        let kind = if has_error {
            WitnessKind::ExecutionError
        } else if !engines_agree {
            WitnessKind::EngineDisagreement
        } else {
            WitnessKind::OracleDisagreement
        };
        DifferentialCaseOutcome::Disagreement(DifferentialWitness {
            generator_version: case.generator_version,
            campaign_seed: case.campaign_seed,
            case_id: case.case_id,
            case_seed: case.case_seed,
            family: case.family,
            problem_fingerprint: case.problem_fingerprint,
            kind,
            observations,
            engine_caps,
        })
    } else {
        DifferentialCaseOutcome::Agreement(CaseAgreement {
            outcome: observations.reference,
            oracle_checked: observations.oracle.is_some(),
        })
    }
}

fn classify_reference(
    result: Result<ReferenceOutcome, super::engine::EngineError>,
) -> OutcomeClass {
    match result {
        Ok(ReferenceOutcome::Sat { .. }) => OutcomeClass::Sat,
        Ok(ReferenceOutcome::Unsat { .. }) => OutcomeClass::Unsat,
        Ok(ReferenceOutcome::Abstained { .. }) => OutcomeClass::Abstained,
        Err(_) => OutcomeClass::Error,
    }
}

fn classify_oracle(
    result: Result<OracleOutcome, super::finite_oracle::OracleError>,
) -> OutcomeClass {
    match result {
        Ok(OracleOutcome::Sat { .. }) => OutcomeClass::Sat,
        Ok(OracleOutcome::Unsat { .. }) => OutcomeClass::Unsat,
        Ok(OracleOutcome::Abstained { .. }) => OutcomeClass::Abstained,
        Err(_) => OutcomeClass::Error,
    }
}

pub(crate) fn replay_witness(
    witness: &DifferentialWitness,
) -> Result<DifferentialCaseOutcome, GenerationError> {
    if witness.generator_version != GENERATOR_VERSION {
        return Err(GenerationError::GeneratorVersionMismatch {
            witness: witness.generator_version,
            current: GENERATOR_VERSION,
        });
    }
    let case = generate_case(
        witness.campaign_seed,
        witness.case_id,
        GenerationCaps::default(),
    )?;
    if case.case_seed != witness.case_seed
        || case.problem_fingerprint != witness.problem_fingerprint
    {
        return Err(GenerationError::GeneratorDrift {
            expected_case_seed: witness.case_seed,
            actual_case_seed: case.case_seed,
            expected_fingerprint: witness.problem_fingerprint,
            actual_fingerprint: case.problem_fingerprint,
        });
    }
    Ok(compare_generated_case(&case, witness.engine_caps))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CampaignLimits {
    pub(crate) max_cases: u64,
    pub(crate) max_total_terms: u64,
    pub(crate) max_total_atoms: u64,
    pub(crate) max_total_expression_nodes: u64,
}

impl Default for CampaignLimits {
    fn default() -> Self {
        Self {
            max_cases: ONE_MILLION_CASES,
            max_total_terms: ONE_MILLION_CASES * MAX_GENERATED_TERMS as u64,
            max_total_atoms: ONE_MILLION_CASES * 8,
            max_total_expression_nodes: ONE_MILLION_CASES * 64,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CampaignSpec {
    pub(crate) seed: u64,
    pub(crate) first_case: CaseId,
    pub(crate) case_count: u64,
    pub(crate) generation_caps: GenerationCaps,
    pub(crate) engine_caps: EngineCaps,
    pub(crate) limits: CampaignLimits,
}

impl CampaignSpec {
    pub(crate) fn new(seed: u64, case_count: u64) -> Self {
        Self {
            seed,
            first_case: CaseId::new(0),
            case_count,
            generation_caps: GenerationCaps::default(),
            engine_caps: EngineCaps::default(),
            limits: CampaignLimits::default(),
        }
    }

    pub(crate) fn one_million(seed: u64) -> Self {
        Self::new(seed, ONE_MILLION_CASES)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CampaignResource {
    Cases,
    CaseIdentifiers,
    TotalTerms,
    TotalAtoms,
    TotalExpressionNodes,
}

impl fmt::Display for CampaignResource {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str(match self {
            Self::Cases => "cases",
            Self::CaseIdentifiers => "case identifiers",
            Self::TotalTerms => "total terms",
            Self::TotalAtoms => "total atoms",
            Self::TotalExpressionNodes => "total expression nodes",
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CampaignError {
    CapExceeded {
        resource: CampaignResource,
        attempted: u64,
        limit: u64,
        case_id: Option<CaseId>,
    },
    ArithmeticOverflow {
        resource: CampaignResource,
        case_id: Option<CaseId>,
    },
    Generation {
        seed: u64,
        case_id: CaseId,
        error: GenerationError,
    },
}

impl fmt::Display for CampaignError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapExceeded {
                resource,
                attempted,
                limit,
                case_id,
            } => {
                write!(
                    output,
                    "generated differential {resource} cap exceeded: attempted {attempted}, limit {limit}"
                )?;
                if let Some(case_id) = case_id {
                    write!(output, " at case {case_id}")?;
                }
                Ok(())
            }
            Self::ArithmeticOverflow { resource, case_id } => {
                write!(output, "generated differential {resource} count overflowed")?;
                if let Some(case_id) = case_id {
                    write!(output, " at case {case_id}")?;
                }
                Ok(())
            }
            Self::Generation {
                seed,
                case_id,
                error,
            } => write!(
                output,
                "generated differential seed={seed:#018x} case={case_id} failed: {error}"
            ),
        }
    }
}

impl Error for CampaignError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Generation { error, .. } => Some(error),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CampaignReport {
    pub(crate) seed: u64,
    pub(crate) first_case: CaseId,
    pub(crate) cases_run: u64,
    pub(crate) sat_cases: u64,
    pub(crate) unsat_cases: u64,
    pub(crate) abstained_cases: u64,
    pub(crate) oracle_cases: u64,
    pub(crate) oracle_skipped: u64,
    pub(crate) total_terms: u64,
    pub(crate) total_atoms: u64,
    pub(crate) total_expression_nodes: u64,
    pub(crate) campaign_fingerprint: u64,
}

impl CampaignReport {
    fn new(spec: CampaignSpec) -> Self {
        Self {
            seed: spec.seed,
            first_case: spec.first_case,
            cases_run: 0,
            sat_cases: 0,
            unsat_cases: 0,
            abstained_cases: 0,
            oracle_cases: 0,
            oracle_skipped: 0,
            total_terms: 0,
            total_atoms: 0,
            total_expression_nodes: 0,
            campaign_fingerprint: FINGERPRINT_OFFSET,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CampaignOutcome {
    Complete(CampaignReport),
    Disagreement {
        cases_checked: u64,
        witness: DifferentialWitness,
    },
}

pub(crate) fn run_campaign(spec: CampaignSpec) -> Result<CampaignOutcome, CampaignError> {
    enforce_campaign_cap(
        CampaignResource::Cases,
        spec.case_count,
        spec.limits.max_cases,
        None,
    )?;
    if let Some(last_offset) = spec.case_count.checked_sub(1) {
        spec.first_case.raw().checked_add(last_offset).ok_or(
            CampaignError::ArithmeticOverflow {
                resource: CampaignResource::CaseIdentifiers,
                case_id: None,
            },
        )?;
    }

    let mut report = CampaignReport::new(spec);
    for offset in 0..spec.case_count {
        let raw_id =
            spec.first_case
                .raw()
                .checked_add(offset)
                .ok_or(CampaignError::ArithmeticOverflow {
                    resource: CampaignResource::CaseIdentifiers,
                    case_id: None,
                })?;
        let case_id = CaseId::new(raw_id);
        let case = generate_case(spec.seed, case_id, spec.generation_caps).map_err(|error| {
            CampaignError::Generation {
                seed: spec.seed,
                case_id,
                error,
            }
        })?;
        charge_campaign(
            &mut report.total_terms,
            case.metrics.terms as u64,
            spec.limits.max_total_terms,
            CampaignResource::TotalTerms,
            case_id,
        )?;
        charge_campaign(
            &mut report.total_atoms,
            case.metrics.atoms as u64,
            spec.limits.max_total_atoms,
            CampaignResource::TotalAtoms,
            case_id,
        )?;
        charge_campaign(
            &mut report.total_expression_nodes,
            case.metrics.expression_nodes as u64,
            spec.limits.max_total_expression_nodes,
            CampaignResource::TotalExpressionNodes,
            case_id,
        )?;

        match compare_generated_case(&case, spec.engine_caps) {
            DifferentialCaseOutcome::Agreement(agreement) => {
                report.cases_run += 1;
                match agreement.outcome {
                    OutcomeClass::Sat => report.sat_cases += 1,
                    OutcomeClass::Unsat => report.unsat_cases += 1,
                    OutcomeClass::Abstained => report.abstained_cases += 1,
                    OutcomeClass::Error => {
                        return Err(CampaignError::Generation {
                            seed: spec.seed,
                            case_id,
                            error: GenerationError::Invariant(
                                "execution errors cannot be reported as agreement",
                            ),
                        });
                    }
                }
                if agreement.oracle_checked {
                    report.oracle_cases += 1;
                } else {
                    report.oracle_skipped += 1;
                }
                report.campaign_fingerprint =
                    mix64(report.campaign_fingerprint ^ case.problem_fingerprint ^ case_id.raw());
            }
            DifferentialCaseOutcome::Disagreement(witness) => {
                return Ok(CampaignOutcome::Disagreement {
                    cases_checked: report.cases_run,
                    witness,
                });
            }
        }
    }
    Ok(CampaignOutcome::Complete(report))
}

fn charge_campaign(
    total: &mut u64,
    amount: u64,
    limit: u64,
    resource: CampaignResource,
    case_id: CaseId,
) -> Result<(), CampaignError> {
    let attempted = total
        .checked_add(amount)
        .ok_or(CampaignError::ArithmeticOverflow {
            resource,
            case_id: Some(case_id),
        })?;
    enforce_campaign_cap(resource, attempted, limit, Some(case_id))?;
    *total = attempted;
    Ok(())
}

fn enforce_campaign_cap(
    resource: CampaignResource,
    attempted: u64,
    limit: u64,
    case_id: Option<CaseId>,
) -> Result<(), CampaignError> {
    if attempted <= limit {
        Ok(())
    } else {
        Err(CampaignError::CapExceeded {
            resource,
            attempted,
            limit,
            case_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SEED: u64 = 0x243f_6a88_85a3_08d3;

    #[test]
    fn generation_is_random_access_and_reproducible() {
        let id = CaseId::new(37);
        let first = generate_case(TEST_SEED, id, GenerationCaps::default()).unwrap();
        for prefix in 0..37 {
            generate_case(TEST_SEED, CaseId::new(prefix), GenerationCaps::default()).unwrap();
        }
        let second = generate_case(TEST_SEED, id, GenerationCaps::default()).unwrap();

        assert_eq!(first, second);
        assert_eq!(first.generator_version, GENERATOR_VERSION);
        assert_eq!(first.case_seed, 0x4c3e_a577_a711_73b6);
        assert_eq!(first.problem_fingerprint, 0x7574_0980_85d2_3362);
    }

    #[test]
    fn consecutive_cases_cover_typed_families_and_oracle_envelope() {
        let mut seen = [false; FAMILY_COUNT as usize];
        for raw in 0..FAMILY_COUNT {
            let case =
                generate_case(TEST_SEED, CaseId::new(raw), GenerationCaps::default()).unwrap();
            let family = match case.family {
                GeneratorFamily::Equality => 0,
                GeneratorFamily::Congruence => 1,
                GeneratorFamily::BooleanData => 2,
                GeneratorFamily::ManySorted => 3,
            };
            seen[family] = true;
            assert!(case.oracle_applicable);
            assert!(case.problem.terms.len() <= ORACLE_MAX_SEMANTIC_TERMS);
            for atom in &case.problem.atoms {
                if let SemanticAtom::Equality(left, right) = atom {
                    assert_eq!(
                        case.problem.terms[left.index()].sort,
                        case.problem.terms[right.index()].sort
                    );
                }
            }
        }
        assert!(seen.into_iter().all(|value| value));
    }

    #[test]
    fn generation_caps_fail_before_oversized_problem_is_returned() {
        let mut caps = GenerationCaps::default();
        caps.max_terms = 0;
        assert_eq!(
            generate_case(TEST_SEED, CaseId::new(0), caps).unwrap_err(),
            GenerationError::CapExceeded {
                resource: GenerationResource::Terms,
                attempted: 1,
                limit: 0,
            }
        );
    }

    #[test]
    fn first_disagreement_is_compact_and_replayable() {
        let case = generate_case(TEST_SEED, CaseId::new(0), GenerationCaps::default()).unwrap();
        let mut caps = EngineCaps::default();
        caps.watches.max_atoms = 0;
        let DifferentialCaseOutcome::Disagreement(witness) = compare_generated_case(&case, caps)
        else {
            panic!("zero watch capacity must distinguish watched execution");
        };
        assert_eq!(witness.kind, WitnessKind::EngineDisagreement);
        let rendered = witness.to_string();
        assert!(rendered.contains(&format!("seed={TEST_SEED:#018x}")));
        assert!(rendered.contains("case=0"));
        assert!(rendered.contains("caps=custom-embedded"));
        assert_eq!(
            replay_witness(&witness).unwrap(),
            DifferentialCaseOutcome::Disagreement(witness)
        );
    }

    #[test]
    fn campaign_limits_are_checked_before_generation() {
        let mut spec = CampaignSpec::new(TEST_SEED, 2);
        spec.limits.max_cases = 1;
        assert_eq!(
            run_campaign(spec).unwrap_err(),
            CampaignError::CapExceeded {
                resource: CampaignResource::Cases,
                attempted: 2,
                limit: 1,
                case_id: None,
            }
        );
    }

    #[test]
    fn maximum_case_id_is_a_valid_single_case_range() {
        let mut spec = CampaignSpec::new(TEST_SEED, 1);
        spec.first_case = CaseId::new(u64::MAX);
        let CampaignOutcome::Complete(report) = run_campaign(spec).unwrap() else {
            panic!("maximum case ID found a differential disagreement");
        };
        assert_eq!(report.first_case, CaseId::new(u64::MAX));
        assert_eq!(report.cases_run, 1);
    }

    #[test]
    fn fast_generated_differential_campaign_agrees() {
        let spec = CampaignSpec::new(TEST_SEED, 64);
        let CampaignOutcome::Complete(report) = run_campaign(spec).unwrap() else {
            panic!("fast generated differential found a disagreement");
        };
        assert_eq!(report.cases_run, 64);
        assert_eq!(report.oracle_cases, 64);
        assert_eq!(report.oracle_skipped, 0);
        assert_eq!(report.abstained_cases, 0);
        assert_eq!(report.sat_cases + report.unsat_cases, 64);
        assert_ne!(report.campaign_fingerprint, FINGERPRINT_OFFSET);
    }

    #[test]
    #[ignore = "one-million-case Fabric promotion gate"]
    fn one_million_generated_cases_match_all_fabric_arms_and_finite_oracle() {
        let spec = CampaignSpec::one_million(DEFAULT_CAMPAIGN_SEED);
        let CampaignOutcome::Complete(report) = run_campaign(spec).unwrap() else {
            panic!("one-million-case generated differential found a disagreement");
        };
        assert_eq!(report.cases_run, ONE_MILLION_CASES);
        assert_eq!(report.oracle_cases, ONE_MILLION_CASES);
        assert_eq!(report.oracle_skipped, 0);
        assert_eq!(report.abstained_cases, 0);
        assert_eq!(report.sat_cases + report.unsat_cases, ONE_MILLION_CASES);
    }
}
