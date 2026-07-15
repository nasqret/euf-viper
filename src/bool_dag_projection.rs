use super::{BOOL_SORT, BoolAtomKey, BoolExpr, BoolProblem, TermArena, TermId, normalized_pair};
use rustc_hash::{FxHashMap as HashMap, FxHashSet as HashSet};
use std::io::{self, Write};
use std::rc::Rc;
use std::time::Instant;

const DEFAULT_MAX_SYNTAX_OCCURRENCES: usize = 5_000_000;
const DEFAULT_MAX_CANONICAL_NODES: usize = 2_000_000;
const DEFAULT_MAX_CANONICAL_EDGES: usize = 10_000_000;
const DEFAULT_MAX_VARIABLES: usize = 20_000_000;
const DEFAULT_MAX_CLAUSES: usize = 20_000_000;
const DEFAULT_MAX_LITERAL_OCCURRENCES: usize = 100_000_000;
const DEFAULT_MAX_PROVENANCE_BYTES: usize = 64 * 1024 * 1024;
const DEFAULT_MAX_ENCODING_DEPTH: usize = 1_024;
const PROVENANCE_RECORD_BYTES: usize = 17;

pub(crate) const GUARDED_EUF_NEXT_INTERFACE: &str = "GuardProvider::prove(TypedCanonicalKey,TypedCanonicalKey,RequiredPolarity)->Result<Option<ReplayableGuard{argument_equalities,witness_bytes}>,GuardError>";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProjectionLimits {
    pub(crate) max_syntax_occurrences: usize,
    pub(crate) max_canonical_nodes: usize,
    pub(crate) max_canonical_edges: usize,
    pub(crate) max_variables: usize,
    pub(crate) max_clauses: usize,
    pub(crate) max_literal_occurrences: usize,
    pub(crate) max_provenance_bytes: usize,
    pub(crate) max_encoding_depth: usize,
}

impl Default for ProjectionLimits {
    fn default() -> Self {
        Self {
            max_syntax_occurrences: DEFAULT_MAX_SYNTAX_OCCURRENCES,
            max_canonical_nodes: DEFAULT_MAX_CANONICAL_NODES,
            max_canonical_edges: DEFAULT_MAX_CANONICAL_EDGES,
            max_variables: DEFAULT_MAX_VARIABLES,
            max_clauses: DEFAULT_MAX_CLAUSES,
            max_literal_occurrences: DEFAULT_MAX_LITERAL_OCCURRENCES,
            max_provenance_bytes: DEFAULT_MAX_PROVENANCE_BYTES,
            max_encoding_depth: DEFAULT_MAX_ENCODING_DEPTH,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProjectionFailureReason {
    UnsupportedBooleanSyntax,
    SyntaxOccurrenceCap,
    CanonicalNodeCap,
    CanonicalEdgeCap,
    VariableCap,
    ClauseCap,
    LiteralOccurrenceCap,
    ProvenanceByteCap,
    EncodingDepthCap,
    InvalidTermId,
    IllSortedEquality,
    NonBooleanTerm,
    MissingAtomId,
    InconsistentProjection,
    ArithmeticOverflow,
    AllocationFailure,
    ClockRegression,
}

impl ProjectionFailureReason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedBooleanSyntax => "unsupported_boolean_syntax",
            Self::SyntaxOccurrenceCap => "syntax_occurrence_cap",
            Self::CanonicalNodeCap => "canonical_node_cap",
            Self::CanonicalEdgeCap => "canonical_edge_cap",
            Self::VariableCap => "variable_cap",
            Self::ClauseCap => "clause_cap",
            Self::LiteralOccurrenceCap => "literal_occurrence_cap",
            Self::ProvenanceByteCap => "provenance_byte_cap",
            Self::EncodingDepthCap => "encoding_depth_cap",
            Self::InvalidTermId => "invalid_term_id",
            Self::IllSortedEquality => "ill_sorted_equality",
            Self::NonBooleanTerm => "non_boolean_term",
            Self::MissingAtomId => "missing_atom_id",
            Self::InconsistentProjection => "inconsistent_projection",
            Self::ArithmeticOverflow => "arithmetic_overflow",
            Self::AllocationFailure => "allocation_failure",
            Self::ClockRegression => "clock_regression",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProjectionFailure {
    pub(crate) reason: ProjectionFailureReason,
    pub(crate) observed: usize,
    pub(crate) limit: Option<usize>,
}

impl ProjectionFailure {
    fn capped(reason: ProjectionFailureReason, observed: usize, limit: usize) -> Self {
        Self {
            reason,
            observed,
            limit: Some(limit),
        }
    }

    fn invalid(reason: ProjectionFailureReason, observed: usize) -> Self {
        Self {
            reason,
            observed,
            limit: None,
        }
    }

    pub(crate) fn write_to<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writeln!(writer, "t6_projection_version 1")?;
        writeln!(writer, "status abstained")?;
        writeln!(writer, "control syntactic_only")?;
        writeln!(writer, "production_routing false")?;
        writeln!(writer, "solver_invoked false")?;
        writeln!(writer, "guarded_euf_claim none")?;
        writeln!(
            writer,
            "guarded_euf_next_interface {GUARDED_EUF_NEXT_INTERFACE}"
        )?;
        write!(
            writer,
            "reason {} observed {}",
            self.reason.as_str(),
            self.observed
        )?;
        if let Some(limit) = self.limit {
            write!(writer, " limit {limit}")?;
        }
        writeln!(writer)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ArmMetrics {
    pub(crate) variables: usize,
    pub(crate) clauses: usize,
    pub(crate) literal_occurrences: usize,
    pub(crate) estimated_watch_slots: usize,
    pub(crate) encoder_nanoseconds: u128,
    pub(crate) canonical_nodes: usize,
    pub(crate) canonical_edges: usize,
    pub(crate) provenance_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AtomId {
    pub(crate) variable: i32,
    pub(crate) atom: BoolAtomKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProjectionReport {
    pub(crate) baseline: ArmMetrics,
    pub(crate) syntactic: ArmMetrics,
    pub(crate) atoms: Vec<AtomId>,
    pub(crate) candidate_clauses: Vec<Vec<i32>>,
    candidate_provenance: Vec<u8>,
}

impl ProjectionReport {
    pub(crate) fn write_to<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writeln!(writer, "t6_projection_version 1")?;
        writeln!(writer, "status projected")?;
        writeln!(writer, "control syntactic_only")?;
        writeln!(writer, "production_routing false")?;
        writeln!(writer, "solver_invoked false")?;
        writeln!(writer, "guarded_euf_claim none")?;
        writeln!(
            writer,
            "guarded_euf_next_interface {GUARDED_EUF_NEXT_INTERFACE}"
        )?;
        write_arm(&mut writer, "baseline_direct_root", &self.baseline)?;
        write_arm(&mut writer, "syntactic_polarity_dag", &self.syntactic)?;
        for atom in &self.atoms {
            match atom.atom {
                BoolAtomKey::Eq(left, right) => {
                    writeln!(writer, "atom {} equality {left} {right}", atom.variable)?;
                }
                BoolAtomKey::BoolTerm(term) => {
                    writeln!(writer, "atom {} bool_term {term}", atom.variable)?;
                }
            }
        }
        writeln!(writer, "candidate_cnf_begin")?;
        writeln!(
            writer,
            "p cnf {} {}",
            self.syntactic.variables, self.syntactic.clauses
        )?;
        for clause in &self.candidate_clauses {
            for literal in clause {
                write!(writer, "{literal} ")?;
            }
            writeln!(writer, "0")?;
        }
        writeln!(writer, "candidate_cnf_end")
    }

    #[cfg(test)]
    fn rendered(&self) -> String {
        let mut bytes = Vec::new();
        self.write_to(&mut bytes).unwrap();
        String::from_utf8(bytes).unwrap()
    }
}

fn write_arm<W: Write>(writer: &mut W, name: &str, metrics: &ArmMetrics) -> io::Result<()> {
    writeln!(
        writer,
        "arm {name} variables {} clauses {} literal_occurrences {} estimated_watch_slots {} encoder_nanoseconds {} canonical_nodes {} canonical_edges {} provenance_bytes {}",
        metrics.variables,
        metrics.clauses,
        metrics.literal_occurrences,
        metrics.estimated_watch_slots,
        metrics.encoder_nanoseconds,
        metrics.canonical_nodes,
        metrics.canonical_edges,
        metrics.provenance_bytes,
    )
}

#[derive(Debug, Clone, Copy)]
struct ProvenanceOrigin {
    kind: u8,
    node: NodeId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClauseBuffer {
    clauses: Vec<Vec<i32>>,
    literal_occurrences: usize,
    estimated_watch_slots: usize,
    provenance: Vec<u8>,
    limits: ProjectionLimits,
}

impl ClauseBuffer {
    fn new(limits: ProjectionLimits) -> Self {
        Self {
            clauses: Vec::new(),
            literal_occurrences: 0,
            estimated_watch_slots: 0,
            provenance: Vec::new(),
            limits,
        }
    }

    fn push(
        &mut self,
        clause: Vec<i32>,
        origin: Option<ProvenanceOrigin>,
    ) -> Result<(), ProjectionFailure> {
        let next_clauses = self.clauses.len().checked_add(1).ok_or_else(|| {
            ProjectionFailure::invalid(ProjectionFailureReason::ArithmeticOverflow, usize::MAX)
        })?;
        if next_clauses > self.limits.max_clauses {
            return Err(ProjectionFailure::capped(
                ProjectionFailureReason::ClauseCap,
                next_clauses,
                self.limits.max_clauses,
            ));
        }

        let next_literals = self
            .literal_occurrences
            .checked_add(clause.len())
            .ok_or_else(|| {
                ProjectionFailure::invalid(ProjectionFailureReason::ArithmeticOverflow, usize::MAX)
            })?;
        if next_literals > self.limits.max_literal_occurrences {
            return Err(ProjectionFailure::capped(
                ProjectionFailureReason::LiteralOccurrenceCap,
                next_literals,
                self.limits.max_literal_occurrences,
            ));
        }

        let next_watch_slots = self
            .estimated_watch_slots
            .checked_add(usize::from(clause.len() >= 2) * 2)
            .ok_or_else(|| {
                ProjectionFailure::invalid(ProjectionFailureReason::ArithmeticOverflow, usize::MAX)
            })?;
        let provenance_bytes = usize::from(origin.is_some()) * PROVENANCE_RECORD_BYTES;
        let next_provenance = self
            .provenance
            .len()
            .checked_add(provenance_bytes)
            .ok_or_else(|| {
                ProjectionFailure::invalid(ProjectionFailureReason::ArithmeticOverflow, usize::MAX)
            })?;
        if next_provenance > self.limits.max_provenance_bytes {
            return Err(ProjectionFailure::capped(
                ProjectionFailureReason::ProvenanceByteCap,
                next_provenance,
                self.limits.max_provenance_bytes,
            ));
        }

        self.clauses
            .try_reserve(1)
            .map_err(|_| allocation_failure())?;
        self.provenance
            .try_reserve(provenance_bytes)
            .map_err(|_| allocation_failure())?;
        if let Some(origin) = origin {
            let node = u64::try_from(origin.node).map_err(|_| {
                ProjectionFailure::invalid(ProjectionFailureReason::ArithmeticOverflow, origin.node)
            })?;
            let clause_index = u64::try_from(self.clauses.len()).map_err(|_| {
                ProjectionFailure::invalid(
                    ProjectionFailureReason::ArithmeticOverflow,
                    self.clauses.len(),
                )
            })?;
            self.provenance.push(origin.kind);
            self.provenance.extend_from_slice(&node.to_le_bytes());
            self.provenance
                .extend_from_slice(&clause_index.to_le_bytes());
        }
        self.literal_occurrences = next_literals;
        self.estimated_watch_slots = next_watch_slots;
        self.clauses.push(clause);
        Ok(())
    }
}

fn allocation_failure() -> ProjectionFailure {
    ProjectionFailure::invalid(ProjectionFailureReason::AllocationFailure, 0)
}

struct ValidatedSyntax<'a> {
    nodes: Vec<&'a BoolExpr>,
}

fn validate_source<'a>(
    bool_problem: &'a BoolProblem,
    arena: &TermArena,
    limits: ProjectionLimits,
) -> Result<ValidatedSyntax<'a>, ProjectionFailure> {
    if !bool_problem.unsupported.is_empty() {
        return Err(ProjectionFailure::invalid(
            ProjectionFailureReason::UnsupportedBooleanSyntax,
            bool_problem.unsupported.len(),
        ));
    }
    validate_boolean_term(bool_problem.true_term, arena)?;
    validate_boolean_term(bool_problem.false_term, arena)?;
    for &term in &bool_problem.data_terms {
        validate_boolean_term(term, arena)?;
    }

    let mut nodes = Vec::new();
    let mut stack = Vec::new();
    stack
        .try_reserve(bool_problem.assertions.len())
        .map_err(|_| allocation_failure())?;
    stack.extend(bool_problem.assertions.iter().rev());
    while let Some(expression) = stack.pop() {
        let next_occurrences = nodes.len().checked_add(1).ok_or_else(|| {
            ProjectionFailure::invalid(ProjectionFailureReason::ArithmeticOverflow, usize::MAX)
        })?;
        if next_occurrences > limits.max_syntax_occurrences {
            return Err(ProjectionFailure::capped(
                ProjectionFailureReason::SyntaxOccurrenceCap,
                next_occurrences,
                limits.max_syntax_occurrences,
            ));
        }
        validate_expression_terms(expression, arena)?;
        nodes.try_reserve(1).map_err(|_| allocation_failure())?;
        nodes.push(expression);
        push_expression_children(expression, &mut stack)?;
    }
    let projected_occurrences = nodes
        .len()
        .checked_add(bool_problem.data_terms.len())
        .ok_or_else(|| {
            ProjectionFailure::invalid(ProjectionFailureReason::ArithmeticOverflow, usize::MAX)
        })?;
    if projected_occurrences > limits.max_syntax_occurrences {
        return Err(ProjectionFailure::capped(
            ProjectionFailureReason::SyntaxOccurrenceCap,
            projected_occurrences,
            limits.max_syntax_occurrences,
        ));
    }
    Ok(ValidatedSyntax { nodes })
}

fn validate_expression_terms(
    expression: &BoolExpr,
    arena: &TermArena,
) -> Result<(), ProjectionFailure> {
    match expression {
        BoolExpr::Atom(BoolAtomKey::Eq(left, right)) => {
            let left_sort = arena
                .terms
                .get(*left)
                .map(|term| term.sort)
                .ok_or_else(|| {
                    ProjectionFailure::invalid(ProjectionFailureReason::InvalidTermId, *left)
                })?;
            let right_sort = arena
                .terms
                .get(*right)
                .map(|term| term.sort)
                .ok_or_else(|| {
                    ProjectionFailure::invalid(ProjectionFailureReason::InvalidTermId, *right)
                })?;
            if left_sort != right_sort {
                return Err(ProjectionFailure::invalid(
                    ProjectionFailureReason::IllSortedEquality,
                    *right,
                ));
            }
        }
        BoolExpr::Atom(BoolAtomKey::BoolTerm(term)) => validate_boolean_term(*term, arena)?,
        _ => {}
    }
    Ok(())
}

fn validate_boolean_term(term: TermId, arena: &TermArena) -> Result<(), ProjectionFailure> {
    let sort =
        arena.terms.get(term).map(|term| term.sort).ok_or_else(|| {
            ProjectionFailure::invalid(ProjectionFailureReason::InvalidTermId, term)
        })?;
    if sort != BOOL_SORT {
        return Err(ProjectionFailure::invalid(
            ProjectionFailureReason::NonBooleanTerm,
            term,
        ));
    }
    Ok(())
}

fn push_expression_children<'a>(
    expression: &'a BoolExpr,
    stack: &mut Vec<&'a BoolExpr>,
) -> Result<(), ProjectionFailure> {
    let children = expression_child_count(expression);
    stack
        .try_reserve(children)
        .map_err(|_| allocation_failure())?;
    match expression {
        BoolExpr::Const(_) | BoolExpr::Atom(_) => {}
        BoolExpr::Not(child) => stack.push(child),
        BoolExpr::And(children) | BoolExpr::Or(children) | BoolExpr::Iff(children) => {
            stack.extend(children.iter().rev());
        }
        BoolExpr::Ite(condition, then_expression, else_expression) => {
            stack.push(else_expression);
            stack.push(then_expression);
            stack.push(condition);
        }
    }
    Ok(())
}

fn expression_child_count(expression: &BoolExpr) -> usize {
    match expression {
        BoolExpr::Const(_) | BoolExpr::Atom(_) => 0,
        BoolExpr::Not(_) => 1,
        BoolExpr::And(children) | BoolExpr::Or(children) | BoolExpr::Iff(children) => {
            children.len()
        }
        BoolExpr::Ite(_, _, _) => 3,
    }
}

struct BaselineEncoder {
    clauses: ClauseBuffer,
    var_atoms: Vec<Option<BoolAtomKey>>,
    atom_vars: HashMap<BoolAtomKey, i32>,
    true_lit: Option<i32>,
    limits: ProjectionLimits,
}

impl BaselineEncoder {
    fn build(
        bool_problem: &BoolProblem,
        limits: ProjectionLimits,
    ) -> Result<Self, ProjectionFailure> {
        let mut encoder = Self {
            clauses: ClauseBuffer::new(limits),
            var_atoms: vec![None],
            atom_vars: HashMap::default(),
            true_lit: None,
            limits,
        };
        for &term in &bool_problem.data_terms {
            encoder.atom_lit(BoolAtomKey::BoolTerm(term))?;
        }
        for assertion in &bool_problem.assertions {
            encoder.add_direct_assertion(assertion, 0)?;
        }
        Ok(encoder)
    }

    fn var_count(&self) -> usize {
        self.var_atoms.len() - 1
    }

    fn check_depth(&self, depth: usize) -> Result<(), ProjectionFailure> {
        if depth > self.limits.max_encoding_depth {
            return Err(ProjectionFailure::capped(
                ProjectionFailureReason::EncodingDepthCap,
                depth,
                self.limits.max_encoding_depth,
            ));
        }
        Ok(())
    }

    fn new_var(&mut self, atom: Option<BoolAtomKey>) -> Result<i32, ProjectionFailure> {
        let next_variables = self.var_count().checked_add(1).ok_or_else(|| {
            ProjectionFailure::invalid(ProjectionFailureReason::ArithmeticOverflow, usize::MAX)
        })?;
        if next_variables > self.limits.max_variables {
            return Err(ProjectionFailure::capped(
                ProjectionFailureReason::VariableCap,
                next_variables,
                self.limits.max_variables,
            ));
        }
        let variable = i32::try_from(next_variables).map_err(|_| {
            ProjectionFailure::invalid(ProjectionFailureReason::ArithmeticOverflow, next_variables)
        })?;
        self.var_atoms
            .try_reserve(1)
            .map_err(|_| allocation_failure())?;
        self.var_atoms.push(atom);
        Ok(variable)
    }

    fn atom_lit(&mut self, atom: BoolAtomKey) -> Result<i32, ProjectionFailure> {
        let atom = normalize_atom(atom);
        if let Some(&literal) = self.atom_vars.get(&atom) {
            return Ok(literal);
        }
        let literal = self.new_var(Some(atom.clone()))?;
        self.atom_vars
            .try_reserve(1)
            .map_err(|_| allocation_failure())?;
        self.atom_vars.insert(atom, literal);
        Ok(literal)
    }

    fn literal_const(&mut self, value: bool) -> Result<i32, ProjectionFailure> {
        let literal = match self.true_lit {
            Some(literal) => literal,
            None => {
                let literal = self.new_var(None)?;
                self.clauses.push(vec![literal], None)?;
                self.true_lit = Some(literal);
                literal
            }
        };
        Ok(if value { literal } else { -literal })
    }

    fn add_direct_assertion(
        &mut self,
        expression: &BoolExpr,
        depth: usize,
    ) -> Result<(), ProjectionFailure> {
        self.check_depth(depth)?;
        match expression {
            BoolExpr::Const(true) => {}
            BoolExpr::Const(false) => self.clauses.push(Vec::new(), None)?,
            BoolExpr::Atom(atom) => {
                let literal = self.atom_lit(atom.clone())?;
                self.clauses.push(vec![literal], None)?;
            }
            BoolExpr::Not(child) => {
                let literal = self.encode_expr(child, depth + 1)?;
                self.clauses.push(vec![-literal], None)?;
            }
            BoolExpr::And(children) => {
                for child in children {
                    self.add_direct_assertion(child, depth + 1)?;
                }
            }
            BoolExpr::Or(children) => {
                let mut clause = Vec::new();
                clause
                    .try_reserve(children.len())
                    .map_err(|_| allocation_failure())?;
                for child in children {
                    clause.push(self.encode_expr(child, depth + 1)?);
                }
                self.clauses.push(clause, None)?;
            }
            BoolExpr::Iff(children) => {
                let Some((first, rest)) = children.split_first() else {
                    return Ok(());
                };
                let first = self.encode_expr(first, depth + 1)?;
                for child in rest {
                    let child = self.encode_expr(child, depth + 1)?;
                    self.clauses.push(vec![-first, child], None)?;
                    self.clauses.push(vec![first, -child], None)?;
                }
            }
            BoolExpr::Ite(condition, then_expression, else_expression) => {
                let condition = self.encode_expr(condition, depth + 1)?;
                let then_expression = self.encode_expr(then_expression, depth + 1)?;
                let else_expression = self.encode_expr(else_expression, depth + 1)?;
                self.clauses.push(vec![-condition, then_expression], None)?;
                self.clauses.push(vec![condition, else_expression], None)?;
            }
        }
        Ok(())
    }

    fn encode_expr(
        &mut self,
        expression: &BoolExpr,
        depth: usize,
    ) -> Result<i32, ProjectionFailure> {
        self.check_depth(depth)?;
        match expression {
            BoolExpr::Const(value) => self.literal_const(*value),
            BoolExpr::Atom(atom) => self.atom_lit(atom.clone()),
            BoolExpr::Not(child) => Ok(-self.encode_expr(child, depth + 1)?),
            BoolExpr::And(children) => self.encode_and(children, depth + 1),
            BoolExpr::Or(children) => self.encode_or(children, depth + 1),
            BoolExpr::Iff(children) => self.encode_iff(children, depth + 1),
            BoolExpr::Ite(condition, then_expression, else_expression) => {
                let condition = self.encode_expr(condition, depth + 1)?;
                let then_expression = self.encode_expr(then_expression, depth + 1)?;
                let else_expression = self.encode_expr(else_expression, depth + 1)?;
                let extension = self.new_var(None)?;
                self.clauses
                    .push(vec![-condition, -then_expression, extension], None)?;
                self.clauses
                    .push(vec![-condition, then_expression, -extension], None)?;
                self.clauses
                    .push(vec![condition, -else_expression, extension], None)?;
                self.clauses
                    .push(vec![condition, else_expression, -extension], None)?;
                Ok(extension)
            }
        }
    }

    fn encode_and(
        &mut self,
        children: &[BoolExpr],
        depth: usize,
    ) -> Result<i32, ProjectionFailure> {
        match children {
            [] => self.literal_const(true),
            [single] => self.encode_expr(single, depth + 1),
            _ => {
                let literals = self.encode_children(children, depth + 1)?;
                self.encode_and_literals(&literals)
            }
        }
    }

    fn encode_and_literals(&mut self, literals: &[i32]) -> Result<i32, ProjectionFailure> {
        let extension = self.new_var(None)?;
        for &literal in literals {
            self.clauses.push(vec![-extension, literal], None)?;
        }
        let capacity = literals.len().checked_add(1).ok_or_else(|| {
            ProjectionFailure::invalid(ProjectionFailureReason::ArithmeticOverflow, usize::MAX)
        })?;
        let mut clause = Vec::new();
        clause
            .try_reserve(capacity)
            .map_err(|_| allocation_failure())?;
        clause.push(extension);
        clause.extend(literals.iter().map(|literal| -*literal));
        self.clauses.push(clause, None)?;
        Ok(extension)
    }

    fn encode_or(&mut self, children: &[BoolExpr], depth: usize) -> Result<i32, ProjectionFailure> {
        match children {
            [] => self.literal_const(false),
            [single] => self.encode_expr(single, depth + 1),
            _ => {
                let literals = self.encode_children(children, depth + 1)?;
                let extension = self.new_var(None)?;
                for &literal in &literals {
                    self.clauses.push(vec![extension, -literal], None)?;
                }
                let capacity = literals.len().checked_add(1).ok_or_else(|| {
                    ProjectionFailure::invalid(
                        ProjectionFailureReason::ArithmeticOverflow,
                        usize::MAX,
                    )
                })?;
                let mut clause = Vec::new();
                clause
                    .try_reserve(capacity)
                    .map_err(|_| allocation_failure())?;
                clause.push(-extension);
                clause.extend_from_slice(&literals);
                self.clauses.push(clause, None)?;
                Ok(extension)
            }
        }
    }

    fn encode_iff(
        &mut self,
        children: &[BoolExpr],
        depth: usize,
    ) -> Result<i32, ProjectionFailure> {
        match children {
            [] | [_] => self.literal_const(true),
            [left, right] => self.encode_iff_pair(left, right, depth + 1),
            _ => {
                let first = &children[0];
                let mut pairs = Vec::new();
                pairs
                    .try_reserve(children.len() - 1)
                    .map_err(|_| allocation_failure())?;
                for child in &children[1..] {
                    pairs.push(self.encode_iff_pair(first, child, depth + 1)?);
                }
                self.encode_and_literals(&pairs)
            }
        }
    }

    fn encode_iff_pair(
        &mut self,
        left: &BoolExpr,
        right: &BoolExpr,
        depth: usize,
    ) -> Result<i32, ProjectionFailure> {
        let left = self.encode_expr(left, depth + 1)?;
        let right = self.encode_expr(right, depth + 1)?;
        let extension = self.new_var(None)?;
        self.clauses.push(vec![-extension, -left, right], None)?;
        self.clauses.push(vec![-extension, left, -right], None)?;
        self.clauses.push(vec![extension, -left, -right], None)?;
        self.clauses.push(vec![extension, left, right], None)?;
        Ok(extension)
    }

    fn encode_children(
        &mut self,
        children: &[BoolExpr],
        depth: usize,
    ) -> Result<Vec<i32>, ProjectionFailure> {
        let mut literals = Vec::new();
        literals
            .try_reserve(children.len())
            .map_err(|_| allocation_failure())?;
        for child in children {
            literals.push(self.encode_expr(child, depth + 1)?);
        }
        Ok(literals)
    }
}

fn normalize_atom(atom: BoolAtomKey) -> BoolAtomKey {
    match atom {
        BoolAtomKey::Eq(left, right) => {
            let (left, right) = normalized_pair(left, right);
            BoolAtomKey::Eq(left, right)
        }
        atom => atom,
    }
}

type NodeId = usize;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum CanonicalNode {
    Const(bool),
    Atom(BoolAtomKey),
    Not(NodeId),
    And(Vec<NodeId>),
    Or(Vec<NodeId>),
    Iff(Vec<NodeId>),
    Ite([NodeId; 3]),
}

impl CanonicalNode {
    fn children(&self) -> &[NodeId] {
        match self {
            Self::Const(_) | Self::Atom(_) => &[],
            Self::Not(child) => std::slice::from_ref(child),
            Self::And(children) | Self::Or(children) | Self::Iff(children) => children,
            Self::Ite(children) => children,
        }
    }

    fn has_extension_definition(&self) -> bool {
        matches!(
            self,
            Self::And(_) | Self::Or(_) | Self::Iff(_) | Self::Ite(_)
        )
    }
}

struct CanonicalInterner {
    nodes: Vec<Rc<CanonicalNode>>,
    ids: HashMap<Rc<CanonicalNode>, NodeId>,
    stored_edges: usize,
    limits: ProjectionLimits,
}

impl CanonicalInterner {
    fn new(limits: ProjectionLimits) -> Self {
        Self {
            nodes: Vec::new(),
            ids: HashMap::default(),
            stored_edges: 0,
            limits,
        }
    }

    fn node(&self, node: NodeId) -> &CanonicalNode {
        self.nodes[node].as_ref()
    }

    fn intern(&mut self, node: CanonicalNode) -> Result<NodeId, ProjectionFailure> {
        if let Some(&node_id) = self.ids.get(&node) {
            return Ok(node_id);
        }
        let next_nodes = self.nodes.len().checked_add(1).ok_or_else(|| {
            ProjectionFailure::invalid(ProjectionFailureReason::ArithmeticOverflow, usize::MAX)
        })?;
        if next_nodes > self.limits.max_canonical_nodes {
            return Err(ProjectionFailure::capped(
                ProjectionFailureReason::CanonicalNodeCap,
                next_nodes,
                self.limits.max_canonical_nodes,
            ));
        }
        let next_edges = self
            .stored_edges
            .checked_add(node.children().len())
            .ok_or_else(|| {
                ProjectionFailure::invalid(ProjectionFailureReason::ArithmeticOverflow, usize::MAX)
            })?;
        if next_edges > self.limits.max_canonical_edges {
            return Err(ProjectionFailure::capped(
                ProjectionFailureReason::CanonicalEdgeCap,
                next_edges,
                self.limits.max_canonical_edges,
            ));
        }
        self.nodes
            .try_reserve(1)
            .map_err(|_| allocation_failure())?;
        self.ids.try_reserve(1).map_err(|_| allocation_failure())?;
        let node_id = self.nodes.len();
        let node = Rc::new(node);
        self.nodes.push(Rc::clone(&node));
        self.ids.insert(node, node_id);
        self.stored_edges = next_edges;
        Ok(node_id)
    }

    fn associative_children(
        &self,
        child_ids: &[NodeId],
        conjunction: bool,
    ) -> Result<Vec<NodeId>, ProjectionFailure> {
        let mut flattened_len = 0usize;
        for &child in child_ids {
            let contribution = match (conjunction, self.node(child)) {
                (true, CanonicalNode::And(nested)) | (false, CanonicalNode::Or(nested)) => {
                    nested.len()
                }
                _ => 1,
            };
            flattened_len = flattened_len.checked_add(contribution).ok_or_else(|| {
                ProjectionFailure::invalid(ProjectionFailureReason::ArithmeticOverflow, usize::MAX)
            })?;
            if flattened_len > self.limits.max_canonical_edges {
                return Err(ProjectionFailure::capped(
                    ProjectionFailureReason::CanonicalEdgeCap,
                    flattened_len,
                    self.limits.max_canonical_edges,
                ));
            }
        }
        let mut flattened = Vec::new();
        flattened
            .try_reserve(flattened_len)
            .map_err(|_| allocation_failure())?;
        for &child in child_ids {
            match (conjunction, self.node(child)) {
                (true, CanonicalNode::And(nested)) | (false, CanonicalNode::Or(nested)) => {
                    flattened.extend_from_slice(nested);
                }
                _ => flattened.push(child),
            }
        }
        flattened.sort_unstable();
        Ok(flattened)
    }

    fn expression_node(
        &self,
        expression: &BoolExpr,
        children: &[NodeId],
    ) -> Result<CanonicalNode, ProjectionFailure> {
        Ok(match expression {
            BoolExpr::Const(value) => CanonicalNode::Const(*value),
            BoolExpr::Atom(atom) => CanonicalNode::Atom(normalize_atom(atom.clone())),
            BoolExpr::Not(_) => CanonicalNode::Not(children[0]),
            BoolExpr::And(_) => CanonicalNode::And(self.associative_children(children, true)?),
            BoolExpr::Or(_) => CanonicalNode::Or(self.associative_children(children, false)?),
            // IFF stays in source order. Only associative AND/OR receive AC normalization.
            BoolExpr::Iff(_) => CanonicalNode::Iff(children.to_vec()),
            BoolExpr::Ite(_, _, _) => CanonicalNode::Ite([children[0], children[1], children[2]]),
        })
    }
}

struct CanonicalGraph {
    nodes: Vec<Rc<CanonicalNode>>,
    roots: Vec<NodeId>,
    fanout: Vec<usize>,
    reachable: Vec<bool>,
    canonical_nodes: usize,
    canonical_edges: usize,
}

impl CanonicalGraph {
    fn build(
        syntax: &ValidatedSyntax<'_>,
        assertions: &[BoolExpr],
        limits: ProjectionLimits,
    ) -> Result<Self, ProjectionFailure> {
        let mut interner = CanonicalInterner::new(limits);
        let mut occurrence_ids = HashMap::<usize, NodeId>::default();
        occurrence_ids
            .try_reserve(syntax.nodes.len())
            .map_err(|_| allocation_failure())?;
        for &expression in syntax.nodes.iter().rev() {
            let mut children = Vec::new();
            children
                .try_reserve(expression_child_count(expression))
                .map_err(|_| allocation_failure())?;
            append_child_ids(expression, &occurrence_ids, &mut children)?;
            let node = interner.expression_node(expression, &children)?;
            let node_id = interner.intern(node)?;
            occurrence_ids.insert(expression_address(expression), node_id);
        }

        let mut roots = Vec::new();
        roots
            .try_reserve(assertions.len())
            .map_err(|_| allocation_failure())?;
        for assertion in assertions {
            let node_id = occurrence_ids
                .get(&expression_address(assertion))
                .copied()
                .ok_or_else(|| {
                    ProjectionFailure::invalid(
                        ProjectionFailureReason::InconsistentProjection,
                        expression_address(assertion),
                    )
                })?;
            roots.push(node_id);
        }

        let mut reachable = vec![false; interner.nodes.len()];
        let mut stack = roots.clone();
        let mut canonical_nodes = 0usize;
        let mut canonical_edges = 0usize;
        while let Some(node_id) = stack.pop() {
            if reachable[node_id] {
                continue;
            }
            reachable[node_id] = true;
            canonical_nodes = canonical_nodes.checked_add(1).ok_or_else(|| {
                ProjectionFailure::invalid(ProjectionFailureReason::ArithmeticOverflow, usize::MAX)
            })?;
            let children = interner.node(node_id).children();
            canonical_edges = canonical_edges.checked_add(children.len()).ok_or_else(|| {
                ProjectionFailure::invalid(ProjectionFailureReason::ArithmeticOverflow, usize::MAX)
            })?;
            stack
                .try_reserve(children.len())
                .map_err(|_| allocation_failure())?;
            stack.extend_from_slice(children);
        }

        let mut fanout = vec![0usize; interner.nodes.len()];
        for &root in &roots {
            fanout[root] = fanout[root].checked_add(1).ok_or_else(|| {
                ProjectionFailure::invalid(ProjectionFailureReason::ArithmeticOverflow, usize::MAX)
            })?;
        }
        for (node_id, is_reachable) in reachable.iter().copied().enumerate() {
            if !is_reachable {
                continue;
            }
            for &child in interner.node(node_id).children() {
                fanout[child] = fanout[child].checked_add(1).ok_or_else(|| {
                    ProjectionFailure::invalid(
                        ProjectionFailureReason::ArithmeticOverflow,
                        usize::MAX,
                    )
                })?;
            }
        }

        Ok(Self {
            nodes: interner.nodes,
            roots,
            fanout,
            reachable,
            canonical_nodes,
            canonical_edges,
        })
    }

    fn node(&self, node: NodeId) -> &CanonicalNode {
        self.nodes[node].as_ref()
    }

    fn is_shared_extension(&self, node: NodeId) -> bool {
        self.fanout[node] >= 2 && self.node(node).has_extension_definition()
    }
}

fn append_child_ids(
    expression: &BoolExpr,
    occurrence_ids: &HashMap<usize, NodeId>,
    children: &mut Vec<NodeId>,
) -> Result<(), ProjectionFailure> {
    let mut append = |child: &BoolExpr| -> Result<(), ProjectionFailure> {
        let address = expression_address(child);
        let child_id = occurrence_ids.get(&address).copied().ok_or_else(|| {
            ProjectionFailure::invalid(ProjectionFailureReason::InconsistentProjection, address)
        })?;
        children.push(child_id);
        Ok(())
    };
    match expression {
        BoolExpr::Const(_) | BoolExpr::Atom(_) => {}
        BoolExpr::Not(child) => append(child)?,
        BoolExpr::And(items) | BoolExpr::Or(items) | BoolExpr::Iff(items) => {
            for child in items {
                append(child)?;
            }
        }
        BoolExpr::Ite(condition, then_expression, else_expression) => {
            append(condition)?;
            append(then_expression)?;
            append(else_expression)?;
        }
    }
    Ok(())
}

fn expression_address(expression: &BoolExpr) -> usize {
    std::ptr::from_ref(expression) as usize
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Polarity {
    Positive,
    Negative,
}

impl Polarity {
    fn bit(self) -> u8 {
        match self {
            Self::Positive => 1,
            Self::Negative => 2,
        }
    }

    fn flipped(self) -> Self {
        match self {
            Self::Positive => Self::Negative,
            Self::Negative => Self::Positive,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FormulaLiteral {
    Const(bool),
    Lit(i32),
}

struct VariableAllocator {
    free_baseline_auxiliaries: Vec<i32>,
    next_free: usize,
    next_appended: usize,
    max_used: usize,
    max_variables: usize,
}

impl VariableAllocator {
    fn new(baseline: &BaselineEncoder, max_variables: usize) -> Result<Self, ProjectionFailure> {
        let mut free_baseline_auxiliaries = Vec::new();
        free_baseline_auxiliaries
            .try_reserve(baseline.var_count())
            .map_err(|_| allocation_failure())?;
        let mut max_used = 0usize;
        for (variable, atom) in baseline.var_atoms.iter().enumerate().skip(1) {
            if atom.is_some() {
                max_used = max_used.max(variable);
            } else {
                free_baseline_auxiliaries.push(i32::try_from(variable).map_err(|_| {
                    ProjectionFailure::invalid(
                        ProjectionFailureReason::ArithmeticOverflow,
                        variable,
                    )
                })?);
            }
        }
        if max_used > max_variables {
            return Err(ProjectionFailure::capped(
                ProjectionFailureReason::VariableCap,
                max_used,
                max_variables,
            ));
        }
        let next_appended = baseline.var_count().checked_add(1).ok_or_else(|| {
            ProjectionFailure::invalid(ProjectionFailureReason::ArithmeticOverflow, usize::MAX)
        })?;
        Ok(Self {
            free_baseline_auxiliaries,
            next_free: 0,
            next_appended,
            max_used,
            max_variables,
        })
    }

    fn allocate(&mut self) -> Result<i32, ProjectionFailure> {
        let variable = if let Some(&variable) = self.free_baseline_auxiliaries.get(self.next_free) {
            self.next_free = self.next_free.checked_add(1).ok_or_else(|| {
                ProjectionFailure::invalid(ProjectionFailureReason::ArithmeticOverflow, usize::MAX)
            })?;
            usize::try_from(variable).map_err(|_| {
                ProjectionFailure::invalid(ProjectionFailureReason::ArithmeticOverflow, 0)
            })?
        } else {
            let variable = self.next_appended;
            self.next_appended = self.next_appended.checked_add(1).ok_or_else(|| {
                ProjectionFailure::invalid(ProjectionFailureReason::ArithmeticOverflow, usize::MAX)
            })?;
            variable
        };
        if variable > self.max_variables {
            return Err(ProjectionFailure::capped(
                ProjectionFailureReason::VariableCap,
                variable,
                self.max_variables,
            ));
        }
        let variable_i32 = i32::try_from(variable).map_err(|_| {
            ProjectionFailure::invalid(ProjectionFailureReason::ArithmeticOverflow, variable)
        })?;
        self.max_used = self.max_used.max(variable);
        Ok(variable_i32)
    }
}

struct CandidateEncoder<'a> {
    graph: &'a CanonicalGraph,
    atom_vars: &'a HashMap<BoolAtomKey, i32>,
    variables: VariableAllocator,
    clauses: ClauseBuffer,
    node_variables: Vec<Option<i32>>,
    definition_polarities: Vec<u8>,
    limits: ProjectionLimits,
}

impl<'a> CandidateEncoder<'a> {
    fn build(
        graph: &'a CanonicalGraph,
        baseline: &'a BaselineEncoder,
        limits: ProjectionLimits,
    ) -> Result<Self, ProjectionFailure> {
        for (node_id, is_reachable) in graph.reachable.iter().copied().enumerate() {
            if !is_reachable {
                continue;
            }
            if let CanonicalNode::Atom(atom) = graph.node(node_id)
                && !baseline.atom_vars.contains_key(atom)
            {
                return Err(ProjectionFailure::invalid(
                    ProjectionFailureReason::MissingAtomId,
                    node_id,
                ));
            }
        }

        let mut encoder = Self {
            graph,
            atom_vars: &baseline.atom_vars,
            variables: VariableAllocator::new(baseline, limits.max_variables)?,
            clauses: ClauseBuffer::new(limits),
            node_variables: vec![None; graph.nodes.len()],
            definition_polarities: vec![0; graph.nodes.len()],
            limits,
        };
        let mut asserted_roots = HashSet::default();
        asserted_roots
            .try_reserve(graph.roots.len())
            .map_err(|_| allocation_failure())?;
        for &root in &graph.roots {
            if asserted_roots.insert(root) {
                encoder.assert_node(root, Polarity::Positive, 0)?;
            }
        }
        Ok(encoder)
    }

    fn check_depth(&self, depth: usize) -> Result<(), ProjectionFailure> {
        if depth > self.limits.max_encoding_depth {
            return Err(ProjectionFailure::capped(
                ProjectionFailureReason::EncodingDepthCap,
                depth,
                self.limits.max_encoding_depth,
            ));
        }
        Ok(())
    }

    fn extension_variable(&mut self, node: NodeId) -> Result<i32, ProjectionFailure> {
        if let Some(variable) = self.node_variables[node] {
            return Ok(variable);
        }
        let variable = self.variables.allocate()?;
        self.node_variables[node] = Some(variable);
        Ok(variable)
    }

    fn literal(
        &mut self,
        node: NodeId,
        polarity: Polarity,
        depth: usize,
    ) -> Result<FormulaLiteral, ProjectionFailure> {
        self.check_depth(depth)?;
        let canonical = Rc::clone(&self.graph.nodes[node]);
        match canonical.as_ref() {
            CanonicalNode::Const(value) => Ok(FormulaLiteral::Const(match polarity {
                Polarity::Positive => *value,
                Polarity::Negative => !*value,
            })),
            CanonicalNode::Atom(atom) => {
                let literal = self.atom_vars.get(atom).copied().ok_or_else(|| {
                    ProjectionFailure::invalid(ProjectionFailureReason::MissingAtomId, node)
                })?;
                Ok(FormulaLiteral::Lit(match polarity {
                    Polarity::Positive => literal,
                    Polarity::Negative => -literal,
                }))
            }
            CanonicalNode::Not(child) => self.literal(*child, polarity.flipped(), depth + 1),
            CanonicalNode::And(children) | CanonicalNode::Or(children) if children.is_empty() => {
                let value = matches!(canonical.as_ref(), CanonicalNode::And(_));
                Ok(FormulaLiteral::Const(match polarity {
                    Polarity::Positive => value,
                    Polarity::Negative => !value,
                }))
            }
            CanonicalNode::And(children) | CanonicalNode::Or(children) if children.len() == 1 => {
                self.literal(children[0], polarity, depth + 1)
            }
            CanonicalNode::Iff(children) if children.len() <= 1 => Ok(FormulaLiteral::Const(
                matches!(polarity, Polarity::Positive),
            )),
            CanonicalNode::And(_)
            | CanonicalNode::Or(_)
            | CanonicalNode::Iff(_)
            | CanonicalNode::Ite(_) => {
                let variable = self.extension_variable(node)?;
                self.ensure_definition(node, polarity, depth + 1)?;
                Ok(FormulaLiteral::Lit(match polarity {
                    Polarity::Positive => variable,
                    Polarity::Negative => -variable,
                }))
            }
        }
    }

    fn assert_node(
        &mut self,
        node: NodeId,
        polarity: Polarity,
        depth: usize,
    ) -> Result<(), ProjectionFailure> {
        self.check_depth(depth)?;
        if self.graph.is_shared_extension(node) {
            let literal = self.literal(node, polarity, depth + 1)?;
            return self.emit_clause(vec![literal], ProvenanceOrigin { kind: 1, node });
        }
        let canonical = Rc::clone(&self.graph.nodes[node]);
        match canonical.as_ref() {
            CanonicalNode::Const(value) => {
                let required = match polarity {
                    Polarity::Positive => *value,
                    Polarity::Negative => !*value,
                };
                self.emit_clause(
                    vec![FormulaLiteral::Const(required)],
                    ProvenanceOrigin { kind: 1, node },
                )
            }
            CanonicalNode::Atom(_) => {
                let literal = self.literal(node, polarity, depth + 1)?;
                self.emit_clause(vec![literal], ProvenanceOrigin { kind: 1, node })
            }
            CanonicalNode::Not(child) => self.assert_node(*child, polarity.flipped(), depth + 1),
            CanonicalNode::And(children) if matches!(polarity, Polarity::Positive) => {
                for &child in children {
                    self.assert_node(child, Polarity::Positive, depth + 1)?;
                }
                Ok(())
            }
            CanonicalNode::And(children) => {
                let literals = self.literals(children, Polarity::Negative, depth + 1)?;
                self.emit_clause(literals, ProvenanceOrigin { kind: 1, node })
            }
            CanonicalNode::Or(children) if matches!(polarity, Polarity::Negative) => {
                for &child in children {
                    self.assert_node(child, Polarity::Negative, depth + 1)?;
                }
                Ok(())
            }
            CanonicalNode::Or(children) => {
                let literals = self.literals(children, Polarity::Positive, depth + 1)?;
                self.emit_clause(literals, ProvenanceOrigin { kind: 1, node })
            }
            CanonicalNode::Iff(children) => self.assert_iff(node, children, polarity, depth + 1),
            CanonicalNode::Ite(children) => self.assert_ite(node, *children, polarity, depth + 1),
        }
    }

    fn assert_iff(
        &mut self,
        node: NodeId,
        children: &[NodeId],
        polarity: Polarity,
        depth: usize,
    ) -> Result<(), ProjectionFailure> {
        if children.len() <= 1 {
            return if matches!(polarity, Polarity::Positive) {
                Ok(())
            } else {
                self.emit_clause(Vec::new(), ProvenanceOrigin { kind: 1, node })
            };
        }
        match polarity {
            Polarity::Positive => {
                let first = children[0];
                for &child in &children[1..] {
                    let first_negative = self.literal(first, Polarity::Negative, depth + 1)?;
                    let child_positive = self.literal(child, Polarity::Positive, depth + 1)?;
                    self.emit_clause(
                        vec![first_negative, child_positive],
                        ProvenanceOrigin { kind: 1, node },
                    )?;
                    let first_positive = self.literal(first, Polarity::Positive, depth + 1)?;
                    let child_negative = self.literal(child, Polarity::Negative, depth + 1)?;
                    self.emit_clause(
                        vec![first_positive, child_negative],
                        ProvenanceOrigin { kind: 1, node },
                    )?;
                }
                Ok(())
            }
            Polarity::Negative => {
                let negative = self.literals(children, Polarity::Negative, depth + 1)?;
                self.emit_clause(negative, ProvenanceOrigin { kind: 1, node })?;
                let positive = self.literals(children, Polarity::Positive, depth + 1)?;
                self.emit_clause(positive, ProvenanceOrigin { kind: 1, node })
            }
        }
    }

    fn assert_ite(
        &mut self,
        node: NodeId,
        children: [NodeId; 3],
        polarity: Polarity,
        depth: usize,
    ) -> Result<(), ProjectionFailure> {
        let condition_negative = self.literal(children[0], Polarity::Negative, depth + 1)?;
        let branch_polarity = polarity;
        let then_literal = self.literal(children[1], branch_polarity, depth + 1)?;
        self.emit_clause(
            vec![condition_negative, then_literal],
            ProvenanceOrigin { kind: 1, node },
        )?;
        let condition_positive = self.literal(children[0], Polarity::Positive, depth + 1)?;
        let else_literal = self.literal(children[2], branch_polarity, depth + 1)?;
        self.emit_clause(
            vec![condition_positive, else_literal],
            ProvenanceOrigin { kind: 1, node },
        )
    }

    fn ensure_definition(
        &mut self,
        node: NodeId,
        polarity: Polarity,
        depth: usize,
    ) -> Result<(), ProjectionFailure> {
        self.check_depth(depth)?;
        let bit = polarity.bit();
        if self.definition_polarities[node] & bit != 0 {
            return Ok(());
        }
        self.definition_polarities[node] |= bit;
        let extension = self.node_variables[node].ok_or_else(|| {
            ProjectionFailure::invalid(ProjectionFailureReason::InconsistentProjection, node)
        })?;
        let canonical = Rc::clone(&self.graph.nodes[node]);
        match polarity {
            Polarity::Positive => {
                self.emit_positive_definition(node, extension, canonical.as_ref(), depth + 1)
            }
            Polarity::Negative => {
                self.emit_negative_definition(node, extension, canonical.as_ref(), depth + 1)
            }
        }
    }

    fn emit_positive_definition(
        &mut self,
        node: NodeId,
        extension: i32,
        canonical: &CanonicalNode,
        depth: usize,
    ) -> Result<(), ProjectionFailure> {
        let origin = ProvenanceOrigin { kind: 2, node };
        match canonical {
            CanonicalNode::And(children) => {
                for &child in children {
                    let literal = self.literal(child, Polarity::Positive, depth + 1)?;
                    self.emit_clause(vec![FormulaLiteral::Lit(-extension), literal], origin)?;
                }
                Ok(())
            }
            CanonicalNode::Or(children) => {
                let mut clause = vec![FormulaLiteral::Lit(-extension)];
                clause.extend(self.literals(children, Polarity::Positive, depth + 1)?);
                self.emit_clause(clause, origin)
            }
            CanonicalNode::Iff(children) => {
                if children.len() <= 1 {
                    return Ok(());
                }
                let first = children[0];
                for &child in &children[1..] {
                    let first_negative = self.literal(first, Polarity::Negative, depth + 1)?;
                    let child_positive = self.literal(child, Polarity::Positive, depth + 1)?;
                    self.emit_clause(
                        vec![
                            FormulaLiteral::Lit(-extension),
                            first_negative,
                            child_positive,
                        ],
                        origin,
                    )?;
                    let first_positive = self.literal(first, Polarity::Positive, depth + 1)?;
                    let child_negative = self.literal(child, Polarity::Negative, depth + 1)?;
                    self.emit_clause(
                        vec![
                            FormulaLiteral::Lit(-extension),
                            first_positive,
                            child_negative,
                        ],
                        origin,
                    )?;
                }
                Ok(())
            }
            CanonicalNode::Ite(children) => {
                let condition_negative =
                    self.literal(children[0], Polarity::Negative, depth + 1)?;
                let then_positive = self.literal(children[1], Polarity::Positive, depth + 1)?;
                self.emit_clause(
                    vec![
                        FormulaLiteral::Lit(-extension),
                        condition_negative,
                        then_positive,
                    ],
                    origin,
                )?;
                let condition_positive =
                    self.literal(children[0], Polarity::Positive, depth + 1)?;
                let else_positive = self.literal(children[2], Polarity::Positive, depth + 1)?;
                self.emit_clause(
                    vec![
                        FormulaLiteral::Lit(-extension),
                        condition_positive,
                        else_positive,
                    ],
                    origin,
                )
            }
            CanonicalNode::Const(_) | CanonicalNode::Atom(_) | CanonicalNode::Not(_) => Err(
                ProjectionFailure::invalid(ProjectionFailureReason::InconsistentProjection, node),
            ),
        }
    }

    fn emit_negative_definition(
        &mut self,
        node: NodeId,
        extension: i32,
        canonical: &CanonicalNode,
        depth: usize,
    ) -> Result<(), ProjectionFailure> {
        let origin = ProvenanceOrigin { kind: 3, node };
        match canonical {
            CanonicalNode::And(children) => {
                let mut clause = vec![FormulaLiteral::Lit(extension)];
                clause.extend(self.literals(children, Polarity::Negative, depth + 1)?);
                self.emit_clause(clause, origin)
            }
            CanonicalNode::Or(children) => {
                for &child in children {
                    let literal = self.literal(child, Polarity::Negative, depth + 1)?;
                    self.emit_clause(vec![FormulaLiteral::Lit(extension), literal], origin)?;
                }
                Ok(())
            }
            CanonicalNode::Iff(children) => {
                if children.len() <= 1 {
                    return self.emit_clause(vec![FormulaLiteral::Lit(extension)], origin);
                }
                let mut all_true = vec![FormulaLiteral::Lit(extension)];
                all_true.extend(self.literals(children, Polarity::Negative, depth + 1)?);
                self.emit_clause(all_true, origin)?;
                let mut all_false = vec![FormulaLiteral::Lit(extension)];
                all_false.extend(self.literals(children, Polarity::Positive, depth + 1)?);
                self.emit_clause(all_false, origin)
            }
            CanonicalNode::Ite(children) => {
                let condition_negative =
                    self.literal(children[0], Polarity::Negative, depth + 1)?;
                let then_negative = self.literal(children[1], Polarity::Negative, depth + 1)?;
                self.emit_clause(
                    vec![
                        FormulaLiteral::Lit(extension),
                        condition_negative,
                        then_negative,
                    ],
                    origin,
                )?;
                let condition_positive =
                    self.literal(children[0], Polarity::Positive, depth + 1)?;
                let else_negative = self.literal(children[2], Polarity::Negative, depth + 1)?;
                self.emit_clause(
                    vec![
                        FormulaLiteral::Lit(extension),
                        condition_positive,
                        else_negative,
                    ],
                    origin,
                )
            }
            CanonicalNode::Const(_) | CanonicalNode::Atom(_) | CanonicalNode::Not(_) => Err(
                ProjectionFailure::invalid(ProjectionFailureReason::InconsistentProjection, node),
            ),
        }
    }

    fn literals(
        &mut self,
        nodes: &[NodeId],
        polarity: Polarity,
        depth: usize,
    ) -> Result<Vec<FormulaLiteral>, ProjectionFailure> {
        let mut literals = Vec::new();
        literals
            .try_reserve(nodes.len())
            .map_err(|_| allocation_failure())?;
        for &node in nodes {
            literals.push(self.literal(node, polarity, depth + 1)?);
        }
        Ok(literals)
    }

    fn emit_clause(
        &mut self,
        values: Vec<FormulaLiteral>,
        origin: ProvenanceOrigin,
    ) -> Result<(), ProjectionFailure> {
        if values
            .iter()
            .any(|value| matches!(value, FormulaLiteral::Const(true)))
        {
            return Ok(());
        }
        let literal_count = values
            .iter()
            .filter(|value| matches!(value, FormulaLiteral::Lit(_)))
            .count();
        let mut clause = Vec::new();
        clause
            .try_reserve(literal_count)
            .map_err(|_| allocation_failure())?;
        for value in values {
            if let FormulaLiteral::Lit(literal) = value {
                clause.push(literal);
            }
        }
        self.clauses.push(clause, Some(origin))
    }
}

pub(crate) fn project(
    bool_problem: &BoolProblem,
    arena: &TermArena,
) -> Result<ProjectionReport, ProjectionFailure> {
    let epoch = Instant::now();
    project_with_limits_and_clock(bool_problem, arena, ProjectionLimits::default(), || {
        epoch.elapsed().as_nanos()
    })
}

#[cfg(test)]
fn project_with_limits(
    bool_problem: &BoolProblem,
    arena: &TermArena,
    limits: ProjectionLimits,
) -> Result<ProjectionReport, ProjectionFailure> {
    let epoch = Instant::now();
    project_with_limits_and_clock(bool_problem, arena, limits, || epoch.elapsed().as_nanos())
}

fn project_with_limits_and_clock<F>(
    bool_problem: &BoolProblem,
    arena: &TermArena,
    limits: ProjectionLimits,
    mut clock: F,
) -> Result<ProjectionReport, ProjectionFailure>
where
    F: FnMut() -> u128,
{
    let syntax = validate_source(bool_problem, arena, limits)?;

    let baseline_start = clock();
    let baseline = BaselineEncoder::build(bool_problem, limits)?;
    let baseline_end = clock();
    let baseline_nanoseconds = elapsed_nanoseconds(baseline_start, baseline_end)?;

    let syntactic_start = clock();
    let graph = CanonicalGraph::build(&syntax, &bool_problem.assertions, limits)?;
    let candidate = CandidateEncoder::build(&graph, &baseline, limits)?;
    let syntactic_end = clock();
    let syntactic_nanoseconds = elapsed_nanoseconds(syntactic_start, syntactic_end)?;

    let baseline_metrics = ArmMetrics {
        variables: baseline.var_count(),
        clauses: baseline.clauses.clauses.len(),
        literal_occurrences: baseline.clauses.literal_occurrences,
        estimated_watch_slots: baseline.clauses.estimated_watch_slots,
        encoder_nanoseconds: baseline_nanoseconds,
        canonical_nodes: 0,
        canonical_edges: 0,
        provenance_bytes: 0,
    };
    let syntactic_metrics = ArmMetrics {
        variables: candidate.variables.max_used,
        clauses: candidate.clauses.clauses.len(),
        literal_occurrences: candidate.clauses.literal_occurrences,
        estimated_watch_slots: candidate.clauses.estimated_watch_slots,
        encoder_nanoseconds: syntactic_nanoseconds,
        canonical_nodes: graph.canonical_nodes,
        canonical_edges: graph.canonical_edges,
        provenance_bytes: candidate.clauses.provenance.len(),
    };

    let mut atoms = Vec::new();
    atoms
        .try_reserve(baseline.atom_vars.len())
        .map_err(|_| allocation_failure())?;
    for (variable, atom) in baseline.var_atoms.iter().enumerate().skip(1) {
        if let Some(atom) = atom {
            atoms.push(AtomId {
                variable: i32::try_from(variable).map_err(|_| {
                    ProjectionFailure::invalid(
                        ProjectionFailureReason::ArithmeticOverflow,
                        variable,
                    )
                })?,
                atom: atom.clone(),
            });
        }
    }

    debug_assert_eq!(
        syntactic_metrics.provenance_bytes,
        candidate.clauses.provenance.len()
    );
    Ok(ProjectionReport {
        baseline: baseline_metrics,
        syntactic: syntactic_metrics,
        atoms,
        candidate_clauses: candidate.clauses.clauses,
        candidate_provenance: candidate.clauses.provenance,
    })
}

fn elapsed_nanoseconds(start: u128, end: u128) -> Result<u128, ProjectionFailure> {
    end.checked_sub(start)
        .ok_or_else(|| ProjectionFailure::invalid(ProjectionFailureReason::ClockRegression, 0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CnfProblem, ScopedLetMode, SortId, atomize_bool_data_terms,
        parse_problem_with_scoped_let_mode,
    };
    use varisat::{ExtendFormula, Lit, Solver};

    const U_SORT: SortId = SortId(1);

    fn nullary(arena: &mut TermArena, function: u32, sort: SortId) -> TermId {
        arena.intern_typed(function, Vec::new(), sort)
    }

    fn bool_atom(term: TermId) -> BoolExpr {
        BoolExpr::Atom(BoolAtomKey::BoolTerm(term))
    }

    fn test_problem(assertions: Vec<BoolExpr>) -> (TermArena, BoolProblem) {
        let mut arena = TermArena::default();
        let true_term = nullary(&mut arena, 0, BOOL_SORT);
        let false_term = nullary(&mut arena, 1, BOOL_SORT);
        (
            arena,
            BoolProblem {
                assertions,
                unsupported: Vec::new(),
                true_term,
                false_term,
                data_terms: Vec::new(),
            },
        )
    }

    fn deterministic_projection(bool_problem: &BoolProblem, arena: &TermArena) -> ProjectionReport {
        let mut ticks = [10u128, 17, 20, 31].into_iter();
        project_with_limits_and_clock(bool_problem, arena, ProjectionLimits::default(), || {
            ticks.next().unwrap()
        })
        .unwrap()
    }

    fn production_direct_root(bool_problem: &BoolProblem) -> CnfProblem {
        let mut cnf = CnfProblem::new();
        atomize_bool_data_terms(&mut cnf, bool_problem);
        for assertion in &bool_problem.assertions {
            cnf.add_direct_assertion_with_negated_root(assertion, false);
        }
        cnf
    }

    fn dimacs_bytes(cnf: &CnfProblem) -> Vec<u8> {
        let mut output = format!("p cnf {} {}\n", cnf.var_count(), cnf.clauses.len()).into_bytes();
        for clause in &cnf.clauses {
            for literal in clause {
                output.extend_from_slice(format!("{literal} ").as_bytes());
            }
            output.extend_from_slice(b"0\n");
        }
        output
    }

    fn eval(expression: &BoolExpr, assignment: &HashMap<BoolAtomKey, bool>) -> bool {
        match expression {
            BoolExpr::Const(value) => *value,
            BoolExpr::Atom(atom) => assignment[&normalize_atom(atom.clone())],
            BoolExpr::Not(child) => !eval(child, assignment),
            BoolExpr::And(children) => children.iter().all(|child| eval(child, assignment)),
            BoolExpr::Or(children) => children.iter().any(|child| eval(child, assignment)),
            BoolExpr::Iff(children) => children.split_first().is_none_or(|(first, rest)| {
                let first = eval(first, assignment);
                rest.iter().all(|child| eval(child, assignment) == first)
            }),
            BoolExpr::Ite(condition, then_expression, else_expression) => {
                if eval(condition, assignment) {
                    eval(then_expression, assignment)
                } else {
                    eval(else_expression, assignment)
                }
            }
        }
    }

    fn candidate_sat(report: &ProjectionReport, assignment_bits: usize) -> bool {
        let mut solver = Solver::new();
        for clause in &report.candidate_clauses {
            let clause = clause
                .iter()
                .map(|literal| Lit::from_dimacs(*literal as isize))
                .collect::<Vec<_>>();
            solver.add_clause(&clause);
        }
        for (index, atom) in report.atoms.iter().enumerate() {
            let literal = if assignment_bits & (1usize << index) != 0 {
                atom.variable
            } else {
                -atom.variable
            };
            solver.add_clause(&[Lit::from_dimacs(literal as isize)]);
        }
        solver.solve().unwrap()
    }

    fn assert_truth_table(bool_problem: &BoolProblem, arena: &TermArena) {
        let report = deterministic_projection(bool_problem, arena);
        for assignment_bits in 0..(1usize << report.atoms.len()) {
            let assignment = report
                .atoms
                .iter()
                .enumerate()
                .map(|(index, atom)| (atom.atom.clone(), assignment_bits & (1usize << index) != 0))
                .collect::<HashMap<_, _>>();
            let expected = bool_problem
                .assertions
                .iter()
                .all(|assertion| eval(assertion, &assignment));
            assert_eq!(
                candidate_sat(&report, assignment_bits),
                expected,
                "assignment {assignment_bits:0width$b}",
                width = report.atoms.len()
            );
        }
    }

    #[test]
    fn deterministic_projection_output_and_clause_order() {
        let (mut arena, mut problem) = test_problem(Vec::new());
        let p = nullary(&mut arena, 2, BOOL_SORT);
        let q = nullary(&mut arena, 3, BOOL_SORT);
        let r = nullary(&mut arena, 4, BOOL_SORT);
        let repeated = BoolExpr::And(vec![bool_atom(p), bool_atom(q)]);
        problem.assertions = vec![BoolExpr::Or(vec![
            repeated.clone(),
            BoolExpr::Or(vec![bool_atom(r), repeated]),
        ])];

        let first = deterministic_projection(&problem, &arena);
        let second = deterministic_projection(&problem, &arena);
        assert_eq!(first, second);
        assert_eq!(first.rendered(), second.rendered());
        assert!(first.rendered().contains("control syntactic_only\n"));
        assert!(first.rendered().contains("guarded_euf_claim none\n"));
        assert!(first.rendered().contains("candidate_cnf_begin\n"));
        assert_eq!(first.baseline.encoder_nanoseconds, 7);
        assert_eq!(first.syntactic.encoder_nanoseconds, 11);
        assert_eq!(
            first.syntactic.provenance_bytes,
            first.candidate_clauses.len() * PROVENANCE_RECORD_BYTES
        );
    }

    #[test]
    fn baseline_is_exact_and_projection_does_not_mutate_the_off_path() {
        let (mut arena, mut problem) = test_problem(Vec::new());
        let p = nullary(&mut arena, 2, BOOL_SORT);
        let q = nullary(&mut arena, 3, BOOL_SORT);
        let r = nullary(&mut arena, 4, BOOL_SORT);
        problem.data_terms.push(r);
        problem.assertions = vec![
            BoolExpr::Const(true),
            BoolExpr::Not(Box::new(BoolExpr::Or(vec![
                BoolExpr::And(vec![bool_atom(p), BoolExpr::Const(false)]),
                BoolExpr::Iff(vec![bool_atom(q), bool_atom(r)]),
                BoolExpr::Ite(
                    Box::new(bool_atom(p)),
                    Box::new(bool_atom(q)),
                    Box::new(bool_atom(r)),
                ),
            ]))),
        ];

        let before = production_direct_root(&problem);
        let before_bytes = dimacs_bytes(&before);
        let baseline = BaselineEncoder::build(&problem, ProjectionLimits::default()).unwrap();
        assert_eq!(baseline.var_atoms, before.var_atoms);
        assert_eq!(baseline.atom_vars, before.atom_vars);
        assert_eq!(baseline.clauses.clauses.len(), before.clauses.len());
        assert!(
            baseline
                .clauses
                .clauses
                .iter()
                .zip(&before.clauses)
                .all(|(left, right)| left.as_slice() == right)
        );

        let _diagnostic = deterministic_projection(&problem, &arena);
        let after = production_direct_root(&problem);
        assert_eq!(before_bytes, dimacs_bytes(&after));
        assert_eq!(before.var_atoms, after.var_atoms);
        assert_eq!(before.atom_vars, after.atom_vars);
    }

    #[test]
    fn candidate_matches_truth_tables_for_all_operators_and_bool_uf_atoms() {
        let input = "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun a () U)
            (declare-fun p () Bool)
            (declare-fun q () Bool)
            (declare-fun pred (U) Bool)
            (assert
              (ite p
                   (= (pred a) (not q))
                   (or (and true p) (and false q))))
            (check-sat)
        ";
        let parsed = parse_problem_with_scoped_let_mode(input, ScopedLetMode::Auto).unwrap();
        let bool_problem = parsed.bool_problem.as_ref().unwrap();
        let report = deterministic_projection(bool_problem, &parsed.arena);
        assert!(report.atoms.iter().any(|atom| {
            matches!(atom.atom, BoolAtomKey::BoolTerm(term) if !parsed.arena.terms[term].args.is_empty())
        }));

        assert_truth_table(bool_problem, &parsed.arena);
    }

    #[test]
    fn candidate_matches_negative_and_mixed_polarity_truth_tables() {
        let mut arena = TermArena::default();
        let true_term = nullary(&mut arena, 0, BOOL_SORT);
        let false_term = nullary(&mut arena, 1, BOOL_SORT);
        let p = nullary(&mut arena, 2, BOOL_SORT);
        let q = nullary(&mut arena, 3, BOOL_SORT);
        let r = nullary(&mut arena, 4, BOOL_SORT);
        let atom = |term| bool_atom(term);
        let repeated = BoolExpr::And(vec![atom(p), atom(q)]);
        let formulas = vec![
            BoolExpr::Const(true),
            BoolExpr::Const(false),
            BoolExpr::Not(Box::new(BoolExpr::And(vec![atom(p), atom(q)]))),
            BoolExpr::Not(Box::new(BoolExpr::Or(vec![atom(p), atom(q)]))),
            BoolExpr::Not(Box::new(BoolExpr::Iff(vec![atom(p), atom(q), atom(r)]))),
            BoolExpr::Not(Box::new(BoolExpr::Ite(
                Box::new(atom(p)),
                Box::new(atom(q)),
                Box::new(atom(r)),
            ))),
            BoolExpr::And(vec![
                BoolExpr::Or(vec![repeated.clone(), atom(r)]),
                BoolExpr::Or(vec![BoolExpr::Not(Box::new(repeated)), atom(q)]),
            ]),
            BoolExpr::Iff(Vec::new()),
            BoolExpr::Iff(vec![atom(p)]),
            BoolExpr::Ite(
                Box::new(BoolExpr::Iff(vec![atom(p), atom(q)])),
                Box::new(BoolExpr::Or(vec![atom(q), BoolExpr::Const(false)])),
                Box::new(BoolExpr::And(vec![atom(r), BoolExpr::Const(true)])),
            ),
        ];
        for formula in formulas {
            let problem = BoolProblem {
                assertions: vec![formula],
                unsupported: Vec::new(),
                true_term,
                false_term,
                data_terms: Vec::new(),
            };
            assert_truth_table(&problem, &arena);
        }
    }

    #[test]
    fn caps_and_overflow_fail_without_partial_clause_state() {
        let (mut arena, mut problem) = test_problem(Vec::new());
        let p = nullary(&mut arena, 2, BOOL_SORT);
        problem.assertions = vec![bool_atom(p)];
        let failure = project_with_limits(
            &problem,
            &arena,
            ProjectionLimits {
                max_clauses: 0,
                ..ProjectionLimits::default()
            },
        )
        .unwrap_err();
        assert_eq!(failure.reason, ProjectionFailureReason::ClauseCap);

        let syntax_failure = project_with_limits(
            &problem,
            &arena,
            ProjectionLimits {
                max_syntax_occurrences: 0,
                ..ProjectionLimits::default()
            },
        )
        .unwrap_err();
        assert_eq!(
            syntax_failure.reason,
            ProjectionFailureReason::SyntaxOccurrenceCap
        );

        let variable_failure = project_with_limits(
            &problem,
            &arena,
            ProjectionLimits {
                max_variables: 0,
                ..ProjectionLimits::default()
            },
        )
        .unwrap_err();
        assert_eq!(
            variable_failure.reason,
            ProjectionFailureReason::VariableCap
        );

        let provenance_failure = project_with_limits(
            &problem,
            &arena,
            ProjectionLimits {
                max_provenance_bytes: 0,
                ..ProjectionLimits::default()
            },
        )
        .unwrap_err();
        assert_eq!(
            provenance_failure.reason,
            ProjectionFailureReason::ProvenanceByteCap
        );

        let mut buffer = ClauseBuffer::new(ProjectionLimits {
            max_literal_occurrences: usize::MAX,
            ..ProjectionLimits::default()
        });
        buffer.literal_occurrences = usize::MAX;
        let before = buffer.clone();
        let overflow = buffer.push(vec![1], None).unwrap_err();
        assert_eq!(overflow.reason, ProjectionFailureReason::ArithmeticOverflow);
        assert_eq!(buffer, before);
    }

    #[test]
    fn repeated_complete_subgraph_reduces_actual_emitted_literals() {
        let (mut arena, mut problem) = test_problem(Vec::new());
        let p = nullary(&mut arena, 2, BOOL_SORT);
        let q = nullary(&mut arena, 3, BOOL_SORT);
        let r = nullary(&mut arena, 4, BOOL_SORT);
        let guards = (0..4)
            .map(|index| nullary(&mut arena, 5 + index, BOOL_SORT))
            .collect::<Vec<_>>();
        let repeated = BoolExpr::And(vec![bool_atom(p), bool_atom(q), bool_atom(r)]);
        problem.assertions = vec![BoolExpr::And(
            guards
                .iter()
                .map(|guard| BoolExpr::Or(vec![repeated.clone(), bool_atom(*guard)]))
                .collect(),
        )];

        let report = deterministic_projection(&problem, &arena);
        let actual_candidate_literals =
            report.candidate_clauses.iter().map(Vec::len).sum::<usize>();
        let actual_watch_slots = report
            .candidate_clauses
            .iter()
            .filter(|clause| clause.len() >= 2)
            .count()
            * 2;
        assert_eq!(
            actual_candidate_literals,
            report.syntactic.literal_occurrences
        );
        assert_eq!(actual_watch_slots, report.syntactic.estimated_watch_slots);
        assert!(
            report.syntactic.literal_occurrences < report.baseline.literal_occurrences,
            "baseline={} candidate={}",
            report.baseline.literal_occurrences,
            report.syntactic.literal_occurrences
        );
        assert!(report.syntactic.clauses < report.baseline.clauses);
    }

    #[test]
    fn ac_nodes_canonicalize_but_ite_branch_order_does_not() {
        let (mut arena, mut problem) = test_problem(Vec::new());
        let p = nullary(&mut arena, 2, BOOL_SORT);
        let q = nullary(&mut arena, 3, BOOL_SORT);
        let r = nullary(&mut arena, 4, BOOL_SORT);
        problem.assertions = vec![
            BoolExpr::And(vec![
                bool_atom(p),
                BoolExpr::And(vec![bool_atom(q), bool_atom(r)]),
            ]),
            BoolExpr::And(vec![
                BoolExpr::And(vec![bool_atom(r), bool_atom(p)]),
                bool_atom(q),
            ]),
            BoolExpr::Ite(
                Box::new(bool_atom(p)),
                Box::new(bool_atom(q)),
                Box::new(bool_atom(r)),
            ),
            BoolExpr::Ite(
                Box::new(bool_atom(p)),
                Box::new(bool_atom(r)),
                Box::new(bool_atom(q)),
            ),
        ];
        let syntax = validate_source(&problem, &arena, ProjectionLimits::default()).unwrap();
        let graph =
            CanonicalGraph::build(&syntax, &problem.assertions, ProjectionLimits::default())
                .unwrap();
        assert_eq!(graph.roots[0], graph.roots[1]);
        assert_ne!(graph.roots[2], graph.roots[3]);
    }

    #[test]
    fn source_theory_atom_ids_are_reused_exactly() {
        let mut arena = TermArena::default();
        let true_term = nullary(&mut arena, 0, BOOL_SORT);
        let false_term = nullary(&mut arena, 1, BOOL_SORT);
        let p = nullary(&mut arena, 2, BOOL_SORT);
        let a = nullary(&mut arena, 3, U_SORT);
        let b = nullary(&mut arena, 4, U_SORT);
        let equality = BoolExpr::Atom(BoolAtomKey::Eq(b, a));
        let problem = BoolProblem {
            assertions: vec![BoolExpr::Or(vec![bool_atom(p), equality])],
            unsupported: Vec::new(),
            true_term,
            false_term,
            data_terms: vec![p],
        };
        let production = production_direct_root(&problem);
        let report = deterministic_projection(&problem, &arena);
        for atom in &report.atoms {
            assert_eq!(production.atom_vars[&atom.atom], atom.variable);
        }
        assert!(
            report
                .atoms
                .iter()
                .any(|atom| atom.atom == BoolAtomKey::Eq(a, b))
        );
    }
}
