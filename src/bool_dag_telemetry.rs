use super::{BOOL_SORT, BoolAtomKey, BoolExpr, BoolProblem, SortId, SymId, TermArena, TermId};
use rustc_hash::{FxHashMap as HashMap, FxHashSet as HashSet};
use std::rc::Rc;

const DEFAULT_MAX_SYNTAX_OCCURRENCES: usize = 5_000_000;
const DEFAULT_MAX_EQUALITY_FACTS: usize = 1_000_000;
const DEFAULT_MAX_CANONICAL_NODES: usize = 2_000_000;
const DEFAULT_MAX_CANONICAL_EDGES: usize = 10_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Limits {
    pub(crate) max_syntax_occurrences: usize,
    pub(crate) max_equality_facts: usize,
    pub(crate) max_canonical_nodes: usize,
    pub(crate) max_canonical_edges: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_syntax_occurrences: DEFAULT_MAX_SYNTAX_OCCURRENCES,
            max_equality_facts: DEFAULT_MAX_EQUALITY_FACTS,
            max_canonical_nodes: DEFAULT_MAX_CANONICAL_NODES,
            max_canonical_edges: DEFAULT_MAX_CANONICAL_EDGES,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AbstentionReason {
    SyntaxOccurrenceCap,
    EqualityFactCap,
    SyntacticNodeCap,
    SyntacticEdgeCap,
    QuotientNodeCap,
    QuotientEdgeCap,
    InvalidTermId,
    IllSortedEquality,
    NonBooleanTerm,
    InconsistentProjection,
    ArithmeticOverflow,
}

impl AbstentionReason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::SyntaxOccurrenceCap => "syntax_occurrence_cap",
            Self::EqualityFactCap => "equality_fact_cap",
            Self::SyntacticNodeCap => "syntactic_node_cap",
            Self::SyntacticEdgeCap => "syntactic_edge_cap",
            Self::QuotientNodeCap => "quotient_node_cap",
            Self::QuotientEdgeCap => "quotient_edge_cap",
            Self::InvalidTermId => "invalid_term_id",
            Self::IllSortedEquality => "ill_sorted_equality",
            Self::NonBooleanTerm => "non_boolean_term",
            Self::InconsistentProjection => "inconsistent_projection",
            Self::ArithmeticOverflow => "arithmetic_overflow",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Abstention {
    pub(crate) reason: AbstentionReason,
    pub(crate) observed: usize,
    pub(crate) limit: Option<usize>,
}

impl Abstention {
    fn capped(reason: AbstentionReason, observed: usize, limit: usize) -> Self {
        Self {
            reason,
            observed,
            limit: Some(limit),
        }
    }

    fn invalid(reason: AbstentionReason, observed: usize) -> Self {
        Self {
            reason,
            observed,
            limit: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct DagProjection {
    pub(crate) unique_nodes: usize,
    pub(crate) canonical_edges: usize,
    pub(crate) largest_arity: usize,
    pub(crate) duplicate_occurrences: usize,
    pub(crate) duplicate_ratio_ppm: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Telemetry {
    pub(crate) assertion_roots: usize,
    pub(crate) data_term_entries: usize,
    pub(crate) data_term_roots: usize,
    pub(crate) syntax_occurrences: usize,
    pub(crate) projected_occurrences: usize,
    pub(crate) unconditional_equality_facts: usize,
    pub(crate) effective_equality_unions: usize,
    pub(crate) nontrivial_quotient_classes: usize,
    pub(crate) quotiented_terms: usize,
    pub(crate) syntactic: Option<DagProjection>,
    pub(crate) quotient: Option<DagProjection>,
    pub(crate) quotient_unique_reduction: Option<usize>,
    pub(crate) quotient_unique_reduction_ppm: Option<u32>,
    pub(crate) abstention: Option<Abstention>,
}

impl Telemetry {
    fn abstain(&mut self, abstention: Abstention) {
        self.syntactic = None;
        self.quotient = None;
        self.quotient_unique_reduction = None;
        self.quotient_unique_reduction_ppm = None;
        self.abstention = Some(abstention);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum CanonicalNode {
    Const(bool),
    Eq(TermId, TermId),
    BoolTerm(TermId),
    Not(NodeId),
    And(Vec<NodeId>),
    Or(Vec<NodeId>),
    Iff(Vec<NodeId>),
    Ite([NodeId; 3]),
}

impl CanonicalNode {
    fn children(&self) -> &[NodeId] {
        match self {
            Self::Const(_) | Self::Eq(_, _) | Self::BoolTerm(_) => &[],
            Self::Not(child) => std::slice::from_ref(child),
            Self::And(children) | Self::Or(children) | Self::Iff(children) => children,
            Self::Ite(children) => children,
        }
    }
}

type NodeId = usize;

#[derive(Debug, Clone, Copy)]
enum ProjectionKind {
    Syntactic,
    Quotient,
}

impl ProjectionKind {
    fn node_cap(self) -> AbstentionReason {
        match self {
            Self::Syntactic => AbstentionReason::SyntacticNodeCap,
            Self::Quotient => AbstentionReason::QuotientNodeCap,
        }
    }

    fn edge_cap(self) -> AbstentionReason {
        match self {
            Self::Syntactic => AbstentionReason::SyntacticEdgeCap,
            Self::Quotient => AbstentionReason::QuotientEdgeCap,
        }
    }
}

struct CanonicalInterner {
    nodes: Vec<Rc<CanonicalNode>>,
    ids: HashMap<Rc<CanonicalNode>, NodeId>,
    stored_edges: usize,
    limits: Limits,
    kind: ProjectionKind,
}

impl CanonicalInterner {
    fn new(limits: Limits, kind: ProjectionKind) -> Self {
        Self {
            nodes: Vec::new(),
            ids: HashMap::default(),
            stored_edges: 0,
            limits,
            kind,
        }
    }

    fn node(&self, id: NodeId) -> &CanonicalNode {
        self.nodes[id].as_ref()
    }

    fn intern(&mut self, node: CanonicalNode) -> Result<NodeId, Abstention> {
        if let Some(&id) = self.ids.get(&node) {
            return Ok(id);
        }

        let next_nodes =
            self.nodes.len().checked_add(1).ok_or_else(|| {
                Abstention::invalid(AbstentionReason::ArithmeticOverflow, usize::MAX)
            })?;
        if next_nodes > self.limits.max_canonical_nodes {
            return Err(Abstention::capped(
                self.kind.node_cap(),
                next_nodes,
                self.limits.max_canonical_nodes,
            ));
        }

        let next_edges = self
            .stored_edges
            .checked_add(node.children().len())
            .ok_or_else(|| Abstention::invalid(AbstentionReason::ArithmeticOverflow, usize::MAX))?;
        if next_edges > self.limits.max_canonical_edges {
            return Err(Abstention::capped(
                self.kind.edge_cap(),
                next_edges,
                self.limits.max_canonical_edges,
            ));
        }

        let id = self.nodes.len();
        let node = Rc::new(node);
        self.nodes.push(Rc::clone(&node));
        self.ids.insert(node, id);
        self.stored_edges = next_edges;
        Ok(id)
    }

    fn associative_children(
        &self,
        children: &[NodeId],
        and: bool,
    ) -> Result<Vec<NodeId>, Abstention> {
        let mut flattened_len = 0usize;
        for &child in children {
            let contribution = match (and, self.node(child)) {
                (true, CanonicalNode::And(nested)) | (false, CanonicalNode::Or(nested)) => {
                    nested.len()
                }
                _ => 1,
            };
            flattened_len = flattened_len.checked_add(contribution).ok_or_else(|| {
                Abstention::invalid(AbstentionReason::ArithmeticOverflow, usize::MAX)
            })?;
            if flattened_len > self.limits.max_canonical_edges {
                return Err(Abstention::capped(
                    self.kind.edge_cap(),
                    flattened_len,
                    self.limits.max_canonical_edges,
                ));
            }
        }

        let mut flattened = Vec::with_capacity(flattened_len);
        for &child in children {
            match (and, self.node(child)) {
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
        child_ids: &[NodeId],
        term_map: Option<&[TermId]>,
    ) -> Result<CanonicalNode, Abstention> {
        let map_term = |term: TermId| term_map.map_or(term, |map| map[term]);
        Ok(match expression {
            BoolExpr::Const(value) => CanonicalNode::Const(*value),
            BoolExpr::Atom(BoolAtomKey::Eq(left, right)) => {
                let (left, right) = normalized_pair(map_term(*left), map_term(*right));
                CanonicalNode::Eq(left, right)
            }
            BoolExpr::Atom(BoolAtomKey::BoolTerm(term)) => CanonicalNode::BoolTerm(map_term(*term)),
            BoolExpr::Not(_) => CanonicalNode::Not(child_ids[0]),
            BoolExpr::And(_) => CanonicalNode::And(self.associative_children(child_ids, true)?),
            BoolExpr::Or(_) => CanonicalNode::Or(self.associative_children(child_ids, false)?),
            BoolExpr::Iff(_) => {
                let mut children = child_ids.to_vec();
                children.sort_unstable();
                CanonicalNode::Iff(children)
            }
            BoolExpr::Ite(_, _, _) => {
                CanonicalNode::Ite([child_ids[0], child_ids[1], child_ids[2]])
            }
        })
    }

    fn projection(
        &self,
        roots: &[NodeId],
        projected_occurrences: usize,
    ) -> Result<DagProjection, Abstention> {
        let mut reachable = HashSet::default();
        let mut stack = roots.to_vec();
        let mut canonical_edges = 0usize;
        let mut largest_arity = 0usize;
        while let Some(node_id) = stack.pop() {
            if !reachable.insert(node_id) {
                continue;
            }
            let children = self.node(node_id).children();
            canonical_edges = canonical_edges.checked_add(children.len()).ok_or_else(|| {
                Abstention::invalid(AbstentionReason::ArithmeticOverflow, usize::MAX)
            })?;
            largest_arity = largest_arity.max(children.len());
            stack.extend_from_slice(children);
        }

        let unique_nodes = reachable.len();
        let duplicate_occurrences =
            projected_occurrences
                .checked_sub(unique_nodes)
                .ok_or_else(|| {
                    Abstention::invalid(AbstentionReason::InconsistentProjection, unique_nodes)
                })?;
        Ok(DagProjection {
            unique_nodes,
            canonical_edges,
            largest_arity,
            duplicate_occurrences,
            duplicate_ratio_ppm: ratio_ppm(duplicate_occurrences, projected_occurrences),
        })
    }
}

#[derive(Debug)]
struct UnionFind {
    parent: Vec<TermId>,
    size: Vec<usize>,
    minimum: Vec<TermId>,
}

impl UnionFind {
    fn new(terms: usize) -> Self {
        Self {
            parent: (0..terms).collect(),
            size: vec![1; terms],
            minimum: (0..terms).collect(),
        }
    }

    fn find(&mut self, term: TermId) -> TermId {
        let mut root = term;
        while self.parent[root] != root {
            root = self.parent[root];
        }
        let mut cursor = term;
        while self.parent[cursor] != cursor {
            let next = self.parent[cursor];
            self.parent[cursor] = root;
            cursor = next;
        }
        root
    }

    fn union(&mut self, left: TermId, right: TermId) -> bool {
        let mut left = self.find(left);
        let mut right = self.find(right);
        if left == right {
            return false;
        }
        if self.size[left] < self.size[right]
            || (self.size[left] == self.size[right] && self.minimum[left] > self.minimum[right])
        {
            std::mem::swap(&mut left, &mut right);
        }
        self.parent[right] = left;
        self.size[left] += self.size[right];
        self.minimum[left] = self.minimum[left].min(self.minimum[right]);
        true
    }

    fn term_map(mut self) -> (Vec<TermId>, usize, usize) {
        let mut map = Vec::with_capacity(self.parent.len());
        let mut roots = HashSet::default();
        let mut quotiented_terms = 0usize;
        for term in 0..self.parent.len() {
            let root = self.find(term);
            let representative = self.minimum[root];
            map.push(representative);
            if self.size[root] > 1 {
                roots.insert(root);
                quotiented_terms += 1;
            }
        }
        (map, roots.len(), quotiented_terms)
    }
}

pub(crate) fn analyze(bool_problem: &BoolProblem, arena: &TermArena) -> Telemetry {
    analyze_with_limits(bool_problem, arena, Limits::default())
}

pub(crate) fn analyze_with_limits(
    bool_problem: &BoolProblem,
    arena: &TermArena,
    limits: Limits,
) -> Telemetry {
    let mut telemetry = Telemetry {
        assertion_roots: bool_problem.assertions.len(),
        data_term_entries: bool_problem.data_terms.len(),
        ..Telemetry::default()
    };

    if let Err(abstention) = validate_boolean_term(bool_problem.true_term, arena) {
        telemetry.abstain(abstention);
        return telemetry;
    }
    if let Err(abstention) = validate_boolean_term(bool_problem.false_term, arena) {
        telemetry.abstain(abstention);
        return telemetry;
    }

    let mut data_terms = bool_problem.data_terms.clone();
    data_terms.sort_unstable();
    data_terms.dedup();
    telemetry.data_term_roots = data_terms.len();
    for &term in &data_terms {
        if let Err(abstention) = validate_boolean_term(term, arena) {
            telemetry.abstain(abstention);
            return telemetry;
        }
    }

    let syntax_nodes = match scan_syntax(bool_problem, arena, limits, &mut telemetry) {
        Ok(nodes) => nodes,
        Err(abstention) => {
            telemetry.abstain(abstention);
            return telemetry;
        }
    };
    telemetry.projected_occurrences = match telemetry
        .syntax_occurrences
        .checked_add(telemetry.data_term_roots)
    {
        Some(occurrences) => occurrences,
        None => {
            telemetry.abstain(Abstention::invalid(
                AbstentionReason::ArithmeticOverflow,
                usize::MAX,
            ));
            return telemetry;
        }
    };

    let equality_facts = match unconditional_equality_facts(bool_problem, limits, &mut telemetry) {
        Ok(facts) => facts,
        Err(abstention) => {
            telemetry.abstain(abstention);
            return telemetry;
        }
    };
    let mut quotient = UnionFind::new(arena.terms.len());
    for &(left, right) in &equality_facts {
        telemetry.effective_equality_unions += usize::from(quotient.union(left, right));
    }
    let (term_map, nontrivial_classes, quotiented_terms) = quotient.term_map();
    telemetry.nontrivial_quotient_classes = nontrivial_classes;
    telemetry.quotiented_terms = quotiented_terms;

    let (syntactic, quotient) = match canonicalize(
        &syntax_nodes,
        &bool_problem.assertions,
        &data_terms,
        &term_map,
        telemetry.projected_occurrences,
        limits,
    ) {
        Ok(projections) => projections,
        Err(abstention) => {
            telemetry.abstain(abstention);
            return telemetry;
        }
    };

    let Some(reduction) = syntactic.unique_nodes.checked_sub(quotient.unique_nodes) else {
        telemetry.abstain(Abstention::invalid(
            AbstentionReason::InconsistentProjection,
            quotient.unique_nodes,
        ));
        return telemetry;
    };
    telemetry.quotient_unique_reduction = Some(reduction);
    telemetry.quotient_unique_reduction_ppm = Some(ratio_ppm(reduction, syntactic.unique_nodes));
    telemetry.syntactic = Some(syntactic);
    telemetry.quotient = Some(quotient);
    telemetry
}

fn scan_syntax<'a>(
    bool_problem: &'a BoolProblem,
    arena: &TermArena,
    limits: Limits,
    telemetry: &mut Telemetry,
) -> Result<Vec<&'a BoolExpr>, Abstention> {
    let mut nodes = Vec::new();
    let mut stack = bool_problem.assertions.iter().rev().collect::<Vec<_>>();
    while let Some(expression) = stack.pop() {
        telemetry.syntax_occurrences = telemetry
            .syntax_occurrences
            .checked_add(1)
            .ok_or_else(|| Abstention::invalid(AbstentionReason::ArithmeticOverflow, usize::MAX))?;
        if telemetry.syntax_occurrences > limits.max_syntax_occurrences {
            return Err(Abstention::capped(
                AbstentionReason::SyntaxOccurrenceCap,
                telemetry.syntax_occurrences,
                limits.max_syntax_occurrences,
            ));
        }
        validate_expression_terms(expression, arena)?;
        nodes.push(expression);
        push_children(expression, &mut stack);
    }
    Ok(nodes)
}

fn validate_expression_terms(expression: &BoolExpr, arena: &TermArena) -> Result<(), Abstention> {
    match expression {
        BoolExpr::Atom(BoolAtomKey::Eq(left, right)) => {
            let left_sort = arena
                .terms
                .get(*left)
                .map(|term| term.sort)
                .ok_or_else(|| Abstention::invalid(AbstentionReason::InvalidTermId, *left))?;
            let right_sort = arena
                .terms
                .get(*right)
                .map(|term| term.sort)
                .ok_or_else(|| Abstention::invalid(AbstentionReason::InvalidTermId, *right))?;
            if left_sort != right_sort {
                return Err(Abstention::invalid(
                    AbstentionReason::IllSortedEquality,
                    *right,
                ));
            }
        }
        BoolExpr::Atom(BoolAtomKey::BoolTerm(term)) => validate_boolean_term(*term, arena)?,
        _ => {}
    }
    Ok(())
}

fn validate_boolean_term(term: TermId, arena: &TermArena) -> Result<(), Abstention> {
    let sort = arena
        .terms
        .get(term)
        .map(|term| term.sort)
        .ok_or_else(|| Abstention::invalid(AbstentionReason::InvalidTermId, term))?;
    if sort != BOOL_SORT {
        return Err(Abstention::invalid(AbstentionReason::NonBooleanTerm, term));
    }
    Ok(())
}

fn push_children<'a>(expression: &'a BoolExpr, stack: &mut Vec<&'a BoolExpr>) {
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
}

fn unconditional_equality_facts(
    bool_problem: &BoolProblem,
    limits: Limits,
    telemetry: &mut Telemetry,
) -> Result<Vec<(TermId, TermId)>, Abstention> {
    let mut facts = Vec::new();
    let mut stack = bool_problem.assertions.iter().rev().collect::<Vec<_>>();
    while let Some(expression) = stack.pop() {
        match expression {
            BoolExpr::And(children) => stack.extend(children.iter().rev()),
            BoolExpr::Atom(BoolAtomKey::Eq(left, right)) => {
                telemetry.unconditional_equality_facts = telemetry
                    .unconditional_equality_facts
                    .checked_add(1)
                    .ok_or_else(|| {
                        Abstention::invalid(AbstentionReason::ArithmeticOverflow, usize::MAX)
                    })?;
                if telemetry.unconditional_equality_facts > limits.max_equality_facts {
                    return Err(Abstention::capped(
                        AbstentionReason::EqualityFactCap,
                        telemetry.unconditional_equality_facts,
                        limits.max_equality_facts,
                    ));
                }
                facts.push(normalized_pair(*left, *right));
            }
            _ => {}
        }
    }
    Ok(facts)
}

fn canonicalize(
    syntax_nodes: &[&BoolExpr],
    assertion_roots: &[BoolExpr],
    data_terms: &[TermId],
    term_map: &[TermId],
    projected_occurrences: usize,
    limits: Limits,
) -> Result<(DagProjection, DagProjection), Abstention> {
    let mut syntactic = CanonicalInterner::new(limits, ProjectionKind::Syntactic);
    let mut quotient = CanonicalInterner::new(limits, ProjectionKind::Quotient);
    let mut node_ids = HashMap::<usize, (NodeId, NodeId)>::default();

    for &expression in syntax_nodes.iter().rev() {
        let child_count = expression_child_count(expression);
        let mut syntactic_children = Vec::with_capacity(child_count);
        let mut quotient_children = Vec::with_capacity(child_count);
        append_expression_child_ids(
            expression,
            &node_ids,
            &mut syntactic_children,
            &mut quotient_children,
        );

        let syntactic_node = syntactic.expression_node(expression, &syntactic_children, None)?;
        let syntactic_id = syntactic.intern(syntactic_node)?;
        let quotient_node =
            quotient.expression_node(expression, &quotient_children, Some(term_map))?;
        let quotient_id = quotient.intern(quotient_node)?;
        node_ids.insert(expression_address(expression), (syntactic_id, quotient_id));
    }

    let mut syntactic_roots = Vec::with_capacity(assertion_roots.len() + data_terms.len());
    let mut quotient_roots = Vec::with_capacity(assertion_roots.len() + data_terms.len());
    for expression in assertion_roots {
        let ids = node_ids[&expression_address(expression)];
        syntactic_roots.push(ids.0);
        quotient_roots.push(ids.1);
    }

    for &term in data_terms {
        let syntactic_id = syntactic.intern(CanonicalNode::BoolTerm(term))?;
        let quotient_id = quotient.intern(CanonicalNode::BoolTerm(term_map[term]))?;
        syntactic_roots.push(syntactic_id);
        quotient_roots.push(quotient_id);
    }

    Ok((
        syntactic.projection(&syntactic_roots, projected_occurrences)?,
        quotient.projection(&quotient_roots, projected_occurrences)?,
    ))
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

fn append_expression_child_ids(
    expression: &BoolExpr,
    node_ids: &HashMap<usize, (NodeId, NodeId)>,
    syntactic: &mut Vec<NodeId>,
    quotient: &mut Vec<NodeId>,
) {
    let mut append = |child: &BoolExpr| {
        let ids = node_ids[&expression_address(child)];
        syntactic.push(ids.0);
        quotient.push(ids.1);
    };
    match expression {
        BoolExpr::Const(_) | BoolExpr::Atom(_) => {}
        BoolExpr::Not(child) => append(child),
        BoolExpr::And(children) | BoolExpr::Or(children) | BoolExpr::Iff(children) => {
            children.iter().for_each(&mut append);
        }
        BoolExpr::Ite(condition, then_expression, else_expression) => {
            append(condition);
            append(then_expression);
            append(else_expression);
        }
    }
}

fn expression_address(expression: &BoolExpr) -> usize {
    std::ptr::from_ref(expression) as usize
}

fn normalized_pair(left: TermId, right: TermId) -> (TermId, TermId) {
    if left <= right {
        (left, right)
    } else {
        (right, left)
    }
}

fn ratio_ppm(numerator: usize, denominator: usize) -> u32 {
    if denominator == 0 {
        return 0;
    }
    let scaled = (numerator as u128) * 1_000_000 / (denominator as u128);
    scaled.min(u32::MAX as u128) as u32
}

const DEFAULT_ABLATION_MAX_TERMS: usize = 2_000_000;
const DEFAULT_ABLATION_MAX_CONGRUENCE_ROUNDS: usize = 4_096;
const DEFAULT_ABLATION_MAX_SIGNATURE_ENTRIES: usize = 20_000_000;
const DEFAULT_ABLATION_MAX_CLAUSES: u64 = 50_000_000;
const DEFAULT_ABLATION_MAX_LITERAL_SLOTS: u64 = 500_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AblationLimits {
    pub(crate) max_syntax_occurrences: usize,
    pub(crate) max_unconditional_equalities: usize,
    pub(crate) max_terms: usize,
    pub(crate) max_gate_definitions: usize,
    pub(crate) max_gate_edges: usize,
    pub(crate) max_congruence_rounds: usize,
    pub(crate) max_congruence_signature_entries: usize,
    pub(crate) max_clauses: u64,
    pub(crate) max_literal_slots: u64,
}

impl Default for AblationLimits {
    fn default() -> Self {
        Self {
            max_syntax_occurrences: DEFAULT_MAX_SYNTAX_OCCURRENCES,
            max_unconditional_equalities: DEFAULT_MAX_EQUALITY_FACTS,
            max_terms: DEFAULT_ABLATION_MAX_TERMS,
            max_gate_definitions: DEFAULT_MAX_CANONICAL_NODES,
            max_gate_edges: DEFAULT_MAX_CANONICAL_EDGES,
            max_congruence_rounds: DEFAULT_ABLATION_MAX_CONGRUENCE_ROUNDS,
            max_congruence_signature_entries: DEFAULT_ABLATION_MAX_SIGNATURE_ENTRIES,
            max_clauses: DEFAULT_ABLATION_MAX_CLAUSES,
            max_literal_slots: DEFAULT_ABLATION_MAX_LITERAL_SLOTS,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AblationAbstentionReason {
    SyntaxOccurrenceCap,
    EqualityFactCap,
    TermCap,
    GateDefinitionCap,
    GateEdgeCap,
    CongruenceRoundCap,
    CongruenceSignatureCap,
    ClauseCap,
    LiteralSlotCap,
    InvalidTermId,
    IllSortedEquality,
    NonBooleanTerm,
    InconsistentBooleanConstants,
    ArithmeticOverflow,
}

impl AblationAbstentionReason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::SyntaxOccurrenceCap => "syntax_occurrence_cap",
            Self::EqualityFactCap => "equality_fact_cap",
            Self::TermCap => "term_cap",
            Self::GateDefinitionCap => "gate_definition_cap",
            Self::GateEdgeCap => "gate_edge_cap",
            Self::CongruenceRoundCap => "congruence_round_cap",
            Self::CongruenceSignatureCap => "congruence_signature_cap",
            Self::ClauseCap => "clause_cap",
            Self::LiteralSlotCap => "literal_slot_cap",
            Self::InvalidTermId => "invalid_term_id",
            Self::IllSortedEquality => "ill_sorted_equality",
            Self::NonBooleanTerm => "non_boolean_term",
            Self::InconsistentBooleanConstants => "inconsistent_boolean_constants",
            Self::ArithmeticOverflow => "arithmetic_overflow",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AblationAbstention {
    pub(crate) reason: AblationAbstentionReason,
    pub(crate) observed: u64,
    pub(crate) limit: Option<u64>,
}

impl AblationAbstention {
    fn capped(reason: AblationAbstentionReason, observed: usize, limit: usize) -> Self {
        Self {
            reason,
            observed: observed as u64,
            limit: Some(limit as u64),
        }
    }

    fn capped_u64(reason: AblationAbstentionReason, observed: u64, limit: u64) -> Self {
        Self {
            reason,
            observed,
            limit: Some(limit),
        }
    }

    fn invalid(reason: AblationAbstentionReason, observed: usize) -> Self {
        Self {
            reason,
            observed: observed as u64,
            limit: None,
        }
    }

    fn overflow() -> Self {
        Self {
            reason: AblationAbstentionReason::ArithmeticOverflow,
            observed: u64::MAX,
            limit: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ProjectedCnf {
    pub(crate) atom_variables: u64,
    pub(crate) constant_variables: u64,
    pub(crate) tseitin_variables: u64,
    pub(crate) variables: u64,
    pub(crate) clauses: u64,
    pub(crate) literal_slots: u64,
    pub(crate) unit_clauses: u64,
    pub(crate) two_watch_entries: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct AblationProjection {
    pub(crate) source_occurrences: u64,
    pub(crate) assertion_roots: u64,
    pub(crate) boolean_data_roots: u64,
    pub(crate) gate_definitions: u64,
    pub(crate) gate_edges: u64,
    pub(crate) cnf: ProjectedCnf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AblationTelemetry {
    pub(crate) assertion_roots: u64,
    pub(crate) boolean_data_roots: u64,
    pub(crate) source_occurrences: u64,
    pub(crate) unconditional_equality_facts: u64,
    pub(crate) root_equality_unions: u64,
    pub(crate) congruence_unions: u64,
    pub(crate) congruence_rounds: u64,
    pub(crate) congruence_signature_entries: u64,
    pub(crate) tree_no_sharing: AblationProjection,
    pub(crate) generic_source_dag: AblationProjection,
    pub(crate) root_union_dag: AblationProjection,
    pub(crate) full_euf_dag: AblationProjection,
}

#[derive(Debug)]
struct AblationUnionFind {
    parent: Vec<TermId>,
    size: Vec<usize>,
    minimum: Vec<TermId>,
}

impl AblationUnionFind {
    fn new(terms: usize) -> Self {
        Self {
            parent: (0..terms).collect(),
            size: vec![1; terms],
            minimum: (0..terms).collect(),
        }
    }

    fn find(&mut self, term: TermId) -> TermId {
        let mut root = term;
        while self.parent[root] != root {
            root = self.parent[root];
        }
        let mut cursor = term;
        while self.parent[cursor] != cursor {
            let next = self.parent[cursor];
            self.parent[cursor] = root;
            cursor = next;
        }
        root
    }

    fn union(&mut self, left: TermId, right: TermId) -> bool {
        let mut left = self.find(left);
        let mut right = self.find(right);
        if left == right {
            return false;
        }
        if self.size[left] < self.size[right]
            || (self.size[left] == self.size[right] && self.minimum[left] > self.minimum[right])
        {
            std::mem::swap(&mut left, &mut right);
        }
        self.parent[right] = left;
        self.size[left] += self.size[right];
        self.minimum[left] = self.minimum[left].min(self.minimum[right]);
        true
    }

    fn representatives(&mut self) -> Vec<TermId> {
        (0..self.parent.len())
            .map(|term| {
                let root = self.find(term);
                self.minimum[root]
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TypedApplicationSignature {
    function: SymId,
    result_sort: SortId,
    arguments: Vec<TermId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct AblationLiteral {
    variable: usize,
    negated: bool,
}

impl AblationLiteral {
    fn negated(self) -> Self {
        Self {
            variable: self.variable,
            negated: !self.negated,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum AblationAtom {
    Eq(TermId, TermId),
    BoolTerm(TermId),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum AblationGate {
    And(Vec<AblationLiteral>),
    Or(Vec<AblationLiteral>),
    Iff(Vec<AblationLiteral>),
    Ite([AblationLiteral; 3]),
}

struct ProjectionEncoder<'a> {
    arena: &'a TermArena,
    term_map: &'a [TermId],
    mapped_true: TermId,
    mapped_false: TermId,
    share_gates: bool,
    limits: AblationLimits,
    atoms: HashMap<AblationAtom, usize>,
    gates: HashMap<AblationGate, AblationLiteral>,
    true_variable: Option<usize>,
    next_variable: usize,
    projection: AblationProjection,
}

impl<'a> ProjectionEncoder<'a> {
    fn new(
        arena: &'a TermArena,
        term_map: &'a [TermId],
        true_term: TermId,
        false_term: TermId,
        share_gates: bool,
        limits: AblationLimits,
        source_occurrences: usize,
        assertion_roots: usize,
        boolean_data_roots: usize,
    ) -> Self {
        Self {
            arena,
            term_map,
            mapped_true: term_map[true_term],
            mapped_false: term_map[false_term],
            share_gates,
            limits,
            atoms: HashMap::default(),
            gates: HashMap::default(),
            true_variable: None,
            next_variable: 0,
            projection: AblationProjection {
                source_occurrences: source_occurrences as u64,
                assertion_roots: assertion_roots as u64,
                boolean_data_roots: boolean_data_roots as u64,
                ..AblationProjection::default()
            },
        }
    }

    fn new_variable(&mut self) -> Result<usize, AblationAbstention> {
        let variable = self.next_variable;
        self.next_variable = self
            .next_variable
            .checked_add(1)
            .ok_or_else(AblationAbstention::overflow)?;
        Ok(variable)
    }

    fn add_clause(&mut self, literal_slots: u64) -> Result<(), AblationAbstention> {
        self.projection.cnf.clauses = self
            .projection
            .cnf
            .clauses
            .checked_add(1)
            .ok_or_else(AblationAbstention::overflow)?;
        if self.projection.cnf.clauses > self.limits.max_clauses {
            return Err(AblationAbstention::capped_u64(
                AblationAbstentionReason::ClauseCap,
                self.projection.cnf.clauses,
                self.limits.max_clauses,
            ));
        }
        self.projection.cnf.literal_slots = self
            .projection
            .cnf
            .literal_slots
            .checked_add(literal_slots)
            .ok_or_else(AblationAbstention::overflow)?;
        if self.projection.cnf.literal_slots > self.limits.max_literal_slots {
            return Err(AblationAbstention::capped_u64(
                AblationAbstentionReason::LiteralSlotCap,
                self.projection.cnf.literal_slots,
                self.limits.max_literal_slots,
            ));
        }
        match literal_slots {
            1 => {
                self.projection.cnf.unit_clauses = self
                    .projection
                    .cnf
                    .unit_clauses
                    .checked_add(1)
                    .ok_or_else(AblationAbstention::overflow)?;
            }
            2.. => {
                self.projection.cnf.two_watch_entries = self
                    .projection
                    .cnf
                    .two_watch_entries
                    .checked_add(2)
                    .ok_or_else(AblationAbstention::overflow)?;
            }
            _ => {}
        }
        Ok(())
    }

    fn constant_literal(&mut self, value: bool) -> Result<AblationLiteral, AblationAbstention> {
        let variable = if let Some(variable) = self.true_variable {
            variable
        } else {
            let variable = self.new_variable()?;
            self.true_variable = Some(variable);
            self.projection.cnf.constant_variables = 1;
            self.add_clause(1)?;
            variable
        };
        Ok(AblationLiteral {
            variable,
            negated: !value,
        })
    }

    fn mapped_term(&self, term: TermId) -> Result<TermId, AblationAbstention> {
        self.term_map.get(term).copied().ok_or_else(|| {
            AblationAbstention::invalid(AblationAbstentionReason::InvalidTermId, term)
        })
    }

    fn atom_literal(&mut self, atom: &BoolAtomKey) -> Result<AblationLiteral, AblationAbstention> {
        let atom = match atom {
            BoolAtomKey::Eq(left, right) => {
                let left = self.mapped_term(*left)?;
                let right = self.mapped_term(*right)?;
                if left == right {
                    return self.constant_literal(true);
                }
                if self.arena.terms[left].sort == BOOL_SORT {
                    let is_true_false = (left == self.mapped_true && right == self.mapped_false)
                        || (left == self.mapped_false && right == self.mapped_true);
                    if is_true_false {
                        return self.constant_literal(false);
                    }
                }
                let (left, right) = normalized_pair(left, right);
                AblationAtom::Eq(left, right)
            }
            BoolAtomKey::BoolTerm(term) => {
                let term = self.mapped_term(*term)?;
                if term == self.mapped_true {
                    return self.constant_literal(true);
                }
                if term == self.mapped_false {
                    return self.constant_literal(false);
                }
                AblationAtom::BoolTerm(term)
            }
        };
        if let Some(&variable) = self.atoms.get(&atom) {
            return Ok(AblationLiteral {
                variable,
                negated: false,
            });
        }
        let variable = self.new_variable()?;
        self.atoms.insert(atom, variable);
        self.projection.cnf.atom_variables = self
            .projection
            .cnf
            .atom_variables
            .checked_add(1)
            .ok_or_else(AblationAbstention::overflow)?;
        Ok(AblationLiteral {
            variable,
            negated: false,
        })
    }

    fn emit_gate(&mut self, gate: AblationGate) -> Result<AblationLiteral, AblationAbstention> {
        if self.share_gates {
            if let Some(&literal) = self.gates.get(&gate) {
                return Ok(literal);
            }
        }
        let gate_edges = match &gate {
            AblationGate::And(children)
            | AblationGate::Or(children)
            | AblationGate::Iff(children) => children.len(),
            AblationGate::Ite(_) => 3,
        };
        let next_definitions = (self.projection.gate_definitions as usize)
            .checked_add(1)
            .ok_or_else(AblationAbstention::overflow)?;
        if next_definitions > self.limits.max_gate_definitions {
            return Err(AblationAbstention::capped(
                AblationAbstentionReason::GateDefinitionCap,
                next_definitions,
                self.limits.max_gate_definitions,
            ));
        }
        let next_edges = (self.projection.gate_edges as usize)
            .checked_add(gate_edges)
            .ok_or_else(AblationAbstention::overflow)?;
        if next_edges > self.limits.max_gate_edges {
            return Err(AblationAbstention::capped(
                AblationAbstentionReason::GateEdgeCap,
                next_edges,
                self.limits.max_gate_edges,
            ));
        }

        let variable = self.new_variable()?;
        let literal = AblationLiteral {
            variable,
            negated: false,
        };
        self.projection.gate_definitions = next_definitions as u64;
        self.projection.gate_edges = next_edges as u64;
        self.projection.cnf.tseitin_variables = self
            .projection
            .cnf
            .tseitin_variables
            .checked_add(1)
            .ok_or_else(AblationAbstention::overflow)?;

        match &gate {
            AblationGate::And(children) | AblationGate::Or(children) => {
                for _ in children {
                    self.add_clause(2)?;
                }
                self.add_clause(
                    (children.len() as u64)
                        .checked_add(1)
                        .ok_or_else(AblationAbstention::overflow)?,
                )?;
            }
            AblationGate::Iff(children) => {
                let arity = children.len() as u64;
                for _ in 0..2 * children.len().saturating_sub(1) {
                    self.add_clause(3)?;
                }
                self.add_clause(
                    arity
                        .checked_add(1)
                        .ok_or_else(AblationAbstention::overflow)?,
                )?;
                self.add_clause(
                    arity
                        .checked_add(1)
                        .ok_or_else(AblationAbstention::overflow)?,
                )?;
            }
            AblationGate::Ite(_) => {
                for _ in 0..4 {
                    self.add_clause(3)?;
                }
            }
        }
        if self.share_gates {
            self.gates.insert(gate, literal);
        }
        Ok(literal)
    }

    fn encode(&mut self, expression: &BoolExpr) -> Result<AblationLiteral, AblationAbstention> {
        match expression {
            BoolExpr::Const(value) => self.constant_literal(*value),
            BoolExpr::Atom(atom) => self.atom_literal(atom),
            BoolExpr::Not(child) => Ok(self.encode(child)?.negated()),
            BoolExpr::And(children) => match children.as_slice() {
                [] => self.constant_literal(true),
                [single] => self.encode(single),
                _ => {
                    let children = children
                        .iter()
                        .map(|child| self.encode(child))
                        .collect::<Result<Vec<_>, _>>()?;
                    self.emit_gate(AblationGate::And(children))
                }
            },
            BoolExpr::Or(children) => match children.as_slice() {
                [] => self.constant_literal(false),
                [single] => self.encode(single),
                _ => {
                    let children = children
                        .iter()
                        .map(|child| self.encode(child))
                        .collect::<Result<Vec<_>, _>>()?;
                    self.emit_gate(AblationGate::Or(children))
                }
            },
            BoolExpr::Iff(children) => match children.as_slice() {
                [] | [_] => self.constant_literal(true),
                _ => {
                    let children = children
                        .iter()
                        .map(|child| self.encode(child))
                        .collect::<Result<Vec<_>, _>>()?;
                    self.emit_gate(AblationGate::Iff(children))
                }
            },
            BoolExpr::Ite(condition, then_expression, else_expression) => {
                let children = [
                    self.encode(condition)?,
                    self.encode(then_expression)?,
                    self.encode(else_expression)?,
                ];
                self.emit_gate(AblationGate::Ite(children))
            }
        }
    }

    fn finish(
        mut self,
        assertions: &[BoolExpr],
        data_terms: &[TermId],
    ) -> Result<AblationProjection, AblationAbstention> {
        for assertion in assertions {
            self.encode(assertion)?;
            self.add_clause(1)?;
        }
        for &term in data_terms {
            self.atom_literal(&BoolAtomKey::BoolTerm(term))?;
        }
        self.projection.cnf.variables = self
            .projection
            .cnf
            .atom_variables
            .checked_add(self.projection.cnf.constant_variables)
            .and_then(|value| value.checked_add(self.projection.cnf.tseitin_variables))
            .ok_or_else(AblationAbstention::overflow)?;
        if self.projection.cnf.variables != self.next_variable as u64 {
            return Err(AblationAbstention::invalid(
                AblationAbstentionReason::ArithmeticOverflow,
                self.next_variable,
            ));
        }
        Ok(self.projection)
    }
}

fn scan_ablation_syntax(
    bool_problem: &BoolProblem,
    arena: &TermArena,
    limits: AblationLimits,
) -> Result<usize, AblationAbstention> {
    let mut occurrences = 0usize;
    let mut stack = bool_problem.assertions.iter().rev().collect::<Vec<_>>();
    while let Some(expression) = stack.pop() {
        occurrences = occurrences
            .checked_add(1)
            .ok_or_else(AblationAbstention::overflow)?;
        if occurrences > limits.max_syntax_occurrences {
            return Err(AblationAbstention::capped(
                AblationAbstentionReason::SyntaxOccurrenceCap,
                occurrences,
                limits.max_syntax_occurrences,
            ));
        }
        match expression {
            BoolExpr::Atom(BoolAtomKey::Eq(left, right)) => {
                let left_sort = arena
                    .terms
                    .get(*left)
                    .map(|term| term.sort)
                    .ok_or_else(|| {
                        AblationAbstention::invalid(AblationAbstentionReason::InvalidTermId, *left)
                    })?;
                let right_sort =
                    arena
                        .terms
                        .get(*right)
                        .map(|term| term.sort)
                        .ok_or_else(|| {
                            AblationAbstention::invalid(
                                AblationAbstentionReason::InvalidTermId,
                                *right,
                            )
                        })?;
                if left_sort != right_sort {
                    return Err(AblationAbstention::invalid(
                        AblationAbstentionReason::IllSortedEquality,
                        *right,
                    ));
                }
            }
            BoolExpr::Atom(BoolAtomKey::BoolTerm(term)) => {
                validate_ablation_boolean_term(*term, arena)?;
            }
            _ => {}
        }
        push_children(expression, &mut stack);
    }
    Ok(occurrences)
}

fn validate_ablation_boolean_term(
    term: TermId,
    arena: &TermArena,
) -> Result<(), AblationAbstention> {
    let sort = arena.terms.get(term).map(|term| term.sort).ok_or_else(|| {
        AblationAbstention::invalid(AblationAbstentionReason::InvalidTermId, term)
    })?;
    if sort != BOOL_SORT {
        return Err(AblationAbstention::invalid(
            AblationAbstentionReason::NonBooleanTerm,
            term,
        ));
    }
    Ok(())
}

fn collect_ablation_equalities(
    bool_problem: &BoolProblem,
    limits: AblationLimits,
) -> Result<Vec<(TermId, TermId)>, AblationAbstention> {
    let mut facts = Vec::new();
    let mut stack = bool_problem.assertions.iter().rev().collect::<Vec<_>>();
    while let Some(expression) = stack.pop() {
        match expression {
            BoolExpr::And(children) => stack.extend(children.iter().rev()),
            BoolExpr::Atom(BoolAtomKey::Eq(left, right)) => {
                push_ablation_equality(&mut facts, *left, *right, limits)?;
            }
            BoolExpr::Iff(children) => {
                let terms = children
                    .iter()
                    .map(|child| direct_boolean_term(child, bool_problem))
                    .collect::<Option<Vec<_>>>();
                if let Some((first, rest)) = terms.as_deref().and_then(|terms| terms.split_first())
                {
                    for &term in rest {
                        push_ablation_equality(&mut facts, *first, term, limits)?;
                    }
                }
            }
            _ => {}
        }
    }
    Ok(facts)
}

fn direct_boolean_term(expression: &BoolExpr, bool_problem: &BoolProblem) -> Option<TermId> {
    match expression {
        BoolExpr::Const(true) => Some(bool_problem.true_term),
        BoolExpr::Const(false) => Some(bool_problem.false_term),
        BoolExpr::Atom(BoolAtomKey::BoolTerm(term)) => Some(*term),
        _ => None,
    }
}

fn push_ablation_equality(
    facts: &mut Vec<(TermId, TermId)>,
    left: TermId,
    right: TermId,
    limits: AblationLimits,
) -> Result<(), AblationAbstention> {
    facts.push(normalized_pair(left, right));
    if facts.len() > limits.max_unconditional_equalities {
        return Err(AblationAbstention::capped(
            AblationAbstentionReason::EqualityFactCap,
            facts.len(),
            limits.max_unconditional_equalities,
        ));
    }
    Ok(())
}

fn checked_union_facts(
    union_find: &mut AblationUnionFind,
    facts: &[(TermId, TermId)],
    arena: &TermArena,
) -> Result<usize, AblationAbstention> {
    let mut effective = 0usize;
    for &(left, right) in facts {
        let left_sort = arena.terms.get(left).map(|term| term.sort).ok_or_else(|| {
            AblationAbstention::invalid(AblationAbstentionReason::InvalidTermId, left)
        })?;
        let right_sort = arena
            .terms
            .get(right)
            .map(|term| term.sort)
            .ok_or_else(|| {
                AblationAbstention::invalid(AblationAbstentionReason::InvalidTermId, right)
            })?;
        if left_sort != right_sort {
            return Err(AblationAbstention::invalid(
                AblationAbstentionReason::IllSortedEquality,
                right,
            ));
        }
        effective = effective
            .checked_add(usize::from(union_find.union(left, right)))
            .ok_or_else(AblationAbstention::overflow)?;
    }
    Ok(effective)
}

fn close_typed_congruence(
    union_find: &mut AblationUnionFind,
    arena: &TermArena,
    limits: AblationLimits,
) -> Result<(usize, usize, usize), AblationAbstention> {
    let mut effective_unions = 0usize;
    let mut rounds = 0usize;
    let mut signature_entries = 0usize;
    loop {
        let representatives = union_find.representatives();
        let mut signatures = HashMap::<TypedApplicationSignature, TermId>::default();
        let mut round_unions = 0usize;
        for (term_id, term) in arena.terms.iter().enumerate() {
            if term.args.is_empty() {
                continue;
            }
            signature_entries = signature_entries
                .checked_add(1)
                .ok_or_else(AblationAbstention::overflow)?;
            if signature_entries > limits.max_congruence_signature_entries {
                return Err(AblationAbstention::capped(
                    AblationAbstentionReason::CongruenceSignatureCap,
                    signature_entries,
                    limits.max_congruence_signature_entries,
                ));
            }
            let arguments = term
                .args
                .iter()
                .map(|&argument| {
                    representatives.get(argument).copied().ok_or_else(|| {
                        AblationAbstention::invalid(
                            AblationAbstentionReason::InvalidTermId,
                            argument,
                        )
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let signature = TypedApplicationSignature {
                function: term.fun,
                result_sort: term.sort,
                arguments,
            };
            if let Some(&previous) = signatures.get(&signature) {
                if arena.terms[previous].sort != term.sort {
                    return Err(AblationAbstention::invalid(
                        AblationAbstentionReason::IllSortedEquality,
                        term_id,
                    ));
                }
                round_unions = round_unions
                    .checked_add(usize::from(union_find.union(previous, term_id)))
                    .ok_or_else(AblationAbstention::overflow)?;
            } else {
                signatures.insert(signature, term_id);
            }
        }
        if round_unions == 0 {
            return Ok((effective_unions, rounds, signature_entries));
        }
        rounds = rounds
            .checked_add(1)
            .ok_or_else(AblationAbstention::overflow)?;
        if rounds > limits.max_congruence_rounds {
            return Err(AblationAbstention::capped(
                AblationAbstentionReason::CongruenceRoundCap,
                rounds,
                limits.max_congruence_rounds,
            ));
        }
        effective_unions = effective_unions
            .checked_add(round_unions)
            .ok_or_else(AblationAbstention::overflow)?;
    }
}

pub(crate) fn analyze_four_way_ablation(
    bool_problem: &BoolProblem,
    arena: &TermArena,
) -> Result<AblationTelemetry, AblationAbstention> {
    analyze_four_way_ablation_with_limits(bool_problem, arena, AblationLimits::default())
}

pub(crate) fn analyze_four_way_ablation_with_limits(
    bool_problem: &BoolProblem,
    arena: &TermArena,
    limits: AblationLimits,
) -> Result<AblationTelemetry, AblationAbstention> {
    if arena.terms.len() > limits.max_terms {
        return Err(AblationAbstention::capped(
            AblationAbstentionReason::TermCap,
            arena.terms.len(),
            limits.max_terms,
        ));
    }
    validate_ablation_boolean_term(bool_problem.true_term, arena)?;
    validate_ablation_boolean_term(bool_problem.false_term, arena)?;
    for term in &arena.terms {
        for &argument in &term.args {
            if argument >= arena.terms.len() {
                return Err(AblationAbstention::invalid(
                    AblationAbstentionReason::InvalidTermId,
                    argument,
                ));
            }
        }
    }
    let source_occurrences = scan_ablation_syntax(bool_problem, arena, limits)?;
    let mut data_terms = bool_problem.data_terms.clone();
    data_terms.sort_unstable();
    data_terms.dedup();
    for &term in &data_terms {
        validate_ablation_boolean_term(term, arena)?;
    }
    let facts = collect_ablation_equalities(bool_problem, limits)?;

    let mut root_union = AblationUnionFind::new(arena.terms.len());
    let root_equality_unions = checked_union_facts(&mut root_union, &facts, arena)?;
    let root_map = root_union.representatives();

    let mut full_union = AblationUnionFind::new(arena.terms.len());
    let full_root_unions = checked_union_facts(&mut full_union, &facts, arena)?;
    if full_root_unions != root_equality_unions {
        return Err(AblationAbstention::overflow());
    }
    let (congruence_unions, congruence_rounds, congruence_signature_entries) =
        close_typed_congruence(&mut full_union, arena, limits)?;
    let full_map = full_union.representatives();
    if root_map[bool_problem.true_term] == root_map[bool_problem.false_term]
        || full_map[bool_problem.true_term] == full_map[bool_problem.false_term]
    {
        return Err(AblationAbstention::invalid(
            AblationAbstentionReason::InconsistentBooleanConstants,
            bool_problem.false_term,
        ));
    }
    let identity_map = (0..arena.terms.len()).collect::<Vec<_>>();
    let encode = |term_map: &[TermId], share_gates: bool| {
        ProjectionEncoder::new(
            arena,
            term_map,
            bool_problem.true_term,
            bool_problem.false_term,
            share_gates,
            limits,
            source_occurrences,
            bool_problem.assertions.len(),
            data_terms.len(),
        )
        .finish(&bool_problem.assertions, &data_terms)
    };

    Ok(AblationTelemetry {
        assertion_roots: bool_problem.assertions.len() as u64,
        boolean_data_roots: data_terms.len() as u64,
        source_occurrences: source_occurrences as u64,
        unconditional_equality_facts: facts.len() as u64,
        root_equality_unions: root_equality_unions as u64,
        congruence_unions: congruence_unions as u64,
        congruence_rounds: congruence_rounds as u64,
        congruence_signature_entries: congruence_signature_entries as u64,
        tree_no_sharing: encode(&identity_map, false)?,
        generic_source_dag: encode(&identity_map, true)?,
        root_union_dag: encode(&root_map, true)?,
        full_euf_dag: encode(&full_map, true)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SortId, parse_problem};

    const U_SORT: SortId = SortId(1);

    fn nullary(arena: &mut TermArena, fun: u32, sort: SortId) -> TermId {
        arena.intern_typed(fun, Vec::new(), sort)
    }

    fn bool_problem(
        assertions: Vec<BoolExpr>,
        data_terms: Vec<TermId>,
        true_term: TermId,
        false_term: TermId,
    ) -> BoolProblem {
        BoolProblem {
            assertions,
            unsupported: Vec::new(),
            true_term,
            false_term,
            data_terms,
        }
    }

    fn bool_atom(term: TermId) -> BoolExpr {
        BoolExpr::Atom(BoolAtomKey::BoolTerm(term))
    }

    fn equality(left: TermId, right: TermId) -> BoolExpr {
        BoolExpr::Atom(BoolAtomKey::Eq(left, right))
    }

    #[test]
    fn deterministic_ac_counts_preserve_polarity_and_ite_order() {
        let mut arena = TermArena::default();
        let true_term = nullary(&mut arena, 0, BOOL_SORT);
        let false_term = nullary(&mut arena, 1, BOOL_SORT);
        let p = nullary(&mut arena, 2, BOOL_SORT);
        let q = nullary(&mut arena, 3, BOOL_SORT);
        let r = nullary(&mut arena, 4, BOOL_SORT);
        let assertions = vec![
            BoolExpr::And(vec![
                bool_atom(p),
                BoolExpr::And(vec![bool_atom(q), bool_atom(r)]),
            ]),
            BoolExpr::And(vec![
                BoolExpr::And(vec![bool_atom(r), bool_atom(q)]),
                bool_atom(p),
            ]),
            BoolExpr::Or(vec![
                bool_atom(p),
                BoolExpr::Or(vec![bool_atom(q), bool_atom(r)]),
            ]),
            BoolExpr::Or(vec![
                BoolExpr::Or(vec![bool_atom(r), bool_atom(p)]),
                bool_atom(q),
            ]),
            BoolExpr::Iff(vec![bool_atom(p), bool_atom(q), bool_atom(r)]),
            BoolExpr::Iff(vec![bool_atom(r), bool_atom(p), bool_atom(q)]),
            BoolExpr::Not(Box::new(bool_atom(p))),
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
        let problem = bool_problem(assertions, Vec::new(), true_term, false_term);

        let first = analyze(&problem, &arena);
        let second = analyze(&problem, &arena);
        assert_eq!(first, second);
        assert_eq!(first.abstention, None);
        assert_eq!(first.syntax_occurrences, 38);
        assert_eq!(first.projected_occurrences, 38);
        assert_eq!(first.syntactic.unwrap().unique_nodes, 9);
        assert_eq!(first.syntactic.unwrap().canonical_edges, 16);
        assert_eq!(first.syntactic.unwrap().duplicate_ratio_ppm, 763_157);
        assert_eq!(first.quotient, first.syntactic);
    }

    #[test]
    fn guarded_or_equality_never_enters_the_term_quotient() {
        let mut arena = TermArena::default();
        let true_term = nullary(&mut arena, 0, BOOL_SORT);
        let false_term = nullary(&mut arena, 1, BOOL_SORT);
        let guard = nullary(&mut arena, 2, BOOL_SORT);
        let a = nullary(&mut arena, 3, U_SORT);
        let b = nullary(&mut arena, 4, U_SORT);
        let c = nullary(&mut arena, 5, U_SORT);
        let guarded = |left, right| BoolExpr::Or(vec![equality(left, right), bool_atom(guard)]);
        let problem = bool_problem(
            vec![guarded(a, b), guarded(a, c), guarded(c, a), guarded(b, c)],
            Vec::new(),
            true_term,
            false_term,
        );

        let telemetry = analyze(&problem, &arena);
        assert_eq!(telemetry.unconditional_equality_facts, 0);
        assert_eq!(telemetry.effective_equality_unions, 0);
        assert_eq!(telemetry.syntax_occurrences, 12);
        assert_eq!(telemetry.syntactic.unwrap().unique_nodes, 7);
        assert_eq!(telemetry.quotient, telemetry.syntactic);
        assert_eq!(telemetry.quotient_unique_reduction, Some(0));
    }

    #[test]
    fn unconditional_positive_equality_merges_boolean_dag_nodes() {
        let mut arena = TermArena::default();
        let true_term = nullary(&mut arena, 0, BOOL_SORT);
        let false_term = nullary(&mut arena, 1, BOOL_SORT);
        let guard = nullary(&mut arena, 2, BOOL_SORT);
        let a = nullary(&mut arena, 3, U_SORT);
        let b = nullary(&mut arena, 4, U_SORT);
        let c = nullary(&mut arena, 5, U_SORT);
        let problem = bool_problem(
            vec![
                equality(a, b),
                BoolExpr::Or(vec![equality(a, c), bool_atom(guard)]),
                BoolExpr::Or(vec![equality(b, c), bool_atom(guard)]),
            ],
            Vec::new(),
            true_term,
            false_term,
        );

        let telemetry = analyze(&problem, &arena);
        assert_eq!(telemetry.syntax_occurrences, 7);
        assert_eq!(telemetry.unconditional_equality_facts, 1);
        assert_eq!(telemetry.effective_equality_unions, 1);
        assert_eq!(telemetry.nontrivial_quotient_classes, 1);
        assert_eq!(telemetry.quotiented_terms, 2);
        assert_eq!(telemetry.syntactic.unwrap().unique_nodes, 6);
        assert_eq!(telemetry.syntactic.unwrap().duplicate_ratio_ppm, 142_857);
        assert_eq!(telemetry.quotient.unwrap().unique_nodes, 4);
        assert_eq!(telemetry.quotient.unwrap().duplicate_ratio_ppm, 428_571);
        assert_eq!(telemetry.quotient_unique_reduction, Some(2));
        assert_eq!(telemetry.quotient_unique_reduction_ppm, Some(333_333));
    }

    #[test]
    fn bool_as_data_terms_are_projected_as_atom_roots() {
        let input = "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun p () Bool)
            (declare-fun q () Bool)
            (declare-fun r () Bool)
            (declare-fun f (Bool) U)
            (assert (distinct (f p) (f q) (f r)))
            (check-sat)
        ";
        let problem = parse_problem(input).unwrap();
        let bool_problem = problem.bool_problem.as_ref().unwrap();
        let telemetry = analyze(bool_problem, &problem.arena);

        assert_eq!(telemetry.abstention, None);
        assert_eq!(telemetry.assertion_roots, 1);
        assert_eq!(telemetry.data_term_entries, 3);
        assert_eq!(telemetry.data_term_roots, 3);
        assert_eq!(telemetry.syntax_occurrences, 7);
        assert_eq!(telemetry.projected_occurrences, 10);
        assert_eq!(telemetry.syntactic.unwrap().unique_nodes, 10);
        assert_eq!(telemetry.quotient, telemetry.syntactic);
    }

    #[test]
    fn cap_is_reported_without_partial_projection() {
        let mut arena = TermArena::default();
        let true_term = nullary(&mut arena, 0, BOOL_SORT);
        let false_term = nullary(&mut arena, 1, BOOL_SORT);
        let p = nullary(&mut arena, 2, BOOL_SORT);
        let q = nullary(&mut arena, 3, BOOL_SORT);
        let problem = bool_problem(
            vec![BoolExpr::And(vec![bool_atom(p), bool_atom(q)])],
            Vec::new(),
            true_term,
            false_term,
        );
        let limits = Limits {
            max_syntax_occurrences: 2,
            ..Limits::default()
        };

        let telemetry = analyze_with_limits(&problem, &arena, limits);
        assert_eq!(telemetry.syntax_occurrences, 3);
        assert_eq!(telemetry.syntactic, None);
        assert_eq!(telemetry.quotient, None);
        assert_eq!(
            telemetry.abstention,
            Some(Abstention::capped(
                AbstentionReason::SyntaxOccurrenceCap,
                3,
                2,
            ))
        );
        assert_eq!(
            telemetry.abstention.unwrap().reason.as_str(),
            "syntax_occurrence_cap"
        );
    }

    fn parsed_ablation(input: &str) -> AblationTelemetry {
        let problem = parse_problem(input).unwrap();
        assert!(problem.terms_are_well_sorted());
        let boolean = problem.bool_problem.as_ref().unwrap();
        analyze_four_way_ablation(boolean, &problem.arena).unwrap()
    }

    #[test]
    fn four_way_ablation_attributes_syntactic_sharing_only_to_b_c_and_d() {
        let telemetry = parsed_ablation(
            "
            (set-logic QF_UF)
            (declare-fun p () Bool)
            (declare-fun q () Bool)
            (assert (and p q))
            (assert (and p q))
            (check-sat)
            ",
        );

        assert_eq!(telemetry.unconditional_equality_facts, 0);
        assert_eq!(telemetry.tree_no_sharing.gate_definitions, 2);
        assert_eq!(telemetry.generic_source_dag.gate_definitions, 1);
        assert_eq!(telemetry.root_union_dag, telemetry.generic_source_dag);
        assert_eq!(telemetry.full_euf_dag, telemetry.generic_source_dag);
        assert_eq!(
            telemetry.tree_no_sharing.cnf,
            ProjectedCnf {
                atom_variables: 2,
                constant_variables: 0,
                tseitin_variables: 2,
                variables: 4,
                clauses: 8,
                literal_slots: 16,
                unit_clauses: 2,
                two_watch_entries: 12,
            }
        );
        assert_eq!(
            telemetry.generic_source_dag.cnf,
            ProjectedCnf {
                atom_variables: 2,
                constant_variables: 0,
                tseitin_variables: 1,
                variables: 3,
                clauses: 5,
                literal_slots: 9,
                unit_clauses: 2,
                two_watch_entries: 6,
            }
        );
    }

    #[test]
    fn frozen_gate_templates_have_exact_projected_counts() {
        let cases = [
            (
                "(declare-fun p () Bool) (declare-fun q () Bool) (assert (and p q))",
                ProjectedCnf {
                    atom_variables: 2,
                    constant_variables: 0,
                    tseitin_variables: 1,
                    variables: 3,
                    clauses: 4,
                    literal_slots: 8,
                    unit_clauses: 1,
                    two_watch_entries: 6,
                },
            ),
            (
                "(declare-fun p () Bool) (declare-fun q () Bool) (assert (or p q))",
                ProjectedCnf {
                    atom_variables: 2,
                    constant_variables: 0,
                    tseitin_variables: 1,
                    variables: 3,
                    clauses: 4,
                    literal_slots: 8,
                    unit_clauses: 1,
                    two_watch_entries: 6,
                },
            ),
            (
                "(declare-fun p () Bool) (declare-fun q () Bool) (assert (= p q))",
                ProjectedCnf {
                    atom_variables: 2,
                    constant_variables: 0,
                    tseitin_variables: 1,
                    variables: 3,
                    clauses: 5,
                    literal_slots: 13,
                    unit_clauses: 1,
                    two_watch_entries: 8,
                },
            ),
            (
                "(declare-fun p () Bool) (declare-fun q () Bool) (declare-fun r () Bool) \
                 (assert (ite p q r))",
                ProjectedCnf {
                    atom_variables: 3,
                    constant_variables: 0,
                    tseitin_variables: 1,
                    variables: 4,
                    clauses: 5,
                    literal_slots: 13,
                    unit_clauses: 1,
                    two_watch_entries: 8,
                },
            ),
        ];

        for (body, expected) in cases {
            let input = format!("(set-logic QF_UF) {body} (check-sat)");
            assert_eq!(parsed_ablation(&input).tree_no_sharing.cnf, expected);
        }
    }

    #[test]
    fn root_union_shares_rewritten_gates_without_congruence() {
        let telemetry = parsed_ablation(
            "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun a () U)
            (declare-fun b () U)
            (declare-fun c () U)
            (declare-fun p () Bool)
            (assert (= a b))
            (assert (or (= a c) p))
            (assert (or (= b c) p))
            (check-sat)
            ",
        );

        assert_eq!(telemetry.root_equality_unions, 1);
        assert_eq!(telemetry.congruence_unions, 0);
        assert_eq!(telemetry.generic_source_dag.gate_definitions, 2);
        assert_eq!(telemetry.root_union_dag.gate_definitions, 1);
        assert_eq!(telemetry.full_euf_dag, telemetry.root_union_dag);
    }

    #[test]
    fn only_full_typed_euf_projection_sees_deeper_congruence() {
        let telemetry = parsed_ablation(
            "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun a () U)
            (declare-fun b () U)
            (declare-fun c () U)
            (declare-fun f (U) U)
            (declare-fun p () Bool)
            (assert (= a b))
            (assert (or (= (f a) c) p))
            (assert (or (= (f b) c) p))
            (check-sat)
            ",
        );

        assert_eq!(telemetry.root_equality_unions, 1);
        assert_eq!(telemetry.congruence_unions, 1);
        assert_eq!(telemetry.congruence_rounds, 1);
        assert_eq!(telemetry.root_union_dag.gate_definitions, 2);
        assert_eq!(telemetry.full_euf_dag.gate_definitions, 1);
        assert_eq!(telemetry.root_union_dag.cnf.literal_slots, 18);
        assert_eq!(telemetry.full_euf_dag.cnf.literal_slots, 11);
    }

    #[test]
    fn boolean_term_equalities_seed_typed_root_and_congruence_unions() {
        let telemetry = parsed_ablation(
            "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun p () Bool)
            (declare-fun q () Bool)
            (declare-fun c () U)
            (declare-fun f (Bool) U)
            (declare-fun guard () Bool)
            (assert (= p q))
            (assert (or (= (f p) c) guard))
            (assert (or (= (f q) c) guard))
            (check-sat)
            ",
        );

        assert_eq!(telemetry.unconditional_equality_facts, 1);
        assert_eq!(telemetry.root_equality_unions, 1);
        assert_eq!(telemetry.congruence_unions, 1);
        assert_eq!(telemetry.root_union_dag.gate_definitions, 3);
        assert_eq!(telemetry.full_euf_dag.gate_definitions, 2);
    }

    #[test]
    fn conditional_equalities_never_seed_c_or_d() {
        let telemetry = parsed_ablation(
            "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun a () U)
            (declare-fun b () U)
            (declare-fun c () U)
            (declare-fun f (U) U)
            (declare-fun p () Bool)
            (assert (or (= a b) p))
            (assert (or (= (f a) c) p))
            (assert (or (= (f b) c) p))
            (check-sat)
            ",
        );

        assert_eq!(telemetry.unconditional_equality_facts, 0);
        assert_eq!(telemetry.root_equality_unions, 0);
        assert_eq!(telemetry.congruence_unions, 0);
        assert_eq!(telemetry.root_union_dag, telemetry.generic_source_dag);
        assert_eq!(telemetry.full_euf_dag, telemetry.generic_source_dag);
    }

    #[test]
    fn conditional_boolean_term_equalities_do_not_seed_the_quotient() {
        let telemetry = parsed_ablation(
            "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun p () Bool)
            (declare-fun q () Bool)
            (declare-fun c () U)
            (declare-fun f (Bool) U)
            (declare-fun guard () Bool)
            (assert (or (= p q) guard))
            (assert (or (= (f p) c) guard))
            (assert (or (= (f q) c) guard))
            (check-sat)
            ",
        );

        assert_eq!(telemetry.unconditional_equality_facts, 0);
        assert_eq!(telemetry.root_equality_unions, 0);
        assert_eq!(telemetry.congruence_unions, 0);
        assert_eq!(telemetry.root_union_dag, telemetry.generic_source_dag);
        assert_eq!(telemetry.full_euf_dag, telemetry.generic_source_dag);
    }

    #[test]
    fn typed_congruence_keeps_mixed_sorts_separate() {
        let telemetry = parsed_ablation(
            "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-sort V 0)
            (declare-fun a () U)
            (declare-fun b () U)
            (declare-fun x () V)
            (declare-fun y () V)
            (declare-fun f (U) U)
            (declare-fun g (V) V)
            (declare-fun p () Bool)
            (assert (= a b))
            (assert (= x y))
            (assert (or (= (f a) a) p))
            (assert (or (= (f b) a) p))
            (assert (or (= (g x) x) p))
            (assert (or (= (g y) x) p))
            (check-sat)
            ",
        );

        assert_eq!(telemetry.root_equality_unions, 2);
        assert_eq!(telemetry.congruence_unions, 2);
        assert_eq!(telemetry.root_union_dag.gate_definitions, 4);
        assert_eq!(telemetry.full_euf_dag.gate_definitions, 2);
    }

    #[test]
    fn four_way_projection_retains_bool_as_data_atoms() {
        let telemetry = parsed_ablation(
            "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun p () Bool)
            (declare-fun q () Bool)
            (declare-fun r () Bool)
            (declare-fun f (Bool) U)
            (assert (distinct (f p) (f q) (f r)))
            (check-sat)
            ",
        );

        assert_eq!(telemetry.boolean_data_roots, 3);
        for projection in [
            telemetry.tree_no_sharing,
            telemetry.generic_source_dag,
            telemetry.root_union_dag,
            telemetry.full_euf_dag,
        ] {
            assert_eq!(projection.boolean_data_roots, 3);
            assert_eq!(projection.cnf.atom_variables, 6);
        }
    }

    #[test]
    fn four_way_ablation_caps_fail_without_a_partial_projection() {
        let problem = parse_problem(
            "
            (set-logic QF_UF)
            (declare-fun p () Bool)
            (declare-fun q () Bool)
            (assert (and p q))
            (check-sat)
            ",
        )
        .unwrap();
        let limits = AblationLimits {
            max_syntax_occurrences: 2,
            ..AblationLimits::default()
        };
        let error = analyze_four_way_ablation_with_limits(
            problem.bool_problem.as_ref().unwrap(),
            &problem.arena,
            limits,
        )
        .unwrap_err();

        assert_eq!(error.reason, AblationAbstentionReason::SyntaxOccurrenceCap);
        assert_eq!(error.observed, 3);
        assert_eq!(error.limit, Some(2));
        assert_eq!(error.reason.as_str(), "syntax_occurrence_cap");
    }
}
