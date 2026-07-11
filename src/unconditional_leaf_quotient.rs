use crate::{BoolAtomKey, BoolExpr, HashMap, HashSet, TermId, normalized_pair};
use std::rc::Rc;

pub(crate) const ENV: &str = "EUF_VIPER_UNCONDITIONAL_QUOTIENT";

const DEFAULT_MAX_TERMS: usize = 1_000_000;
const DEFAULT_MAX_SUPPORTING_FACTS: usize = 65_536;
const DEFAULT_MAX_SYNTAX_OCCURRENCES: usize = 5_000_000;
const DEFAULT_MAX_EQUALITY_FACTS: usize = 1_000_000;
const DEFAULT_MAX_CANONICAL_NODES: usize = 2_000_000;
const DEFAULT_MAX_CANONICAL_EDGES: usize = 10_000_000;

pub(crate) const AUTO_REDUCTION_THRESHOLD: usize = 1_000;
// Frozen minima for the pre-registered census population; exact reduction is still the final gate.
const AUTO_MIN_UNCONDITIONAL_FACTS: usize = 696;
const AUTO_MIN_EFFECTIVE_UNIONS: usize = 522;
const AUTO_MIN_QUOTIENTED_TERMS: usize = 788;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    Off,
    Shadow,
    On,
    Auto,
}

impl Mode {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Shadow => "shadow",
            Self::On => "on",
            Self::Auto => "auto",
        }
    }
}

pub(crate) fn parse_mode(value: Option<&str>) -> Result<Mode, String> {
    match value {
        None | Some("off") => Ok(Mode::Off),
        Some("shadow") => Ok(Mode::Shadow),
        Some("on") => Ok(Mode::On),
        Some("auto") => Ok(Mode::Auto),
        Some(_) => Err(format!("{ENV} must be off, shadow, on, or auto")),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BuildFailure {
    TermLimit,
    SupportingFactLimit,
    InvalidTerm,
}

impl BuildFailure {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::TermLimit => "term_limit",
            Self::SupportingFactLimit => "supporting_fact_limit",
            Self::InvalidTerm => "invalid_term",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AutoRejection {
    Plan(BuildFailure),
    EqualityFactLimit,
    InvalidDataTerm,
    PrefilterFacts,
    PrefilterEffectiveUnions,
    PrefilterQuotientedTerms,
    SyntaxOccurrenceLimit,
    RawNodeLimit,
    RawEdgeLimit,
    ProjectedNodeLimit,
    ProjectedEdgeLimit,
    ArithmeticOverflow,
    InconsistentProjection,
    BelowThreshold,
}

impl AutoRejection {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Plan(failure) => failure.as_str(),
            Self::EqualityFactLimit => "equality_fact_limit",
            Self::InvalidDataTerm => "invalid_data_term",
            Self::PrefilterFacts => "prefilter_facts",
            Self::PrefilterEffectiveUnions => "prefilter_effective_unions",
            Self::PrefilterQuotientedTerms => "prefilter_quotiented_terms",
            Self::SyntaxOccurrenceLimit => "syntax_occurrence_limit",
            Self::RawNodeLimit => "raw_node_limit",
            Self::RawEdgeLimit => "raw_edge_limit",
            Self::ProjectedNodeLimit => "projected_node_limit",
            Self::ProjectedEdgeLimit => "projected_edge_limit",
            Self::ArithmeticOverflow => "arithmetic_overflow",
            Self::InconsistentProjection => "inconsistent_projection",
            Self::BelowThreshold => "below_threshold",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct AutoTelemetry {
    pub(crate) unconditional_equality_facts: usize,
    pub(crate) unique_supporting_facts: usize,
    pub(crate) effective_equality_unions: usize,
    pub(crate) projected_terms: usize,
    pub(crate) quotiented_terms: usize,
    pub(crate) raw_unique_nodes: Option<usize>,
    pub(crate) projected_unique_nodes: Option<usize>,
    pub(crate) reduction: Option<usize>,
    pub(crate) admitted: bool,
    pub(crate) rejection: Option<AutoRejection>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AutoOutcome {
    plan: Option<Plan>,
    pub(crate) telemetry: AutoTelemetry,
}

impl AutoOutcome {
    pub(crate) fn into_parts(self) -> (Option<Plan>, AutoTelemetry) {
        (self.plan, self.telemetry)
    }
}

#[derive(Debug, Clone, Copy)]
struct Limits {
    max_terms: usize,
    max_supporting_facts: usize,
}

#[derive(Debug, Clone, Copy)]
struct AutoLimits {
    max_syntax_occurrences: usize,
    max_equality_facts: usize,
    max_canonical_nodes: usize,
    max_canonical_edges: usize,
}

impl Default for AutoLimits {
    fn default() -> Self {
        Self {
            max_syntax_occurrences: DEFAULT_MAX_SYNTAX_OCCURRENCES,
            max_equality_facts: DEFAULT_MAX_EQUALITY_FACTS,
            max_canonical_nodes: DEFAULT_MAX_CANONICAL_NODES,
            max_canonical_edges: DEFAULT_MAX_CANONICAL_EDGES,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct AutoConfig {
    min_unconditional_facts: usize,
    min_effective_unions: usize,
    min_quotiented_terms: usize,
    reduction_threshold: usize,
    limits: AutoLimits,
}

impl Default for AutoConfig {
    fn default() -> Self {
        Self {
            min_unconditional_facts: AUTO_MIN_UNCONDITIONAL_FACTS,
            min_effective_unions: AUTO_MIN_EFFECTIVE_UNIONS,
            min_quotiented_terms: AUTO_MIN_QUOTIENTED_TERMS,
            reduction_threshold: AUTO_REDUCTION_THRESHOLD,
            limits: AutoLimits::default(),
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_terms: DEFAULT_MAX_TERMS,
            max_supporting_facts: DEFAULT_MAX_SUPPORTING_FACTS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Plan {
    representatives: Vec<TermId>,
    supporting_facts: HashSet<(TermId, TermId)>,
    projected_terms: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProjectedLeaf {
    Const(bool),
    Atom(BoolAtomKey),
}

impl Plan {
    pub(crate) fn build(assertions: &[BoolExpr], term_count: usize) -> Result<Self, BuildFailure> {
        Self::build_with_limits(assertions, term_count, Limits::default())
    }

    pub(crate) fn build_auto(
        assertions: &[BoolExpr],
        data_terms: &[TermId],
        term_count: usize,
    ) -> AutoOutcome {
        Self::build_auto_with_config(assertions, data_terms, term_count, AutoConfig::default())
    }

    fn build_auto_with_config(
        assertions: &[BoolExpr],
        data_terms: &[TermId],
        term_count: usize,
        config: AutoConfig,
    ) -> AutoOutcome {
        let mut telemetry = AutoTelemetry::default();
        telemetry.unconditional_equality_facts = match count_unconditional_equality_facts(
            assertions,
            config.limits.max_equality_facts,
        ) {
            Ok(facts) => facts,
            Err(rejection) => {
                telemetry.rejection = Some(rejection);
                return AutoOutcome {
                    plan: None,
                    telemetry,
                };
            }
        };
        if telemetry.unconditional_equality_facts < config.min_unconditional_facts {
            telemetry.rejection = Some(AutoRejection::PrefilterFacts);
            return AutoOutcome {
                plan: None,
                telemetry,
            };
        }

        let plan = match Self::build(assertions, term_count) {
            Ok(plan) => plan,
            Err(failure) => {
                telemetry.rejection = Some(AutoRejection::Plan(failure));
                return AutoOutcome {
                    plan: None,
                    telemetry,
                };
            }
        };

        telemetry.unique_supporting_facts = plan.supporting_fact_count();
        telemetry.effective_equality_unions = plan.projected_term_count();
        telemetry.projected_terms = plan.projected_term_count();
        telemetry.quotiented_terms = plan.quotiented_term_count();

        if data_terms.iter().any(|&term| term >= term_count) {
            telemetry.rejection = Some(AutoRejection::InvalidDataTerm);
            return AutoOutcome {
                plan: None,
                telemetry,
            };
        }

        let prefilter_rejection =
            if telemetry.effective_equality_unions < config.min_effective_unions {
                Some(AutoRejection::PrefilterEffectiveUnions)
            } else if telemetry.quotiented_terms < config.min_quotiented_terms {
                Some(AutoRejection::PrefilterQuotientedTerms)
            } else {
                None
            };
        if let Some(rejection) = prefilter_rejection {
            telemetry.rejection = Some(rejection);
            return AutoOutcome {
                plan: None,
                telemetry,
            };
        }

        let (raw_unique_nodes, projected_unique_nodes) =
            match canonical_unique_nodes(assertions, data_terms, &plan, config.limits) {
                Ok(counts) => counts,
                Err(rejection) => {
                    telemetry.rejection = Some(rejection);
                    return AutoOutcome {
                        plan: None,
                        telemetry,
                    };
                }
            };
        telemetry.raw_unique_nodes = Some(raw_unique_nodes);
        telemetry.projected_unique_nodes = Some(projected_unique_nodes);
        let Some(reduction) = raw_unique_nodes.checked_sub(projected_unique_nodes) else {
            telemetry.rejection = Some(AutoRejection::InconsistentProjection);
            return AutoOutcome {
                plan: None,
                telemetry,
            };
        };
        telemetry.reduction = Some(reduction);

        if reduction < config.reduction_threshold {
            telemetry.rejection = Some(AutoRejection::BelowThreshold);
            return AutoOutcome {
                plan: None,
                telemetry,
            };
        }

        telemetry.admitted = true;
        AutoOutcome {
            plan: Some(plan),
            telemetry,
        }
    }

    fn build_with_limits(
        assertions: &[BoolExpr],
        term_count: usize,
        limits: Limits,
    ) -> Result<Self, BuildFailure> {
        if term_count > limits.max_terms {
            return Err(BuildFailure::TermLimit);
        }
        for assertion in assertions {
            validate_terms(assertion, term_count)?;
        }

        let mut supporting_facts = HashSet::default();
        for assertion in assertions {
            collect_root_equalities(
                assertion,
                &mut supporting_facts,
                limits.max_supporting_facts,
            )?;
        }

        if supporting_facts.iter().all(|(left, right)| left == right) {
            return Ok(Self {
                representatives: Vec::new(),
                supporting_facts,
                projected_terms: 0,
            });
        }

        let mut representatives = (0..term_count).collect::<Vec<_>>();
        let mut facts = supporting_facts.iter().copied().collect::<Vec<_>>();
        facts.sort_unstable();
        for (left, right) in facts {
            union_minimum(&mut representatives, left, right);
        }
        for term in 0..term_count {
            representatives[term] = find(&mut representatives, term);
        }
        let projected_terms = representatives
            .iter()
            .enumerate()
            .filter(|&(term, representative)| term != *representative)
            .count();

        Ok(Self {
            representatives,
            supporting_facts,
            projected_terms,
        })
    }

    pub(crate) fn project(&self, atom: &BoolAtomKey) -> ProjectedLeaf {
        if self.representatives.is_empty() {
            return ProjectedLeaf::Atom(atom.clone());
        }
        match *atom {
            BoolAtomKey::Eq(left, right) => {
                let raw = normalized_pair(left, right);
                if self.supporting_facts.contains(&raw) {
                    return ProjectedLeaf::Atom(BoolAtomKey::Eq(raw.0, raw.1));
                }
                let left = self.representatives[left];
                let right = self.representatives[right];
                if left == right {
                    ProjectedLeaf::Const(true)
                } else {
                    let (left, right) = normalized_pair(left, right);
                    ProjectedLeaf::Atom(BoolAtomKey::Eq(left, right))
                }
            }
            BoolAtomKey::BoolTerm(term) => {
                ProjectedLeaf::Atom(BoolAtomKey::BoolTerm(self.representatives[term]))
            }
        }
    }

    pub(crate) fn supporting_fact_count(&self) -> usize {
        self.supporting_facts.len()
    }

    pub(crate) fn projected_term_count(&self) -> usize {
        self.projected_terms
    }

    fn quotiented_term_count(&self) -> usize {
        if self.representatives.is_empty() {
            return 0;
        }
        let mut nontrivial_representatives = HashSet::default();
        for (term, &representative) in self.representatives.iter().enumerate() {
            if term != representative {
                nontrivial_representatives.insert(representative);
            }
        }
        self.projected_terms + nontrivial_representatives.len()
    }

    fn representative(&self, term: TermId) -> TermId {
        if self.representatives.is_empty() {
            term
        } else {
            self.representatives[term]
        }
    }

    pub(crate) fn is_effective(&self) -> bool {
        self.projected_terms != 0
    }
}

fn validate_terms(expr: &BoolExpr, term_count: usize) -> Result<(), BuildFailure> {
    match expr {
        BoolExpr::Const(_) => Ok(()),
        BoolExpr::Atom(BoolAtomKey::Eq(left, right)) => {
            if *left < term_count && *right < term_count {
                Ok(())
            } else {
                Err(BuildFailure::InvalidTerm)
            }
        }
        BoolExpr::Atom(BoolAtomKey::BoolTerm(term)) => {
            if *term < term_count {
                Ok(())
            } else {
                Err(BuildFailure::InvalidTerm)
            }
        }
        BoolExpr::Not(child) => validate_terms(child, term_count),
        BoolExpr::And(children) | BoolExpr::Or(children) | BoolExpr::Iff(children) => {
            for child in children {
                validate_terms(child, term_count)?;
            }
            Ok(())
        }
        BoolExpr::Ite(condition, then_expr, else_expr) => {
            validate_terms(condition, term_count)?;
            validate_terms(then_expr, term_count)?;
            validate_terms(else_expr, term_count)
        }
    }
}

fn collect_root_equalities(
    expr: &BoolExpr,
    facts: &mut HashSet<(TermId, TermId)>,
    max_facts: usize,
) -> Result<(), BuildFailure> {
    match expr {
        BoolExpr::Atom(BoolAtomKey::Eq(left, right)) => {
            let fact = normalized_pair(*left, *right);
            if !facts.contains(&fact) && facts.len() == max_facts {
                return Err(BuildFailure::SupportingFactLimit);
            }
            facts.insert(fact);
        }
        BoolExpr::And(children) => {
            for child in children {
                collect_root_equalities(child, facts, max_facts)?;
            }
        }
        BoolExpr::Const(_)
        | BoolExpr::Atom(BoolAtomKey::BoolTerm(_))
        | BoolExpr::Not(_)
        | BoolExpr::Or(_)
        | BoolExpr::Iff(_)
        | BoolExpr::Ite(_, _, _) => {}
    }
    Ok(())
}

fn count_unconditional_equality_facts(
    assertions: &[BoolExpr],
    max_facts: usize,
) -> Result<usize, AutoRejection> {
    let mut facts = 0usize;
    let mut stack = assertions.iter().rev().collect::<Vec<_>>();
    while let Some(expression) = stack.pop() {
        match expression {
            BoolExpr::And(children) => stack.extend(children.iter().rev()),
            BoolExpr::Atom(BoolAtomKey::Eq(_, _)) => {
                facts = facts
                    .checked_add(1)
                    .ok_or(AutoRejection::ArithmeticOverflow)?;
                if facts > max_facts {
                    return Err(AutoRejection::EqualityFactLimit);
                }
            }
            BoolExpr::Const(_)
            | BoolExpr::Atom(BoolAtomKey::BoolTerm(_))
            | BoolExpr::Not(_)
            | BoolExpr::Or(_)
            | BoolExpr::Iff(_)
            | BoolExpr::Ite(_, _, _) => {}
        }
    }
    Ok(facts)
}

type NodeId = usize;

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

#[derive(Debug, Clone, Copy)]
enum ProjectionKind {
    Raw,
    Projected,
}

impl ProjectionKind {
    fn node_limit(self) -> AutoRejection {
        match self {
            Self::Raw => AutoRejection::RawNodeLimit,
            Self::Projected => AutoRejection::ProjectedNodeLimit,
        }
    }

    fn edge_limit(self) -> AutoRejection {
        match self {
            Self::Raw => AutoRejection::RawEdgeLimit,
            Self::Projected => AutoRejection::ProjectedEdgeLimit,
        }
    }
}

struct CanonicalInterner {
    nodes: Vec<Rc<CanonicalNode>>,
    ids: HashMap<Rc<CanonicalNode>, NodeId>,
    stored_edges: usize,
    limits: AutoLimits,
    kind: ProjectionKind,
}

impl CanonicalInterner {
    fn new(limits: AutoLimits, kind: ProjectionKind) -> Self {
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

    fn intern(&mut self, node: CanonicalNode) -> Result<NodeId, AutoRejection> {
        if let Some(&id) = self.ids.get(&node) {
            return Ok(id);
        }

        let next_nodes = self
            .nodes
            .len()
            .checked_add(1)
            .ok_or(AutoRejection::ArithmeticOverflow)?;
        if next_nodes > self.limits.max_canonical_nodes {
            return Err(self.kind.node_limit());
        }
        let next_edges = self
            .stored_edges
            .checked_add(node.children().len())
            .ok_or(AutoRejection::ArithmeticOverflow)?;
        if next_edges > self.limits.max_canonical_edges {
            return Err(self.kind.edge_limit());
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
    ) -> Result<Vec<NodeId>, AutoRejection> {
        let mut flattened_len = 0usize;
        for &child in children {
            let contribution = match (and, self.node(child)) {
                (true, CanonicalNode::And(nested)) | (false, CanonicalNode::Or(nested)) => {
                    nested.len()
                }
                _ => 1,
            };
            flattened_len = flattened_len
                .checked_add(contribution)
                .ok_or(AutoRejection::ArithmeticOverflow)?;
            if flattened_len > self.limits.max_canonical_edges {
                return Err(self.kind.edge_limit());
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
        plan: Option<&Plan>,
    ) -> Result<CanonicalNode, AutoRejection> {
        let map_term = |term: TermId| plan.map_or(term, |plan| plan.representative(term));
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

    fn reachable_unique_nodes(&self, roots: &[NodeId]) -> usize {
        let mut reachable = HashSet::default();
        let mut stack = roots.to_vec();
        while let Some(node_id) = stack.pop() {
            if !reachable.insert(node_id) {
                continue;
            }
            stack.extend_from_slice(self.node(node_id).children());
        }
        reachable.len()
    }
}

fn canonical_unique_nodes(
    assertions: &[BoolExpr],
    data_terms: &[TermId],
    plan: &Plan,
    limits: AutoLimits,
) -> Result<(usize, usize), AutoRejection> {
    let syntax_nodes = scan_syntax(assertions, limits.max_syntax_occurrences)?;
    let mut raw = CanonicalInterner::new(limits, ProjectionKind::Raw);
    let mut projected = CanonicalInterner::new(limits, ProjectionKind::Projected);
    let mut node_ids = HashMap::<usize, (NodeId, NodeId)>::default();

    for &expression in syntax_nodes.iter().rev() {
        let child_count = expression_child_count(expression);
        let mut raw_children = Vec::with_capacity(child_count);
        let mut projected_children = Vec::with_capacity(child_count);
        append_expression_child_ids(
            expression,
            &node_ids,
            &mut raw_children,
            &mut projected_children,
        );

        let raw_node = raw.expression_node(expression, &raw_children, None)?;
        let raw_id = raw.intern(raw_node)?;
        let projected_node =
            projected.expression_node(expression, &projected_children, Some(plan))?;
        let projected_id = projected.intern(projected_node)?;
        node_ids.insert(expression_address(expression), (raw_id, projected_id));
    }

    let mut sorted_data_terms = data_terms.to_vec();
    sorted_data_terms.sort_unstable();
    sorted_data_terms.dedup();
    let mut raw_roots = Vec::with_capacity(assertions.len() + sorted_data_terms.len());
    let mut projected_roots = Vec::with_capacity(assertions.len() + sorted_data_terms.len());
    for assertion in assertions {
        let ids = node_ids[&expression_address(assertion)];
        raw_roots.push(ids.0);
        projected_roots.push(ids.1);
    }
    for term in sorted_data_terms {
        raw_roots.push(raw.intern(CanonicalNode::BoolTerm(term))?);
        projected_roots.push(projected.intern(CanonicalNode::BoolTerm(plan.representative(term)))?);
    }

    Ok((
        raw.reachable_unique_nodes(&raw_roots),
        projected.reachable_unique_nodes(&projected_roots),
    ))
}

fn scan_syntax(
    assertions: &[BoolExpr],
    max_syntax_occurrences: usize,
) -> Result<Vec<&BoolExpr>, AutoRejection> {
    let mut nodes = Vec::new();
    let mut stack = assertions.iter().rev().collect::<Vec<_>>();
    while let Some(expression) = stack.pop() {
        let next_occurrences = nodes
            .len()
            .checked_add(1)
            .ok_or(AutoRejection::ArithmeticOverflow)?;
        if next_occurrences > max_syntax_occurrences {
            return Err(AutoRejection::SyntaxOccurrenceLimit);
        }
        nodes.push(expression);
        push_expression_children(expression, &mut stack);
    }
    Ok(nodes)
}

fn push_expression_children<'a>(expression: &'a BoolExpr, stack: &mut Vec<&'a BoolExpr>) {
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
    raw: &mut Vec<NodeId>,
    projected: &mut Vec<NodeId>,
) {
    let mut append = |child: &BoolExpr| {
        let ids = node_ids[&expression_address(child)];
        raw.push(ids.0);
        projected.push(ids.1);
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

fn find(parent: &mut [TermId], mut term: TermId) -> TermId {
    while parent[term] != term {
        parent[term] = parent[parent[term]];
        term = parent[term];
    }
    term
}

fn union_minimum(parent: &mut [TermId], left: TermId, right: TermId) {
    let left = find(parent, left);
    let right = find(parent, right);
    if left != right {
        let minimum = left.min(right);
        let maximum = left.max(right);
        parent[maximum] = minimum;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eq(left: TermId, right: TermId) -> BoolExpr {
        BoolExpr::Atom(BoolAtomKey::Eq(left, right))
    }

    fn bool_atom(term: TermId) -> BoolExpr {
        BoolExpr::Atom(BoolAtomKey::BoolTerm(term))
    }

    fn generated_disjoint_pairs(pair_count: usize) -> (Vec<BoolExpr>, Vec<TermId>) {
        let assertions = (0..pair_count)
            .map(|pair| eq(2 * pair, 2 * pair + 1))
            .collect();
        let data_terms = (0..2 * pair_count).collect();
        (assertions, data_terms)
    }

    #[test]
    fn mode_is_strict_and_defaults_off() {
        assert_eq!(parse_mode(None), Ok(Mode::Off));
        assert_eq!(parse_mode(Some("off")), Ok(Mode::Off));
        assert_eq!(parse_mode(Some("shadow")), Ok(Mode::Shadow));
        assert_eq!(parse_mode(Some("on")), Ok(Mode::On));
        assert_eq!(parse_mode(Some("auto")), Ok(Mode::Auto));
        for invalid in ["", "0", "1", "true", "ON", " on"] {
            assert!(parse_mode(Some(invalid)).is_err());
        }
    }

    #[test]
    fn extracts_only_roots_and_recursive_root_ands() {
        let assertions = vec![
            BoolExpr::And(vec![
                eq(5, 4),
                BoolExpr::And(vec![eq(4, 3)]),
                BoolExpr::Not(Box::new(eq(3, 2))),
                BoolExpr::Or(vec![eq(3, 1)]),
                BoolExpr::Iff(vec![eq(3, 0), BoolExpr::Const(true)]),
                BoolExpr::Ite(
                    Box::new(eq(2, 1)),
                    Box::new(eq(2, 0)),
                    Box::new(BoolExpr::Const(true)),
                ),
            ]),
            eq(7, 6),
        ];
        let plan = Plan::build(&assertions, 8).unwrap();

        assert_eq!(plan.supporting_fact_count(), 3);
        assert_eq!(
            plan.project(&BoolAtomKey::Eq(5, 3)),
            ProjectedLeaf::Const(true)
        );
        assert_eq!(
            plan.project(&BoolAtomKey::Eq(3, 2)),
            ProjectedLeaf::Atom(BoolAtomKey::Eq(2, 3))
        );
        assert_eq!(
            plan.project(&BoolAtomKey::Eq(6, 7)),
            ProjectedLeaf::Atom(BoolAtomKey::Eq(6, 7))
        );
    }

    #[test]
    fn transitive_classes_use_deterministic_minimum_representatives() {
        let plan = Plan::build(&[eq(7, 5), eq(3, 7), eq(5, 4)], 8).unwrap();

        assert_eq!(plan.projected_term_count(), 3);
        assert_eq!(
            plan.project(&BoolAtomKey::BoolTerm(7)),
            ProjectedLeaf::Atom(BoolAtomKey::BoolTerm(3))
        );
        assert_eq!(
            plan.project(&BoolAtomKey::Eq(4, 7)),
            ProjectedLeaf::Const(true)
        );
    }

    #[test]
    fn invalid_or_capped_builds_fail_atomically() {
        let tiny = Limits {
            max_terms: 3,
            max_supporting_facts: 1,
        };
        assert_eq!(
            Plan::build_with_limits(&[eq(0, 1)], 4, tiny),
            Err(BuildFailure::TermLimit)
        );
        assert_eq!(
            Plan::build_with_limits(&[eq(0, 1), eq(1, 2)], 3, tiny),
            Err(BuildFailure::SupportingFactLimit)
        );
        assert_eq!(
            Plan::build_with_limits(&[BoolExpr::Not(Box::new(eq(0, 3)))], 3, tiny),
            Err(BuildFailure::InvalidTerm)
        );
    }

    #[test]
    fn formulas_without_effective_supporting_facts_have_no_identity_map() {
        let atom = BoolAtomKey::BoolTerm(2);
        let plan = Plan::build(&[eq(1, 1), BoolExpr::Not(Box::new(eq(0, 1)))], 3).unwrap();

        assert!(!plan.is_effective());
        assert!(plan.representatives.is_empty());
        assert_eq!(plan.supporting_fact_count(), 1);
        assert_eq!(plan.project(&atom), ProjectedLeaf::Atom(atom));
    }

    #[test]
    fn canonical_counts_match_frozen_boolean_dag_semantics() {
        let p = 0;
        let q = 1;
        let r = 2;
        let data_only = 3;
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
            BoolExpr::Const(true),
            BoolExpr::Const(false),
        ];
        let outcome = Plan::build_auto_with_config(
            &assertions,
            &[data_only, p, data_only],
            4,
            AutoConfig {
                min_unconditional_facts: 0,
                min_effective_unions: 0,
                min_quotiented_terms: 0,
                reduction_threshold: 1,
                limits: AutoLimits::default(),
            },
        );

        assert_eq!(outcome.telemetry.raw_unique_nodes, Some(12));
        assert_eq!(outcome.telemetry.projected_unique_nodes, Some(12));
        assert_eq!(outcome.telemetry.reduction, Some(0));
        assert_eq!(
            outcome.telemetry.rejection,
            Some(AutoRejection::BelowThreshold)
        );
        assert!(outcome.plan.is_none());
    }

    #[test]
    fn exact_auto_threshold_rejects_999_and_admits_1000() {
        let (assertions_999, data_terms_999) = generated_disjoint_pairs(999);
        let rejected = Plan::build_auto(&assertions_999, &data_terms_999, 1_998);
        assert_eq!(rejected.telemetry.unconditional_equality_facts, 999);
        assert_eq!(rejected.telemetry.effective_equality_unions, 999);
        assert_eq!(rejected.telemetry.quotiented_terms, 1_998);
        assert_eq!(rejected.telemetry.raw_unique_nodes, Some(2_997));
        assert_eq!(rejected.telemetry.projected_unique_nodes, Some(1_998));
        assert_eq!(rejected.telemetry.reduction, Some(999));
        assert_eq!(
            rejected.telemetry.rejection,
            Some(AutoRejection::BelowThreshold)
        );
        assert!(!rejected.telemetry.admitted);
        assert!(rejected.plan.is_none());

        let (assertions_1000, data_terms_1000) = generated_disjoint_pairs(1_000);
        let admitted = Plan::build_auto(&assertions_1000, &data_terms_1000, 2_000);
        assert_eq!(admitted.telemetry.unconditional_equality_facts, 1_000);
        assert_eq!(admitted.telemetry.effective_equality_unions, 1_000);
        assert_eq!(admitted.telemetry.quotiented_terms, 2_000);
        assert_eq!(admitted.telemetry.raw_unique_nodes, Some(3_000));
        assert_eq!(admitted.telemetry.projected_unique_nodes, Some(2_000));
        assert_eq!(admitted.telemetry.reduction, Some(AUTO_REDUCTION_THRESHOLD));
        assert_eq!(admitted.telemetry.rejection, None);
        assert!(admitted.telemetry.admitted);
        assert!(admitted.plan.is_some());
    }

    #[test]
    fn auto_prefilter_rejects_each_frozen_structural_gate_before_canonicalization() {
        let (facts_assertions, facts_data_terms) = generated_disjoint_pairs(695);
        let facts = Plan::build_auto(&facts_assertions, &facts_data_terms, 1_390);
        assert_eq!(
            facts.telemetry.rejection,
            Some(AutoRejection::PrefilterFacts)
        );

        let (mut union_assertions, union_data_terms) = generated_disjoint_pairs(521);
        union_assertions.extend(std::iter::repeat_n(eq(0, 1), 175));
        let unions = Plan::build_auto(&union_assertions, &union_data_terms, 1_042);
        assert_eq!(unions.telemetry.unconditional_equality_facts, 696);
        assert_eq!(unions.telemetry.effective_equality_unions, 521);
        assert_eq!(
            unions.telemetry.rejection,
            Some(AutoRejection::PrefilterEffectiveUnions)
        );

        let mut quotiented_assertions = (0..522).map(|term| eq(term, term + 1)).collect::<Vec<_>>();
        quotiented_assertions.extend(std::iter::repeat_n(eq(0, 1), 174));
        let quotiented =
            Plan::build_auto(&quotiented_assertions, &(0..523).collect::<Vec<_>>(), 523);
        assert_eq!(quotiented.telemetry.unconditional_equality_facts, 696);
        assert_eq!(quotiented.telemetry.effective_equality_unions, 522);
        assert_eq!(quotiented.telemetry.quotiented_terms, 523);
        assert_eq!(
            quotiented.telemetry.rejection,
            Some(AutoRejection::PrefilterQuotientedTerms)
        );

        for outcome in [facts, unions, quotiented] {
            assert_eq!(outcome.telemetry.raw_unique_nodes, None);
            assert_eq!(outcome.telemetry.projected_unique_nodes, None);
            assert_eq!(outcome.telemetry.reduction, None);
            assert!(!outcome.telemetry.admitted);
            assert!(outcome.plan.is_none());
        }
    }

    #[test]
    fn fact_prefilter_runs_before_plan_allocation() {
        let outcome = Plan::build_auto(&[], &[], DEFAULT_MAX_TERMS + 1);

        assert_eq!(outcome.telemetry.unconditional_equality_facts, 0);
        assert_eq!(
            outcome.telemetry.rejection,
            Some(AutoRejection::PrefilterFacts)
        );
        assert!(outcome.plan.is_none());
    }

    #[test]
    fn canonical_caps_reject_auto_without_returning_a_partial_plan() {
        let outcome = Plan::build_auto_with_config(
            &[bool_atom(0)],
            &[],
            1,
            AutoConfig {
                min_unconditional_facts: 0,
                min_effective_unions: 0,
                min_quotiented_terms: 0,
                reduction_threshold: 0,
                limits: AutoLimits {
                    max_canonical_nodes: 0,
                    ..AutoLimits::default()
                },
            },
        );

        assert_eq!(
            outcome.telemetry.rejection,
            Some(AutoRejection::RawNodeLimit)
        );
        assert!(!outcome.telemetry.admitted);
        assert!(outcome.plan.is_none());
    }
}
