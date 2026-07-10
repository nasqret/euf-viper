use super::{BoolAtomKey, BoolExpr, TermId};
use rustc_hash::FxHashMap as HashMap;
use std::rc::Rc;

const DEFAULT_MAX_WORK: usize = 2_000_000;
const DEFAULT_MAX_ENTRIES: usize = 100_000;
const DEFAULT_MAX_STAR_EDGES: usize = 100_000;

#[derive(Debug, Clone, Copy)]
pub(super) struct Limits {
    max_work: usize,
    max_entries: usize,
    max_star_edges: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_work: DEFAULT_MAX_WORK,
            max_entries: DEFAULT_MAX_ENTRIES,
            max_star_edges: DEFAULT_MAX_STAR_EDGES,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CapReason {
    Work,
    Entries,
    StarEdges,
    Arithmetic,
}

impl CapReason {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Work => "work",
            Self::Entries => "entries",
            Self::StarEdges => "star_edges",
            Self::Arithmetic => "arithmetic",
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub(super) struct Metrics {
    pub(super) nodes: usize,
    pub(super) memo_entries: usize,
    pub(super) memo_hits: usize,
    pub(super) work: usize,
    pub(super) classes: usize,
    pub(super) partition_terms: usize,
}

#[derive(Debug, Clone)]
pub(super) struct Outcome {
    pub(super) star_edges: Vec<(TermId, TermId)>,
    pub(super) infeasible: bool,
    pub(super) cap_reason: Option<CapReason>,
    pub(super) metrics: Metrics,
    #[cfg(test)]
    partition: Partition,
}

impl Outcome {
    fn capped(reason: CapReason, metrics: Metrics) -> Self {
        Self {
            star_edges: Vec::new(),
            infeasible: false,
            cap_reason: Some(reason),
            metrics,
            #[cfg(test)]
            partition: Partition::empty(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Partition {
    // Classes and their terms are sorted. Singleton classes are omitted.
    classes: Vec<Vec<TermId>>,
}

impl Partition {
    fn empty() -> Self {
        Self::default()
    }

    fn pair(left: TermId, right: TermId) -> Self {
        debug_assert_ne!(left, right);
        let (left, right) = if left < right {
            (left, right)
        } else {
            (right, left)
        };
        Self {
            classes: vec![vec![left, right]],
        }
    }

    fn from_classes(mut classes: Vec<Vec<TermId>>) -> Self {
        for class in &mut classes {
            class.sort_unstable();
            class.dedup();
        }
        classes.retain(|class| class.len() >= 2);
        classes.sort_unstable();
        Self { classes }
    }

    fn is_empty(&self) -> bool {
        self.classes.is_empty()
    }

    fn term_count(&self) -> Result<usize, CapReason> {
        self.classes.iter().try_fold(0usize, |total, class| {
            total.checked_add(class.len()).ok_or(CapReason::Arithmetic)
        })
    }

    fn star_edges(
        &self,
        limit: usize,
        budget: &mut Budget,
    ) -> Result<Vec<(TermId, TermId)>, CapReason> {
        let edge_count = self.classes.iter().try_fold(0usize, |total, class| {
            total
                .checked_add(class.len().checked_sub(1).unwrap_or(0))
                .ok_or(CapReason::Arithmetic)
        })?;
        if edge_count > limit {
            return Err(CapReason::StarEdges);
        }
        budget.spend(edge_count)?;

        let mut edges = Vec::new();
        edges
            .try_reserve_exact(edge_count)
            .map_err(|_| CapReason::Entries)?;
        for class in &self.classes {
            let Some((&root, rest)) = class.split_first() else {
                continue;
            };
            edges.extend(rest.iter().map(|&term| (root, term)));
        }
        Ok(edges)
    }
}

#[derive(Debug, Clone)]
enum AbstractValue {
    Infeasible,
    Feasible(Rc<Partition>),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Node {
    Const(bool),
    Atom(BoolAtomKey),
    Not(NodeId),
    And(Vec<NodeId>),
    Or(Vec<NodeId>),
    Iff(Vec<NodeId>),
    Ite(NodeId, NodeId, NodeId),
}

type NodeId = usize;

#[derive(Debug)]
struct Budget {
    limit: usize,
    used: usize,
}

impl Budget {
    fn new(limit: usize) -> Self {
        Self { limit, used: 0 }
    }

    fn spend(&mut self, amount: usize) -> Result<(), CapReason> {
        let next = self.used.checked_add(amount).ok_or(CapReason::Arithmetic)?;
        if next > self.limit {
            return Err(CapReason::Work);
        }
        self.used = next;
        Ok(())
    }
}

fn ensure_entry_capacity(current: usize, additional: usize, limit: usize) -> Result<(), CapReason> {
    let next = current
        .checked_add(additional)
        .ok_or(CapReason::Arithmetic)?;
    if next > limit {
        Err(CapReason::Entries)
    } else {
        Ok(())
    }
}

fn expr_pointer(expr: &BoolExpr) -> usize {
    std::ptr::from_ref(expr) as usize
}

fn child_count(expr: &BoolExpr) -> usize {
    match expr {
        BoolExpr::Const(_) | BoolExpr::Atom(_) => 0,
        BoolExpr::Not(_) => 1,
        BoolExpr::And(children) | BoolExpr::Or(children) | BoolExpr::Iff(children) => {
            children.len()
        }
        BoolExpr::Ite(_, _, _) => 3,
    }
}

struct Interner {
    nodes: Vec<Node>,
    structural: HashMap<Node, NodeId>,
    pointer_ids: HashMap<usize, NodeId>,
    roots: Vec<NodeId>,
    max_entries: usize,
}

impl Interner {
    fn new(max_entries: usize) -> Self {
        Self {
            nodes: Vec::new(),
            structural: HashMap::default(),
            pointer_ids: HashMap::default(),
            roots: Vec::new(),
            max_entries,
        }
    }

    fn intern_assertions(
        &mut self,
        assertions: &[BoolExpr],
        budget: &mut Budget,
    ) -> Result<(), CapReason> {
        ensure_entry_capacity(0, assertions.len(), self.max_entries)?;
        for assertion in assertions {
            self.intern_root(assertion, budget)?;
            let id = self.pointer_ids[&expr_pointer(assertion)];
            self.roots.push(id);
        }
        Ok(())
    }

    fn intern_root(&mut self, root: &BoolExpr, budget: &mut Budget) -> Result<(), CapReason> {
        if self.pointer_ids.contains_key(&expr_pointer(root)) {
            return Ok(());
        }

        let mut stack = vec![(root, false)];
        while let Some((expr, expanded)) = stack.pop() {
            budget.spend(1)?;
            let pointer = expr_pointer(expr);
            if self.pointer_ids.contains_key(&pointer) {
                continue;
            }

            if !expanded {
                let count = child_count(expr);
                let frame_count = count.checked_add(1).ok_or(CapReason::Arithmetic)?;
                ensure_entry_capacity(stack.len(), frame_count, self.max_entries)?;
                budget.spend(frame_count)?;
                stack.push((expr, true));
                match expr {
                    BoolExpr::Const(_) | BoolExpr::Atom(_) => {}
                    BoolExpr::Not(child) => stack.push((child, false)),
                    BoolExpr::And(children) | BoolExpr::Or(children) | BoolExpr::Iff(children) => {
                        stack.extend(children.iter().rev().map(|child| (child, false)));
                    }
                    BoolExpr::Ite(cond, then_expr, else_expr) => {
                        stack.push((else_expr, false));
                        stack.push((then_expr, false));
                        stack.push((cond, false));
                    }
                }
                continue;
            }

            let node = self.node_for_expr(expr)?;
            let id = if let Some(&id) = self.structural.get(&node) {
                id
            } else {
                ensure_entry_capacity(self.nodes.len(), 1, self.max_entries)?;
                let id = self.nodes.len();
                self.nodes.push(node.clone());
                self.structural.insert(node, id);
                id
            };
            ensure_entry_capacity(self.pointer_ids.len(), 1, self.max_entries)?;
            self.pointer_ids.insert(pointer, id);
        }
        Ok(())
    }

    fn node_for_expr(&self, expr: &BoolExpr) -> Result<Node, CapReason> {
        let child_id = |child: &BoolExpr| {
            self.pointer_ids
                .get(&expr_pointer(child))
                .copied()
                .ok_or(CapReason::Arithmetic)
        };
        Ok(match expr {
            BoolExpr::Const(value) => Node::Const(*value),
            BoolExpr::Atom(BoolAtomKey::Eq(left, right)) => {
                let (left, right) = if left <= right {
                    (*left, *right)
                } else {
                    (*right, *left)
                };
                Node::Atom(BoolAtomKey::Eq(left, right))
            }
            BoolExpr::Atom(atom) => Node::Atom(atom.clone()),
            BoolExpr::Not(child) => Node::Not(child_id(child)?),
            BoolExpr::And(children) => Node::And(
                children
                    .iter()
                    .map(child_id)
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            BoolExpr::Or(children) => Node::Or(
                children
                    .iter()
                    .map(child_id)
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            BoolExpr::Iff(children) => Node::Iff(
                children
                    .iter()
                    .map(child_id)
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            BoolExpr::Ite(cond, then_expr, else_expr) => {
                Node::Ite(child_id(cond)?, child_id(then_expr)?, child_id(else_expr)?)
            }
        })
    }
}

#[derive(Default)]
struct ScratchDsu {
    indices: HashMap<TermId, usize>,
    terms: Vec<TermId>,
    parent: Vec<usize>,
}

impl ScratchDsu {
    fn reset(&mut self) {
        self.indices.clear();
        self.terms.clear();
        self.parent.clear();
    }

    fn ensure(
        &mut self,
        term: TermId,
        max_entries: usize,
        budget: &mut Budget,
    ) -> Result<usize, CapReason> {
        budget.spend(1)?;
        if let Some(&index) = self.indices.get(&term) {
            return Ok(index);
        }
        ensure_entry_capacity(self.terms.len(), 1, max_entries)?;
        let index = self.terms.len();
        self.indices.insert(term, index);
        self.terms.push(term);
        self.parent.push(index);
        Ok(index)
    }

    fn find(&mut self, index: usize, budget: &mut Budget) -> Result<usize, CapReason> {
        let mut root = index;
        while self.parent[root] != root {
            budget.spend(1)?;
            root = self.parent[root];
        }
        let mut current = index;
        while self.parent[current] != current {
            budget.spend(1)?;
            let next = self.parent[current];
            self.parent[current] = root;
            current = next;
        }
        Ok(root)
    }

    fn union(
        &mut self,
        left: TermId,
        right: TermId,
        max_entries: usize,
        budget: &mut Budget,
    ) -> Result<(), CapReason> {
        let left = self.ensure(left, max_entries, budget)?;
        let right = self.ensure(right, max_entries, budget)?;
        let left_root = self.find(left, budget)?;
        let right_root = self.find(right, budget)?;
        if left_root != right_root {
            budget.spend(1)?;
            let (root, child) = if self.terms[left_root] <= self.terms[right_root] {
                (left_root, right_root)
            } else {
                (right_root, left_root)
            };
            self.parent[child] = root;
        }
        Ok(())
    }

    fn partition(&mut self, budget: &mut Budget) -> Result<Partition, CapReason> {
        let mut groups: HashMap<usize, Vec<TermId>> = HashMap::default();
        for index in 0..self.terms.len() {
            budget.spend(1)?;
            let root = self.find(index, budget)?;
            groups.entry(root).or_default().push(self.terms[index]);
        }
        Ok(Partition::from_classes(groups.into_values().collect()))
    }
}

struct Evaluator {
    nodes: Vec<Node>,
    memo: Vec<Option<AbstractValue>>,
    memo_entries: usize,
    memo_hits: usize,
    empty: Rc<Partition>,
    scratch: ScratchDsu,
    limits: Limits,
    budget: Budget,
}

impl Evaluator {
    fn new(nodes: Vec<Node>, limits: Limits, budget: Budget) -> Result<Self, CapReason> {
        let memo_len = nodes.len().checked_mul(2).ok_or(CapReason::Arithmetic)?;
        if memo_len > limits.max_entries {
            return Err(CapReason::Entries);
        }
        Ok(Self {
            nodes,
            memo: vec![None; memo_len],
            memo_entries: 0,
            memo_hits: 0,
            empty: Rc::new(Partition::empty()),
            scratch: ScratchDsu::default(),
            limits,
            budget,
        })
    }

    fn slot(node: NodeId, polarity: bool) -> Result<usize, CapReason> {
        node.checked_mul(2)
            .and_then(|slot| slot.checked_add(usize::from(polarity)))
            .ok_or(CapReason::Arithmetic)
    }

    fn memo_value(&self, node: NodeId, polarity: bool) -> AbstractValue {
        self.memo[Self::slot(node, polarity).expect("interned node index")]
            .as_ref()
            .expect("evaluation dependency is memoized")
            .clone()
    }

    fn empty_value(&self) -> AbstractValue {
        AbstractValue::Feasible(Rc::clone(&self.empty))
    }

    fn evaluate(&mut self, root: NodeId, polarity: bool) -> Result<AbstractValue, CapReason> {
        let root_slot = Self::slot(root, polarity)?;
        if let Some(value) = &self.memo[root_slot] {
            self.memo_hits = self.memo_hits.checked_add(1).ok_or(CapReason::Arithmetic)?;
            return Ok(value.clone());
        }

        let mut stack = vec![(root, polarity, false)];
        while let Some((node, polarity, expanded)) = stack.pop() {
            self.budget.spend(1)?;
            let slot = Self::slot(node, polarity)?;
            if self.memo[slot].is_some() {
                self.memo_hits = self.memo_hits.checked_add(1).ok_or(CapReason::Arithmetic)?;
                continue;
            }

            if !expanded {
                let dependencies = self.dependencies(node, polarity)?;
                let frame_count = dependencies
                    .len()
                    .checked_add(1)
                    .ok_or(CapReason::Arithmetic)?;
                ensure_entry_capacity(stack.len(), frame_count, self.limits.max_entries)?;
                self.budget.spend(frame_count)?;
                stack.push((node, polarity, true));
                for &(dependency, dependency_polarity) in dependencies.iter().rev() {
                    let dependency_slot = Self::slot(dependency, dependency_polarity)?;
                    if self.memo[dependency_slot].is_none() {
                        stack.push((dependency, dependency_polarity, false));
                    } else {
                        self.memo_hits =
                            self.memo_hits.checked_add(1).ok_or(CapReason::Arithmetic)?;
                    }
                }
                continue;
            }

            let value = self.compute(node, polarity)?;
            self.memo[slot] = Some(value);
            self.memo_entries = self
                .memo_entries
                .checked_add(1)
                .ok_or(CapReason::Arithmetic)?;
        }

        Ok(self.memo[root_slot]
            .as_ref()
            .expect("root is memoized after evaluation")
            .clone())
    }

    fn dependencies(&self, node: NodeId, polarity: bool) -> Result<Vec<(NodeId, bool)>, CapReason> {
        let node = &self.nodes[node];
        let count = match node {
            Node::Const(_) | Node::Atom(_) => 0,
            Node::Not(_) => 1,
            Node::And(children) | Node::Or(children) => children.len(),
            Node::Iff(children) => children
                .len()
                .checked_sub(1)
                .unwrap_or(0)
                .checked_mul(4)
                .ok_or(CapReason::Arithmetic)?,
            Node::Ite(_, _, _) => 4,
        };
        ensure_entry_capacity(0, count, self.limits.max_entries)?;
        let mut dependencies = Vec::new();
        dependencies
            .try_reserve_exact(count)
            .map_err(|_| CapReason::Entries)?;
        match node {
            Node::Const(_) | Node::Atom(_) => {}
            Node::Not(child) => dependencies.push((*child, !polarity)),
            Node::And(children) | Node::Or(children) => {
                dependencies.extend(children.iter().map(|&child| (child, polarity)));
            }
            Node::Iff(children) => {
                if let Some((&first, rest)) = children.split_first() {
                    for &child in rest {
                        dependencies.extend([
                            (first, true),
                            (first, false),
                            (child, polarity),
                            (child, !polarity),
                        ]);
                    }
                }
            }
            Node::Ite(cond, then_expr, else_expr) => {
                dependencies.extend([
                    (*cond, true),
                    (*cond, false),
                    (*then_expr, polarity),
                    (*else_expr, polarity),
                ]);
            }
        }
        Ok(dependencies)
    }

    fn compute(&mut self, node: NodeId, polarity: bool) -> Result<AbstractValue, CapReason> {
        let descriptor = self.nodes[node].clone();
        match descriptor {
            Node::Const(value) => {
                if value == polarity {
                    Ok(self.empty_value())
                } else {
                    Ok(AbstractValue::Infeasible)
                }
            }
            Node::Atom(BoolAtomKey::Eq(left, right)) => {
                if left == right {
                    if polarity {
                        Ok(self.empty_value())
                    } else {
                        Ok(AbstractValue::Infeasible)
                    }
                } else if polarity {
                    Ok(AbstractValue::Feasible(Rc::new(Partition::pair(
                        left, right,
                    ))))
                } else {
                    Ok(self.empty_value())
                }
            }
            Node::Atom(BoolAtomKey::BoolTerm(_)) => Ok(self.empty_value()),
            Node::Not(child) => Ok(self.memo_value(child, !polarity)),
            Node::And(children) => {
                let values = children
                    .iter()
                    .map(|&child| self.memo_value(child, polarity))
                    .collect::<Vec<_>>();
                if polarity {
                    self.abstract_and(&values)
                } else {
                    self.abstract_or(&values)
                }
            }
            Node::Or(children) => {
                let values = children
                    .iter()
                    .map(|&child| self.memo_value(child, polarity))
                    .collect::<Vec<_>>();
                if polarity {
                    self.abstract_or(&values)
                } else {
                    self.abstract_and(&values)
                }
            }
            Node::Iff(children) => self.abstract_iff(&children, polarity),
            Node::Ite(cond, then_expr, else_expr) => {
                self.abstract_ite(cond, then_expr, else_expr, polarity)
            }
        }
    }

    // Yices calls closure of the union a meet in this abstract domain.
    fn abstract_and(&mut self, values: &[AbstractValue]) -> Result<AbstractValue, CapReason> {
        if values
            .iter()
            .any(|value| matches!(value, AbstractValue::Infeasible))
        {
            return Ok(AbstractValue::Infeasible);
        }
        let partitions = values
            .iter()
            .filter_map(|value| match value {
                AbstractValue::Feasible(partition) if !partition.is_empty() => {
                    Some(Rc::clone(partition))
                }
                AbstractValue::Feasible(_) | AbstractValue::Infeasible => None,
            })
            .collect::<Vec<_>>();
        match partitions.as_slice() {
            [] => Ok(self.empty_value()),
            [partition] => Ok(AbstractValue::Feasible(Rc::clone(partition))),
            _ => {
                let references = partitions.iter().map(Rc::as_ref).collect::<Vec<_>>();
                let partition = self.meet_partitions(&references)?;
                Ok(AbstractValue::Feasible(Rc::new(partition)))
            }
        }
    }

    // Yices calls relation intersection a join in this abstract domain.
    fn abstract_or(&mut self, values: &[AbstractValue]) -> Result<AbstractValue, CapReason> {
        let feasible = values
            .iter()
            .filter_map(|value| match value {
                AbstractValue::Infeasible => None,
                AbstractValue::Feasible(partition) => Some(Rc::clone(partition)),
            })
            .collect::<Vec<_>>();
        if feasible.is_empty() {
            return Ok(AbstractValue::Infeasible);
        }
        if feasible.iter().any(|partition| partition.is_empty()) {
            return Ok(self.empty_value());
        }
        let mut result = Rc::clone(&feasible[0]);
        for partition in &feasible[1..] {
            result = Rc::new(self.join_partitions(&result, partition)?);
            if result.is_empty() {
                break;
            }
        }
        Ok(AbstractValue::Feasible(result))
    }

    fn abstract_iff(
        &mut self,
        children: &[NodeId],
        polarity: bool,
    ) -> Result<AbstractValue, CapReason> {
        let Some((&first, rest)) = children.split_first() else {
            return if polarity {
                Ok(self.empty_value())
            } else {
                Ok(AbstractValue::Infeasible)
            };
        };
        if rest.is_empty() {
            return if polarity {
                Ok(self.empty_value())
            } else {
                Ok(AbstractValue::Infeasible)
            };
        }

        let mut pair_values = Vec::new();
        pair_values
            .try_reserve_exact(rest.len())
            .map_err(|_| CapReason::Entries)?;
        for &second in rest {
            if first == second {
                pair_values.push(if polarity {
                    self.empty_value()
                } else {
                    AbstractValue::Infeasible
                });
                continue;
            }

            // (first <=> u) = (not first or u) and (not u or first),
            // where u is second at positive polarity and not second otherwise.
            let first_positive = self.memo_value(first, true);
            let first_negative = self.memo_value(first, false);
            let second_requested = self.memo_value(second, polarity);
            let second_opposite = self.memo_value(second, !polarity);
            let forward = self.abstract_or(&[first_negative, second_requested])?;
            let backward = self.abstract_or(&[second_opposite, first_positive])?;
            pair_values.push(self.abstract_and(&[forward, backward])?);
        }

        if polarity {
            self.abstract_and(&pair_values)
        } else {
            self.abstract_or(&pair_values)
        }
    }

    fn abstract_ite(
        &mut self,
        cond: NodeId,
        then_expr: NodeId,
        else_expr: NodeId,
        polarity: bool,
    ) -> Result<AbstractValue, CapReason> {
        // (ite c u1 u2) = (not c or u1) and (c or u2), where u1/u2
        // are the branches at the requested polarity.
        let cond_positive = self.memo_value(cond, true);
        let cond_negative = self.memo_value(cond, false);
        let then_requested = self.memo_value(then_expr, polarity);
        let else_requested = self.memo_value(else_expr, polarity);
        let then_guard = self.abstract_or(&[cond_negative, then_requested])?;
        let else_guard = self.abstract_or(&[cond_positive, else_requested])?;
        self.abstract_and(&[then_guard, else_guard])
    }

    fn meet_partitions(&mut self, partitions: &[&Partition]) -> Result<Partition, CapReason> {
        self.scratch.reset();
        for partition in partitions {
            for class in &partition.classes {
                let (&first, rest) = class.split_first().expect("canonical classes are nonempty");
                for &term in rest {
                    self.budget.spend(1)?;
                    self.scratch
                        .union(first, term, self.limits.max_entries, &mut self.budget)?;
                }
            }
        }
        self.scratch.partition(&mut self.budget)
    }

    fn join_partitions(
        &mut self,
        left: &Partition,
        right: &Partition,
    ) -> Result<Partition, CapReason> {
        let mut right_labels = HashMap::default();
        for (class_id, class) in right.classes.iter().enumerate() {
            for &term in class {
                self.budget.spend(1)?;
                ensure_entry_capacity(right_labels.len(), 1, self.limits.max_entries)?;
                right_labels.insert(term, class_id);
            }
        }

        let mut classes = Vec::new();
        let mut output_terms = 0usize;
        for left_class in &left.classes {
            let mut subclasses: HashMap<usize, Vec<TermId>> = HashMap::default();
            for &term in left_class {
                self.budget.spend(1)?;
                if let Some(&right_class) = right_labels.get(&term) {
                    subclasses.entry(right_class).or_default().push(term);
                }
            }
            for class in subclasses.into_values() {
                if class.len() < 2 {
                    continue;
                }
                output_terms = output_terms
                    .checked_add(class.len())
                    .ok_or(CapReason::Arithmetic)?;
                if output_terms > self.limits.max_entries {
                    return Err(CapReason::Entries);
                }
                classes.push(class);
            }
        }
        Ok(Partition::from_classes(classes))
    }

    fn metrics(&self, partition: &Partition) -> Result<Metrics, CapReason> {
        Ok(Metrics {
            nodes: self.nodes.len(),
            memo_entries: self.memo_entries,
            memo_hits: self.memo_hits,
            work: self.budget.used,
            classes: partition.classes.len(),
            partition_terms: partition.term_count()?,
        })
    }
}

pub(super) fn analyze(assertions: &[BoolExpr]) -> Outcome {
    analyze_with_limits(assertions, Limits::default())
}

fn analyze_with_limits(assertions: &[BoolExpr], limits: Limits) -> Outcome {
    let mut budget = Budget::new(limits.max_work);
    let mut interner = Interner::new(limits.max_entries);
    if let Err(reason) = interner.intern_assertions(assertions, &mut budget) {
        return Outcome::capped(
            reason,
            Metrics {
                nodes: interner.nodes.len(),
                work: budget.used,
                ..Metrics::default()
            },
        );
    }

    let roots = std::mem::take(&mut interner.roots);
    let node_count = interner.nodes.len();
    let mut evaluator = match Evaluator::new(interner.nodes, limits, budget) {
        Ok(evaluator) => evaluator,
        Err(reason) => {
            return Outcome::capped(
                reason,
                Metrics {
                    nodes: node_count,
                    ..Metrics::default()
                },
            );
        }
    };

    let mut values = Vec::new();
    if values.try_reserve_exact(roots.len()).is_err() {
        return Outcome::capped(
            CapReason::Entries,
            Metrics {
                nodes: node_count,
                work: evaluator.budget.used,
                ..Metrics::default()
            },
        );
    }
    for root in roots {
        match evaluator.evaluate(root, true) {
            Ok(value) => values.push(value),
            Err(reason) => {
                let metrics = Metrics {
                    nodes: node_count,
                    memo_entries: evaluator.memo_entries,
                    memo_hits: evaluator.memo_hits,
                    work: evaluator.budget.used,
                    ..Metrics::default()
                };
                return Outcome::capped(reason, metrics);
            }
        }
    }

    let abstraction = match evaluator.abstract_and(&values) {
        Ok(value) => value,
        Err(reason) => {
            let metrics = Metrics {
                nodes: node_count,
                memo_entries: evaluator.memo_entries,
                memo_hits: evaluator.memo_hits,
                work: evaluator.budget.used,
                ..Metrics::default()
            };
            return Outcome::capped(reason, metrics);
        }
    };

    match abstraction {
        AbstractValue::Infeasible => {
            let partition = Partition::empty();
            let metrics = evaluator.metrics(&partition).unwrap_or(Metrics {
                nodes: node_count,
                memo_entries: evaluator.memo_entries,
                memo_hits: evaluator.memo_hits,
                work: evaluator.budget.used,
                ..Metrics::default()
            });
            Outcome {
                star_edges: Vec::new(),
                infeasible: true,
                cap_reason: None,
                metrics,
                #[cfg(test)]
                partition,
            }
        }
        AbstractValue::Feasible(partition) => {
            let partition = partition.as_ref().clone();
            let star_edges =
                match partition.star_edges(limits.max_star_edges, &mut evaluator.budget) {
                    Ok(edges) => edges,
                    Err(reason) => {
                        let metrics = Metrics {
                            nodes: node_count,
                            memo_entries: evaluator.memo_entries,
                            memo_hits: evaluator.memo_hits,
                            work: evaluator.budget.used,
                            ..Metrics::default()
                        };
                        return Outcome::capped(reason, metrics);
                    }
                };
            let metrics = match evaluator.metrics(&partition) {
                Ok(metrics) => metrics,
                Err(reason) => return Outcome::capped(reason, Metrics::default()),
            };
            Outcome {
                star_edges,
                infeasible: false,
                cap_reason: None,
                metrics,
                #[cfg(test)]
                partition,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eq(left: TermId, right: TermId) -> BoolExpr {
        BoolExpr::Atom(BoolAtomKey::Eq(left, right))
    }

    fn bool_term(term: TermId) -> BoolExpr {
        BoolExpr::Atom(BoolAtomKey::BoolTerm(term))
    }

    fn generous_limits() -> Limits {
        Limits {
            max_work: 20_000_000,
            max_entries: 20_000,
            max_star_edges: 20_000,
        }
    }

    fn abstract_value(expr: &BoolExpr, polarity: bool) -> AbstractValue {
        let limits = generous_limits();
        let mut budget = Budget::new(limits.max_work);
        let mut interner = Interner::new(limits.max_entries);
        interner
            .intern_assertions(std::slice::from_ref(expr), &mut budget)
            .unwrap();
        let root = interner.roots[0];
        let mut evaluator = Evaluator::new(interner.nodes, limits, budget).unwrap();
        evaluator.evaluate(root, polarity).unwrap()
    }

    fn partition(expr: &BoolExpr, polarity: bool) -> Partition {
        match abstract_value(expr, polarity) {
            AbstractValue::Feasible(partition) => partition.as_ref().clone(),
            AbstractValue::Infeasible => panic!("expected feasible abstraction"),
        }
    }

    fn is_infeasible(expr: &BoolExpr, polarity: bool) -> bool {
        matches!(abstract_value(expr, polarity), AbstractValue::Infeasible)
    }

    fn relation(partition: &Partition, size: usize) -> Vec<Vec<bool>> {
        let mut relation = vec![vec![false; size]; size];
        for (index, row) in relation.iter_mut().enumerate() {
            row[index] = true;
        }
        for class in &partition.classes {
            for &left in class {
                for &right in class {
                    relation[left][right] = true;
                }
            }
        }
        relation
    }

    fn reference_meet(left: &Partition, right: &Partition, size: usize) -> Vec<Vec<bool>> {
        let left = relation(left, size);
        let right = relation(right, size);
        let mut result = vec![vec![false; size]; size];
        for i in 0..size {
            for j in 0..size {
                result[i][j] = left[i][j] || right[i][j];
            }
        }
        for pivot in 0..size {
            for i in 0..size {
                for j in 0..size {
                    result[i][j] |= result[i][pivot] && result[pivot][j];
                }
            }
        }
        result
    }

    fn reference_join(left: &Partition, right: &Partition, size: usize) -> Vec<Vec<bool>> {
        let left = relation(left, size);
        let right = relation(right, size);
        (0..size)
            .map(|i| (0..size).map(|j| left[i][j] && right[i][j]).collect())
            .collect()
    }

    fn enumerate_partitions(size: usize) -> Vec<Partition> {
        fn visit(
            term: usize,
            size: usize,
            classes: &mut Vec<Vec<usize>>,
            output: &mut Vec<Partition>,
        ) {
            if term == size {
                output.push(Partition::from_classes(classes.clone()));
                return;
            }
            for index in 0..classes.len() {
                classes[index].push(term);
                visit(term + 1, size, classes, output);
                classes[index].pop();
            }
            classes.push(vec![term]);
            visit(term + 1, size, classes, output);
            classes.pop();
        }

        let mut output = Vec::new();
        visit(0, size, &mut Vec::new(), &mut output);
        output
    }

    fn partition_engine() -> Evaluator {
        let limits = generous_limits();
        Evaluator::new(Vec::new(), limits, Budget::new(limits.max_work)).unwrap()
    }

    #[test]
    fn partition_meet_and_join_match_reference_through_five_elements() {
        for size in 0..=5 {
            let partitions = enumerate_partitions(size);
            for left in &partitions {
                for right in &partitions {
                    let mut engine = partition_engine();
                    let meet = engine.meet_partitions(&[left, right]).unwrap();
                    let mut engine = partition_engine();
                    let join = engine.join_partitions(left, right).unwrap();
                    assert_eq!(relation(&meet, size), reference_meet(left, right, size));
                    assert_eq!(relation(&join, size), reference_join(left, right, size));

                    let mut engine = partition_engine();
                    let reverse_meet = engine.meet_partitions(&[right, left]).unwrap();
                    let mut engine = partition_engine();
                    let reverse_join = engine.join_partitions(right, left).unwrap();
                    assert_eq!(meet, reverse_meet);
                    assert_eq!(join, reverse_join);

                    let mut engine = partition_engine();
                    let meet_absorption = engine.meet_partitions(&[left, &join]).unwrap();
                    let mut engine = partition_engine();
                    let join_absorption = engine.join_partitions(left, &meet).unwrap();
                    assert_eq!(meet_absorption, *left);
                    assert_eq!(join_absorption, *left);
                }
            }
        }
    }

    #[test]
    fn learns_transitive_equalities_common_to_or_branches_and_assertions() {
        let branch_formula = BoolExpr::Or(vec![
            BoolExpr::And(vec![eq(0, 1), eq(1, 2)]),
            BoolExpr::And(vec![eq(0, 3), eq(3, 2)]),
        ]);
        assert_eq!(
            partition(&branch_formula, true),
            Partition::from_classes(vec![vec![0, 2]])
        );

        let with_false = BoolExpr::Or(vec![BoolExpr::Const(false), branch_formula]);
        assert_eq!(
            partition(&with_false, true),
            Partition::from_classes(vec![vec![0, 2]])
        );

        let outcome = analyze_with_limits(&[eq(0, 1), eq(1, 2)], generous_limits());
        assert_eq!(
            outcome.partition,
            Partition::from_classes(vec![vec![0, 1, 2]])
        );
        assert_eq!(outcome.star_edges, vec![(0, 1), (0, 2)]);
    }

    #[test]
    fn handles_both_polarities_and_reflexive_equalities() {
        assert_eq!(
            partition(&eq(0, 1), true),
            Partition::from_classes(vec![vec![0, 1]])
        );
        assert_eq!(partition(&eq(0, 1), false), Partition::empty());
        assert_eq!(partition(&eq(0, 0), true), Partition::empty());
        assert!(is_infeasible(&eq(0, 0), false));

        let negative_or = BoolExpr::Or(vec![
            BoolExpr::Not(Box::new(eq(0, 1))),
            BoolExpr::Not(Box::new(eq(1, 2))),
        ]);
        assert_eq!(
            partition(&negative_or, false),
            Partition::from_classes(vec![vec![0, 1, 2]])
        );
        assert_eq!(partition(&negative_or, true), Partition::empty());
    }

    #[test]
    fn constants_and_empty_connectives_preserve_feasibility() {
        assert_eq!(partition(&BoolExpr::Const(true), true), Partition::empty());
        assert!(is_infeasible(&BoolExpr::Const(true), false));
        assert!(is_infeasible(&BoolExpr::Const(false), true));
        assert_eq!(
            partition(&BoolExpr::Const(false), false),
            Partition::empty()
        );

        assert_eq!(
            partition(&BoolExpr::And(Vec::new()), true),
            Partition::empty()
        );
        assert!(is_infeasible(&BoolExpr::And(Vec::new()), false));
        assert!(is_infeasible(&BoolExpr::Or(Vec::new()), true));
        assert_eq!(
            partition(&BoolExpr::Or(Vec::new()), false),
            Partition::empty()
        );
        assert_eq!(
            partition(&BoolExpr::Iff(Vec::new()), true),
            Partition::empty()
        );
        assert!(is_infeasible(&BoolExpr::Iff(Vec::new()), false));
    }

    #[test]
    fn yices_iff_formula_uses_requested_polarity() {
        let positive = BoolExpr::Iff(vec![eq(0, 1), BoolExpr::Const(true)]);
        assert_eq!(
            partition(&positive, true),
            Partition::from_classes(vec![vec![0, 1]])
        );
        assert_eq!(partition(&positive, false), Partition::empty());

        let negative = BoolExpr::Iff(vec![eq(0, 1), BoolExpr::Const(false)]);
        assert_eq!(partition(&negative, true), Partition::empty());
        assert_eq!(
            partition(&negative, false),
            Partition::from_classes(vec![vec![0, 1]])
        );

        let reflexive = BoolExpr::Iff(vec![eq(0, 1), eq(1, 0)]);
        assert_eq!(partition(&reflexive, true), Partition::empty());
        assert!(is_infeasible(&reflexive, false));
    }

    #[test]
    fn yices_ite_formula_uses_guarded_meets_and_joins() {
        let positive = BoolExpr::Ite(
            Box::new(eq(0, 1)),
            Box::new(BoolExpr::Const(true)),
            Box::new(BoolExpr::Const(false)),
        );
        assert_eq!(
            partition(&positive, true),
            Partition::from_classes(vec![vec![0, 1]])
        );
        assert_eq!(partition(&positive, false), Partition::empty());

        let negative = BoolExpr::Ite(
            Box::new(eq(0, 1)),
            Box::new(BoolExpr::Const(false)),
            Box::new(BoolExpr::Const(true)),
        );
        assert_eq!(partition(&negative, true), Partition::empty());
        assert_eq!(
            partition(&negative, false),
            Partition::from_classes(vec![vec![0, 1]])
        );

        let fixed_condition = BoolExpr::Ite(
            Box::new(BoolExpr::Const(true)),
            Box::new(eq(2, 3)),
            Box::new(eq(4, 5)),
        );
        assert_eq!(
            partition(&fixed_condition, true),
            Partition::from_classes(vec![vec![2, 3]])
        );
    }

    #[test]
    fn every_cap_rolls_back_to_no_facts() {
        let work_capped = analyze_with_limits(
            &[eq(0, 1)],
            Limits {
                max_work: 0,
                ..generous_limits()
            },
        );
        assert_eq!(work_capped.cap_reason, Some(CapReason::Work));
        assert!(work_capped.star_edges.is_empty());
        assert_eq!(work_capped.partition, Partition::empty());

        let entry_capped = analyze_with_limits(
            &[BoolExpr::And(vec![eq(0, 1), eq(1, 2)])],
            Limits {
                max_entries: 2,
                ..generous_limits()
            },
        );
        assert_eq!(entry_capped.cap_reason, Some(CapReason::Entries));
        assert!(entry_capped.star_edges.is_empty());
        assert_eq!(entry_capped.partition, Partition::empty());

        let star_capped = analyze_with_limits(
            &[eq(0, 1), eq(1, 2)],
            Limits {
                max_star_edges: 1,
                ..generous_limits()
            },
        );
        assert_eq!(star_capped.cap_reason, Some(CapReason::StarEdges));
        assert!(star_capped.star_edges.is_empty());
        assert_eq!(star_capped.partition, Partition::empty());
    }

    #[test]
    fn star_edges_are_canonical_deterministic_and_deduplicated() {
        let assertions = vec![eq(4, 2), eq(3, 4), eq(9, 7), eq(2, 3), eq(7, 9)];
        let first = analyze_with_limits(&assertions, generous_limits());
        let second = analyze_with_limits(&assertions, generous_limits());
        assert_eq!(first.cap_reason, None);
        assert_eq!(first.star_edges, vec![(2, 3), (2, 4), (7, 9)]);
        assert_eq!(second.star_edges, first.star_edges);
    }

    #[test]
    fn bool_term_only_formulas_never_produce_equality_facts() {
        let formula = BoolExpr::And(vec![
            BoolExpr::Iff(vec![bool_term(0), BoolExpr::Const(true)]),
            BoolExpr::Ite(
                Box::new(bool_term(1)),
                Box::new(bool_term(2)),
                Box::new(BoolExpr::Not(Box::new(bool_term(3)))),
            ),
        ]);
        let outcome = analyze_with_limits(&[formula], generous_limits());
        assert_eq!(outcome.cap_reason, None);
        assert!(outcome.star_edges.is_empty());
        assert_eq!(outcome.partition, Partition::empty());
    }

    #[test]
    fn structurally_equal_boolean_trees_share_interned_nodes() {
        let formula = || BoolExpr::And(vec![eq(0, 1), eq(1, 2)]);
        let outcome = analyze_with_limits(&[formula(), formula()], generous_limits());
        assert_eq!(outcome.cap_reason, None);
        assert_eq!(outcome.metrics.nodes, 3);
        assert!(outcome.metrics.memo_hits > 0);
    }
}
