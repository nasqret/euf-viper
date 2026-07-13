//! Rollback congruence closure with replayable equality explanations.
//!
//! This module is solver-independent. It deliberately uses union by size
//! without path compression so every mutation can be undone at a SAT decision
//! level. The initial implementation favors a small auditable state boundary;
//! parent-use indexing and explanation minimization can be optimized after the
//! differential gate passes.

use std::collections::VecDeque;

use rustc_hash::FxHashSet as HashSet;

use super::{SortId, TermArena, TermId, UnionFind, congruence_closure};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RollbackEufLimits {
    pub(crate) max_terms: usize,
    pub(crate) max_facts: usize,
    pub(crate) max_signature_pair_checks: usize,
    pub(crate) max_explanation_edges: usize,
    pub(crate) max_clause_width: usize,
}

impl Default for RollbackEufLimits {
    fn default() -> Self {
        Self {
            max_terms: 1_000_000,
            max_facts: 1_000_000,
            max_signature_pair_checks: 100_000_000,
            max_explanation_edges: 1_000_000,
            max_clause_width: 4_096,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RollbackEufError {
    TermLimitExceeded {
        terms: usize,
        limit: usize,
    },
    TermOutOfRange {
        term: TermId,
        terms: usize,
    },
    FactLimitExceeded {
        facts: usize,
        limit: usize,
    },
    SortMismatch {
        left: TermId,
        left_sort: SortId,
        right: TermId,
        right_sort: SortId,
    },
    InvalidLiteral(i32),
    DuplicateLiteralVariable(u32),
    InvalidRollbackLevel {
        requested: usize,
        current: usize,
    },
    SignaturePairLimitExceeded {
        checks: usize,
        limit: usize,
    },
    ExplanationEdgeLimitExceeded {
        visits: usize,
        limit: usize,
    },
    ClauseWidthLimitExceeded {
        width: usize,
        limit: usize,
    },
    MissingExplanationPath {
        left: TermId,
        right: TermId,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum EqualityReason {
    Literal(i32),
    Congruence(TermId, TermId),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct EqualityEdge {
    to: TermId,
    reason: EqualityReason,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ActiveFact {
    Equality {
        left: TermId,
        right: TermId,
        literal: i32,
    },
    Disequality {
        left: TermId,
        right: TermId,
        literal: Option<i32>,
    },
}

impl ActiveFact {
    fn literal(&self) -> Option<i32> {
        match self {
            Self::Equality { literal, .. } => Some(*literal),
            Self::Disequality { literal, .. } => *literal,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Disequality {
    left: TermId,
    right: TermId,
    literal: Option<i32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EufConflict {
    left: TermId,
    right: TermId,
    disequality_literal: Option<i32>,
    antecedents: Vec<i32>,
    clause: Vec<i32>,
}

impl EufConflict {
    pub(crate) fn antecedents(&self) -> &[i32] {
        &self.antecedents
    }

    pub(crate) fn clause(&self) -> &[i32] {
        &self.clause
    }
}

#[derive(Clone, Copy, Debug)]
struct Snapshot {
    undo_len: usize,
    facts_len: usize,
    disequalities_len: usize,
    conflicts_len: usize,
}

#[derive(Clone, Debug)]
struct MergeUndo {
    winner: TermId,
    loser: TermId,
    winner_size: usize,
    winner_uses_len: usize,
    winner_disequalities_len: usize,
    left: TermId,
    left_edges_len: usize,
    right: TermId,
    right_edges_len: usize,
}

#[derive(Clone, Debug)]
struct DisequalityUndo {
    left_root: TermId,
    left_len: usize,
    right: Option<(TermId, usize)>,
}

#[derive(Clone, Debug)]
enum Undo {
    Merge(MergeUndo),
    Disequality(DisequalityUndo),
}

#[derive(Debug)]
pub(crate) struct RollbackEuf<'arena> {
    arena: &'arena TermArena,
    limits: RollbackEufLimits,
    parent: Vec<TermId>,
    size: Vec<usize>,
    class_uses: Vec<Vec<TermId>>,
    class_disequalities: Vec<Vec<usize>>,
    equality_edges: Vec<Vec<EqualityEdge>>,
    active_facts: Vec<ActiveFact>,
    literal_variables: HashSet<u32>,
    disequalities: Vec<Disequality>,
    conflicting_disequalities: Vec<usize>,
    undo: Vec<Undo>,
    levels: Vec<Snapshot>,
}

impl<'arena> RollbackEuf<'arena> {
    pub(crate) fn new(
        arena: &'arena TermArena,
        limits: RollbackEufLimits,
    ) -> Result<Self, RollbackEufError> {
        let terms = arena.terms.len();
        if terms > limits.max_terms {
            return Err(RollbackEufError::TermLimitExceeded {
                terms,
                limit: limits.max_terms,
            });
        }

        let mut class_uses = vec![Vec::new(); terms];
        for &application in &arena.apps {
            let mut arguments = arena.terms[application].args.clone();
            arguments.sort_unstable();
            arguments.dedup();
            for argument in arguments {
                class_uses[argument].push(application);
            }
        }
        for uses in &mut class_uses {
            uses.sort_unstable();
            uses.dedup();
        }

        let initial = Snapshot {
            undo_len: 0,
            facts_len: 0,
            disequalities_len: 0,
            conflicts_len: 0,
        };
        Ok(Self {
            arena,
            limits,
            parent: (0..terms).collect(),
            size: vec![1; terms],
            class_uses,
            class_disequalities: vec![Vec::new(); terms],
            equality_edges: vec![Vec::new(); terms],
            active_facts: Vec::new(),
            literal_variables: HashSet::default(),
            disequalities: Vec::new(),
            conflicting_disequalities: Vec::new(),
            undo: Vec::new(),
            levels: vec![initial],
        })
    }

    pub(crate) fn level(&self) -> usize {
        self.levels.len() - 1
    }

    pub(crate) fn push_level(&mut self) {
        self.levels.push(self.snapshot());
    }

    pub(crate) fn rollback_to(&mut self, level: usize) -> Result<(), RollbackEufError> {
        let current = self.level();
        if level > current {
            return Err(RollbackEufError::InvalidRollbackLevel {
                requested: level,
                current,
            });
        }
        if level == current {
            return Ok(());
        }
        let snapshot = self.levels[level + 1];
        self.restore(snapshot);
        self.levels.truncate(level + 1);
        Ok(())
    }

    pub(crate) fn assume_distinct_axiom(
        &mut self,
        left: TermId,
        right: TermId,
    ) -> Result<Option<EufConflict>, RollbackEufError> {
        self.validate_pair(left, right)?;
        self.validate_fact_capacity()?;
        self.active_facts.push(ActiveFact::Disequality {
            left,
            right,
            literal: None,
        });
        self.register_disequality(left, right, None);
        self.current_conflict()
    }

    pub(crate) fn assert_equality(
        &mut self,
        left: TermId,
        right: TermId,
        literal: i32,
    ) -> Result<Option<EufConflict>, RollbackEufError> {
        self.validate_pair(left, right)?;
        self.validate_fact_capacity()?;
        self.validate_new_literal(literal)?;
        let snapshot = self.snapshot();
        self.literal_variables.insert(literal.unsigned_abs());
        self.active_facts.push(ActiveFact::Equality {
            left,
            right,
            literal,
        });
        if let Err(error) = self.merge_closure(left, right, EqualityReason::Literal(literal)) {
            self.restore(snapshot);
            return Err(error);
        }
        self.current_conflict()
    }

    pub(crate) fn assert_disequality(
        &mut self,
        left: TermId,
        right: TermId,
        literal: i32,
    ) -> Result<Option<EufConflict>, RollbackEufError> {
        self.validate_pair(left, right)?;
        self.validate_fact_capacity()?;
        self.validate_new_literal(literal)?;
        self.literal_variables.insert(literal.unsigned_abs());
        self.active_facts.push(ActiveFact::Disequality {
            left,
            right,
            literal: Some(literal),
        });
        self.register_disequality(left, right, Some(literal));
        self.current_conflict()
    }

    pub(crate) fn equal(&self, left: TermId, right: TermId) -> Result<bool, RollbackEufError> {
        self.validate_pair(left, right)?;
        Ok(self.root(left) == self.root(right))
    }

    pub(crate) fn current_conflict(&self) -> Result<Option<EufConflict>, RollbackEufError> {
        let Some(&index) = self.conflicting_disequalities.first() else {
            return Ok(None);
        };
        self.make_conflict(&self.disequalities[index]).map(Some)
    }

    pub(crate) fn replay_conflict(&self, conflict: &EufConflict) -> bool {
        if conflict
            .antecedents
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
            || conflict.clause.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return false;
        }
        let mut expected_clause: Vec<i32> = conflict
            .antecedents
            .iter()
            .map(|literal| -*literal)
            .collect();
        expected_clause.sort_unstable();
        if expected_clause != conflict.clause {
            return false;
        }

        let selected_disequality = self.disequalities.iter().find(|disequality| {
            disequality.left == conflict.left
                && disequality.right == conflict.right
                && disequality.literal == conflict.disequality_literal
        });
        let Some(selected_disequality) = selected_disequality else {
            return false;
        };
        if let Some(literal) = selected_disequality.literal {
            if !conflict.antecedents.contains(&literal) {
                return false;
            }
        }

        let mut uf = UnionFind::new(self.arena.terms.len());
        for &literal in &conflict.antecedents {
            if Some(literal) == selected_disequality.literal {
                continue;
            }
            let mut matches = self.active_facts.iter().filter(|fact| {
                matches!(fact, ActiveFact::Equality { literal: fact_literal, .. } if *fact_literal == literal)
            });
            let Some(ActiveFact::Equality { left, right, .. }) = matches.next() else {
                return false;
            };
            if matches.next().is_some() {
                return false;
            }
            uf.union(*left, *right);
        }
        congruence_closure(self.arena, &mut uf);
        uf.find(selected_disequality.left) == uf.find(selected_disequality.right)
    }

    fn snapshot(&self) -> Snapshot {
        Snapshot {
            undo_len: self.undo.len(),
            facts_len: self.active_facts.len(),
            disequalities_len: self.disequalities.len(),
            conflicts_len: self.conflicting_disequalities.len(),
        }
    }

    fn restore(&mut self, snapshot: Snapshot) {
        while self.undo.len() > snapshot.undo_len {
            match self.undo.pop().expect("undo length checked") {
                Undo::Merge(undo) => {
                    self.equality_edges[undo.left].truncate(undo.left_edges_len);
                    self.equality_edges[undo.right].truncate(undo.right_edges_len);
                    self.class_uses[undo.winner].truncate(undo.winner_uses_len);
                    self.class_disequalities[undo.winner].truncate(undo.winner_disequalities_len);
                    self.parent[undo.loser] = undo.loser;
                    self.size[undo.winner] = undo.winner_size;
                }
                Undo::Disequality(undo) => {
                    self.class_disequalities[undo.left_root].truncate(undo.left_len);
                    if let Some((right_root, right_len)) = undo.right {
                        self.class_disequalities[right_root].truncate(right_len);
                    }
                }
            }
        }
        for fact in &self.active_facts[snapshot.facts_len..] {
            if let Some(literal) = fact.literal() {
                self.literal_variables.remove(&literal.unsigned_abs());
            }
        }
        self.active_facts.truncate(snapshot.facts_len);
        self.disequalities.truncate(snapshot.disequalities_len);
        self.conflicting_disequalities
            .truncate(snapshot.conflicts_len);
    }

    fn register_disequality(&mut self, left: TermId, right: TermId, literal: Option<i32>) {
        let index = self.disequalities.len();
        self.disequalities.push(Disequality {
            left,
            right,
            literal,
        });
        let left_root = self.root(left);
        let right_root = self.root(right);
        let left_len = self.class_disequalities[left_root].len();
        self.class_disequalities[left_root].push(index);
        let right_undo = if left_root == right_root {
            self.conflicting_disequalities.push(index);
            None
        } else {
            let right_len = self.class_disequalities[right_root].len();
            self.class_disequalities[right_root].push(index);
            Some((right_root, right_len))
        };
        self.undo.push(Undo::Disequality(DisequalityUndo {
            left_root,
            left_len,
            right: right_undo,
        }));
    }

    fn validate_fact_capacity(&self) -> Result<(), RollbackEufError> {
        if self.active_facts.len() >= self.limits.max_facts {
            return Err(RollbackEufError::FactLimitExceeded {
                facts: self.active_facts.len() + 1,
                limit: self.limits.max_facts,
            });
        }
        Ok(())
    }

    fn validate_pair(&self, left: TermId, right: TermId) -> Result<(), RollbackEufError> {
        let terms = self.arena.terms.len();
        if left >= terms {
            return Err(RollbackEufError::TermOutOfRange { term: left, terms });
        }
        if right >= terms {
            return Err(RollbackEufError::TermOutOfRange { term: right, terms });
        }
        let left_sort = self.arena.terms[left].sort;
        let right_sort = self.arena.terms[right].sort;
        if left_sort != right_sort {
            return Err(RollbackEufError::SortMismatch {
                left,
                left_sort,
                right,
                right_sort,
            });
        }
        Ok(())
    }

    fn validate_new_literal(&self, literal: i32) -> Result<(), RollbackEufError> {
        if literal == 0 || literal == i32::MIN {
            return Err(RollbackEufError::InvalidLiteral(literal));
        }
        let variable = literal.unsigned_abs();
        if self.literal_variables.contains(&variable) {
            return Err(RollbackEufError::DuplicateLiteralVariable(variable));
        }
        Ok(())
    }

    fn root(&self, mut term: TermId) -> TermId {
        while self.parent[term] != term {
            term = self.parent[term];
        }
        term
    }

    fn merge_closure(
        &mut self,
        left: TermId,
        right: TermId,
        reason: EqualityReason,
    ) -> Result<(), RollbackEufError> {
        let mut pending = VecDeque::from([(left, right, reason)]);
        let mut pair_checks = 0usize;
        while let Some((left, right, reason)) = pending.pop_front() {
            let mut winner = self.root(left);
            let mut loser = self.root(right);
            if winner == loser {
                continue;
            }
            if self.size[winner] < self.size[loser]
                || (self.size[winner] == self.size[loser] && winner > loser)
            {
                std::mem::swap(&mut winner, &mut loser);
            }

            let undo = MergeUndo {
                winner,
                loser,
                winner_size: self.size[winner],
                winner_uses_len: self.class_uses[winner].len(),
                winner_disequalities_len: self.class_disequalities[winner].len(),
                left,
                left_edges_len: self.equality_edges[left].len(),
                right,
                right_edges_len: self.equality_edges[right].len(),
            };
            self.parent[loser] = winner;
            self.size[winner] += self.size[loser];
            self.equality_edges[left].push(EqualityEdge {
                to: right,
                reason: reason.clone(),
            });
            self.equality_edges[right].push(EqualityEdge { to: left, reason });
            // Record the merge before any capped signature work so an error
            // can restore the assertion atomically.
            self.undo.push(Undo::Merge(undo));

            for loser_index in 0..self.class_disequalities[loser].len() {
                let disequality_index = self.class_disequalities[loser][loser_index];
                let disequality = &self.disequalities[disequality_index];
                if self.root(disequality.left) == self.root(disequality.right)
                    && !self.conflicting_disequalities.contains(&disequality_index)
                {
                    self.conflicting_disequalities.push(disequality_index);
                }
            }

            for winner_index in 0..self.class_uses[winner].len() {
                let winner_application = self.class_uses[winner][winner_index];
                for loser_index in 0..self.class_uses[loser].len() {
                    pair_checks = pair_checks.checked_add(1).ok_or(
                        RollbackEufError::SignaturePairLimitExceeded {
                            checks: usize::MAX,
                            limit: self.limits.max_signature_pair_checks,
                        },
                    )?;
                    if pair_checks > self.limits.max_signature_pair_checks {
                        return Err(RollbackEufError::SignaturePairLimitExceeded {
                            checks: pair_checks,
                            limit: self.limits.max_signature_pair_checks,
                        });
                    }
                    let loser_application = self.class_uses[loser][loser_index];
                    if winner_application != loser_application
                        && self.applications_congruent(winner_application, loser_application)
                    {
                        pending.push_back((
                            winner_application,
                            loser_application,
                            EqualityReason::Congruence(winner_application, loser_application),
                        ));
                    }
                }
            }

            self.append_loser_uses(winner, loser);
            self.append_loser_disequalities(winner, loser);
        }
        Ok(())
    }

    fn append_loser_uses(&mut self, winner: TermId, loser: TermId) {
        if winner < loser {
            let (before_loser, from_loser) = self.class_uses.split_at_mut(loser);
            before_loser[winner].extend_from_slice(&from_loser[0]);
        } else {
            let (before_winner, from_winner) = self.class_uses.split_at_mut(winner);
            from_winner[0].extend_from_slice(&before_winner[loser]);
        }
    }

    fn append_loser_disequalities(&mut self, winner: TermId, loser: TermId) {
        if winner < loser {
            let (before_loser, from_loser) = self.class_disequalities.split_at_mut(loser);
            before_loser[winner].extend_from_slice(&from_loser[0]);
        } else {
            let (before_winner, from_winner) = self.class_disequalities.split_at_mut(winner);
            from_winner[0].extend_from_slice(&before_winner[loser]);
        }
    }

    fn applications_congruent(&self, left: TermId, right: TermId) -> bool {
        let left_term = &self.arena.terms[left];
        let right_term = &self.arena.terms[right];
        left_term.fun == right_term.fun
            && left_term.args.len() == right_term.args.len()
            && left_term
                .args
                .iter()
                .zip(&right_term.args)
                .all(|(&left_arg, &right_arg)| self.root(left_arg) == self.root(right_arg))
    }

    fn make_conflict(&self, disequality: &Disequality) -> Result<EufConflict, RollbackEufError> {
        let mut literals = HashSet::default();
        let mut expanded = HashSet::default();
        let mut edge_visits = 0usize;
        self.explain_equal(
            disequality.left,
            disequality.right,
            &mut literals,
            &mut expanded,
            &mut edge_visits,
        )?;
        if let Some(literal) = disequality.literal {
            literals.insert(literal);
        }
        if literals.len() > self.limits.max_clause_width {
            return Err(RollbackEufError::ClauseWidthLimitExceeded {
                width: literals.len(),
                limit: self.limits.max_clause_width,
            });
        }
        let mut antecedents: Vec<i32> = literals.into_iter().collect();
        antecedents.sort_unstable();
        let mut clause: Vec<i32> = antecedents.iter().map(|literal| -*literal).collect();
        clause.sort_unstable();
        Ok(EufConflict {
            left: disequality.left,
            right: disequality.right,
            disequality_literal: disequality.literal,
            antecedents,
            clause,
        })
    }

    fn explain_equal(
        &self,
        left: TermId,
        right: TermId,
        literals: &mut HashSet<i32>,
        expanded: &mut HashSet<(TermId, TermId)>,
        edge_visits: &mut usize,
    ) -> Result<(), RollbackEufError> {
        if left == right || !expanded.insert(normalized_pair(left, right)) {
            return Ok(());
        }
        let mut seen = vec![false; self.equality_edges.len()];
        let mut parent: Vec<Option<(TermId, EqualityReason)>> =
            vec![None; self.equality_edges.len()];
        let mut queue = VecDeque::from([left]);
        seen[left] = true;
        while let Some(term) = queue.pop_front() {
            if term == right {
                break;
            }
            for edge in &self.equality_edges[term] {
                *edge_visits = edge_visits.checked_add(1).ok_or(
                    RollbackEufError::ExplanationEdgeLimitExceeded {
                        visits: usize::MAX,
                        limit: self.limits.max_explanation_edges,
                    },
                )?;
                if *edge_visits > self.limits.max_explanation_edges {
                    return Err(RollbackEufError::ExplanationEdgeLimitExceeded {
                        visits: *edge_visits,
                        limit: self.limits.max_explanation_edges,
                    });
                }
                if !seen[edge.to] {
                    seen[edge.to] = true;
                    parent[edge.to] = Some((term, edge.reason.clone()));
                    queue.push_back(edge.to);
                }
            }
        }
        if !seen[right] {
            return Err(RollbackEufError::MissingExplanationPath { left, right });
        }

        let mut current = right;
        while current != left {
            let Some((previous, reason)) = parent[current].clone() else {
                return Err(RollbackEufError::MissingExplanationPath { left, right });
            };
            match reason {
                EqualityReason::Literal(literal) => {
                    literals.insert(literal);
                }
                EqualityReason::Congruence(left_application, right_application) => {
                    let left_term = &self.arena.terms[left_application];
                    let right_term = &self.arena.terms[right_application];
                    if left_term.fun != right_term.fun
                        || left_term.args.len() != right_term.args.len()
                    {
                        return Err(RollbackEufError::MissingExplanationPath { left, right });
                    }
                    for (&left_arg, &right_arg) in left_term.args.iter().zip(&right_term.args) {
                        self.explain_equal(left_arg, right_arg, literals, expanded, edge_visits)?;
                    }
                }
            }
            current = previous;
        }
        Ok(())
    }
}

fn normalized_pair(left: TermId, right: TermId) -> (TermId, TermId) {
    if left <= right {
        (left, right)
    } else {
        (right, left)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy, Debug)]
    enum ReferenceFact {
        Equality(TermId, TermId),
        Disequality(TermId, TermId),
    }

    fn reference_closure(arena: &TermArena, facts: &[Vec<ReferenceFact>]) -> UnionFind {
        let mut uf = UnionFind::new(arena.terms.len());
        for fact in facts.iter().flatten() {
            if let ReferenceFact::Equality(left, right) = fact {
                uf.union(*left, *right);
            }
        }
        congruence_closure(arena, &mut uf);
        uf
    }

    fn reference_conflict(uf: &mut UnionFind, facts: &[Vec<ReferenceFact>]) -> bool {
        facts.iter().flatten().any(|fact| match fact {
            ReferenceFact::Equality(_, _) => false,
            ReferenceFact::Disequality(left, right) => uf.find(*left) == uf.find(*right),
        })
    }

    fn sample_arena() -> (TermArena, Vec<TermId>) {
        let sort = SortId(1);
        let mut arena = TermArena::default();
        let a = arena.intern_typed(1, vec![], sort);
        let b = arena.intern_typed(2, vec![], sort);
        let c = arena.intern_typed(3, vec![], sort);
        let fa = arena.intern_typed(10, vec![a], sort);
        let fb = arena.intern_typed(10, vec![b], sort);
        let fc = arena.intern_typed(10, vec![c], sort);
        let gfa = arena.intern_typed(11, vec![fa], sort);
        let gfb = arena.intern_typed(11, vec![fb], sort);
        (arena, vec![a, b, c, fa, fb, fc, gfa, gfb])
    }

    #[test]
    fn congruence_conflict_has_a_replayable_minimal_path() {
        let (arena, terms) = sample_arena();
        let [a, b, _c, fa, fb, _fc, gfa, gfb] = terms[..] else {
            unreachable!()
        };
        let mut euf = RollbackEuf::new(&arena, RollbackEufLimits::default()).unwrap();

        euf.push_level();
        assert_eq!(euf.assert_equality(a, b, 1).unwrap(), None);
        assert!(euf.equal(fa, fb).unwrap());
        assert!(euf.equal(gfa, gfb).unwrap());
        let conflict = euf.assert_disequality(gfa, gfb, -2).unwrap().unwrap();

        assert_eq!(conflict.antecedents(), &[-2, 1]);
        assert_eq!(conflict.clause(), &[-1, 2]);
        assert!(euf.replay_conflict(&conflict));
        euf.rollback_to(0).unwrap();
        assert!(!euf.equal(a, b).unwrap());
        assert!(!euf.equal(fa, fb).unwrap());
        assert_eq!(euf.current_conflict().unwrap(), None);
    }

    #[test]
    fn permanent_distinct_axiom_replays_without_a_literal() {
        let (arena, terms) = sample_arena();
        let [a, b, ..] = terms[..] else {
            unreachable!()
        };
        let mut euf = RollbackEuf::new(&arena, RollbackEufLimits::default()).unwrap();
        assert_eq!(euf.assume_distinct_axiom(a, b).unwrap(), None);

        let conflict = euf.assert_equality(a, b, 7).unwrap().unwrap();
        assert_eq!(conflict.antecedents(), &[7]);
        assert_eq!(conflict.clause(), &[-7]);
        assert!(euf.replay_conflict(&conflict));
    }

    #[test]
    fn work_cap_rolls_back_the_entire_assertion() {
        let (arena, terms) = sample_arena();
        let [a, b, _c, fa, fb, ..] = terms[..] else {
            unreachable!()
        };
        let limits = RollbackEufLimits {
            max_signature_pair_checks: 0,
            ..RollbackEufLimits::default()
        };
        let mut euf = RollbackEuf::new(&arena, limits).unwrap();

        assert!(matches!(
            euf.assert_equality(a, b, 1),
            Err(RollbackEufError::SignaturePairLimitExceeded { .. })
        ));
        assert!(!euf.equal(a, b).unwrap());
        assert!(!euf.equal(fa, fb).unwrap());
        assert!(euf.active_facts.is_empty());
    }

    #[test]
    fn malformed_inputs_fail_before_mutation() {
        let mut arena = TermArena::default();
        let left = arena.intern_typed(1, vec![], SortId(1));
        let right = arena.intern_typed(2, vec![], SortId(2));
        let mut euf = RollbackEuf::new(&arena, RollbackEufLimits::default()).unwrap();

        assert!(matches!(
            euf.assert_equality(left, right, 1),
            Err(RollbackEufError::SortMismatch { .. })
        ));
        assert!(matches!(
            euf.assert_equality(left, left, 0),
            Err(RollbackEufError::InvalidLiteral(0))
        ));
        assert!(euf.active_facts.is_empty());
    }

    #[test]
    fn rollback_releases_literal_variables_for_reuse() {
        let (arena, terms) = sample_arena();
        let [a, b, c, ..] = terms[..] else {
            unreachable!()
        };
        let mut euf = RollbackEuf::new(&arena, RollbackEufLimits::default()).unwrap();

        euf.push_level();
        assert_eq!(euf.assert_equality(a, b, 9).unwrap(), None);
        assert!(matches!(
            euf.assert_disequality(a, c, -9),
            Err(RollbackEufError::DuplicateLiteralVariable(9))
        ));
        euf.rollback_to(0).unwrap();
        assert_eq!(euf.assert_disequality(a, c, -9).unwrap(), None);
    }

    #[test]
    fn explanation_caps_and_tampering_fail_closed() {
        let (arena, terms) = sample_arena();
        let [a, b, c, ..] = terms[..] else {
            unreachable!()
        };
        let limits = RollbackEufLimits {
            max_clause_width: 2,
            ..RollbackEufLimits::default()
        };
        let mut capped = RollbackEuf::new(&arena, limits).unwrap();
        assert_eq!(capped.assert_equality(a, b, 1).unwrap(), None);
        assert_eq!(capped.assert_equality(b, c, 2).unwrap(), None);
        assert!(matches!(
            capped.assert_disequality(a, c, -3),
            Err(RollbackEufError::ClauseWidthLimitExceeded { width: 3, limit: 2 })
        ));

        let limits = RollbackEufLimits {
            max_explanation_edges: 0,
            ..RollbackEufLimits::default()
        };
        let mut capped = RollbackEuf::new(&arena, limits).unwrap();
        assert_eq!(capped.assert_equality(a, b, 1).unwrap(), None);
        assert!(matches!(
            capped.assert_disequality(a, b, -2),
            Err(RollbackEufError::ExplanationEdgeLimitExceeded {
                visits: 1,
                limit: 0
            })
        ));

        let mut checked = RollbackEuf::new(&arena, RollbackEufLimits::default()).unwrap();
        assert_eq!(checked.assert_equality(a, b, 1).unwrap(), None);
        let conflict = checked.assert_disequality(a, b, -2).unwrap().unwrap();
        assert!(checked.replay_conflict(&conflict));

        let mut tampered = conflict.clone();
        tampered.clause[0] = 17;
        assert!(!checked.replay_conflict(&tampered));
        let mut duplicated = conflict.clone();
        duplicated.antecedents.insert(1, duplicated.antecedents[0]);
        duplicated.clause = duplicated
            .antecedents
            .iter()
            .map(|literal| -*literal)
            .collect();
        duplicated.clause.sort_unstable();
        assert!(!checked.replay_conflict(&duplicated));
    }

    #[test]
    fn fact_and_level_caps_reject_without_mutation() {
        let (arena, terms) = sample_arena();
        let [a, b, c, ..] = terms[..] else {
            unreachable!()
        };
        let limits = RollbackEufLimits {
            max_facts: 1,
            ..RollbackEufLimits::default()
        };
        let mut euf = RollbackEuf::new(&arena, limits).unwrap();
        assert_eq!(euf.assert_equality(a, b, 1).unwrap(), None);
        assert!(matches!(
            euf.assert_equality(b, c, 2),
            Err(RollbackEufError::FactLimitExceeded { facts: 2, limit: 1 })
        ));
        assert!(!euf.equal(a, c).unwrap());
        assert!(matches!(
            euf.rollback_to(1),
            Err(RollbackEufError::InvalidRollbackLevel {
                requested: 1,
                current: 0
            })
        ));
    }

    #[derive(Clone, Copy)]
    struct XorShift64(u64);

    impl XorShift64 {
        fn next(&mut self) -> u64 {
            let mut value = self.0;
            value ^= value << 13;
            value ^= value >> 7;
            value ^= value << 17;
            self.0 = value;
            value
        }

        fn index(&mut self, bound: usize) -> usize {
            (self.next() as usize) % bound
        }
    }

    fn generated_arena(seed: u64) -> TermArena {
        let mut rng = XorShift64(seed | 1);
        let sort = SortId(1);
        let mut arena = TermArena::default();
        let mut terms = Vec::new();
        for symbol in 0..6 {
            terms.push(arena.intern_typed(symbol, vec![], sort));
        }
        for step in 0..30 {
            let arity = 1 + rng.index(3);
            let mut args = Vec::with_capacity(arity);
            for _ in 0..arity {
                args.push(terms[rng.index(terms.len())]);
            }
            let function = 100 + (step % 5) as u32;
            let term = arena.intern_typed(function, args, sort);
            terms.push(term);
        }
        arena
    }

    #[test]
    fn randomized_assignment_and_backtrack_traces_match_fresh_closure() {
        for seed in 1..=64 {
            let arena = generated_arena(seed);
            let mut euf = RollbackEuf::new(&arena, RollbackEufLimits::default()).unwrap();
            let mut reference_levels: Vec<Vec<ReferenceFact>> = vec![Vec::new()];
            let mut rng = XorShift64(seed * 0x9e37_79b9);
            let mut literal = 1i32;

            for _step in 0..160 {
                match rng.index(10) {
                    0 | 1 if euf.level() < 8 => {
                        euf.push_level();
                        reference_levels.push(Vec::new());
                    }
                    2 if euf.level() > 0 => {
                        let target = rng.index(euf.level());
                        euf.rollback_to(target).unwrap();
                        reference_levels.truncate(target + 1);
                    }
                    operation => {
                        let left = rng.index(arena.terms.len());
                        let right = rng.index(arena.terms.len());
                        if operation % 3 == 0 {
                            let signed = -literal;
                            let _ = euf.assert_disequality(left, right, signed).unwrap();
                            reference_levels
                                .last_mut()
                                .unwrap()
                                .push(ReferenceFact::Disequality(left, right));
                        } else {
                            let _ = euf.assert_equality(left, right, literal).unwrap();
                            reference_levels
                                .last_mut()
                                .unwrap()
                                .push(ReferenceFact::Equality(left, right));
                        }
                        literal += 1;
                    }
                }

                let mut reference = reference_closure(&arena, &reference_levels);
                for left in 0..arena.terms.len() {
                    for right in 0..arena.terms.len() {
                        assert_eq!(
                            euf.equal(left, right).unwrap(),
                            reference.find(left) == reference.find(right),
                            "seed={seed} left={left} right={right}"
                        );
                    }
                }
                let expected_conflict = reference_conflict(&mut reference, &reference_levels);
                let conflict = euf.current_conflict().unwrap();
                assert_eq!(conflict.is_some(), expected_conflict, "seed={seed}");
                if let Some(conflict) = conflict {
                    assert!(euf.replay_conflict(&conflict), "seed={seed}");
                }
            }
        }
    }
}
