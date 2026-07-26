#![forbid(unsafe_code)]

//! Deterministic root-level unit compilation for native CNF.
//!
//! The pass executes only propositional unit propagation. Every assignment
//! records the input clause that forced it, and [`verify`] replays those steps
//! without trusting the compiler. Fixed source atoms are retained as unit
//! clauses so an external theory propagator still sees their assignments.

use super::bool_cnf::NativeFormula;
use super::native_clause::{AtomId, Lit};
use rustc_hash::FxHashSet;
use std::collections::VecDeque;
use std::error::Error;
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct UnitStep {
    pub(crate) literal: Lit,
    pub(crate) reason_clause: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UnitCertificate {
    pub(crate) steps: Box<[UnitStep]>,
    pub(crate) conflict_clause: Option<usize>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct RootSimplificationStats {
    pub(crate) input_clauses: usize,
    pub(crate) input_literals: usize,
    pub(crate) fixed_atoms: usize,
    pub(crate) fixed_source_atoms: usize,
    pub(crate) fixed_auxiliary_atoms: usize,
    pub(crate) removed_clauses: usize,
    pub(crate) removed_literals: usize,
    pub(crate) output_clauses: usize,
    pub(crate) output_literals: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RootSimplification {
    pub(crate) formula: NativeFormula,
    pub(crate) fixed_values: Box<[Option<bool>]>,
    pub(crate) certificate: UnitCertificate,
    pub(crate) stats: RootSimplificationStats,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RootSimplificationOutcome {
    Reduced(RootSimplification),
    Unsat {
        fixed_values: Box<[Option<bool>]>,
        certificate: UnitCertificate,
        stats: RootSimplificationStats,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RootSimplificationError {
    AtomOutOfRange {
        atom: AtomId,
        atom_count: usize,
    },
    InvalidSourceCount {
        source_atom_count: usize,
        atom_count: usize,
    },
    CountOverflow(&'static str),
    InvalidCertificate(&'static str),
}

impl fmt::Display for RootSimplificationError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AtomOutOfRange { atom, atom_count } => write!(
                output,
                "native atom {} is outside the formula range 0..{atom_count}",
                atom.index()
            ),
            Self::InvalidSourceCount {
                source_atom_count,
                atom_count,
            } => write!(
                output,
                "source atom count {source_atom_count} exceeds native atom count {atom_count}"
            ),
            Self::CountOverflow(resource) => {
                write!(output, "root simplification {resource} count overflowed")
            }
            Self::InvalidCertificate(message) => {
                write!(output, "invalid root simplification certificate: {message}")
            }
        }
    }
}

impl Error for RootSimplificationError {}

pub(crate) fn simplify(
    formula: &NativeFormula,
) -> Result<RootSimplificationOutcome, RootSimplificationError> {
    simplify_internal(formula, false)
}

pub(crate) fn simplify_with_checker_materialization(
    formula: &NativeFormula,
) -> Result<RootSimplificationOutcome, RootSimplificationError> {
    simplify_internal(formula, true)
}

fn simplify_internal(
    formula: &NativeFormula,
    checker_materializes_reduction: bool,
) -> Result<RootSimplificationOutcome, RootSimplificationError> {
    validate_formula(formula)?;
    let input_literals = formula
        .clauses
        .iter()
        .try_fold(0usize, |total, clause| total.checked_add(clause.len()))
        .ok_or(RootSimplificationError::CountOverflow("input literal"))?;
    let mut stats = RootSimplificationStats {
        input_clauses: formula.clauses.len(),
        input_literals,
        ..RootSimplificationStats::default()
    };

    let occurrence_slots = formula
        .atom_count
        .checked_mul(2)
        .ok_or(RootSimplificationError::CountOverflow("occurrence slot"))?;
    let mut occurrences = vec![Vec::<usize>::new(); occurrence_slots];
    let mut remaining = Vec::with_capacity(formula.clauses.len());
    let mut satisfied = vec![false; formula.clauses.len()];
    let mut pending = VecDeque::new();

    for (clause_index, clause) in formula.clauses.iter().enumerate() {
        remaining.push(clause.len());
        if clause.is_empty() {
            return Ok(RootSimplificationOutcome::Unsat {
                fixed_values: vec![None; formula.atom_count].into_boxed_slice(),
                certificate: UnitCertificate {
                    steps: Box::new([]),
                    conflict_clause: Some(clause_index),
                },
                stats,
            });
        }
        if clause.len() == 1 {
            pending.push_back(UnitStep {
                literal: clause[0],
                reason_clause: clause_index,
            });
        }
        for &literal in clause.iter() {
            occurrences[occurrence_index(literal)].push(clause_index);
        }
    }

    let mut values = vec![None; formula.atom_count];
    let mut steps = Vec::new();
    while let Some(step) = pending.pop_front() {
        let atom = step.literal.atom().index();
        let value = step.literal.is_positive();
        match values[atom] {
            Some(current) if current == value => continue,
            Some(_) => {
                return finish_unsat(formula, values, steps, step.reason_clause, stats);
            }
            None => {}
        }
        values[atom] = Some(value);
        steps.push(step);

        let true_literal = step.literal;
        for &clause_index in &occurrences[occurrence_index(true_literal)] {
            satisfied[clause_index] = true;
        }
        let false_literal = true_literal.negate();
        for &clause_index in &occurrences[occurrence_index(false_literal)] {
            if satisfied[clause_index] {
                continue;
            }
            remaining[clause_index] = remaining[clause_index].checked_sub(1).ok_or(
                RootSimplificationError::InvalidCertificate("clause remaining count underflowed"),
            )?;
            match remaining[clause_index] {
                0 => {
                    return finish_unsat(formula, values, steps, clause_index, stats);
                }
                1 => {
                    let literal = formula.clauses[clause_index]
                        .iter()
                        .copied()
                        .find(|literal| values[literal.atom().index()].is_none())
                        .ok_or(RootSimplificationError::InvalidCertificate(
                            "unit clause has no unassigned literal",
                        ))?;
                    pending.push_back(UnitStep {
                        literal,
                        reason_clause: clause_index,
                    });
                }
                _ => {}
            }
        }
    }

    populate_assignment_stats(formula, &values, &mut stats);
    let certificate = UnitCertificate {
        steps: steps.into_boxed_slice(),
        conflict_clause: None,
    };
    let final_values = if checker_materializes_reduction {
        let replay = replay_unit_certificate(formula, &certificate)?;
        if replay.as_slice() != values.as_slice() {
            return Err(RootSimplificationError::InvalidCertificate(
                "compiler values differ from replayed unit assignments",
            ));
        }
        replay
    } else {
        values
    };
    let clauses = reduce_clauses(formula, &final_values)?;
    let output_literals = clauses
        .iter()
        .try_fold(0usize, |total, clause| total.checked_add(clause.len()))
        .ok_or(RootSimplificationError::CountOverflow("output literal"))?;
    stats.output_clauses = clauses.len();
    stats.output_literals = output_literals;
    stats.removed_clauses = stats.input_clauses.saturating_sub(stats.output_clauses);
    stats.removed_literals = stats.input_literals.saturating_sub(stats.output_literals);
    let reduced = RootSimplification {
        formula: NativeFormula {
            atom_count: formula.atom_count,
            clauses,
            source_atom_count: formula.source_atom_count,
            auxiliary_atom_count: formula.auxiliary_atom_count,
        },
        fixed_values: final_values.into_boxed_slice(),
        certificate,
        stats,
    };
    if !checker_materializes_reduction {
        verify(
            formula,
            &RootSimplificationOutcome::Reduced(reduced.clone()),
        )?;
    }
    Ok(RootSimplificationOutcome::Reduced(reduced))
}

fn finish_unsat(
    formula: &NativeFormula,
    values: Vec<Option<bool>>,
    steps: Vec<UnitStep>,
    conflict_clause: usize,
    mut stats: RootSimplificationStats,
) -> Result<RootSimplificationOutcome, RootSimplificationError> {
    populate_assignment_stats(formula, &values, &mut stats);
    stats.removed_clauses = stats.input_clauses;
    stats.removed_literals = stats.input_literals;
    let outcome = RootSimplificationOutcome::Unsat {
        fixed_values: values.into_boxed_slice(),
        certificate: UnitCertificate {
            steps: steps.into_boxed_slice(),
            conflict_clause: Some(conflict_clause),
        },
        stats,
    };
    verify(formula, &outcome)?;
    Ok(outcome)
}

fn reduce_clauses(
    formula: &NativeFormula,
    values: &[Option<bool>],
) -> Result<Box<[Box<[Lit]>]>, RootSimplificationError> {
    let mut reduced = FxHashSet::default();
    for clause in formula.clauses.iter() {
        if clause
            .iter()
            .copied()
            .any(|literal| values[literal.atom().index()] == Some(literal.is_positive()))
        {
            continue;
        }
        let remaining = clause
            .iter()
            .copied()
            .filter(|literal| values[literal.atom().index()].is_none())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        if remaining.is_empty() {
            return Err(RootSimplificationError::InvalidCertificate(
                "reduced satisfiable formula contains an empty clause",
            ));
        }
        reduced.insert(remaining);
    }
    for (index, value) in values
        .iter()
        .copied()
        .enumerate()
        .take(formula.source_atom_count)
    {
        if let Some(value) = value {
            let atom = AtomId::new(index as u32);
            reduced.insert(Box::new([if value {
                Lit::positive(atom)
            } else {
                Lit::negative(atom)
            }]));
        }
    }
    let mut clauses = reduced.into_iter().collect::<Vec<_>>();
    clauses.sort_unstable();
    Ok(clauses.into_boxed_slice())
}

pub(crate) fn verify(
    formula: &NativeFormula,
    outcome: &RootSimplificationOutcome,
) -> Result<(), RootSimplificationError> {
    validate_formula(formula)?;
    let (fixed_values, certificate) = match outcome {
        RootSimplificationOutcome::Reduced(reduced) => {
            (&reduced.fixed_values, &reduced.certificate)
        }
        RootSimplificationOutcome::Unsat {
            fixed_values,
            certificate,
            ..
        } => (fixed_values, certificate),
    };
    if fixed_values.len() != formula.atom_count {
        return Err(RootSimplificationError::InvalidCertificate(
            "fixed-value vector has the wrong length",
        ));
    }

    let replay = replay_unit_certificate(formula, certificate)?;
    if replay.as_slice() != fixed_values.as_ref() {
        return Err(RootSimplificationError::InvalidCertificate(
            "fixed values differ from replayed unit assignments",
        ));
    }

    match outcome {
        RootSimplificationOutcome::Unsat { .. } => {
            let conflict =
                certificate
                    .conflict_clause
                    .ok_or(RootSimplificationError::InvalidCertificate(
                        "UNSAT has no conflict clause",
                    ))?;
            let clause = formula.clauses.get(conflict).ok_or(
                RootSimplificationError::InvalidCertificate("conflict clause is out of range"),
            )?;
            if clause
                .iter()
                .any(|literal| replay[literal.atom().index()] != Some(!literal.is_positive()))
            {
                return Err(RootSimplificationError::InvalidCertificate(
                    "conflict clause is not false under replayed units",
                ));
            }
        }
        RootSimplificationOutcome::Reduced(reduced) => {
            if certificate.conflict_clause.is_some() {
                return Err(RootSimplificationError::InvalidCertificate(
                    "reduced formula retains a conflict clause",
                ));
            }
            let expected = reduce_clauses(formula, &replay)?;
            if expected != reduced.formula.clauses {
                return Err(RootSimplificationError::InvalidCertificate(
                    "reduced clauses differ from replayed simplification",
                ));
            }
        }
    }
    Ok(())
}

fn replay_unit_certificate(
    formula: &NativeFormula,
    certificate: &UnitCertificate,
) -> Result<Vec<Option<bool>>, RootSimplificationError> {
    let mut replay = vec![None; formula.atom_count];
    for step in certificate.steps.iter().copied() {
        let clause = formula.clauses.get(step.reason_clause).ok_or(
            RootSimplificationError::InvalidCertificate("unit reason clause is out of range"),
        )?;
        let mut unassigned = None;
        for &literal in clause.iter() {
            match replay[literal.atom().index()] {
                Some(value) if value == literal.is_positive() => {
                    return Err(RootSimplificationError::InvalidCertificate(
                        "unit reason is already satisfied",
                    ));
                }
                Some(_) => {}
                None if unassigned.is_none() => unassigned = Some(literal),
                None => {
                    return Err(RootSimplificationError::InvalidCertificate(
                        "unit reason has multiple unassigned literals",
                    ));
                }
            }
        }
        if unassigned != Some(step.literal) {
            return Err(RootSimplificationError::InvalidCertificate(
                "unit reason does not force the recorded literal",
            ));
        }
        let slot = &mut replay[step.literal.atom().index()];
        if slot.is_some() {
            return Err(RootSimplificationError::InvalidCertificate(
                "certificate assigns an atom twice",
            ));
        }
        *slot = Some(step.literal.is_positive());
    }
    Ok(replay)
}

fn validate_formula(formula: &NativeFormula) -> Result<(), RootSimplificationError> {
    if formula.source_atom_count > formula.atom_count {
        return Err(RootSimplificationError::InvalidSourceCount {
            source_atom_count: formula.source_atom_count,
            atom_count: formula.atom_count,
        });
    }
    for clause in formula.clauses.iter() {
        for &literal in clause.iter() {
            if literal.atom().index() >= formula.atom_count {
                return Err(RootSimplificationError::AtomOutOfRange {
                    atom: literal.atom(),
                    atom_count: formula.atom_count,
                });
            }
        }
    }
    Ok(())
}

fn populate_assignment_stats(
    formula: &NativeFormula,
    values: &[Option<bool>],
    stats: &mut RootSimplificationStats,
) {
    stats.fixed_atoms = values.iter().filter(|value| value.is_some()).count();
    stats.fixed_source_atoms = values
        .iter()
        .take(formula.source_atom_count)
        .filter(|value| value.is_some())
        .count();
    stats.fixed_auxiliary_atoms = stats.fixed_atoms.saturating_sub(stats.fixed_source_atoms);
}

fn occurrence_index(literal: Lit) -> usize {
    literal.atom().index() * 2 + usize::from(literal.is_positive())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn atom(index: u32) -> AtomId {
        AtomId::new(index)
    }

    fn formula(source_atoms: usize, clauses: Vec<Vec<Lit>>) -> NativeFormula {
        let atom_count = clauses
            .iter()
            .flatten()
            .map(|literal| literal.atom().index() + 1)
            .max()
            .unwrap_or(source_atoms)
            .max(source_atoms);
        NativeFormula {
            atom_count,
            clauses: clauses
                .into_iter()
                .map(Vec::into_boxed_slice)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            source_atom_count: source_atoms,
            auxiliary_atom_count: atom_count - source_atoms,
        }
    }

    fn evaluates(formula: &NativeFormula, assignment: usize) -> bool {
        formula.clauses.iter().all(|clause| {
            clause.iter().any(|literal| {
                let value = assignment & (1usize << literal.atom().index()) != 0;
                value == literal.is_positive()
            })
        })
    }

    #[test]
    fn chained_units_are_compiled_and_replayed() {
        let input = formula(
            3,
            vec![
                vec![Lit::positive(atom(0))],
                vec![Lit::negative(atom(0)), Lit::positive(atom(1))],
                vec![Lit::negative(atom(1)), Lit::positive(atom(2))],
                vec![Lit::positive(atom(2)), Lit::positive(atom(3))],
            ],
        );
        let outcome = simplify(&input).unwrap();
        verify(&input, &outcome).unwrap();
        let RootSimplificationOutcome::Reduced(reduced) = outcome else {
            panic!("chain must remain satisfiable");
        };
        assert_eq!(reduced.stats.fixed_atoms, 3);
        assert_eq!(reduced.stats.fixed_source_atoms, 3);
        assert_eq!(reduced.formula.clauses.len(), 3);
        assert!(
            reduced
                .formula
                .clauses
                .iter()
                .all(|clause| clause.len() == 1)
        );
    }

    #[test]
    fn opposite_unit_chain_has_a_replayable_conflict() {
        let input = formula(
            2,
            vec![
                vec![Lit::positive(atom(0))],
                vec![Lit::negative(atom(0)), Lit::positive(atom(1))],
                vec![Lit::negative(atom(1))],
            ],
        );
        let outcome = simplify(&input).unwrap();
        verify(&input, &outcome).unwrap();
        assert!(matches!(outcome, RootSimplificationOutcome::Unsat { .. }));
    }

    #[test]
    fn reduction_preserves_exhaustive_satisfiability() {
        let inputs = [
            formula(
                2,
                vec![
                    vec![Lit::positive(atom(0))],
                    vec![Lit::negative(atom(0)), Lit::positive(atom(1))],
                ],
            ),
            formula(
                2,
                vec![
                    vec![Lit::positive(atom(0)), Lit::positive(atom(1))],
                    vec![Lit::negative(atom(0)), Lit::positive(atom(1))],
                ],
            ),
            formula(
                2,
                vec![vec![Lit::positive(atom(0))], vec![Lit::negative(atom(0))]],
            ),
        ];
        for input in inputs {
            let original_sat =
                (0..(1usize << input.atom_count)).any(|assignment| evaluates(&input, assignment));
            let outcome = simplify(&input).unwrap();
            verify(&input, &outcome).unwrap();
            let reduced_sat = match &outcome {
                RootSimplificationOutcome::Unsat { .. } => false,
                RootSimplificationOutcome::Reduced(reduced) => (0..(1usize
                    << reduced.formula.atom_count))
                    .any(|assignment| evaluates(&reduced.formula, assignment)),
            };
            assert_eq!(original_sat, reduced_sat);
        }
    }

    #[test]
    fn checker_materialization_matches_legacy_outcomes_exactly() {
        let inputs = [
            formula(
                3,
                vec![
                    vec![Lit::positive(atom(0))],
                    vec![Lit::negative(atom(0)), Lit::positive(atom(1))],
                    vec![Lit::negative(atom(1)), Lit::positive(atom(2))],
                    vec![Lit::positive(atom(2)), Lit::positive(atom(3))],
                ],
            ),
            formula(
                2,
                vec![
                    vec![Lit::positive(atom(0)), Lit::positive(atom(1))],
                    vec![Lit::negative(atom(0)), Lit::positive(atom(1))],
                ],
            ),
            formula(
                2,
                vec![vec![Lit::positive(atom(0))], vec![Lit::negative(atom(0))]],
            ),
        ];

        for input in inputs {
            let legacy = simplify(&input).unwrap();
            let checker_owned = simplify_with_checker_materialization(&input).unwrap();
            assert_eq!(checker_owned, legacy);
            verify(&input, &checker_owned).unwrap();
        }
    }

    #[test]
    fn malformed_atom_is_rejected() {
        let mut input = formula(1, vec![vec![Lit::positive(atom(0))]]);
        input.clauses[0][0] = Lit::positive(atom(2));
        assert!(matches!(
            simplify(&input),
            Err(RootSimplificationError::AtomOutOfRange { .. })
        ));
    }
}
