use crate::{BoolAtomKey, BoolExpr, HashSet, TermId, normalized_pair};

pub(crate) const ENV: &str = "EUF_VIPER_UNCONDITIONAL_QUOTIENT";

const DEFAULT_MAX_TERMS: usize = 1_000_000;
const DEFAULT_MAX_SUPPORTING_FACTS: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    Off,
    Shadow,
    On,
}

impl Mode {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Shadow => "shadow",
            Self::On => "on",
        }
    }
}

pub(crate) fn parse_mode(value: Option<&str>) -> Result<Mode, String> {
    match value {
        None | Some("off") => Ok(Mode::Off),
        Some("shadow") => Ok(Mode::Shadow),
        Some("on") => Ok(Mode::On),
        Some(_) => Err(format!("{ENV} must be off, shadow, or on")),
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

#[derive(Debug, Clone, Copy)]
struct Limits {
    max_terms: usize,
    max_supporting_facts: usize,
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

    #[test]
    fn mode_is_strict_and_defaults_off() {
        assert_eq!(parse_mode(None), Ok(Mode::Off));
        assert_eq!(parse_mode(Some("off")), Ok(Mode::Off));
        assert_eq!(parse_mode(Some("shadow")), Ok(Mode::Shadow));
        assert_eq!(parse_mode(Some("on")), Ok(Mode::On));
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
}
