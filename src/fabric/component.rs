use super::partition::TermId;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ComponentId(u32);

impl ComponentId {
    pub(crate) const fn index(self) -> usize {
        self.0 as usize
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ComponentError {
    TooManyTerms(usize),
    UnknownTerm { term: TermId, term_count: usize },
}

impl fmt::Display for ComponentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyTerms(count) => {
                write!(
                    formatter,
                    "Fabric supports at most {} terms, got {count}",
                    u32::MAX
                )
            }
            Self::UnknownTerm { term, term_count } => write!(
                formatter,
                "Fabric term {} is outside the term range 0..{term_count}",
                term.index()
            ),
        }
    }
}

#[derive(Debug)]
pub(crate) struct ComponentBuilder {
    parent: Vec<u32>,
}

impl ComponentBuilder {
    pub(crate) fn new(term_count: usize) -> Result<Self, ComponentError> {
        if term_count > u32::MAX as usize {
            return Err(ComponentError::TooManyTerms(term_count));
        }
        Ok(Self {
            parent: (0..term_count).map(|index| index as u32).collect(),
        })
    }

    pub(crate) fn connect(&mut self, left: TermId, right: TermId) -> Result<(), ComponentError> {
        self.validate(left)?;
        self.validate(right)?;
        let left_root = self.root(left.raw());
        let right_root = self.root(right.raw());
        if left_root != right_root {
            let (small, large) = if left_root < right_root {
                (left_root, right_root)
            } else {
                (right_root, left_root)
            };
            self.parent[large as usize] = small;
        }
        Ok(())
    }

    pub(crate) fn connect_all(
        &mut self,
        anchor: TermId,
        terms: impl IntoIterator<Item = TermId>,
    ) -> Result<(), ComponentError> {
        for term in terms {
            self.connect(anchor, term)?;
        }
        Ok(())
    }

    pub(crate) fn finish(mut self) -> ComponentGraph {
        for term in 0..self.parent.len() {
            let root = self.root(term as u32);
            self.parent[term] = root;
        }

        let mut root_to_component = vec![None; self.parent.len()];
        let mut component_count = 0_u32;
        for (term, &root) in self.parent.iter().enumerate() {
            if root as usize == term {
                root_to_component[term] = Some(ComponentId(component_count));
                component_count += 1;
            }
        }

        let owners = self
            .parent
            .iter()
            .map(|&root| root_to_component[root as usize].expect("every root has an ID"))
            .collect::<Vec<_>>();
        let mut offsets = vec![0_usize; component_count as usize + 1];
        for owner in &owners {
            offsets[owner.index() + 1] += 1;
        }
        for index in 1..offsets.len() {
            offsets[index] += offsets[index - 1];
        }
        let mut cursors = offsets[..component_count as usize].to_vec();
        let mut members = vec![TermId::MIN; self.parent.len()];
        for (term, owner) in owners.iter().copied().enumerate() {
            let slot = &mut cursors[owner.index()];
            members[*slot] = TermId::new(term as u32);
            *slot += 1;
        }

        ComponentGraph {
            owners,
            offsets,
            members,
        }
    }

    fn validate(&self, term: TermId) -> Result<(), ComponentError> {
        if term.index() < self.parent.len() {
            Ok(())
        } else {
            Err(ComponentError::UnknownTerm {
                term,
                term_count: self.parent.len(),
            })
        }
    }

    fn root(&self, mut term: u32) -> u32 {
        while self.parent[term as usize] != term {
            term = self.parent[term as usize];
        }
        term
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ComponentGraph {
    owners: Vec<ComponentId>,
    offsets: Vec<usize>,
    members: Vec<TermId>,
}

impl ComponentGraph {
    pub(crate) fn component_count(&self) -> usize {
        self.offsets.len().saturating_sub(1)
    }

    pub(crate) fn owner(&self, term: TermId) -> Option<ComponentId> {
        self.owners.get(term.index()).copied()
    }

    pub(crate) fn members(&self, component: ComponentId) -> Option<&[TermId]> {
        let index = component.index();
        (index < self.component_count())
            .then(|| &self.members[self.offsets[index]..self.offsets[index + 1]])
    }

    pub(crate) fn max_component_size(&self) -> usize {
        self.offsets
            .windows(2)
            .map(|bounds| bounds[1] - bounds[0])
            .max()
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn term(index: usize) -> TermId {
        TermId::try_from(index).unwrap()
    }

    #[test]
    fn isolated_terms_receive_source_order_component_ids() {
        let graph = ComponentBuilder::new(4).unwrap().finish();

        assert_eq!(graph.component_count(), 4);
        for index in 0..4 {
            let owner = graph.owner(term(index)).unwrap();
            assert_eq!(owner.index(), index);
            assert_eq!(graph.members(owner), Some(&[term(index)][..]));
        }
    }

    #[test]
    fn connectivity_is_invariant_under_edge_order() {
        let build = |edges: &[(usize, usize)]| {
            let mut builder = ComponentBuilder::new(6).unwrap();
            for &(left, right) in edges {
                builder.connect(term(left), term(right)).unwrap();
            }
            builder.finish()
        };

        let forward = build(&[(4, 2), (3, 4), (1, 0)]);
        let reverse = build(&[(0, 1), (4, 3), (2, 4)]);

        assert_eq!(forward, reverse);
        assert_eq!(forward.component_count(), 3);
        assert_eq!(
            forward.members(forward.owner(term(4)).unwrap()).unwrap(),
            &[term(2), term(3), term(4)]
        );
        assert_eq!(forward.max_component_size(), 3);
    }

    #[test]
    fn connect_all_builds_a_hyperedge() {
        let mut builder = ComponentBuilder::new(5).unwrap();
        builder
            .connect_all(term(3), [term(0), term(2), term(4)])
            .unwrap();
        let graph = builder.finish();

        assert_eq!(graph.component_count(), 2);
        assert_eq!(
            graph.members(graph.owner(term(0)).unwrap()).unwrap(),
            &[term(0), term(2), term(3), term(4)]
        );
    }

    #[test]
    fn invalid_term_is_rejected_without_mutation() {
        let mut builder = ComponentBuilder::new(2).unwrap();
        let error = builder.connect(term(0), term(2)).unwrap_err();

        assert_eq!(
            error,
            ComponentError::UnknownTerm {
                term: term(2),
                term_count: 2,
            }
        );
        assert_eq!(builder.finish().component_count(), 2);
    }

    #[test]
    fn empty_graph_is_well_formed() {
        let graph = ComponentBuilder::new(0).unwrap().finish();
        assert_eq!(graph.component_count(), 0);
        assert_eq!(graph.max_component_size(), 0);
    }
}
