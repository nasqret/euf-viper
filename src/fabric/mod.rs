#![deny(unsafe_code)]
#![allow(dead_code)]

//! Proof-reconfigurable QF_UF research engine.
//!
//! Fabric remains isolated from the production solve path until its fixed
//! engines and proof checker pass the campaign gates.

pub(crate) mod action;
pub(crate) mod action_nogood;
pub(crate) mod bool_cnf;
pub(crate) mod cadical_up;
pub(crate) mod certificate;
pub(crate) mod component;
pub(crate) mod congruence;
pub(crate) mod cover;
pub(crate) mod domain_proof;
pub(crate) mod domain_watch;
pub(crate) mod engine;
pub(crate) mod finite_hall;
pub(crate) mod finite_oracle;
pub(crate) mod generated_differential;
pub(crate) mod impact;
pub(crate) mod incremental_congruence;
pub(crate) mod latin_exact_cover;
pub(crate) mod learned_clause;
pub(crate) mod learning;
pub(crate) mod model;
pub(crate) mod native_clause;
pub(crate) mod partition;
pub(crate) mod proof;
pub(crate) mod semantic;
pub(crate) mod signature;
pub(crate) mod theory_atom_index;
pub(crate) mod theory_reason;
pub(crate) mod trail;
pub(crate) mod watch;
