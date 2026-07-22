#![deny(unsafe_code)]
#![allow(dead_code)]

//! Proof-reconfigurable QF_UF research engine.
//!
//! Fabric remains isolated from the production solve path until its fixed
//! engines and proof checker pass the campaign gates.

pub(crate) mod bool_cnf;
pub(crate) mod component;
pub(crate) mod congruence;
pub(crate) mod cover;
pub(crate) mod engine;
pub(crate) mod model;
pub(crate) mod native_clause;
pub(crate) mod partition;
pub(crate) mod proof;
pub(crate) mod semantic;
pub(crate) mod trail;
