
Kissat SAT solver
=================

A simple wrapper for the Kissat SAT solver.

Kissat is a state of the art SAT solver by Armin Biere and others. It is
written in C rather than C++, unlike CaDiCaL (upon which it is based) and older
solvers such as minisat and glucose. This makes it particularly nice to embed
in Rust.

This crate builds the entire source code of Kissat, and provides a safe
interface over it.

This version is currently tied to the version of kissat that was submitted to
sc2021.
