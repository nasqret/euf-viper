//! A simple wrapper for the Kissat SAT solver.
//!
//! Kissat is a state of the art SAT solver by Armin Biere and others. It is
//! written in C rather than C++, unlike CaDiCaL (upon which it is based) and
//! older solvers such as minisat and glucose. This makes it particularly nice
//! to embed in Rust.
//!
//! This crate builds the entire source code of Kissat, and provides a safe
//! interface over it.
//!
//! ```rust
//! extern crate kissat;
//! fn main() {
//!     let mut solver = kissat::Solver::new();
//!     let a = solver.var();
//!     let b = solver.var();
//!     solver.add2(a, !b);
//!     solver.add1(b);
//!     match solver.sat() {
//!         Some(solution) => println!("SAT: {:?} {:?}", solution.get(a), solution.get(b)),
//!         None => println!("UNSAT"),
//!     }
//! }
//! ```

use std::mem;
use std::ops::Not;
use std::os::raw::c_int;

#[repr(C)]
struct kissat {
    _unused: [u8; 0],
}

extern "C" {
    fn kissat_init() -> *mut kissat;
    fn kissat_add(solver: *mut kissat, lit: c_int);
    fn kissat_set_conflict_limit(solver: *mut kissat, limit: u32);
    fn kissat_solve(solver: *mut kissat) -> c_int;
    fn kissat_value(solver: *mut kissat, lit: c_int) -> c_int;
    fn kissat_release(solver: *mut kissat);
}

/// A single literal or its negation
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Var {
    id: c_int,
}

impl Not for Var {
    type Output = Var;

    fn not(self) -> Var {
        Var { id: -self.id }
    }
}

/// A SAT problem under construction
pub struct Solver {
    p: *mut kissat,
    n_vars: c_int,
}

impl Solver {
    /// Create a new solver instance
    pub fn new() -> Solver {
        unsafe {
            let p = kissat_init();
            assert!(!p.is_null());
            Solver { p, n_vars: 0 }
        }
    }

    /// Create a new literal
    pub fn var(&mut self) -> Var {
        let id = self.n_vars + 1;
        assert!(id != 1 << 28);
        self.n_vars = id;
        Var { id }
    }

    /// Assert a literal should be true in the solution
    pub fn add1(&mut self, a: Var) {
        unsafe {
            kissat_add(self.p, a.id);
            kissat_add(self.p, 0);
        }
    }

    /// Assert `a or b` should be true in the solution
    pub fn add2(&mut self, a: Var, b: Var) {
        unsafe {
            kissat_add(self.p, a.id);
            kissat_add(self.p, b.id);
            kissat_add(self.p, 0);
        }
    }

    /// Assert `a or b or c` should be true in the solution
    pub fn add3(&mut self, a: Var, b: Var, c: Var) {
        unsafe {
            kissat_add(self.p, a.id);
            kissat_add(self.p, b.id);
            kissat_add(self.p, c.id);
            kissat_add(self.p, 0);
        }
    }

    /// Add an assertion for an arbitrarily long clause
    pub fn add(&mut self, x: &[Var]) {
        unsafe {
            for v in x {
                kissat_add(self.p, v.id);
            }
            kissat_add(self.p, 0);
        }
    }

    fn solve_with_conflict_limit(
        self,
        conflict_limit: Option<u32>,
    ) -> Result<Option<Solution>, ()> {
        unsafe {
            if let Some(limit) = conflict_limit {
                kissat_set_conflict_limit(self.p, limit);
            }
            let ret = kissat_solve(self.p);
            match ret {
                10 => {
                    let p = self.p;
                    mem::forget(self);
                    Ok(Some(Solution { p }))
                }
                20 => Ok(None),
                0 => Err(()),
                _ => Err(()),
            }
        }
    }

    /// Solve the instance, returning either `Some(Solution)` if the problem is
    /// SAT or `None` if the problem is UNSAT.
    pub fn sat(self) -> Option<Solution> {
        self.solve_with_conflict_limit(None)
            .expect("unlimited Kissat solve returned UNKNOWN")
    }

    /// Solve under a conflict budget. `Err(())` is an explicit UNKNOWN result.
    pub fn sat_limited(self, conflict_limit: u32) -> Result<Option<Solution>, ()> {
        self.solve_with_conflict_limit(Some(conflict_limit))
    }

    /// Create a new literal that is true if `a and b`
    pub fn and(&mut self, a: Var, b: Var) -> Var {
        let z = self.var();
        self.add3(!a, !b, z);
        self.add2(a, !z);
        self.add2(b, !z);
        z
    }

    /// Create a new literal that is true if `a or b`
    pub fn or(&mut self, a: Var, b: Var) -> Var {
        let z = self.var();
        self.add3(a, b, !z);
        self.add2(!a, z);
        self.add2(!b, z);
        z
    }

    /// Create a new literal that is true if `a xor b`
    pub fn xor(&mut self, a: Var, b: Var) -> Var {
        let z = self.var();
        self.add3(!a, !b, !z);
        self.add3(a, b, !z);
        self.add3(a, !b, z);
        self.add3(!a, b, z);
        z
    }

    /// Assert that two literals should be equal in the solution
    pub fn eq(&mut self, a: Var, b: Var) {
        self.add2(a, !b);
        self.add2(!a, b);
    }

    /// Create a new literal that if `i ? t : e` (if-then-else)
    pub fn ite(&mut self, i: Var, t: Var, e: Var) -> Var {
        let z = self.var();
        self.add3(!e, i, z);
        self.add3(e, i, !z);
        self.add3(!i, !t, z);
        self.add3(!i, t, !z);
        z
    }
}

impl Default for Solver {
    fn default() -> Solver {
        Solver::new()
    }
}

impl Drop for Solver {
    fn drop(&mut self) {
        unsafe {
            kissat_release(self.p);
        }
    }
}

/// A solved SAT instance, for a problem which is satisfiable
pub struct Solution {
    p: *mut kissat,
}

impl Solution {
    /// Return the assigned value for a given variable, this can be `None`
    /// if it's is don't care for this solution.
    pub fn get(&self, x: Var) -> Option<bool> {
        let ret;
        unsafe {
            ret = kissat_value(self.p, x.id);
        }
        match ret {
            i if i == x.id => Some(true),
            i if i == -x.id => Some(false),
            0 => None,
            _ => unreachable!(),
        }
    }
}

impl Drop for Solution {
    fn drop(&mut self) {
        unsafe {
            kissat_release(self.p);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Solver;

    #[test]
    fn sat() {
        let mut solver = Solver::new();
        let a = solver.var();
        let b = solver.var();
        solver.add(&[a, b]);
        solver.add(&[a, !b]);
        solver.add(&[!a, !b]);
        let solution = solver.sat();
        assert!(solution.is_some());
        let solution = solution.unwrap();
        assert!(solution.get(a) == Some(true));
        assert!(solution.get(b) == Some(false));
    }

    #[test]
    fn unsat() {
        let mut solver = Solver::new();
        let a = solver.var();
        let b = solver.var();
        solver.add(&[a, b]);
        solver.add(&[a, !b]);
        solver.add(&[!a, !b]);
        solver.add(&[b]);
        let solution = solver.sat();
        assert!(solution.is_none());
    }

    #[test]
    fn limited_solve_reports_unknown_without_conflating_it_with_unsat() {
        let mut solver = Solver::new();
        let a = solver.var();
        let b = solver.var();
        solver.add(&[a, b]);
        assert!(solver.sat_limited(0).is_err());
    }

    #[test]
    fn limited_solve_preserves_terminal_results() {
        let mut sat_solver = Solver::new();
        let a = sat_solver.var();
        sat_solver.add1(a);
        assert!(matches!(sat_solver.sat_limited(10), Ok(Some(_))));

        let mut unsat_solver = Solver::new();
        let b = unsat_solver.var();
        unsat_solver.add1(b);
        unsat_solver.add1(!b);
        assert!(matches!(unsat_solver.sat_limited(10), Ok(None)));
    }

    #[test]
    fn miter_mux2() {
        let mut solver = Solver::new();
        let i = solver.var();
        let t = solver.var();
        let e = solver.var();
        // mux2
        let a = solver.ite(i, t, e);
        // constructed manually
        let tmp1 = solver.and(i, t);
        let tmp2 = solver.and(!i, e);
        let b = solver.or(tmp1, tmp2);
        // miter
        let tmp = solver.xor(a, b);
        solver.add1(tmp);
        // should be unsat
        let solution = solver.sat();
        assert!(solution.is_none());
    }

    #[test]
    fn miter_buggy_mux2() {
        let mut solver = Solver::new();
        let i = solver.var();
        let t = solver.var();
        let e = solver.var();
        // mux2
        let a = solver.ite(i, t, e);
        // buggy impl
        let b = solver.and(i, t);
        // miter
        let tmp = solver.xor(a, b);
        solver.add1(tmp);
        // should be sat
        let solution = solver.sat();
        assert!(solution.is_some());
    }
}
