use std::ffi::CString;
use std::mem;
use std::ops::Not;
use std::os::raw::{c_char, c_int};

#[repr(C)]
struct Kissat {
    _unused: [u8; 0],
}

unsafe extern "C" {
    fn kissat_init() -> *mut Kissat;
    fn kissat_add(solver: *mut Kissat, literal: c_int);
    fn kissat_solve(solver: *mut Kissat) -> c_int;
    fn kissat_value(solver: *mut Kissat, literal: c_int) -> c_int;
    fn kissat_release(solver: *mut Kissat);
    fn kissat_set_configuration(solver: *mut Kissat, name: *const c_char) -> c_int;
    fn kissat_set_option(solver: *mut Kissat, name: *const c_char, value: c_int) -> c_int;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Var {
    id: c_int,
}

impl Not for Var {
    type Output = Self;

    fn not(self) -> Self {
        Self { id: -self.id }
    }
}

pub struct Solver {
    solver: *mut Kissat,
    variables: c_int,
}

impl Solver {
    #[must_use]
    pub fn new() -> Self {
        let solver = unsafe { kissat_init() };
        assert!(!solver.is_null(), "kissat_init returned null");
        Self {
            solver,
            variables: 0,
        }
    }

    pub fn var(&mut self) -> Var {
        self.variables += 1;
        assert!(self.variables < 1 << 28, "Kissat variable limit exceeded");
        Var { id: self.variables }
    }

    pub fn add(&mut self, clause: &[Var]) {
        unsafe {
            for literal in clause {
                kissat_add(self.solver, literal.id);
            }
            kissat_add(self.solver, 0);
        }
    }

    pub fn set_configuration(&mut self, name: &str) -> Result<(), String> {
        let name = CString::new(name).map_err(|_| "configuration contains NUL".to_owned())?;
        let accepted = unsafe { kissat_set_configuration(self.solver, name.as_ptr()) };
        (accepted != 0)
            .then_some(())
            .ok_or_else(|| format!("unknown Kissat configuration: {}", name.to_string_lossy()))
    }

    pub fn set_option(&mut self, name: &str, value: i32) -> Result<i32, String> {
        let name = CString::new(name).map_err(|_| "option contains NUL".to_owned())?;
        let previous = unsafe { kissat_set_option(self.solver, name.as_ptr(), value) };
        Ok(previous)
    }

    #[must_use]
    pub fn sat(self) -> Option<Solution> {
        match unsafe { kissat_solve(self.solver) } {
            10 => {
                let solver = self.solver;
                mem::forget(self);
                Some(Solution { solver })
            }
            20 => None,
            result => panic!("unexpected Kissat result {result}"),
        }
    }
}

impl Default for Solver {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Solver {
    fn drop(&mut self) {
        unsafe { kissat_release(self.solver) };
    }
}

pub struct Solution {
    solver: *mut Kissat,
}

impl Solution {
    #[must_use]
    pub fn get(&self, variable: Var) -> Option<bool> {
        match unsafe { kissat_value(self.solver, variable.id) } {
            value if value == variable.id => Some(true),
            value if value == -variable.id => Some(false),
            0 => None,
            value => panic!("unexpected Kissat value {value}"),
        }
    }
}

impl Drop for Solution {
    fn drop(&mut self) {
        unsafe { kissat_release(self.solver) };
    }
}

#[cfg(test)]
mod tests {
    use super::Solver;

    #[test]
    fn options_and_sat_model_work() {
        let mut solver = Solver::new();
        solver.set_configuration("default").unwrap();
        solver.set_option("congruence", 1).unwrap();
        let a = solver.var();
        let b = solver.var();
        solver.add(&[a, b]);
        solver.add(&[a, !b]);
        solver.add(&[!a, !b]);
        let model = solver.sat().unwrap();
        assert_eq!(model.get(a), Some(true));
        assert_eq!(model.get(b), Some(false));
    }

    #[test]
    fn unsat_works() {
        let mut solver = Solver::new();
        let a = solver.var();
        solver.add(&[a]);
        solver.add(&[!a]);
        assert!(solver.sat().is_none());
    }
}
