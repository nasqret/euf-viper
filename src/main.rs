#[cfg(test)]
mod bool_dag_telemetry;
mod eq_abstraction;
mod finite_analysis;
#[cfg(test)]
mod forbidden_orbit_probe;
#[cfg(test)]
mod forbidden_table_mdd;
#[cfg(test)]
mod forbidden_table_mvdd;
#[cfg(test)]
mod hall_certificate;
#[cfg(test)]
mod model_scout;
#[cfg(test)]
mod novelty_census;
#[cfg(test)]
#[allow(dead_code)]
mod orbit_canon;
#[cfg(test)]
mod orbit_cover;
#[cfg(test)]
mod quotient_csp;
#[cfg(test)]
mod quotient_state_search;
mod smt2_stream;
#[cfg(test)]
mod stabilizer_order;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use kissat::{Solver as KissatSolver, Var as KissatVar};
use rustc_hash::{FxHashMap as HashMap, FxHashSet as HashSet};
use rustsat::solvers::{
    GetInternalStats, LimitConflicts, Solve as RustSatSolve, SolverResult as RustSatResult,
};
use rustsat::types::{Clause as RustSatClause, Lit as RustSatLit, TernaryVal};
#[cfg(feature = "certificates")]
use rustsat_cadical::ProofFormat as CadicalProofFormat;
use rustsat_cadical::{CaDiCaL as CadicalSolver, Config as CadicalConfig};
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
use rustsat_kissat::{Config as KissatConfig, Kissat as KissatSolver};
#[cfg(feature = "certificates")]
use serde::Serialize;
#[cfg(feature = "certificates")]
use sha2::{Digest, Sha256};
use std::cmp::Reverse;
use std::collections::{BinaryHeap, VecDeque};
use std::env;
use std::fs;
use std::io::{self, Read};
#[cfg(feature = "certificates")]
use std::io::{BufReader, BufWriter, Write};
#[cfg(feature = "certificates")]
use std::path::{Path, PathBuf};
use std::process::{self, Command};
use std::time::Instant;
use varisat::{ExtendFormula, Lit, Solver as VarisatSolver};

type SymId = u32;
type TermId = usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct SortId(u32);

const BOOL_SORT: SortId = SortId(0);

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    LParen,
    RParen,
    Atom(String),
    QuotedAtom(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Sexp {
    Atom(String),
    QuotedAtom(String),
    List(Vec<Sexp>),
}

#[derive(Debug, Default)]
struct SymbolInterner {
    ids: HashMap<String, SymId>,
}

impl SymbolInterner {
    fn intern(&mut self, text: &str) -> SymId {
        if let Some(&id) = self.ids.get(text) {
            return id;
        }
        let id = self.ids.len() as SymId;
        self.ids.insert(text.to_owned(), id);
        id
    }

    fn ordered_names(&self) -> Vec<String> {
        let mut names = vec![String::new(); self.ids.len()];
        for (name, &symbol) in &self.ids {
            names[symbol as usize] = name.clone();
        }
        names
    }
}

#[derive(Debug)]
struct SortTable {
    ids: HashMap<SymId, SortId>,
    names: Vec<String>,
}

impl Default for SortTable {
    fn default() -> Self {
        Self {
            ids: HashMap::default(),
            names: vec!["Bool".to_owned()],
        }
    }
}

impl SortTable {
    fn declare(&mut self, sym: SymId, name: &str) -> Result<SortId, String> {
        if name == "Bool" {
            return Err("cannot redeclare built-in sort `Bool`".to_owned());
        }
        if self.ids.contains_key(&sym) {
            return Err(format!("sort `{name}` is already declared"));
        }
        let id = SortId(self.names.len() as u32);
        self.ids.insert(sym, id);
        self.names.push(name.to_owned());
        Ok(id)
    }

    fn get(&self, sym: SymId) -> Option<SortId> {
        self.ids.get(&sym).copied()
    }

    fn name(&self, sort: SortId) -> &str {
        &self.names[sort.0 as usize]
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TermKey {
    fun: SymId,
    args: Vec<TermId>,
}

#[derive(Debug, Clone)]
struct Term {
    fun: SymId,
    args: Vec<TermId>,
    sort: SortId,
}

#[derive(Debug, Default)]
struct TermArena {
    terms: Vec<Term>,
    interned: HashMap<TermKey, TermId>,
    apps: Vec<TermId>,
}

impl TermArena {
    fn intern_typed(&mut self, fun: SymId, args: Vec<TermId>, sort: SortId) -> TermId {
        let key = TermKey { fun, args };
        if let Some(&id) = self.interned.get(&key) {
            debug_assert_eq!(self.terms[id].sort, sort);
            return id;
        }
        let id = self.terms.len();
        if !key.args.is_empty() {
            self.apps.push(id);
        }
        self.terms.push(Term {
            fun: key.fun,
            args: key.args.clone(),
            sort,
        });
        self.interned.insert(key, id);
        id
    }

    #[cfg(test)]
    fn intern(&mut self, fun: SymId, args: Vec<TermId>) -> TermId {
        self.intern_typed(fun, args, SortId(u32::MAX))
    }

    fn app_count(&self) -> usize {
        self.apps.len()
    }
}

#[derive(Debug)]
struct Problem {
    sorts: SortTable,
    fun_decls: FunDeclTable,
    arena: TermArena,
    eqs: Vec<(TermId, TermId)>,
    diseqs: Vec<(TermId, TermId)>,
    unsupported: Vec<String>,
    bool_problem: Option<BoolProblem>,
    contradiction: bool,
}

impl Problem {
    fn terms_are_well_sorted(&self) -> bool {
        self.arena.terms.iter().all(|term| {
            if term.sort.0 as usize >= self.sorts.names.len() {
                return false;
            }
            let Some(decl) = self.fun_decls.get(term.fun) else {
                return false;
            };
            decl.result_sort == term.sort
                && decl.arg_sorts.len() == term.args.len()
                && term
                    .args
                    .iter()
                    .zip(&decl.arg_sorts)
                    .all(|(&arg, &sort)| self.arena.terms[arg].sort == sort)
        })
    }
}

#[derive(Debug, Default)]
struct BranchLiterals {
    eqs: Vec<(TermId, TermId)>,
    diseqs: Vec<(TermId, TermId)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FunDecl {
    arg_sorts: Vec<SortId>,
    result_sort: SortId,
}

#[derive(Debug, Default)]
struct FunDeclTable {
    slots: Vec<Option<FunDecl>>,
}

impl FunDeclTable {
    #[inline]
    fn get(&self, sym: SymId) -> Option<&FunDecl> {
        self.slots.get(sym as usize).and_then(Option::as_ref)
    }

    fn insert(&mut self, sym: SymId, decl: FunDecl) {
        let index = sym as usize;
        if self.slots.len() <= index {
            self.slots.resize_with(index + 1, || None);
        }
        self.slots[index] = Some(decl);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum BoolAtomKey {
    Eq(TermId, TermId),
    BoolTerm(TermId),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum BoolExpr {
    Const(bool),
    Atom(BoolAtomKey),
    Not(Box<BoolExpr>),
    And(Vec<BoolExpr>),
    Or(Vec<BoolExpr>),
    Iff(Vec<BoolExpr>),
    Ite(Box<BoolExpr>, Box<BoolExpr>, Box<BoolExpr>),
}

#[derive(Debug, Clone)]
enum BindingValue {
    Term(TermId),
    Bool(BoolExpr),
}

struct ScopedBindings<'a, V> {
    env: &'a mut HashMap<String, V>,
    restore: Vec<(String, Option<V>)>,
}

impl<'a, V> ScopedBindings<'a, V> {
    fn new(env: &'a mut HashMap<String, V>, bindings: Vec<(String, V)>) -> Self {
        let mut restore = Vec::with_capacity(bindings.len());
        for (name, value) in bindings {
            let previous = env.insert(name.clone(), value);
            restore.push((name, previous));
        }
        Self { env, restore }
    }

    fn env(&mut self) -> &mut HashMap<String, V> {
        self.env
    }
}

impl<V> Drop for ScopedBindings<'_, V> {
    fn drop(&mut self) {
        while let Some((name, previous)) = self.restore.pop() {
            match previous {
                Some(value) => {
                    self.env.insert(name, value);
                }
                None => {
                    self.env.remove(&name);
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
struct BoolProblem {
    assertions: Vec<BoolExpr>,
    unsupported: Vec<String>,
    true_term: TermId,
    false_term: TermId,
    data_terms: Vec<TermId>,
}

#[derive(Debug, Default)]
struct OrAnalysis {
    branches: usize,
    pruned_unsat: usize,
    extracted_equalities: usize,
    proved_unsat: bool,
}

#[derive(Debug, Default)]
struct ParseCtx {
    symbols: SymbolInterner,
    sorts: SortTable,
    arena: TermArena,
    eqs: Vec<(TermId, TermId)>,
    diseqs: Vec<(TermId, TermId)>,
    unsupported: Vec<String>,
    bool_assertions: Vec<BoolExpr>,
    bool_unsupported: Vec<String>,
    fun_decls: FunDeclTable,
    bool_definitions: HashMap<SymId, BoolExpr>,
    bool_value_terms: Option<(TermId, TermId)>,
    bool_data_terms: HashSet<TermId>,
    fresh_internal_counter: usize,
    preprocess_branch_intersections: bool,
    scoped_let_selected: bool,
    check_sat_seen: bool,
    exit_seen: bool,
    contradiction: bool,
    #[cfg(test)]
    assertion_sort_validations: usize,
}

impl ParseCtx {
    fn new(scoped_let_selected: bool) -> Self {
        Self {
            scoped_let_selected,
            ..Self::default()
        }
    }

    fn finish(self) -> Problem {
        let mut bool_data_terms = self.bool_data_terms.into_iter().collect::<Vec<_>>();
        bool_data_terms.sort_unstable();
        let bool_problem = (!self.bool_assertions.is_empty()
            || !self.bool_unsupported.is_empty()
            || !bool_data_terms.is_empty())
        .then(|| {
            let (true_term, false_term) = self
                .bool_value_terms
                .expect("Boolean parsing initializes value terms");
            BoolProblem {
                assertions: self.bool_assertions,
                unsupported: self.bool_unsupported,
                true_term,
                false_term,
                data_terms: bool_data_terms,
            }
        });
        Problem {
            sorts: self.sorts,
            fun_decls: self.fun_decls,
            arena: self.arena,
            eqs: self.eqs,
            diseqs: self.diseqs,
            unsupported: self.unsupported,
            bool_problem,
            contradiction: self.contradiction,
        }
    }

    fn finish_with_symbol_names(self) -> (Problem, Vec<String>) {
        let symbol_names = self.symbols.ordered_names();
        (self.finish(), symbol_names)
    }

    fn add_unsupported(&mut self, msg: impl Into<String>) {
        self.unsupported.push(msg.into());
    }

    fn parse_sort(&mut self, sexp: &Sexp, context: &str) -> Result<SortId, String> {
        let Some(name) = atom_text(sexp) else {
            return Err(format!("{context} is not a sort symbol"));
        };
        if syntax_atom_text(sexp) == Some("Bool") {
            return Ok(BOOL_SORT);
        }
        let sym = self.symbols.intern(name);
        self.sorts
            .get(sym)
            .ok_or_else(|| format!("unknown sort `{name}` in {context}"))
    }

    fn declare_function(
        &mut self,
        name: &str,
        arg_sorts: Vec<SortId>,
        result_sort: SortId,
    ) -> Result<SymId, String> {
        let sym = self.symbols.intern(name);
        if self.fun_decls.get(sym).is_some() {
            return Err(format!("function `{name}` is already declared"));
        }
        self.fun_decls.insert(
            sym,
            FunDecl {
                arg_sorts,
                result_sort,
            },
        );
        Ok(sym)
    }

    fn sort_mismatch(&self, context: &str, expected: SortId, found: SortId) -> String {
        format!(
            "sort mismatch in {context}: expected `{}`, found `{}`",
            self.sorts.name(expected),
            self.sorts.name(found)
        )
    }

    fn validate_expected_sort(
        &self,
        context: &str,
        found: Option<SortId>,
        expected: SortId,
    ) -> Result<(), String> {
        if let Some(found) = found
            && found != expected
        {
            return Err(self.sort_mismatch(context, expected, found));
        }
        Ok(())
    }

    fn validate_expr_sort(
        &mut self,
        sexp: &Sexp,
        env: &HashMap<String, Option<SortId>>,
    ) -> Result<Option<SortId>, String> {
        match sexp {
            Sexp::Atom(atom) if matches!(atom.as_str(), "true" | "false") => Ok(Some(BOOL_SORT)),
            Sexp::Atom(atom) | Sexp::QuotedAtom(atom) => {
                if let Some(sort) = env.get(atom) {
                    return Ok(*sort);
                }
                let sym = self.symbols.intern(atom);
                let Some(decl) = self.fun_decls.get(sym) else {
                    return Ok(None);
                };
                if !decl.arg_sorts.is_empty() {
                    return Err(format!(
                        "arity mismatch in application `{atom}`: expected {} arguments, found 0",
                        decl.arg_sorts.len()
                    ));
                }
                Ok(Some(decl.result_sort))
            }
            Sexp::List(items) => {
                if items.is_empty() {
                    return Ok(None);
                }
                let Some(head) = atom_text(&items[0]) else {
                    return Ok(None);
                };
                match syntax_atom_text(&items[0]) {
                    Some("!") => {
                        let Some(payload) = items.get(1) else {
                            return Ok(None);
                        };
                        self.validate_expr_sort(payload, env)
                    }
                    Some("and" | "or") => {
                        for child in &items[1..] {
                            let sort = self.validate_expr_sort(child, env)?;
                            self.validate_expected_sort(
                                &format!("`{head}` argument"),
                                sort,
                                BOOL_SORT,
                            )?;
                        }
                        Ok(Some(BOOL_SORT))
                    }
                    Some("not") => {
                        if items.len() != 2 {
                            return Ok(None);
                        }
                        let sort = self.validate_expr_sort(&items[1], env)?;
                        self.validate_expected_sort("`not` argument", sort, BOOL_SORT)?;
                        Ok(Some(BOOL_SORT))
                    }
                    Some("=>" | "xor") => {
                        if items.len() < 3 {
                            return Ok(None);
                        }
                        for child in &items[1..] {
                            let sort = self.validate_expr_sort(child, env)?;
                            self.validate_expected_sort(
                                &format!("`{head}` argument"),
                                sort,
                                BOOL_SORT,
                            )?;
                        }
                        Ok(Some(BOOL_SORT))
                    }
                    Some("=" | "distinct") => {
                        if items.len() < 3 {
                            return Ok(None);
                        }
                        let mut expected = None;
                        for child in &items[1..] {
                            let sort = self.validate_expr_sort(child, env)?;
                            if let Some(sort) = sort {
                                if let Some(expected) = expected {
                                    if sort != expected {
                                        return Err(self.sort_mismatch(
                                            if head == "=" { "equality" } else { "distinct" },
                                            expected,
                                            sort,
                                        ));
                                    }
                                } else {
                                    expected = Some(sort);
                                }
                            }
                        }
                        Ok(Some(BOOL_SORT))
                    }
                    Some("ite") => {
                        if items.len() != 4 {
                            return Ok(None);
                        }
                        let condition = self.validate_expr_sort(&items[1], env)?;
                        self.validate_expected_sort("ite condition", condition, BOOL_SORT)?;
                        let then_sort = self.validate_expr_sort(&items[2], env)?;
                        let else_sort = self.validate_expr_sort(&items[3], env)?;
                        if let (Some(then_sort), Some(else_sort)) = (then_sort, else_sort)
                            && then_sort != else_sort
                        {
                            return Err(self.sort_mismatch("ite branches", then_sort, else_sort));
                        }
                        Ok(then_sort.or(else_sort))
                    }
                    Some("let") => {
                        if items.len() != 3 {
                            return Ok(None);
                        }
                        let Sexp::List(binding_list) = &items[1] else {
                            return Ok(None);
                        };
                        let mut parsed = Vec::with_capacity(binding_list.len());
                        for binding in binding_list {
                            let Sexp::List(pair) = binding else {
                                return Ok(None);
                            };
                            if pair.len() != 2 {
                                return Ok(None);
                            }
                            let Some(name) = atom_text(&pair[0]) else {
                                return Ok(None);
                            };
                            parsed.push((name.to_owned(), self.validate_expr_sort(&pair[1], env)?));
                        }
                        let mut local = env.clone();
                        for (name, sort) in parsed {
                            local.insert(name, sort);
                        }
                        self.validate_expr_sort(&items[2], &local)
                    }
                    _ => {
                        let sym = self.symbols.intern(head);
                        let Some(decl) = self.fun_decls.get(sym).cloned() else {
                            return Ok(None);
                        };
                        let args = &items[1..];
                        if args.len() != decl.arg_sorts.len() {
                            return Err(format!(
                                "arity mismatch in application `{head}`: expected {} arguments, found {}",
                                decl.arg_sorts.len(),
                                args.len()
                            ));
                        }
                        for (index, (arg, expected)) in args.iter().zip(&decl.arg_sorts).enumerate()
                        {
                            let found = self.validate_expr_sort(arg, env)?;
                            self.validate_expected_sort(
                                &format!("application `{head}` argument {}", index + 1),
                                found,
                                *expected,
                            )?;
                        }
                        Ok(Some(decl.result_sort))
                    }
                }
            }
        }
    }

    fn validate_assertion_sort(&mut self, sexp: &Sexp) -> Result<(), String> {
        #[cfg(test)]
        {
            self.assertion_sort_validations += 1;
        }
        let sort = self.validate_expr_sort(sexp, &HashMap::default())?;
        self.validate_expected_sort("assertion", sort, BOOL_SORT)
    }

    fn parse_command(&mut self, sexp: &Sexp) -> Result<(), String> {
        let Sexp::List(items) = sexp else {
            return Ok(());
        };
        if items.is_empty() {
            return Ok(());
        }
        let Some(head) = syntax_atom_text(&items[0]) else {
            return Err("top-level command head must be an unquoted symbol".to_owned());
        };
        if self.exit_seen {
            return Err(format!("command `{head}` appears after `exit`"));
        }
        if self.check_sat_seen && !matches!(head, "get-model" | "get-value" | "exit") {
            return Err(format!(
                "command `{head}` after `check-sat` is unsupported in single-query mode"
            ));
        }
        match head {
            "assert" => {
                if items.len() != 2 {
                    self.add_unsupported("assert command with arity other than 1");
                    return Ok(());
                }
                self.ensure_bool_value_terms();
                let mut mixed_env = HashMap::default();
                let aux_start = self.bool_assertions.len();
                match self.parse_bool_expr(&items[1], &mut mixed_env) {
                    Ok(expr) => {
                        let preprocess_branch_intersections =
                            should_preprocess_branch_intersections(&expr);
                        self.bool_assertions.push(expr);
                        let term_limit = env::var("EUF_VIPER_LEGACY_PREPROCESS_TERM_LIMIT")
                            .ok()
                            .and_then(|value| value.parse().ok())
                            .unwrap_or(1_024usize);
                        if self.preprocess_branch_intersections
                            && preprocess_branch_intersections
                            && term_limit > 0
                            && self.arena.terms.len() <= term_limit
                        {
                            let mut env = HashMap::default();
                            self.collect_formula(&items[1], true, &mut env)?;
                        }
                    }
                    Err(err) => {
                        self.bool_assertions.truncate(aux_start);
                        self.validate_assertion_sort(&items[1])?;
                        self.bool_unsupported.push(err);
                        let mut env = HashMap::default();
                        self.collect_formula(&items[1], true, &mut env)?;
                    }
                }
            }
            "declare-fun" => {
                if items.len() != 4 {
                    return Err(
                        "declare-fun command must have name, arguments, and result sort".to_owned(),
                    );
                }
                let Some(name) = atom_text(&items[1]) else {
                    return Err("declare-fun name is not a symbol".to_owned());
                };
                let Sexp::List(arg_sort_exprs) = &items[2] else {
                    return Err(format!("argument sorts for `{name}` are not a list"));
                };
                let mut arg_sorts = Vec::with_capacity(arg_sort_exprs.len());
                for (index, sort) in arg_sort_exprs.iter().enumerate() {
                    arg_sorts.push(
                        self.parse_sort(sort, &format!("argument {} of `{name}`", index + 1))?,
                    );
                }
                let result_sort = self.parse_sort(&items[3], &format!("result of `{name}`"))?;
                self.declare_function(name, arg_sorts, result_sort)?;
            }
            "declare-const" => {
                if items.len() != 3 {
                    return Err("declare-const command must have a name and sort".to_owned());
                }
                let Some(name) = atom_text(&items[1]) else {
                    return Err("declare-const name is not a symbol".to_owned());
                };
                let result_sort = self.parse_sort(&items[2], &format!("result of `{name}`"))?;
                let sym = self.declare_function(name, Vec::new(), result_sort)?;
                if result_sort != BOOL_SORT {
                    self.arena.intern_typed(sym, Vec::new(), result_sort);
                }
            }
            "declare-sort" => {
                if items.len() != 3 {
                    return Err("declare-sort command must have a name and arity".to_owned());
                }
                let Some(name) = atom_text(&items[1]) else {
                    return Err("declare-sort name is not a symbol".to_owned());
                };
                if syntax_atom_text(&items[2]) != Some("0") {
                    return Err(format!(
                        "sort `{name}` must have arity 0 in the QF_UF parser"
                    ));
                }
                let sym = self.symbols.intern(name);
                self.sorts.declare(sym, name)?;
            }
            "set-logic" | "set-option" | "set-info" | "get-model" | "get-value" => {}
            "check-sat" => {
                if items.len() != 1 {
                    return Err("check-sat command must not have arguments".to_owned());
                }
                self.check_sat_seen = true;
            }
            "exit" => {
                if items.len() != 1 {
                    return Err("exit command must not have arguments".to_owned());
                }
                self.exit_seen = true;
            }
            "define-fun" => {
                if items.len() != 5 {
                    self.add_unsupported("define-fun with unexpected arity");
                    return Ok(());
                }
                let Some(name) = items.get(1).and_then(atom_text) else {
                    self.add_unsupported("define-fun name is not a symbol");
                    return Ok(());
                };
                let Some(parameters) = items.get(2) else {
                    self.add_unsupported("define-fun is missing parameters");
                    return Ok(());
                };
                let Sexp::List(parameters) = parameters else {
                    self.add_unsupported("define-fun parameters are not a list");
                    return Ok(());
                };
                if !parameters.is_empty() || items.get(3).and_then(syntax_atom_text) != Some("Bool")
                {
                    self.add_unsupported("only zero-arity Boolean define-fun macros are supported");
                    return Ok(());
                }

                self.ensure_bool_value_terms();
                let already_declared = self.fun_decls.get(self.symbols.intern(name)).is_some();
                let mut env = HashMap::default();
                match self.parse_bool_expr(&items[4], &mut env) {
                    Ok(body) => {
                        if already_declared {
                            return Err(format!("function `{name}` is already declared"));
                        }
                        let sym = self.declare_function(name, Vec::new(), BOOL_SORT)?;
                        self.bool_definitions.insert(sym, body);
                    }
                    Err(err) => {
                        self.validate_assertion_sort(&items[4])?;
                        if already_declared {
                            return Err(format!("function `{name}` is already declared"));
                        }
                        self.add_unsupported(format!("define-fun `{name}`: {err}"));
                        self.bool_unsupported
                            .push(format!("define-fun `{name}`: {err}"));
                    }
                }
            }
            "define-fun-rec" | "define-funs-rec" => {
                self.add_unsupported(format!("{head} is not expanded in this verifier yet"));
            }
            other => {
                self.add_unsupported(format!("unsupported top-level command {other}"));
            }
        }
        Ok(())
    }

    fn collect_formula(
        &mut self,
        sexp: &Sexp,
        polarity: bool,
        env: &mut HashMap<String, TermId>,
    ) -> Result<(), String> {
        match sexp {
            Sexp::Atom(atom) if atom == "true" && polarity => Ok(()),
            Sexp::Atom(atom) if atom == "false" && polarity => {
                self.contradiction = true;
                Ok(())
            }
            Sexp::Atom(atom) if atom == "true" => {
                self.contradiction = true;
                Ok(())
            }
            Sexp::Atom(atom) if atom == "false" => Ok(()),
            Sexp::Atom(name) | Sexp::QuotedAtom(name) => {
                self.add_unsupported(format!(
                    "Boolean atom `{name}` is not handled without SAT search"
                ));
                Ok(())
            }
            Sexp::List(items) => {
                if items.is_empty() {
                    self.add_unsupported("empty formula list");
                    return Ok(());
                }
                let Some(head) = atom_text(&items[0]) else {
                    self.add_unsupported("formula head is not a symbol");
                    return Ok(());
                };
                match syntax_atom_text(&items[0]) {
                    Some("!") => {
                        if items.len() < 2 {
                            self.add_unsupported("annotation without a payload");
                        } else {
                            self.collect_formula(&items[1], polarity, env)?;
                        }
                    }
                    Some("and") if polarity => {
                        let mut delayed_or = Vec::new();
                        for child in &items[1..] {
                            if is_positive_or(child) {
                                delayed_or.push(child);
                            } else {
                                self.collect_formula(child, true, env)?;
                            }
                        }
                        for child in delayed_or {
                            self.collect_formula(child, true, env)?;
                        }
                    }
                    Some("or") if !polarity => {
                        for child in &items[1..] {
                            self.collect_formula(child, false, env)?;
                        }
                    }
                    Some("not") => {
                        if items.len() != 2 {
                            self.add_unsupported("not with arity other than 1");
                        } else {
                            self.collect_formula(&items[1], !polarity, env)?;
                        }
                    }
                    Some("=") => self.collect_equality(&items[1..], polarity, env)?,
                    Some("distinct") => self.collect_distinct(&items[1..], polarity, env)?,
                    Some("let") => {
                        if items.len() != 3 {
                            self.add_unsupported("let formula with unexpected arity");
                        } else if self.scoped_let_selected {
                            let bindings = self.parse_let_bindings(&items[1], env)?;
                            let mut scope = ScopedBindings::new(env, bindings);
                            self.collect_formula(&items[2], polarity, scope.env())?;
                        } else {
                            let mut local = self.extend_let_env(&items[1], env)?;
                            self.collect_formula(&items[2], polarity, &mut local)?;
                        }
                    }
                    Some("or") if polarity => {
                        let analysis = self.analyze_positive_or(&items[1..], env)?;
                        if !analysis.proved_unsat {
                            self.add_unsupported(format!(
                                "positive or needs DPLL(T); branches={} pruned_unsat={} extracted_equalities={}",
                                analysis.branches,
                                analysis.pruned_unsat,
                                analysis.extracted_equalities
                            ));
                        }
                    }
                    Some("and" | "=>" | "xor" | "ite") => {
                        self.add_unsupported(format!(
                            "Boolean connective `{head}` needs DPLL(T), not only EUF closure"
                        ));
                    }
                    _ => {
                        self.add_unsupported(format!(
                            "formula headed by `{head}` is outside conjunctive EUF"
                        ));
                    }
                }
                Ok(())
            }
        }
    }

    fn analyze_positive_or(
        &mut self,
        branches: &[Sexp],
        env: &mut HashMap<String, TermId>,
    ) -> Result<OrAnalysis, String> {
        let mut analysis = OrAnalysis {
            branches: branches.len(),
            ..OrAnalysis::default()
        };
        if branches.is_empty() {
            analysis.proved_unsat = true;
            self.contradiction = true;
            return Ok(analysis);
        }

        let mut parsed_branches = Vec::with_capacity(branches.len());
        for branch in branches {
            let mut local = env.clone();
            let Some(lits) = self.collect_branch_literals(branch, true, &mut local)? else {
                return Ok(analysis);
            };
            parsed_branches.push(lits);
        }

        let term_count = self.arena.terms.len();
        let mut satisfiable_roots = Vec::with_capacity(parsed_branches.len());
        for lits in &parsed_branches {
            let mut uf = UnionFind::new(term_count);
            for &(a, b) in &self.eqs {
                uf.union(a, b);
            }
            for &(a, b) in &lits.eqs {
                uf.union(a, b);
            }
            congruence_closure(&self.arena, &mut uf);

            let mut branch_unsat = false;
            for &(a, b) in self.diseqs.iter().chain(lits.diseqs.iter()) {
                if uf.find(a) == uf.find(b) {
                    branch_unsat = true;
                    break;
                }
            }
            if branch_unsat {
                analysis.pruned_unsat += 1;
                continue;
            }

            satisfiable_roots.push(
                (0..term_count)
                    .map(|term_id| uf.root_const(term_id))
                    .collect::<Vec<_>>(),
            );
        }

        if satisfiable_roots.is_empty() {
            analysis.proved_unsat = true;
            self.contradiction = true;
            return Ok(analysis);
        }

        let mut common_classes: HashMap<Vec<usize>, Vec<TermId>> = HashMap::default();
        for term_id in 0..term_count {
            let signature = satisfiable_roots
                .iter()
                .map(|roots| roots[term_id])
                .collect::<Vec<_>>();
            common_classes.entry(signature).or_default().push(term_id);
        }

        let mut existing = HashSet::default();
        for &(a, b) in &self.eqs {
            existing.insert(normalized_pair(a, b));
        }

        let mut added = 0usize;
        const COMMON_PAIR_LIMIT: usize = 100_000;
        'classes: for class in common_classes.values() {
            let Some((&representative, rest)) = class.split_first() else {
                continue;
            };
            for &term in rest {
                if existing.insert(normalized_pair(representative, term)) {
                    self.eqs.push((representative, term));
                    added += 1;
                    if added >= COMMON_PAIR_LIMIT {
                        break 'classes;
                    }
                }
            }
        }
        analysis.extracted_equalities = added;
        Ok(analysis)
    }

    fn collect_branch_literals(
        &mut self,
        sexp: &Sexp,
        polarity: bool,
        env: &mut HashMap<String, TermId>,
    ) -> Result<Option<BranchLiterals>, String> {
        let mut lits = BranchLiterals::default();
        let ok = self.collect_branch_literals_into(sexp, polarity, env, &mut lits)?;
        Ok(ok.then_some(lits))
    }

    fn collect_branch_literals_into(
        &mut self,
        sexp: &Sexp,
        polarity: bool,
        env: &mut HashMap<String, TermId>,
        lits: &mut BranchLiterals,
    ) -> Result<bool, String> {
        match sexp {
            Sexp::Atom(atom) => Ok((atom == "true" && polarity) || (atom == "false" && !polarity)),
            Sexp::QuotedAtom(_) => Ok(false),
            Sexp::List(items) => {
                if items.is_empty() {
                    return Ok(false);
                }
                let Some(_) = atom_text(&items[0]) else {
                    return Ok(false);
                };
                match syntax_atom_text(&items[0]) {
                    Some("!") if items.len() >= 2 => {
                        self.collect_branch_literals_into(&items[1], polarity, env, lits)
                    }
                    Some("and") if polarity => {
                        for child in &items[1..] {
                            if !self.collect_branch_literals_into(child, true, env, lits)? {
                                return Ok(false);
                            }
                        }
                        Ok(true)
                    }
                    Some("or") if !polarity => {
                        for child in &items[1..] {
                            if !self.collect_branch_literals_into(child, false, env, lits)? {
                                return Ok(false);
                            }
                        }
                        Ok(true)
                    }
                    Some("not") if items.len() == 2 => {
                        self.collect_branch_literals_into(&items[1], !polarity, env, lits)
                    }
                    Some("=") if polarity => {
                        let terms = self.parse_terms(&items[1..], env)?;
                        if terms.len() < 2 {
                            return Ok(false);
                        }
                        self.ensure_terms_same_sort("equality", &terms)?;
                        let first = terms[0];
                        for &term in &terms[1..] {
                            lits.eqs.push((first, term));
                        }
                        Ok(true)
                    }
                    Some("=") if !polarity && items.len() == 3 => {
                        let terms = self.parse_terms(&items[1..], env)?;
                        self.ensure_terms_same_sort("equality", &terms)?;
                        lits.diseqs.push((terms[0], terms[1]));
                        Ok(true)
                    }
                    Some("distinct") if !polarity && items.len() == 3 => {
                        let terms = self.parse_terms(&items[1..], env)?;
                        self.ensure_terms_same_sort("distinct", &terms)?;
                        lits.eqs.push((terms[0], terms[1]));
                        Ok(true)
                    }
                    Some("distinct") if polarity => {
                        let terms = self.parse_terms(&items[1..], env)?;
                        self.ensure_terms_same_sort("distinct", &terms)?;
                        for i in 0..terms.len() {
                            for j in (i + 1)..terms.len() {
                                lits.diseqs.push((terms[i], terms[j]));
                            }
                        }
                        Ok(true)
                    }
                    Some("let") if items.len() == 3 => {
                        if self.scoped_let_selected {
                            let bindings = self.parse_let_bindings(&items[1], env)?;
                            let mut scope = ScopedBindings::new(env, bindings);
                            self.collect_branch_literals_into(
                                &items[2],
                                polarity,
                                scope.env(),
                                lits,
                            )
                        } else {
                            let mut local = self.extend_let_env(&items[1], env)?;
                            self.collect_branch_literals_into(&items[2], polarity, &mut local, lits)
                        }
                    }
                    _ => Ok(false),
                }
            }
        }
    }

    fn parse_bool_expr(
        &mut self,
        sexp: &Sexp,
        env: &mut HashMap<String, BindingValue>,
    ) -> Result<BoolExpr, String> {
        match sexp {
            Sexp::Atom(atom) if atom == "true" => Ok(BoolExpr::Const(true)),
            Sexp::Atom(atom) if atom == "false" => Ok(BoolExpr::Const(false)),
            Sexp::Atom(name) | Sexp::QuotedAtom(name) => match env.get(name).cloned() {
                Some(BindingValue::Bool(expr)) => Ok(expr),
                Some(BindingValue::Term(_)) => {
                    Err(format!("term binding `{name}` used as a Boolean formula"))
                }
                None => {
                    let sym = self.symbols.intern(name);
                    if let Some(body) = self.bool_definitions.get(&sym).cloned() {
                        Ok(body)
                    } else if self.is_bool_symbol(sym, 0) {
                        self.bool_app_expr(sym, name, Vec::new())
                    } else {
                        Err(format!("non-Boolean atom `{name}` used as a formula"))
                    }
                }
            },
            Sexp::List(items) => {
                if items.is_empty() {
                    return Err("empty Boolean formula list".to_owned());
                }
                let Some(head) = atom_text(&items[0]) else {
                    return Err("Boolean formula head is not a symbol".to_owned());
                };
                match syntax_atom_text(&items[0]) {
                    Some("!") => {
                        if items.len() < 2 {
                            Err("annotation without a payload".to_owned())
                        } else {
                            self.parse_bool_expr(&items[1], env)
                        }
                    }
                    Some("and") => {
                        let mut children = Vec::with_capacity(items.len().saturating_sub(1));
                        for child in &items[1..] {
                            children.push(self.parse_bool_expr(child, env)?);
                        }
                        Ok(BoolExpr::And(children))
                    }
                    Some("or") => {
                        let mut children = Vec::with_capacity(items.len().saturating_sub(1));
                        for child in &items[1..] {
                            children.push(self.parse_bool_expr(child, env)?);
                        }
                        Ok(BoolExpr::Or(children))
                    }
                    Some("not") => {
                        if items.len() != 2 {
                            Err("not with arity other than 1".to_owned())
                        } else {
                            Ok(BoolExpr::Not(Box::new(
                                self.parse_bool_expr(&items[1], env)?,
                            )))
                        }
                    }
                    Some("=>") => {
                        if items.len() < 3 {
                            return Err("=> with fewer than 2 arguments".to_owned());
                        }
                        let mut children = Vec::with_capacity(items.len().saturating_sub(1));
                        for child in &items[1..] {
                            children.push(self.parse_bool_expr(child, env)?);
                        }
                        let last = children.pop().expect("checked implication arity");
                        let premise = if children.len() == 1 {
                            children.pop().expect("single premise")
                        } else {
                            BoolExpr::And(children)
                        };
                        Ok(BoolExpr::Or(vec![BoolExpr::Not(Box::new(premise)), last]))
                    }
                    Some("xor") => {
                        if items.len() < 3 {
                            return Err("xor with fewer than 2 arguments".to_owned());
                        }
                        let mut expr = self.parse_bool_expr(&items[1], env)?;
                        for child in &items[2..] {
                            let rhs = self.parse_bool_expr(child, env)?;
                            expr = BoolExpr::Not(Box::new(BoolExpr::Iff(vec![expr, rhs])));
                        }
                        Ok(expr)
                    }
                    Some("ite") => {
                        if items.len() != 4 {
                            Err("Boolean ite with arity other than 3".to_owned())
                        } else {
                            Ok(BoolExpr::Ite(
                                Box::new(self.parse_bool_expr(&items[1], env)?),
                                Box::new(self.parse_bool_expr(&items[2], env)?),
                                Box::new(self.parse_bool_expr(&items[3], env)?),
                            ))
                        }
                    }
                    Some("=") => self.parse_bool_equality(&items[1..], env),
                    Some("distinct") => self.parse_bool_distinct(&items[1..], env),
                    Some("let") => {
                        if items.len() != 3 {
                            Err("let formula with unexpected arity".to_owned())
                        } else if self.scoped_let_selected {
                            let bindings = self.parse_mixed_let_bindings(&items[1], env)?;
                            let mut scope = ScopedBindings::new(env, bindings);
                            self.parse_bool_expr(&items[2], scope.env())
                        } else {
                            let mut local = self.extend_mixed_let_env(&items[1], env)?;
                            self.parse_bool_expr(&items[2], &mut local)
                        }
                    }
                    _ => {
                        let sym = self.symbols.intern(head);
                        if items.len() == 1 {
                            if let Some(body) = self.bool_definitions.get(&sym).cloned() {
                                return Ok(body);
                            }
                        }
                        if self.is_bool_symbol(sym, items.len().saturating_sub(1)) {
                            let mut args = Vec::with_capacity(items.len().saturating_sub(1));
                            for child in &items[1..] {
                                args.push(self.parse_argument_term(child, env)?);
                            }
                            self.bool_app_expr(sym, head, args)
                        } else {
                            Err(format!("formula headed by `{head}` is not Boolean"))
                        }
                    }
                }
            }
        }
    }

    fn parse_bool_equality(
        &mut self,
        args: &[Sexp],
        env: &mut HashMap<String, BindingValue>,
    ) -> Result<BoolExpr, String> {
        if args.len() < 2 {
            return Err("equality with fewer than two arguments".to_owned());
        }
        let mut values = Vec::with_capacity(args.len());
        for arg in args {
            values.push(self.parse_bool_or_term(arg, env)?);
        }
        match &values[0] {
            BindingValue::Term(first) => {
                let mut conjuncts = Vec::with_capacity(values.len().saturating_sub(1));
                for value in &values[1..] {
                    let BindingValue::Term(term) = value else {
                        return Err(self.sort_mismatch(
                            "equality",
                            self.arena.terms[*first].sort,
                            BOOL_SORT,
                        ));
                    };
                    self.ensure_same_term_sort("equality", *first, *term)?;
                    conjuncts.push(BoolExpr::Atom(BoolAtomKey::Eq(*first, *term)));
                }
                Ok(if conjuncts.len() == 1 {
                    conjuncts.pop().expect("single equality")
                } else {
                    BoolExpr::And(conjuncts)
                })
            }
            BindingValue::Bool(first) => {
                let mut exprs = Vec::with_capacity(values.len());
                exprs.push(first.clone());
                for value in &values[1..] {
                    let BindingValue::Bool(expr) = value else {
                        let BindingValue::Term(term) = value else {
                            unreachable!();
                        };
                        return Err(self.sort_mismatch(
                            "equality",
                            BOOL_SORT,
                            self.arena.terms[*term].sort,
                        ));
                    };
                    exprs.push(expr.clone());
                }
                Ok(BoolExpr::Iff(exprs))
            }
        }
    }

    fn parse_bool_distinct(
        &mut self,
        args: &[Sexp],
        env: &mut HashMap<String, BindingValue>,
    ) -> Result<BoolExpr, String> {
        if args.len() < 2 {
            return Ok(BoolExpr::Const(true));
        }
        let mut values = Vec::with_capacity(args.len());
        for arg in args {
            values.push(self.parse_bool_or_term(arg, env)?);
        }
        match &values[0] {
            BindingValue::Term(first) => {
                let expected = self.arena.terms[*first].sort;
                let mut terms = Vec::with_capacity(values.len());
                for value in values {
                    let BindingValue::Term(term) = value else {
                        return Err(self.sort_mismatch("distinct", expected, BOOL_SORT));
                    };
                    terms.push(term);
                }
                self.ensure_terms_same_sort("distinct", &terms)?;
                let mut conjuncts = Vec::new();
                for i in 0..terms.len() {
                    for j in (i + 1)..terms.len() {
                        conjuncts.push(BoolExpr::Not(Box::new(BoolExpr::Atom(BoolAtomKey::Eq(
                            terms[i], terms[j],
                        )))));
                    }
                }
                Ok(BoolExpr::And(conjuncts))
            }
            BindingValue::Bool(_) => {
                let mut exprs = Vec::with_capacity(values.len());
                for value in values {
                    let BindingValue::Bool(expr) = value else {
                        let BindingValue::Term(term) = value else {
                            unreachable!();
                        };
                        return Err(self.sort_mismatch(
                            "distinct",
                            BOOL_SORT,
                            self.arena.terms[term].sort,
                        ));
                    };
                    exprs.push(expr);
                }
                if exprs.len() == 2 {
                    Ok(BoolExpr::Not(Box::new(BoolExpr::Iff(exprs))))
                } else {
                    Ok(BoolExpr::Const(false))
                }
            }
        }
    }

    fn parse_bool_or_term(
        &mut self,
        sexp: &Sexp,
        env: &mut HashMap<String, BindingValue>,
    ) -> Result<BindingValue, String> {
        match sexp {
            Sexp::Atom(atom) if atom == "true" => Ok(BindingValue::Bool(BoolExpr::Const(true))),
            Sexp::Atom(atom) if atom == "false" => Ok(BindingValue::Bool(BoolExpr::Const(false))),
            Sexp::Atom(atom) | Sexp::QuotedAtom(atom) => {
                if let Some(value) = env.get(atom).cloned() {
                    return Ok(value);
                }
                let sym = self.symbols.intern(atom);
                if let Some(body) = self.bool_definitions.get(&sym).cloned() {
                    Ok(BindingValue::Bool(body))
                } else if self.is_bool_symbol(sym, 0) {
                    Ok(BindingValue::Bool(self.bool_app_expr(
                        sym,
                        atom,
                        Vec::new(),
                    )?))
                } else {
                    Ok(BindingValue::Term(self.parse_typed_term(sexp, env)?))
                }
            }
            Sexp::List(items) => {
                if items.is_empty() {
                    return Err("empty expression list".to_owned());
                }
                let Some(head) = atom_text(&items[0]) else {
                    return Err("expression head is not a symbol".to_owned());
                };
                let syntax_head = syntax_atom_text(&items[0]);
                if syntax_head == Some("!") {
                    if items.len() < 2 {
                        return Err("annotation without a payload".to_owned());
                    }
                    return self.parse_bool_or_term(&items[1], env);
                }
                if matches!(
                    syntax_head,
                    Some("and" | "or" | "not" | "=>" | "xor" | "=" | "distinct")
                ) {
                    return Ok(BindingValue::Bool(self.parse_bool_expr(sexp, env)?));
                }
                if syntax_head == Some("ite") {
                    if let Ok(expr) = self.parse_bool_expr(sexp, env) {
                        return Ok(BindingValue::Bool(expr));
                    }
                    return Ok(BindingValue::Term(self.parse_typed_term(sexp, env)?));
                }
                if syntax_head == Some("let") {
                    if let Ok(expr) = self.parse_bool_expr(sexp, env) {
                        return Ok(BindingValue::Bool(expr));
                    }
                    return Ok(BindingValue::Term(self.parse_typed_term(sexp, env)?));
                }
                let sym = self.symbols.intern(head);
                if items.len() == 1 {
                    if let Some(body) = self.bool_definitions.get(&sym).cloned() {
                        return Ok(BindingValue::Bool(body));
                    }
                }
                if self.is_bool_symbol(sym, items.len().saturating_sub(1)) {
                    Ok(BindingValue::Bool(self.parse_bool_expr(sexp, env)?))
                } else {
                    Ok(BindingValue::Term(self.parse_typed_term(sexp, env)?))
                }
            }
        }
    }

    fn parse_typed_term(
        &mut self,
        sexp: &Sexp,
        env: &mut HashMap<String, BindingValue>,
    ) -> Result<TermId, String> {
        match sexp {
            Sexp::Atom(atom) if matches!(atom.as_str(), "true" | "false") => {
                let (true_term, false_term) = self.ensure_bool_value_terms();
                Ok(if atom == "true" {
                    true_term
                } else {
                    false_term
                })
            }
            Sexp::Atom(atom) | Sexp::QuotedAtom(atom) => {
                if let Some(value) = env.get(atom).cloned() {
                    return match value {
                        BindingValue::Term(term) => Ok(term),
                        BindingValue::Bool(expr) => Ok(self.materialize_bool_expr(expr)),
                    };
                }
                let sym = self.symbols.intern(atom);
                self.intern_application(sym, atom, Vec::new())
            }
            Sexp::List(items) => {
                if items.is_empty() {
                    return Err("empty term list".to_owned());
                }
                let Some(head) = atom_text(&items[0]) else {
                    return Err("term head is not a symbol".to_owned());
                };
                let syntax_head = syntax_atom_text(&items[0]);
                if syntax_head == Some("!") {
                    if items.len() < 2 {
                        return Err("annotation without a payload".to_owned());
                    }
                    return self.parse_typed_term(&items[1], env);
                }
                if syntax_head == Some("let") {
                    if items.len() != 3 {
                        return Err("let term with unexpected arity".to_owned());
                    }
                    if self.scoped_let_selected {
                        let bindings = self.parse_mixed_let_bindings(&items[1], env)?;
                        let mut scope = ScopedBindings::new(env, bindings);
                        return self.parse_typed_term(&items[2], scope.env());
                    }
                    let mut local = self.extend_mixed_let_env(&items[1], env)?;
                    return self.parse_typed_term(&items[2], &mut local);
                }
                if syntax_head == Some("ite") {
                    if items.len() != 4 {
                        return Err("term-level ite with arity other than 3".to_owned());
                    }
                    let cond = self.parse_bool_expr(&items[1], env)?;
                    let then_term = self.parse_typed_term(&items[2], env)?;
                    let else_term = self.parse_typed_term(&items[3], env)?;
                    self.ensure_same_term_sort("ite branches", then_term, else_term)?;
                    if then_term == else_term {
                        return Ok(then_term);
                    }

                    let ite_term =
                        self.fresh_internal_term("ite", self.arena.terms[then_term].sort);
                    let then_eq = BoolExpr::Atom(BoolAtomKey::Eq(ite_term, then_term));
                    let else_eq = BoolExpr::Atom(BoolAtomKey::Eq(ite_term, else_term));
                    self.bool_assertions.push(BoolExpr::Or(vec![
                        BoolExpr::Not(Box::new(cond.clone())),
                        then_eq,
                    ]));
                    self.bool_assertions.push(BoolExpr::Or(vec![cond, else_eq]));
                    return Ok(ite_term);
                }
                let fun = self.symbols.intern(head);
                let mut args = Vec::with_capacity(items.len().saturating_sub(1));
                for child in &items[1..] {
                    args.push(self.parse_argument_term(child, env)?);
                }
                self.intern_application(fun, head, args)
            }
        }
    }

    fn parse_mixed_let_bindings(
        &mut self,
        bindings: &Sexp,
        env: &mut HashMap<String, BindingValue>,
    ) -> Result<Vec<(String, BindingValue)>, String> {
        let Sexp::List(binding_list) = bindings else {
            return Err("let binding block is not a list".to_owned());
        };
        let mut parsed = Vec::with_capacity(binding_list.len());
        for binding in binding_list {
            let Sexp::List(pair) = binding else {
                return Err("let binding is not a pair".to_owned());
            };
            if pair.len() != 2 {
                return Err("let binding does not have arity 2".to_owned());
            }
            let Some(name) = atom_text(&pair[0]) else {
                return Err("let binding name is not a symbol".to_owned());
            };
            let value = self.parse_bool_or_term(&pair[1], env)?;
            parsed.push((name.to_owned(), value));
        }
        Ok(parsed)
    }

    fn extend_mixed_let_env(
        &mut self,
        bindings: &Sexp,
        env: &mut HashMap<String, BindingValue>,
    ) -> Result<HashMap<String, BindingValue>, String> {
        let parsed = self.parse_mixed_let_bindings(bindings, env)?;
        let mut local = env.clone();
        for (name, value) in parsed {
            local.insert(name, value);
        }
        Ok(local)
    }

    fn is_bool_symbol(&self, sym: SymId, arity: usize) -> bool {
        self.fun_decls
            .get(sym)
            .is_some_and(|decl| decl.result_sort == BOOL_SORT && decl.arg_sorts.len() == arity)
    }

    fn application_result_sort(
        &self,
        fun: SymId,
        name: &str,
        args: &[TermId],
    ) -> Result<SortId, String> {
        let Some(decl) = self.fun_decls.get(fun) else {
            return Err(format!("undeclared function `{name}`"));
        };
        if args.len() != decl.arg_sorts.len() {
            return Err(format!(
                "arity mismatch in application `{name}`: expected {} arguments, found {}",
                decl.arg_sorts.len(),
                args.len()
            ));
        }
        for (index, (&arg, &expected)) in args.iter().zip(&decl.arg_sorts).enumerate() {
            let found = self.arena.terms[arg].sort;
            if found != expected {
                return Err(self.sort_mismatch(
                    &format!("application `{name}` argument {}", index + 1),
                    expected,
                    found,
                ));
            }
        }
        Ok(decl.result_sort)
    }

    fn intern_application(
        &mut self,
        fun: SymId,
        name: &str,
        args: Vec<TermId>,
    ) -> Result<TermId, String> {
        let result_sort = self.application_result_sort(fun, name, &args)?;
        Ok(self.arena.intern_typed(fun, args, result_sort))
    }

    fn ensure_same_term_sort(
        &self,
        context: &str,
        left: TermId,
        right: TermId,
    ) -> Result<(), String> {
        let expected = self.arena.terms[left].sort;
        let found = self.arena.terms[right].sort;
        if expected != found {
            return Err(self.sort_mismatch(context, expected, found));
        }
        Ok(())
    }

    fn ensure_terms_same_sort(&self, context: &str, terms: &[TermId]) -> Result<(), String> {
        if let Some((&first, rest)) = terms.split_first() {
            for &term in rest {
                self.ensure_same_term_sort(context, first, term)?;
            }
        }
        Ok(())
    }

    fn parse_argument_term(
        &mut self,
        sexp: &Sexp,
        env: &mut HashMap<String, BindingValue>,
    ) -> Result<TermId, String> {
        match self.parse_bool_or_term(sexp, env)? {
            BindingValue::Term(term) => Ok(term),
            BindingValue::Bool(expr) => Ok(self.materialize_bool_expr(expr)),
        }
    }

    fn bool_app_expr(
        &mut self,
        fun: SymId,
        name: &str,
        args: Vec<TermId>,
    ) -> Result<BoolExpr, String> {
        let term = self.intern_application(fun, name, args)?;
        if self.arena.terms[term].sort != BOOL_SORT {
            return Err(self.sort_mismatch(
                &format!("formula application `{name}`"),
                BOOL_SORT,
                self.arena.terms[term].sort,
            ));
        }
        Ok(BoolExpr::Atom(BoolAtomKey::BoolTerm(term)))
    }

    fn materialize_bool_expr(&mut self, expr: BoolExpr) -> TermId {
        self.ensure_bool_value_terms();
        let term = match expr {
            BoolExpr::Const(value) => {
                let (true_term, false_term) = self.ensure_bool_value_terms();
                if value { true_term } else { false_term }
            }
            BoolExpr::Atom(BoolAtomKey::BoolTerm(term)) => term,
            expr => {
                let term = self.fresh_internal_term("bool_expr", BOOL_SORT);
                self.bool_assertions.push(BoolExpr::Iff(vec![
                    BoolExpr::Atom(BoolAtomKey::BoolTerm(term)),
                    expr,
                ]));
                term
            }
        };
        self.bool_data_terms.insert(term);
        term
    }

    fn ensure_bool_value_terms(&mut self) -> (TermId, TermId) {
        if let Some(terms) = self.bool_value_terms {
            return terms;
        }
        let true_term = self.fresh_internal_term("true", BOOL_SORT);
        let false_term = self.fresh_internal_term("false", BOOL_SORT);
        self.bool_value_terms = Some((true_term, false_term));
        (true_term, false_term)
    }

    fn fresh_internal_term(&mut self, kind: &str, sort: SortId) -> TermId {
        loop {
            let name = format!("@euf_viper_{kind}_{}", self.fresh_internal_counter);
            self.fresh_internal_counter += 1;
            if self.symbols.ids.contains_key(&name) {
                continue;
            }
            let sym = self.symbols.intern(&name);
            self.fun_decls.insert(
                sym,
                FunDecl {
                    arg_sorts: Vec::new(),
                    result_sort: sort,
                },
            );
            return self.arena.intern_typed(sym, Vec::new(), sort);
        }
    }

    fn collect_equality(
        &mut self,
        args: &[Sexp],
        polarity: bool,
        env: &mut HashMap<String, TermId>,
    ) -> Result<(), String> {
        if args.len() < 2 {
            self.add_unsupported("equality with fewer than two arguments");
            return Ok(());
        }
        let terms = self.parse_terms(args, env)?;
        self.ensure_terms_same_sort("equality", &terms)?;
        if polarity {
            let first = terms[0];
            for &term in &terms[1..] {
                self.eqs.push((first, term));
            }
        } else if terms.len() == 2 {
            self.diseqs.push((terms[0], terms[1]));
        } else {
            self.add_unsupported("negated n-ary equality is disjunctive");
        }
        Ok(())
    }

    fn collect_distinct(
        &mut self,
        args: &[Sexp],
        polarity: bool,
        env: &mut HashMap<String, TermId>,
    ) -> Result<(), String> {
        if args.len() < 2 {
            return Ok(());
        }
        let terms = self.parse_terms(args, env)?;
        self.ensure_terms_same_sort("distinct", &terms)?;
        if polarity {
            for i in 0..terms.len() {
                for j in (i + 1)..terms.len() {
                    self.diseqs.push((terms[i], terms[j]));
                }
            }
        } else if terms.len() == 2 {
            self.eqs.push((terms[0], terms[1]));
        } else {
            self.add_unsupported("negated distinct with more than two arguments is disjunctive");
        }
        Ok(())
    }

    fn parse_terms(
        &mut self,
        args: &[Sexp],
        env: &mut HashMap<String, TermId>,
    ) -> Result<Vec<TermId>, String> {
        let mut terms = Vec::with_capacity(args.len());
        for arg in args {
            terms.push(self.parse_term(arg, env)?);
        }
        Ok(terms)
    }

    fn parse_term(
        &mut self,
        sexp: &Sexp,
        env: &mut HashMap<String, TermId>,
    ) -> Result<TermId, String> {
        if matches!(sexp, Sexp::List(items) if items.is_empty()) {
            return Err("empty term list".to_owned());
        }
        let mut mixed_env = env
            .iter()
            .map(|(name, &term)| (name.clone(), BindingValue::Term(term)))
            .collect::<HashMap<_, _>>();
        match self.parse_bool_or_term(sexp, &mut mixed_env)? {
            BindingValue::Term(term) => Ok(term),
            BindingValue::Bool(expr) => Ok(self.materialize_bool_expr(expr)),
        }
    }

    fn parse_let_bindings(
        &mut self,
        bindings: &Sexp,
        env: &mut HashMap<String, TermId>,
    ) -> Result<Vec<(String, TermId)>, String> {
        let Sexp::List(binding_list) = bindings else {
            return Err("let binding block is not a list".to_owned());
        };
        let mut parsed = Vec::with_capacity(binding_list.len());
        for binding in binding_list {
            let Sexp::List(pair) = binding else {
                return Err("let binding is not a pair".to_owned());
            };
            if pair.len() != 2 {
                return Err("let binding does not have arity 2".to_owned());
            }
            let Some(name) = atom_text(&pair[0]) else {
                return Err("let binding name is not a symbol".to_owned());
            };
            let value = self.parse_term(&pair[1], env)?;
            parsed.push((name.to_owned(), value));
        }
        Ok(parsed)
    }

    fn extend_let_env(
        &mut self,
        bindings: &Sexp,
        env: &mut HashMap<String, TermId>,
    ) -> Result<HashMap<String, TermId>, String> {
        let parsed = self.parse_let_bindings(bindings, env)?;
        let mut local = env.clone();
        for (name, value) in parsed {
            local.insert(name, value);
        }
        Ok(local)
    }
}

#[derive(Debug)]
struct UnionFind {
    parent: Vec<usize>,
    rank: Vec<u8>,
}

impl UnionFind {
    fn new(n: usize) -> Self {
        Self {
            parent: (0..n).collect(),
            rank: vec![0; n],
        }
    }

    fn root_const(&self, mut x: usize) -> usize {
        while self.parent[x] != x {
            x = self.parent[x];
        }
        x
    }

    fn find(&mut self, x: usize) -> usize {
        let parent = self.parent[x];
        if parent == x {
            x
        } else {
            let root = self.find(parent);
            self.parent[x] = root;
            root
        }
    }

    fn union(&mut self, a: usize, b: usize) -> bool {
        let mut ra = self.find(a);
        let mut rb = self.find(b);
        if ra == rb {
            return false;
        }
        if self.rank[ra] < self.rank[rb] {
            std::mem::swap(&mut ra, &mut rb);
        }
        self.parent[rb] = ra;
        if self.rank[ra] == self.rank[rb] {
            self.rank[ra] = self.rank[ra].saturating_add(1);
        }
        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Signature {
    fun: SymId,
    arg_roots: Vec<usize>,
}

#[derive(Debug, Clone)]
enum EqualityReason {
    Literal(i32),
    Congruence(TermId, TermId),
}

#[derive(Debug, Clone)]
struct EqualityEdge {
    to: TermId,
    reason: EqualityReason,
}

struct ExplainingTheory<'a> {
    arena: &'a TermArena,
    uf: UnionFind,
    edges: Vec<Vec<EqualityEdge>>,
}

impl<'a> ExplainingTheory<'a> {
    fn new(arena: &'a TermArena) -> Self {
        Self {
            arena,
            uf: UnionFind::new(arena.terms.len()),
            edges: vec![Vec::new(); arena.terms.len()],
        }
    }

    fn merge(&mut self, a: TermId, b: TermId, reason: EqualityReason) -> bool {
        if !self.uf.union(a, b) {
            return false;
        }
        self.edges[a].push(EqualityEdge {
            to: b,
            reason: reason.clone(),
        });
        self.edges[b].push(EqualityEdge { to: a, reason });
        true
    }

    fn close_congruence(&mut self) {
        loop {
            let mut changed = false;
            let mut signatures = HashMap::<Signature, TermId>::with_capacity_and_hasher(
                self.arena.apps.len() * 2,
                Default::default(),
            );
            for &term_id in &self.arena.apps {
                let term = &self.arena.terms[term_id];
                let signature = Signature {
                    fun: term.fun,
                    arg_roots: term
                        .args
                        .iter()
                        .map(|arg| self.uf.root_const(*arg))
                        .collect(),
                };
                if let Some(&previous) = signatures.get(&signature) {
                    changed |= self.merge(
                        previous,
                        term_id,
                        EqualityReason::Congruence(previous, term_id),
                    );
                } else {
                    signatures.insert(signature, term_id);
                }
            }
            if !changed {
                break;
            }
        }
    }

    fn equal(&mut self, a: TermId, b: TermId) -> bool {
        self.uf.find(a) == self.uf.find(b)
    }

    fn explain_equal(&self, a: TermId, b: TermId, literals: &mut HashSet<i32>) {
        let mut expanded = HashSet::default();
        self.explain_equal_inner(a, b, literals, &mut expanded);
    }

    fn explain_equal_inner(
        &self,
        a: TermId,
        b: TermId,
        literals: &mut HashSet<i32>,
        expanded: &mut HashSet<(TermId, TermId)>,
    ) {
        if a == b || !expanded.insert(normalized_pair(a, b)) {
            return;
        }

        let mut seen = vec![false; self.edges.len()];
        let mut parent: Vec<Option<(TermId, EqualityReason)>> = vec![None; self.edges.len()];
        let mut queue = VecDeque::new();
        seen[a] = true;
        queue.push_back(a);
        while let Some(node) = queue.pop_front() {
            if node == b {
                break;
            }
            for edge in &self.edges[node] {
                if !seen[edge.to] {
                    seen[edge.to] = true;
                    parent[edge.to] = Some((node, edge.reason.clone()));
                    queue.push_back(edge.to);
                }
            }
        }
        debug_assert!(seen[b], "equal terms must have an explanation path");

        let mut current = b;
        while current != a {
            let (previous, reason) = parent[current]
                .clone()
                .expect("equal terms have a proof path");
            match reason {
                EqualityReason::Literal(literal) => {
                    literals.insert(literal);
                }
                EqualityReason::Congruence(left, right) => {
                    let left_term = &self.arena.terms[left];
                    let right_term = &self.arena.terms[right];
                    debug_assert_eq!(left_term.fun, right_term.fun);
                    debug_assert_eq!(left_term.args.len(), right_term.args.len());
                    for (&left_arg, &right_arg) in left_term.args.iter().zip(&right_term.args) {
                        self.explain_equal_inner(left_arg, right_arg, literals, expanded);
                    }
                }
            }
            current = previous;
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
struct FlatClauses {
    literals: Vec<i32>,
    end_offsets: Vec<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlatClauseStoreError {
    LiteralCapacityExceeded,
    AllocationFailed,
}

impl std::fmt::Display for FlatClauseStoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LiteralCapacityExceeded => {
                formatter.write_str("flat clause literal capacity exceeds u32::MAX")
            }
            Self::AllocationFailed => formatter.write_str("flat clause allocation failed"),
        }
    }
}

impl FlatClauses {
    fn new() -> Self {
        Self {
            literals: Vec::new(),
            end_offsets: vec![0],
        }
    }

    fn len(&self) -> usize {
        self.end_offsets.len() - 1
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn iter(&self) -> FlatClauseIter<'_> {
        FlatClauseIter {
            literals: &self.literals,
            end_offsets: self.end_offsets.windows(2),
        }
    }

    #[cfg(test)]
    fn last(&self) -> Option<&[i32]> {
        self.len().checked_sub(1).map(|index| &self[index])
    }

    fn checked_end_offset(
        literal_count: usize,
        additional_literals: usize,
        max_end_offset: u32,
    ) -> Result<u32, FlatClauseStoreError> {
        let end_offset = literal_count
            .checked_add(additional_literals)
            .and_then(|count| u32::try_from(count).ok())
            .ok_or(FlatClauseStoreError::LiteralCapacityExceeded)?;
        if end_offset > max_end_offset {
            return Err(FlatClauseStoreError::LiteralCapacityExceeded);
        }
        Ok(end_offset)
    }

    fn try_push(&mut self, clause: Vec<i32>) -> Result<(), FlatClauseStoreError> {
        self.try_push_with_max_end_offset(clause, u32::MAX)
    }

    fn try_push_with_max_end_offset(
        &mut self,
        clause: Vec<i32>,
        max_end_offset: u32,
    ) -> Result<(), FlatClauseStoreError> {
        let end_offset =
            Self::checked_end_offset(self.literals.len(), clause.len(), max_end_offset)?;

        self.literals
            .try_reserve(clause.len())
            .map_err(|_| FlatClauseStoreError::AllocationFailed)?;
        self.end_offsets
            .try_reserve(1)
            .map_err(|_| FlatClauseStoreError::AllocationFailed)?;

        self.literals.extend(clause);
        self.end_offsets.push(end_offset);
        Ok(())
    }

    #[track_caller]
    fn push(&mut self, clause: Vec<i32>) {
        if let Err(error) = self.try_push(clause) {
            panic!("{error}");
        }
    }
}

impl Default for FlatClauses {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for FlatClauses {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_list().entries(self.iter()).finish()
    }
}

impl std::ops::Index<usize> for FlatClauses {
    type Output = [i32];

    fn index(&self, index: usize) -> &Self::Output {
        let start = self.end_offsets[index] as usize;
        let end = self.end_offsets[index + 1] as usize;
        &self.literals[start..end]
    }
}

impl Extend<Vec<i32>> for FlatClauses {
    fn extend<T: IntoIterator<Item = Vec<i32>>>(&mut self, clauses: T) {
        for clause in clauses {
            self.push(clause);
        }
    }
}

impl PartialEq<Vec<Vec<i32>>> for FlatClauses {
    fn eq(&self, other: &Vec<Vec<i32>>) -> bool {
        self.len() == other.len()
            && self
                .iter()
                .zip(other)
                .all(|(left, right)| left == right.as_slice())
    }
}

#[derive(Clone)]
struct FlatClauseIter<'a> {
    literals: &'a [i32],
    end_offsets: std::slice::Windows<'a, u32>,
}

impl<'a> Iterator for FlatClauseIter<'a> {
    type Item = &'a [i32];

    fn next(&mut self) -> Option<Self::Item> {
        self.end_offsets
            .next()
            .map(|bounds| &self.literals[bounds[0] as usize..bounds[1] as usize])
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.end_offsets.size_hint()
    }
}

impl DoubleEndedIterator for FlatClauseIter<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.end_offsets
            .next_back()
            .map(|bounds| &self.literals[bounds[0] as usize..bounds[1] as usize])
    }
}

impl ExactSizeIterator for FlatClauseIter<'_> {}
impl std::iter::FusedIterator for FlatClauseIter<'_> {}

impl<'a> IntoIterator for &'a FlatClauses {
    type Item = &'a [i32];
    type IntoIter = FlatClauseIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

#[derive(Debug)]
struct CnfProblem {
    clauses: FlatClauses,
    var_atoms: Vec<Option<BoolAtomKey>>,
    atom_vars: HashMap<BoolAtomKey, i32>,
    true_lit: Option<i32>,
    finite_equalities_complete: bool,
    finite_predicate_congruence_complete: bool,
}

#[cfg(feature = "certificates")]
#[derive(Debug, Serialize)]
struct CertificateTerm {
    id: TermId,
    function: SymId,
    args: Vec<TermId>,
}

#[cfg(feature = "certificates")]
#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum CertificateAtom {
    Auxiliary {
        variable: usize,
    },
    Equality {
        variable: usize,
        left: TermId,
        right: TermId,
    },
    BoolTerm {
        variable: usize,
        term: TermId,
    },
}

#[cfg(feature = "certificates")]
#[derive(Debug, Serialize)]
struct CertificateClauseCounts {
    base: usize,
    transitivity: usize,
    congruence: usize,
    theory_conflicts: usize,
    total: usize,
}

#[cfg(feature = "certificates")]
#[derive(Debug, Serialize)]
struct CertificateManifest {
    format: &'static str,
    result: &'static str,
    encoding: &'static str,
    source: String,
    source_sha256: String,
    dimacs: String,
    dimacs_sha256: String,
    proof: String,
    proof_sha256: String,
    variables: usize,
    true_term: TermId,
    false_term: TermId,
    terms: Vec<CertificateTerm>,
    atoms: Vec<CertificateAtom>,
    clauses: CertificateClauseCounts,
    theory_rounds: usize,
    finite_domain_axioms: usize,
}

#[cfg(feature = "certificates")]
#[derive(Debug, Serialize)]
struct SatCertificateManifest {
    format: &'static str,
    result: &'static str,
    encoding: &'static str,
    source: String,
    source_sha256: String,
    variables: usize,
    assignment: Vec<i32>,
    theory_rounds: usize,
    theory_conflicts: usize,
}

#[cfg(feature = "certificates")]
enum CertificateSaturation {
    Sat {
        theory_rounds: usize,
        conflict_count: usize,
        assignment: Vec<i32>,
    },
    Unsat {
        theory_rounds: usize,
        conflict_count: usize,
    },
}

impl CnfProblem {
    fn new() -> Self {
        Self {
            clauses: FlatClauses::new(),
            var_atoms: vec![None],
            atom_vars: HashMap::default(),
            true_lit: None,
            finite_equalities_complete: false,
            finite_predicate_congruence_complete: false,
        }
    }

    fn var_count(&self) -> usize {
        self.var_atoms.len().saturating_sub(1)
    }

    pub(crate) fn add_clause(&mut self, clause: Vec<i32>) {
        self.clauses.push(clause);
    }

    fn new_var(&mut self, atom: Option<BoolAtomKey>) -> i32 {
        let var = self.var_atoms.len() as i32;
        self.var_atoms.push(atom);
        var
    }

    fn literal_const(&mut self, value: bool) -> i32 {
        let lit = if let Some(lit) = self.true_lit {
            lit
        } else {
            let lit = self.new_var(None);
            self.clauses.push(vec![lit]);
            self.true_lit = Some(lit);
            lit
        };
        if value { lit } else { -lit }
    }

    fn atom_lit(&mut self, atom: BoolAtomKey) -> i32 {
        let atom = match atom {
            BoolAtomKey::Eq(left, right) => {
                let (left, right) = normalized_pair(left, right);
                BoolAtomKey::Eq(left, right)
            }
            atom => atom,
        };
        if let Some(&lit) = self.atom_vars.get(&atom) {
            return lit;
        }
        let lit = self.new_var(Some(atom.clone()));
        self.atom_vars.insert(atom, lit);
        lit
    }

    fn add_assertion(&mut self, expr: &BoolExpr) {
        let literal = self.encode_expr(expr);
        self.clauses.push(vec![literal]);
    }

    #[cfg(test)]
    #[cold]
    #[inline(never)]
    fn add_direct_assertion(&mut self, expr: &BoolExpr) {
        self.add_direct_assertion_with_negated_root(expr, false);
    }

    #[cold]
    #[inline(never)]
    fn add_direct_assertion_with_negated_root(
        &mut self,
        expr: &BoolExpr,
        direct_negated_root: bool,
    ) {
        match expr {
            BoolExpr::Const(true) => {}
            BoolExpr::Const(false) => self.clauses.push(Vec::new()),
            BoolExpr::Atom(atom) => {
                let literal = self.atom_lit(atom.clone());
                self.clauses.push(vec![literal]);
            }
            BoolExpr::Not(child) if direct_negated_root => {
                self.add_direct_negated_assertion(child);
            }
            BoolExpr::Not(child) => {
                let literal = self.encode_expr(child);
                self.clauses.push(vec![-literal]);
            }
            BoolExpr::And(children) => {
                for child in children {
                    self.add_direct_assertion_with_negated_root(child, direct_negated_root);
                }
            }
            BoolExpr::Or(children) => {
                let clause = children
                    .iter()
                    .map(|child| self.encode_expr(child))
                    .collect();
                self.clauses.push(clause);
            }
            BoolExpr::Iff(children) => {
                let Some((first, rest)) = children.split_first() else {
                    return;
                };
                let first = self.encode_expr(first);
                for child in rest {
                    let child = self.encode_expr(child);
                    self.clauses.push(vec![-first, child]);
                    self.clauses.push(vec![first, -child]);
                }
            }
            BoolExpr::Ite(cond, then_expr, else_expr) => {
                let cond = self.encode_expr(cond);
                let then_expr = self.encode_expr(then_expr);
                let else_expr = self.encode_expr(else_expr);
                self.clauses.push(vec![-cond, then_expr]);
                self.clauses.push(vec![cond, else_expr]);
            }
        }
    }

    fn add_direct_negated_assertion(&mut self, expr: &BoolExpr) {
        match expr {
            BoolExpr::Const(true) => self.clauses.push(Vec::new()),
            BoolExpr::Const(false) => {}
            BoolExpr::Atom(atom) => {
                let literal = self.atom_lit(atom.clone());
                self.clauses.push(vec![-literal]);
            }
            BoolExpr::Not(child) => {
                self.add_direct_assertion_with_negated_root(child, true);
            }
            BoolExpr::And(children) => {
                let clause = children
                    .iter()
                    .map(|child| -self.encode_expr(child))
                    .collect();
                self.clauses.push(clause);
            }
            BoolExpr::Or(children) => {
                for child in children {
                    self.add_direct_negated_assertion(child);
                }
            }
            BoolExpr::Iff(_) | BoolExpr::Ite(_, _, _) => {
                let literal = self.encode_expr(expr);
                self.clauses.push(vec![-literal]);
            }
        }
    }

    fn encode_expr(&mut self, expr: &BoolExpr) -> i32 {
        match expr {
            BoolExpr::Const(value) => self.literal_const(*value),
            BoolExpr::Atom(atom) => self.atom_lit(atom.clone()),
            BoolExpr::Not(child) => -self.encode_expr(child),
            BoolExpr::And(children) => self.encode_and(children),
            BoolExpr::Or(children) => self.encode_or(children),
            BoolExpr::Iff(children) => self.encode_iff(children),
            BoolExpr::Ite(cond, then_expr, else_expr) => {
                let c = self.encode_expr(cond);
                let t = self.encode_expr(then_expr);
                let e = self.encode_expr(else_expr);
                let p = self.new_var(None);
                self.clauses.push(vec![-c, -t, p]);
                self.clauses.push(vec![-c, t, -p]);
                self.clauses.push(vec![c, -e, p]);
                self.clauses.push(vec![c, e, -p]);
                p
            }
        }
    }

    fn encode_and(&mut self, children: &[BoolExpr]) -> i32 {
        match children {
            [] => self.literal_const(true),
            [single] => self.encode_expr(single),
            _ => {
                let lits = children
                    .iter()
                    .map(|child| self.encode_expr(child))
                    .collect::<Vec<_>>();
                let p = self.new_var(None);
                for &lit in &lits {
                    self.clauses.push(vec![-p, lit]);
                }
                let mut clause = Vec::with_capacity(lits.len() + 1);
                clause.push(p);
                clause.extend(lits.iter().map(|&lit| -lit));
                self.clauses.push(clause);
                p
            }
        }
    }

    fn encode_or(&mut self, children: &[BoolExpr]) -> i32 {
        match children {
            [] => self.literal_const(false),
            [single] => self.encode_expr(single),
            _ => {
                let lits = children
                    .iter()
                    .map(|child| self.encode_expr(child))
                    .collect::<Vec<_>>();
                let p = self.new_var(None);
                for &lit in &lits {
                    self.clauses.push(vec![p, -lit]);
                }
                let mut clause = Vec::with_capacity(lits.len() + 1);
                clause.push(-p);
                clause.extend(lits);
                self.clauses.push(clause);
                p
            }
        }
    }

    fn encode_iff(&mut self, children: &[BoolExpr]) -> i32 {
        match children {
            [] | [_] => self.literal_const(true),
            [left, right] => {
                let a = self.encode_expr(left);
                let b = self.encode_expr(right);
                let p = self.new_var(None);
                self.clauses.push(vec![-p, -a, b]);
                self.clauses.push(vec![-p, a, -b]);
                self.clauses.push(vec![p, -a, -b]);
                self.clauses.push(vec![p, a, b]);
                p
            }
            _ => {
                let mut pairs = Vec::with_capacity(children.len().saturating_sub(1));
                let first = children[0].clone();
                for child in &children[1..] {
                    pairs.push(BoolExpr::Iff(vec![first.clone(), child.clone()]));
                }
                self.encode_and(&pairs)
            }
        }
    }
}

fn atomize_bool_data_terms(cnf: &mut CnfProblem, bool_problem: &BoolProblem) {
    for &term in &bool_problem.data_terms {
        cnf.atom_lit(BoolAtomKey::BoolTerm(term));
    }
}

#[cold]
#[inline(never)]
fn add_full_ackermann_axioms(cnf: &mut CnfProblem, arena: &TermArena) -> usize {
    let bool_functions = cnf
        .var_atoms
        .iter()
        .filter_map(|atom| match atom {
            Some(BoolAtomKey::BoolTerm(term)) => {
                let application = &arena.terms[*term];
                Some((application.fun, application.args.len()))
            }
            _ => None,
        })
        .collect::<HashSet<_>>();
    let mut groups = HashMap::<(SymId, usize), Vec<TermId>>::default();
    for &term_id in &arena.apps {
        let term = &arena.terms[term_id];
        groups
            .entry((term.fun, term.args.len()))
            .or_default()
            .push(term_id);
    }

    let start_clause_count = cnf.clauses.len();
    for applications in groups.values() {
        for left_index in 0..applications.len() {
            let left_id = applications[left_index];
            let left = &arena.terms[left_id];
            for &right_id in &applications[(left_index + 1)..] {
                let right = &arena.terms[right_id];
                let mut conditions = Vec::with_capacity(left.args.len());
                for (&left_arg, &right_arg) in left.args.iter().zip(&right.args) {
                    if left_arg != right_arg {
                        conditions.push(-cnf.atom_lit(BoolAtomKey::Eq(left_arg, right_arg)));
                    }
                }

                if bool_functions.contains(&(left.fun, left.args.len())) {
                    let left_bool = cnf.atom_lit(BoolAtomKey::BoolTerm(left_id));
                    let right_bool = cnf.atom_lit(BoolAtomKey::BoolTerm(right_id));
                    let mut forward = conditions.clone();
                    forward.extend([-left_bool, right_bool]);
                    cnf.clauses.push(forward);
                    let mut backward = conditions;
                    backward.extend([left_bool, -right_bool]);
                    cnf.clauses.push(backward);
                } else {
                    conditions.push(cnf.atom_lit(BoolAtomKey::Eq(left_id, right_id)));
                    cnf.clauses.push(conditions);
                }
            }
        }
    }
    cnf.clauses.len() - start_clause_count
}

#[cold]
#[inline(never)]
fn add_sparse_transitivity_fill(
    cnf: &mut CnfProblem,
    term_count: usize,
    max_fill_edges: usize,
) -> Option<usize> {
    let mut adjacency = vec![HashSet::<TermId>::default(); term_count];
    for atom in cnf.var_atoms.iter().flatten() {
        let BoolAtomKey::Eq(left, right) = atom else {
            continue;
        };
        if left == right {
            continue;
        }
        adjacency[*left].insert(*right);
        adjacency[*right].insert(*left);
    }

    let mut active = adjacency
        .iter()
        .map(|neighbors| !neighbors.is_empty())
        .collect::<Vec<_>>();
    let mut degree = adjacency.iter().map(HashSet::len).collect::<Vec<_>>();
    let mut queue = BinaryHeap::new();
    for (vertex, &vertex_degree) in degree.iter().enumerate() {
        if active[vertex] {
            queue.push(Reverse((vertex_degree, vertex)));
        }
    }

    let mut fill_edges = Vec::new();
    while let Some(Reverse((queued_degree, vertex))) = queue.pop() {
        if !active[vertex] || degree[vertex] != queued_degree {
            continue;
        }
        let neighbors = adjacency[vertex]
            .iter()
            .copied()
            .filter(|neighbor| active[*neighbor])
            .collect::<Vec<_>>();
        for left_index in 0..neighbors.len() {
            let left = neighbors[left_index];
            for &right in &neighbors[(left_index + 1)..] {
                if adjacency[left].contains(&right) {
                    continue;
                }
                if fill_edges.len() == max_fill_edges {
                    return None;
                }
                adjacency[left].insert(right);
                adjacency[right].insert(left);
                degree[left] += 1;
                degree[right] += 1;
                queue.push(Reverse((degree[left], left)));
                queue.push(Reverse((degree[right], right)));
                fill_edges.push(normalized_pair(left, right));
            }
        }

        active[vertex] = false;
        for neighbor in neighbors {
            degree[neighbor] -= 1;
            queue.push(Reverse((degree[neighbor], neighbor)));
        }
    }

    fill_edges.sort_unstable();
    fill_edges.dedup();
    for (left, right) in &fill_edges {
        cnf.atom_lit(BoolAtomKey::Eq(*left, *right));
    }
    Some(fill_edges.len())
}

#[cold]
#[inline(never)]
fn add_full_ackermann_completion(cnf: &mut CnfProblem, arena: &TermArena) {
    let ackermann_start = Instant::now();
    let added = add_full_ackermann_axioms(cnf, arena);
    profile_phase("full_ackermann", ackermann_start, added);

    if cnf.finite_equalities_complete {
        return;
    }
    let fill_start = Instant::now();
    let max_fill_edges = env::var("EUF_VIPER_CHORDAL_MAX_FILL")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1_000_000usize);
    let fill_edges = add_sparse_transitivity_fill(cnf, arena.terms.len(), max_fill_edges);
    profile_phase(
        "chordal_transitivity_fill",
        fill_start,
        fill_edges.unwrap_or(usize::MAX),
    );
}

fn equality_transitivity_clauses(cnf: &CnfProblem, term_count: usize) -> Vec<Vec<i32>> {
    if cnf.finite_equalities_complete {
        return Vec::new();
    }
    let mut equality_vars = HashMap::default();
    let mut adjacency = vec![Vec::<(TermId, i32)>::new(); term_count];
    let mut clauses = HashSet::default();
    for (var, atom) in cnf.var_atoms.iter().enumerate().skip(1) {
        let Some(BoolAtomKey::Eq(left, right)) = atom else {
            continue;
        };
        let var = var as i32;
        if left == right {
            clauses.insert(vec![var]);
            continue;
        }
        let pair = normalized_pair(*left, *right);
        equality_vars.insert(pair, var);
        adjacency[*left].push((*right, var));
        adjacency[*right].push((*left, var));
    }

    for (&(left, right), &left_right_var) in &equality_vars {
        if left == right {
            continue;
        }
        let incident = if adjacency[left].len() <= adjacency[right].len() {
            &adjacency[left]
        } else {
            &adjacency[right]
        };
        for &(third, _) in incident {
            if third <= right {
                continue;
            }
            let Some(&left_third_var) = equality_vars.get(&normalized_pair(left, third)) else {
                continue;
            };
            let Some(&right_third_var) = equality_vars.get(&normalized_pair(right, third)) else {
                continue;
            };
            clauses.insert(vec![-left_right_var, -left_third_var, right_third_var]);
            clauses.insert(vec![-left_right_var, -right_third_var, left_third_var]);
            clauses.insert(vec![-left_third_var, -right_third_var, left_right_var]);
        }
    }
    let mut clauses = clauses.into_iter().collect::<Vec<_>>();
    order_axiom_clauses(&mut clauses);
    clauses
}

fn add_finite_domain_axioms(
    cnf: &mut CnfProblem,
    arena: &TermArena,
    bool_problem: &BoolProblem,
) -> usize {
    let mut context = finite_analysis::FiniteAnalysisContext::default();
    add_finite_domain_axioms_with_context(cnf, arena, bool_problem, &mut context)
}

fn add_finite_domain_axioms_with_context(
    cnf: &mut CnfProblem,
    arena: &TermArena,
    bool_problem: &BoolProblem,
    context: &mut finite_analysis::FiniteAnalysisContext,
) -> usize {
    let equality_channeling = match env::var("EUF_VIPER_FINITE_EQUALITY_CHANNELING").as_deref() {
        Ok("0" | "off") => FiniteEqualityChanneling::Off,
        Ok("1" | "all") => FiniteEqualityChanneling::All,
        _ => FiniteEqualityChanneling::ValueOnly,
    };
    let predicate_channeling =
        env::var("EUF_VIPER_FINITE_PREDICATE_CHANNELING").as_deref() == Ok("1");
    #[cfg(feature = "finite-symmetry")]
    if arena.apps.len() >= 1_000 {
        let symmetry_mode =
            env::var("EUF_VIPER_FINITE_SYMMETRY").unwrap_or_else(|_| "hybrid".to_owned());
        let symmetry_min_apps = env::var("EUF_VIPER_FINITE_SYMMETRY_MIN_APPS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(1_000);
        if arena.apps.len() >= symmetry_min_apps
            && matches!(symmetry_mode.as_str(), "1" | "constants" | "hybrid" | "lex")
        {
            return add_finite_domain_axioms_with_options_and_context::<true>(
                cnf,
                arena,
                bool_problem,
                equality_channeling,
                predicate_channeling,
                context,
            );
        }
    }
    add_finite_domain_axioms_with_options_and_context::<false>(
        cnf,
        arena,
        bool_problem,
        equality_channeling,
        predicate_channeling,
        context,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FiniteEqualityChanneling {
    Off,
    ValueOnly,
    All,
}

#[cfg(feature = "finite-symmetry")]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum CanonicalBoolKey {
    Const(bool),
    Eq(TermId, TermId),
    BoolTerm(TermId),
    Not(usize),
    And(Vec<usize>),
    Or(Vec<usize>),
    Iff(Vec<usize>),
    Ite(usize, usize, usize),
}

#[cfg(feature = "finite-symmetry")]
#[derive(Debug, Default)]
struct CanonicalBoolInterner {
    keys: HashMap<CanonicalBoolKey, usize>,
}

#[cfg(feature = "finite-symmetry")]
impl CanonicalBoolInterner {
    fn intern(&mut self, key: CanonicalBoolKey) -> usize {
        if let Some(&id) = self.keys.get(&key) {
            return id;
        }
        let id = self.keys.len();
        self.keys.insert(key, id);
        id
    }
}

#[cold]
#[inline(never)]
#[cfg(feature = "finite-symmetry")]
fn canonical_bool_id(
    expression: &BoolExpr,
    term_map: &[TermId],
    interner: &mut CanonicalBoolInterner,
) -> usize {
    let key = match expression {
        BoolExpr::Const(value) => CanonicalBoolKey::Const(*value),
        BoolExpr::Atom(BoolAtomKey::Eq(left, right)) => {
            let (left, right) = normalized_pair(term_map[*left], term_map[*right]);
            CanonicalBoolKey::Eq(left, right)
        }
        BoolExpr::Atom(BoolAtomKey::BoolTerm(term)) => CanonicalBoolKey::BoolTerm(term_map[*term]),
        BoolExpr::Not(child) => CanonicalBoolKey::Not(canonical_bool_id(child, term_map, interner)),
        BoolExpr::And(children) => {
            let mut children = children
                .iter()
                .map(|child| canonical_bool_id(child, term_map, interner))
                .collect::<Vec<_>>();
            children.sort_unstable();
            CanonicalBoolKey::And(children)
        }
        BoolExpr::Or(children) => {
            let mut children = children
                .iter()
                .map(|child| canonical_bool_id(child, term_map, interner))
                .collect::<Vec<_>>();
            children.sort_unstable();
            CanonicalBoolKey::Or(children)
        }
        BoolExpr::Iff(children) => {
            let mut children = children
                .iter()
                .map(|child| canonical_bool_id(child, term_map, interner))
                .collect::<Vec<_>>();
            children.sort_unstable();
            CanonicalBoolKey::Iff(children)
        }
        BoolExpr::Ite(condition, then_expression, else_expression) => CanonicalBoolKey::Ite(
            canonical_bool_id(condition, term_map, interner),
            canonical_bool_id(then_expression, term_map, interner),
            canonical_bool_id(else_expression, term_map, interner),
        ),
    };
    interner.intern(key)
}

#[cold]
#[inline(never)]
#[cfg(feature = "finite-symmetry")]
fn canonical_assertion_ids(
    bool_problem: &BoolProblem,
    term_map: &[TermId],
    interner: &mut CanonicalBoolInterner,
) -> Vec<usize> {
    let mut assertions = bool_problem
        .assertions
        .iter()
        .map(|assertion| canonical_bool_id(assertion, term_map, interner))
        .collect::<Vec<_>>();
    assertions.sort_unstable();
    assertions
}

#[cold]
#[inline(never)]
#[cfg(feature = "finite-symmetry")]
fn term_map_under_swap(arena: &TermArena, left: TermId, right: TermId) -> Option<Vec<TermId>> {
    fn resolve(arena: &TermArena, term_id: TermId, mapped: &mut [TermId]) -> Option<TermId> {
        if mapped[term_id] != TermId::MAX {
            return Some(mapped[term_id]);
        }
        let term = &arena.terms[term_id];
        if term.args.is_empty() {
            mapped[term_id] = term_id;
            return Some(term_id);
        }
        let args = term
            .args
            .iter()
            .map(|arg| resolve(arena, *arg, mapped))
            .collect::<Option<Vec<_>>>()?;
        let mapped_id = *arena.interned.get(&TermKey {
            fun: term.fun,
            args,
        })?;
        mapped[term_id] = mapped_id;
        Some(mapped_id)
    }

    let mut mapped = vec![TermId::MAX; arena.terms.len()];
    mapped[left] = right;
    mapped[right] = left;
    for term_id in 0..arena.terms.len() {
        resolve(arena, term_id, &mut mapped)?;
    }
    Some(mapped)
}

#[cold]
#[inline(never)]
#[cfg(feature = "finite-symmetry")]
fn verified_domain_swap_maps(
    arena: &TermArena,
    bool_problem: &BoolProblem,
    domain: &[TermId],
) -> Option<Vec<Vec<TermId>>> {
    if domain.len() < 2 {
        return Some(Vec::new());
    }
    let identity = (0..arena.terms.len()).collect::<Vec<_>>();
    let mut interner = CanonicalBoolInterner::default();
    let baseline = canonical_assertion_ids(bool_problem, &identity, &mut interner);
    let mut swap_maps = Vec::with_capacity(domain.len() - 1);
    for pair in domain.windows(2) {
        let term_map = term_map_under_swap(arena, pair[0], pair[1])?;
        if canonical_assertion_ids(bool_problem, &term_map, &mut interner) != baseline {
            return None;
        }
        swap_maps.push(term_map);
    }
    Some(swap_maps)
}

#[cold]
#[inline(never)]
#[cfg(feature = "finite-symmetry")]
fn add_finite_constant_symmetry_breaking(
    cnf: &mut CnfProblem,
    arena: &TermArena,
    domain: &[TermId],
    covered_terms: &HashSet<TermId>,
    membership: &HashMap<(TermId, TermId), i32>,
) -> usize {
    let mut constants = covered_terms
        .iter()
        .copied()
        .filter(|term| arena.terms[*term].args.is_empty())
        .collect::<Vec<_>>();
    constants.sort_unstable();
    if constants.is_empty() {
        return 0;
    }

    let start_clause_count = cnf.clauses.len();
    cnf.clauses
        .push(vec![membership[&(constants[0], domain[0])]]);
    for (constant_index, &constant) in constants.iter().enumerate() {
        let highest_allowed = constant_index.min(domain.len() - 1);
        for &value in &domain[(highest_allowed + 1)..] {
            cnf.clauses.push(vec![-membership[&(constant, value)]]);
        }
        for value_index in 1..=highest_allowed {
            let mut clause = Vec::with_capacity(constant_index + 1);
            clause.push(-membership[&(constant, domain[value_index])]);
            clause.extend(
                constants[..constant_index]
                    .iter()
                    .map(|earlier| membership[&(*earlier, domain[value_index - 1])]),
            );
            cnf.clauses.push(clause);
        }
    }
    cnf.clauses.len() - start_clause_count
}

#[cold]
#[inline(never)]
#[cfg(feature = "finite-symmetry")]
fn finite_diagonal_terms(
    arena: &TermArena,
    domain: &[TermId],
    covered_terms: &HashSet<TermId>,
    closed_functions: &HashSet<SymId>,
    rank: usize,
) -> Option<Vec<TermId>> {
    let mut candidates = closed_functions
        .iter()
        .copied()
        .filter_map(|function| {
            covered_terms.iter().find_map(|term_id| {
                let term = &arena.terms[*term_id];
                (term.fun == function && !term.args.is_empty())
                    .then_some((function, term.args.len()))
            })
        })
        .collect::<Vec<_>>();
    candidates.sort_unstable_by_key(|(function, _)| *function);
    let &(function, arity) = candidates.get(rank)?;

    let mut diagonal = Vec::with_capacity(domain.len());
    for &value in domain {
        let key = TermKey {
            fun: function,
            args: vec![value; arity],
        };
        let &term = arena.interned.get(&key)?;
        if !covered_terms.contains(&term) {
            return None;
        }
        diagonal.push(term);
    }
    Some(diagonal)
}

#[cold]
#[inline(never)]
#[cfg(feature = "finite-symmetry")]
fn add_finite_diagonal_ordered_range(
    cnf: &mut CnfProblem,
    arena: &TermArena,
    domain: &[TermId],
    covered_terms: &HashSet<TermId>,
    closed_functions: &HashSet<SymId>,
    membership: &HashMap<(TermId, TermId), i32>,
    rank: usize,
) -> usize {
    let Some(diagonal) =
        finite_diagonal_terms(arena, domain, covered_terms, closed_functions, rank)
    else {
        return 0;
    };

    let start_clause_count = cnf.clauses.len();
    for (input_index, &term) in diagonal.iter().enumerate() {
        let first_forbidden = (input_index + 2).min(domain.len());
        for &output in &domain[first_forbidden..] {
            cnf.clauses.push(vec![-membership[&(term, output)]]);
        }
    }
    cnf.clauses.len() - start_clause_count
}

#[cfg(feature = "finite-symmetry")]
fn finite_hybrid_uses_diagonal(
    symmetry_mode: &str,
    domain_size: usize,
    closed_function_count: usize,
    has_predicates: bool,
) -> bool {
    symmetry_mode == "hybrid" && domain_size == 11 && closed_function_count == 3 && !has_predicates
}

#[cold]
#[inline(never)]
#[cfg(feature = "finite-symmetry")]
fn add_lex_less_or_equal(cnf: &mut CnfProblem, comparison: &[(i32, i32)]) -> usize {
    let comparison = comparison
        .iter()
        .copied()
        .filter(|(left, right)| left != right)
        .collect::<Vec<_>>();
    let start_clause_count = cnf.clauses.len();
    let mut equal_prefix: Option<i32> = None;
    for (index, (left, right)) in comparison.iter().copied().enumerate() {
        if let Some(prefix) = equal_prefix {
            cnf.clauses.push(vec![-prefix, -left, right]);
        } else {
            cnf.clauses.push(vec![-left, right]);
        }
        if index + 1 == comparison.len() {
            break;
        }

        let next_prefix = cnf.new_var(None);
        if let Some(prefix) = equal_prefix {
            cnf.clauses.push(vec![-next_prefix, prefix]);
            cnf.clauses.push(vec![-next_prefix, -left, right]);
            cnf.clauses.push(vec![-next_prefix, left, -right]);
            cnf.clauses.push(vec![-prefix, -left, -right, next_prefix]);
            cnf.clauses.push(vec![-prefix, left, right, next_prefix]);
        } else {
            cnf.clauses.push(vec![-next_prefix, -left, right]);
            cnf.clauses.push(vec![-next_prefix, left, -right]);
            cnf.clauses.push(vec![-left, -right, next_prefix]);
            cnf.clauses.push(vec![left, right, next_prefix]);
        }
        equal_prefix = Some(next_prefix);
    }
    cnf.clauses.len() - start_clause_count
}

#[cold]
#[inline(never)]
#[cfg(feature = "finite-symmetry")]
fn add_finite_table_lex_leaders(
    cnf: &mut CnfProblem,
    arena: &TermArena,
    domain: &[TermId],
    covered_terms: &HashSet<TermId>,
    membership: &HashMap<(TermId, TermId), i32>,
    priority_terms: &[TermId],
    swap_maps: &[Vec<TermId>],
) -> usize {
    let mut terms = covered_terms.iter().copied().collect::<Vec<_>>();
    terms.sort_unstable_by_key(|term| (!arena.terms[*term].args.is_empty(), *term));
    if !priority_terms.is_empty() {
        let priority = priority_terms.iter().copied().collect::<HashSet<_>>();
        if priority.len() != priority_terms.len()
            || !priority.iter().all(|term| covered_terms.contains(term))
        {
            return 0;
        }
        terms.retain(|term| !priority.contains(term));
        let mut ordered = priority_terms.to_vec();
        ordered.extend(terms);
        terms = ordered;
    }
    if terms.is_empty() || swap_maps.is_empty() {
        return 0;
    }

    let mut comparisons = Vec::with_capacity(swap_maps.len());
    for term_map in swap_maps {
        let mut comparison = Vec::with_capacity(terms.len() * domain.len());
        for &term in &terms {
            let mapped_term = term_map[term];
            if !covered_terms.contains(&mapped_term) {
                return 0;
            }
            for &value in domain {
                let Some(&left) = membership.get(&(term, value)) else {
                    return 0;
                };
                let Some(&right) = membership.get(&(mapped_term, term_map[value])) else {
                    return 0;
                };
                // Negated one-hot bits make lower domain values lexicographically smaller.
                comparison.push((-left, -right));
            }
        }
        comparisons.push(comparison);
    }

    let start_clause_count = cnf.clauses.len();
    for comparison in comparisons {
        add_lex_less_or_equal(cnf, &comparison);
    }
    cnf.clauses.len() - start_clause_count
}

fn add_finite_domain_axioms_with_options<const FINITE_SYMMETRY: bool>(
    cnf: &mut CnfProblem,
    arena: &TermArena,
    bool_problem: &BoolProblem,
    equality_channeling: FiniteEqualityChanneling,
    predicate_channeling: bool,
) -> usize {
    let mut context = finite_analysis::FiniteAnalysisContext::default();
    add_finite_domain_axioms_with_options_and_context::<FINITE_SYMMETRY>(
        cnf,
        arena,
        bool_problem,
        equality_channeling,
        predicate_channeling,
        &mut context,
    )
}

fn add_finite_domain_axioms_with_options_and_context<const FINITE_SYMMETRY: bool>(
    cnf: &mut CnfProblem,
    arena: &TermArena,
    bool_problem: &BoolProblem,
    equality_channeling: FiniteEqualityChanneling,
    predicate_channeling: bool,
    context: &mut finite_analysis::FiniteAnalysisContext,
) -> usize {
    context.domain_analysis(arena, bool_problem);
    #[cfg(feature = "finite-symmetry")]
    let max_domain = if FINITE_SYMMETRY {
        env::var("EUF_VIPER_FINITE_DOMAIN_MAX")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(11)
            .min(32)
    } else {
        8
    };
    #[cfg(not(feature = "finite-symmetry"))]
    let max_domain = 8;
    let domain_size = context.domain.as_ref().unwrap().domain.len();
    if domain_size < 3 || domain_size > max_domain {
        return 0;
    }
    context.finite_closure(arena, bool_problem);
    if context
        .closure
        .as_ref()
        .unwrap()
        .closed_functions
        .is_empty()
    {
        return 0;
    }

    #[cfg(feature = "finite-symmetry")]
    let domain_swap_maps = if FINITE_SYMMETRY {
        let symmetry_start = Instant::now();
        let swap_maps = verified_domain_swap_maps(
            arena,
            bool_problem,
            &context.domain.as_ref().unwrap().domain,
        );
        profile_phase(
            "finite_symmetry_check",
            symmetry_start,
            usize::from(swap_maps.is_some()),
        );
        if domain_size > 8 && swap_maps.is_none() {
            return 0;
        }
        swap_maps
    } else {
        None
    };
    #[cfg(feature = "finite-symmetry")]
    let domain_symmetry = domain_swap_maps.is_some();

    let permutation_support_mode = match env::var("EUF_VIPER_FINITE_PERMUTATION_SUPPORT").as_deref()
    {
        Ok("1" | "all") => Some(finite_analysis::PermutationSupportMode::All),
        Ok("auto" | "focused") => Some(finite_analysis::PermutationSupportMode::Focused),
        _ => None,
    };
    if permutation_support_mode.is_some() {
        context.guarded_summary(arena, bool_problem);
    }

    let domain_analysis = context.domain.as_ref().unwrap();
    let closure = context.closure.as_ref().unwrap();
    let domain = &domain_analysis.domain;
    let domain_set = &domain_analysis.domain_set;
    let disequality_edges = &domain_analysis.mandatory_disequalities;
    let covered_terms = &closure.covered_terms;
    let closed_functions = &closure.closed_functions;
    let finite_terms = &closure.finite_terms;

    let mut ordered_finite_terms = finite_terms.iter().copied().collect::<Vec<_>>();
    order_finite_terms(&mut ordered_finite_terms);
    let original_equalities = cnf
        .var_atoms
        .iter()
        .enumerate()
        .skip(1)
        .filter_map(|(var, atom)| match atom {
            Some(BoolAtomKey::Eq(left, right)) => Some((var as i32, *left, *right)),
            _ => None,
        })
        .collect::<Vec<_>>();
    let mut original_predicates = cnf
        .var_atoms
        .iter()
        .filter_map(|atom| match atom {
            Some(BoolAtomKey::BoolTerm(term)) if !arena.terms[*term].args.is_empty() => Some(*term),
            _ => None,
        })
        .collect::<Vec<_>>();
    original_predicates.sort_unstable();
    original_predicates.dedup();

    let mut membership = HashMap::default();
    for &term in &ordered_finite_terms {
        for &value in domain {
            let literal = cnf.atom_lit(BoolAtomKey::Eq(term, value));
            membership.insert((term, value), literal);
        }
    }

    let start_clause_count = cnf.clauses.len();
    for &term in &ordered_finite_terms {
        let values = domain
            .iter()
            .map(|value| membership[&(term, *value)])
            .collect::<Vec<_>>();
        if domain_set.contains(&term) {
            for &value in domain {
                let literal = membership[&(term, value)];
                cnf.clauses
                    .push(vec![if term == value { literal } else { -literal }]);
            }
            continue;
        }
        cnf.clauses.push(values.clone());
        for left in 0..values.len() {
            for right in (left + 1)..values.len() {
                cnf.clauses.push(vec![-values[left], -values[right]]);
            }
        }
    }

    if let Some(permutation_support_mode) = permutation_support_mode {
        let stats = finite_analysis::add_permutation_support(
            cnf,
            &domain,
            &domain_set,
            &finite_terms,
            closed_functions.len(),
            &disequality_edges,
            context.guarded.as_ref().unwrap(),
            &membership,
            permutation_support_mode,
        );
        profile_measurement(
            "finite_permutation_support",
            stats.clauses as u128,
            stats.cliques,
        );
        profile_measurement(
            "finite_permutation_edges",
            stats.candidate_edges as u128,
            stats.guarded_edges,
        );
        profile_measurement(
            "finite_permutation_truncated",
            u128::from(stats.truncated),
            stats.direct_edges,
        );
        profile_measurement(
            "finite_permutation_selected",
            u128::from(stats.selected),
            closed_functions.len(),
        );
    }

    #[cfg(feature = "finite-symmetry")]
    if domain_symmetry {
        let symmetry_mode =
            env::var("EUF_VIPER_FINITE_SYMMETRY").unwrap_or_else(|_| "hybrid".to_owned());
        if finite_hybrid_uses_diagonal(
            &symmetry_mode,
            domain.len(),
            closed_functions.len(),
            !original_predicates.is_empty(),
        ) {
            let diagonal_clauses = add_finite_diagonal_ordered_range(
                cnf,
                arena,
                &domain,
                &covered_terms,
                &closed_functions,
                &membership,
                1,
            );
            profile_measurement(
                "finite_diagonal_ordered_range",
                diagonal_clauses as u128,
                domain.len(),
            );
            if let Some(diagonal) =
                finite_diagonal_terms(arena, &domain, &covered_terms, &closed_functions, 1)
            {
                let lex_clauses = add_finite_table_lex_leaders(
                    cnf,
                    arena,
                    &domain,
                    &covered_terms,
                    &membership,
                    &diagonal,
                    domain_swap_maps.as_deref().unwrap_or_default(),
                );
                profile_measurement(
                    "finite_diagonal_lex_leaders",
                    lex_clauses as u128,
                    domain.len(),
                );
            }
        } else {
            let symmetry_clauses = add_finite_constant_symmetry_breaking(
                cnf,
                arena,
                &domain,
                &covered_terms,
                &membership,
            );
            profile_measurement(
                "finite_constant_symmetry",
                symmetry_clauses as u128,
                domain.len(),
            );
            let lex_min_domain = env::var("EUF_VIPER_FINITE_LEX_MIN_DOMAIN")
                .ok()
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(8);
            if matches!(symmetry_mode.as_str(), "hybrid" | "lex") && domain.len() >= lex_min_domain
            {
                let lex_clauses = add_finite_table_lex_leaders(
                    cnf,
                    arena,
                    &domain,
                    &covered_terms,
                    &membership,
                    &[],
                    domain_swap_maps.as_deref().unwrap_or_default(),
                );
                profile_measurement(
                    "finite_table_lex_leaders",
                    lex_clauses as u128,
                    domain.len(),
                );
            }
        }
    }

    let (predicate_channeling_clauses, predicates_complete) = if predicate_channeling {
        add_finite_predicate_channeling(
            cnf,
            arena,
            &domain,
            &domain_set,
            &finite_terms,
            &membership,
            &original_predicates,
        )
    } else {
        (0, false)
    };
    cnf.finite_predicate_congruence_complete =
        predicate_channeling && predicates_complete && !original_predicates.is_empty();
    profile_measurement(
        "finite_predicate_channeling",
        u128::from(cnf.finite_predicate_congruence_complete),
        predicate_channeling_clauses,
    );

    let direct_equalities = match equality_channeling {
        FiniteEqualityChanneling::Off => false,
        FiniteEqualityChanneling::ValueOnly => original_predicates.is_empty(),
        FiniteEqualityChanneling::All => true,
    };
    let complete_equalities = direct_equalities
        && original_equalities.iter().all(|(_, left, right)| {
            left == right || (finite_terms.contains(left) && finite_terms.contains(right))
        });
    if direct_equalities {
        for &(equality, left, right) in &original_equalities {
            if left == right {
                cnf.clauses.push(vec![equality]);
                continue;
            }
            if !finite_terms.contains(&left) || !finite_terms.contains(&right) {
                continue;
            }
            if domain_set.contains(&left) || domain_set.contains(&right) {
                continue;
            }
            for &value in domain {
                let left_value = membership[&(left, value)];
                let right_value = membership[&(right, value)];
                cnf.clauses.push(vec![-equality, -left_value, right_value]);
                cnf.clauses.push(vec![-equality, left_value, -right_value]);
                cnf.clauses.push(vec![-left_value, -right_value, equality]);
            }
        }
    }
    cnf.finite_equalities_complete = complete_equalities;
    profile_measurement(
        "finite_equalities_complete",
        u128::from(complete_equalities),
        original_equalities.len(),
    );

    for &term_id in &arena.apps {
        if !finite_terms.contains(&term_id) {
            continue;
        }
        let term = &arena.terms[term_id];
        if !closed_functions.contains(&term.fun) {
            continue;
        }
        for tuple in domain_tuples_for_args(&domain, &domain_set, &term.args) {
            let key = TermKey {
                fun: term.fun,
                args: tuple.clone(),
            };
            let Some(&canonical) = arena.interned.get(&key) else {
                continue;
            };
            if canonical == term_id {
                continue;
            }
            let conditions = term
                .args
                .iter()
                .zip(&tuple)
                .filter(|(arg, value)| arg != value)
                .map(|(arg, value)| membership[&(*arg, *value)])
                .collect::<Vec<_>>();
            for &output in domain {
                let mut clause = conditions
                    .iter()
                    .map(|literal| -*literal)
                    .collect::<Vec<_>>();
                clause.push(-membership[&(canonical, output)]);
                clause.push(membership[&(term_id, output)]);
                clause.sort_unstable();
                clause.dedup();
                cnf.clauses.push(clause);
            }
        }
    }
    cnf.clauses.len() - start_clause_count
}

fn add_finite_predicate_channeling(
    cnf: &mut CnfProblem,
    arena: &TermArena,
    domain: &[TermId],
    domain_set: &HashSet<TermId>,
    finite_terms: &HashSet<TermId>,
    membership: &HashMap<(TermId, TermId), i32>,
    predicate_terms: &[TermId],
) -> (usize, bool) {
    let mut clauses = HashSet::default();
    let mut complete = true;
    for &term_id in predicate_terms {
        let term = &arena.terms[term_id];
        if !term.args.iter().all(|arg| finite_terms.contains(arg)) {
            complete = false;
            continue;
        }
        for tuple in domain_tuples_for_args(domain, domain_set, &term.args) {
            let key = TermKey {
                fun: term.fun,
                args: tuple.clone(),
            };
            let Some(&canonical) = arena.interned.get(&key) else {
                complete = false;
                continue;
            };
            let application = cnf.atom_lit(BoolAtomKey::BoolTerm(term_id));
            let canonical = cnf.atom_lit(BoolAtomKey::BoolTerm(canonical));
            if application == canonical {
                continue;
            }
            let conditions = term
                .args
                .iter()
                .zip(&tuple)
                .filter(|(arg, value)| arg != value)
                .map(|(arg, value)| membership[&(*arg, *value)])
                .collect::<Vec<_>>();

            let mut forward = conditions
                .iter()
                .map(|literal| -*literal)
                .collect::<Vec<_>>();
            forward.push(-application);
            forward.push(canonical);
            insert_nontautological_clause(&mut clauses, forward);

            let mut reverse = conditions
                .iter()
                .map(|literal| -*literal)
                .collect::<Vec<_>>();
            reverse.push(application);
            reverse.push(-canonical);
            insert_nontautological_clause(&mut clauses, reverse);
        }
    }
    let mut clauses = clauses.into_iter().collect::<Vec<_>>();
    order_axiom_clauses(&mut clauses);
    let added = clauses.len();
    cnf.clauses.extend(clauses);
    (added, complete)
}

fn collect_mandatory_disequalities(expression: &BoolExpr, edges: &mut HashSet<(TermId, TermId)>) {
    match expression {
        BoolExpr::And(children) => {
            for child in children {
                collect_mandatory_disequalities(child, edges);
            }
        }
        BoolExpr::Not(child) => {
            if let BoolExpr::Atom(BoolAtomKey::Eq(left, right)) = child.as_ref() {
                if left != right {
                    edges.insert(normalized_pair(*left, *right));
                }
            }
        }
        _ => {}
    }
}

fn largest_small_disequality_clique(
    edges: &HashSet<(TermId, TermId)>,
    arena: &TermArena,
) -> Vec<TermId> {
    let mut degree = HashMap::<TermId, usize>::default();
    for &(left, right) in edges {
        *degree.entry(left).or_default() += 1;
        *degree.entry(right).or_default() += 1;
    }
    let mut vertices = degree
        .keys()
        .copied()
        .filter(|term| arena.terms[*term].args.is_empty())
        .collect::<Vec<_>>();
    vertices.sort_by_key(|vertex| std::cmp::Reverse(degree[vertex]));
    let mut best = Vec::new();
    for &seed in &vertices {
        let mut clique = vec![seed];
        for &candidate in &vertices {
            if candidate != seed
                && clique
                    .iter()
                    .all(|member| edges.contains(&normalized_pair(*member, candidate)))
            {
                clique.push(candidate);
            }
        }
        if clique.len() > best.len() {
            best = clique;
        }
    }
    best.sort_unstable();
    best
}

fn collect_mandatory_coverages(
    expression: &BoolExpr,
    domain: &HashSet<TermId>,
    covered_terms: &mut HashSet<TermId>,
) {
    match expression {
        BoolExpr::And(children) => {
            for child in children {
                collect_mandatory_coverages(child, domain, covered_terms);
            }
        }
        BoolExpr::Or(_) => {
            let mut pairs = Vec::new();
            if flatten_equality_disjunction(expression, &mut pairs) {
                let mut candidate = None;
                let mut values = HashSet::default();
                for (left, right) in pairs {
                    let (term, value) = if domain.contains(&left) && !domain.contains(&right) {
                        (right, left)
                    } else if domain.contains(&right) && !domain.contains(&left) {
                        (left, right)
                    } else {
                        return;
                    };
                    if candidate.is_some_and(|existing| existing != term) {
                        return;
                    }
                    candidate = Some(term);
                    values.insert(value);
                }
                if values == *domain {
                    if let Some(term) = candidate {
                        covered_terms.insert(term);
                    }
                }
            }
        }
        _ => {}
    }
}

fn flatten_equality_disjunction(expression: &BoolExpr, pairs: &mut Vec<(TermId, TermId)>) -> bool {
    match expression {
        BoolExpr::Or(children) => children
            .iter()
            .all(|child| flatten_equality_disjunction(child, pairs)),
        BoolExpr::Atom(BoolAtomKey::Eq(left, right)) => {
            pairs.push((*left, *right));
            true
        }
        _ => false,
    }
}

fn domain_tuples_for_args(
    domain: &[TermId],
    domain_set: &HashSet<TermId>,
    args: &[TermId],
) -> Vec<Vec<TermId>> {
    let mut tuples = vec![Vec::new()];
    for arg in args {
        let choices = if domain_set.contains(arg) {
            std::slice::from_ref(arg)
        } else {
            domain
        };
        let mut next = Vec::with_capacity(tuples.len() * choices.len());
        for tuple in tuples {
            for &value in choices {
                let mut extended = tuple.clone();
                extended.push(value);
                next.push(extended);
            }
        }
        tuples = next;
    }
    tuples
}

fn congruence_axiom_clauses(cnf: &CnfProblem, arena: &TermArena) -> Vec<Vec<i32>> {
    let mode = env::var("EUF_VIPER_CONGRUENCE_MODE").unwrap_or_else(|_| "auto".to_owned());
    congruence_axiom_clauses_with_mode(cnf, arena, &mode)
}

fn congruence_axiom_clauses_with_mode(
    cnf: &CnfProblem,
    arena: &TermArena,
    mode: &str,
) -> Vec<Vec<i32>> {
    let mut equality_vars = HashMap::default();
    let mut bool_vars = HashMap::default();
    let mut equality_neighbors = vec![Vec::<(TermId, i32)>::new(); arena.terms.len()];
    for (var, atom) in cnf.var_atoms.iter().enumerate().skip(1) {
        match atom {
            Some(BoolAtomKey::Eq(left, right)) => {
                let var = var as i32;
                equality_vars.insert(normalized_pair(*left, *right), var);
                if left != right {
                    equality_neighbors[*left].push((*right, var));
                    equality_neighbors[*right].push((*left, var));
                }
            }
            Some(BoolAtomKey::BoolTerm(term)) => {
                bool_vars.insert(*term, var as i32);
            }
            None => {}
        }
    }
    for neighbors in &mut equality_neighbors {
        neighbors.sort_unstable_by_key(|(term, _)| *term);
        neighbors.dedup_by_key(|(term, _)| *term);
    }

    let mut clauses = HashSet::default();
    let canonical_values = canonical_value_terms(cnf, arena);
    let canonical_only = mode == "canonical"
        || (mode == "auto"
            && canonical_values.len() >= 3
            && (arena.apps.len() > 1_000 || has_predicate_applications(cnf, arena)));
    profile_measurement(
        "canonical_values",
        usize::from(canonical_only) as u128,
        canonical_values.len(),
    );
    const MAX_CANDIDATES_PER_APPLICATION: usize = 4096;
    for &left_id in &arena.apps {
        let left = &arena.terms[left_id];
        let mut candidate_count = 1usize;
        for &arg in &left.args {
            let choices = equality_neighbors[arg].len() + 1;
            let Some(next_count) = candidate_count.checked_mul(choices) else {
                candidate_count = MAX_CANDIDATES_PER_APPLICATION + 1;
                break;
            };
            candidate_count = next_count;
            if candidate_count > MAX_CANDIDATES_PER_APPLICATION {
                break;
            }
        }
        if candidate_count > MAX_CANDIDATES_PER_APPLICATION {
            continue;
        }

        let mut candidates = vec![(Vec::with_capacity(left.args.len()), Vec::<i32>::new())];
        for &arg in &left.args {
            let mut next =
                Vec::with_capacity(candidates.len() * (equality_neighbors[arg].len() + 1));
            for (arguments, conditions) in candidates {
                let mut same_arguments = arguments.clone();
                same_arguments.push(arg);
                next.push((same_arguments, conditions.clone()));
                for &(neighbor, equality_var) in &equality_neighbors[arg] {
                    let mut neighbor_arguments = arguments.clone();
                    neighbor_arguments.push(neighbor);
                    let mut neighbor_conditions = conditions.clone();
                    neighbor_conditions.push(-equality_var);
                    next.push((neighbor_arguments, neighbor_conditions));
                }
            }
            candidates = next;
        }

        for (arguments, conditions) in candidates {
            if arguments == left.args {
                continue;
            }
            let key = TermKey {
                fun: left.fun,
                args: arguments,
            };
            let Some(&right_id) = arena.interned.get(&key) else {
                continue;
            };
            if right_id == left_id {
                continue;
            }
            if canonical_only
                && !left
                    .args
                    .iter()
                    .all(|argument| canonical_values.contains(argument))
                && !arena.terms[right_id]
                    .args
                    .iter()
                    .all(|argument| canonical_values.contains(argument))
            {
                continue;
            }

            if let Some(&result_var) = equality_vars.get(&normalized_pair(left_id, right_id)) {
                let mut clause = conditions.clone();
                clause.push(result_var);
                insert_nontautological_clause(&mut clauses, clause);
            }

            let (Some(&left_bool), Some(&right_bool)) =
                (bool_vars.get(&left_id), bool_vars.get(&right_id))
            else {
                continue;
            };
            let mut forward = conditions.clone();
            forward.extend([-left_bool, right_bool]);
            insert_nontautological_clause(&mut clauses, forward);

            let mut backward = conditions;
            backward.extend([left_bool, -right_bool]);
            insert_nontautological_clause(&mut clauses, backward);
        }
    }
    let mut clauses = clauses.into_iter().collect::<Vec<_>>();
    order_axiom_clauses(&mut clauses);
    clauses
}

fn axiom_order_seed() -> u64 {
    env::var("EUF_VIPER_AXIOM_SEED")
        .ok()
        .and_then(|seed| seed.parse().ok())
        .unwrap_or(0x9e37_79b9_7f4a_7c15)
}

fn mix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn order_finite_terms(terms: &mut [TermId]) {
    match env::var("EUF_VIPER_AXIOM_ORDER").as_deref() {
        Ok("native") => {}
        Ok("hash") => {
            let seed = axiom_order_seed();
            terms.sort_unstable_by_key(|term| (mix64(*term as u64 ^ seed), *term));
        }
        _ => terms.sort_unstable(),
    }
}

fn clause_order_hash(clause: &[i32], seed: u64) -> u64 {
    clause.iter().fold(seed, |hash, literal| {
        mix64(hash ^ (*literal as i64 as u64).wrapping_mul(0x9e37_79b9))
    })
}

fn order_axiom_clauses(clauses: &mut [Vec<i32>]) {
    match env::var("EUF_VIPER_AXIOM_ORDER").as_deref() {
        Ok("native") => {}
        Ok("hash") => {
            let seed = axiom_order_seed();
            clauses.sort_by(|left, right| {
                clause_order_hash(left, seed)
                    .cmp(&clause_order_hash(right, seed))
                    .then_with(|| left.cmp(right))
            });
        }
        _ => clauses.sort(),
    }
}

fn canonical_value_terms(cnf: &CnfProblem, arena: &TermArena) -> HashSet<TermId> {
    let mut degree = vec![0usize; arena.terms.len()];
    for atom in cnf.var_atoms.iter().flatten() {
        if let BoolAtomKey::Eq(left, right) = atom {
            if left != right {
                degree[*left] += 1;
                degree[*right] += 1;
            }
        }
    }
    degree
        .into_iter()
        .enumerate()
        .filter(|(term, degree)| arena.terms[*term].args.is_empty() && *degree >= 16)
        .map(|(term, _)| term)
        .collect()
}

fn has_predicate_applications(cnf: &CnfProblem, arena: &TermArena) -> bool {
    cnf.var_atoms.iter().flatten().any(
        |atom| matches!(atom, BoolAtomKey::BoolTerm(term) if !arena.terms[*term].args.is_empty()),
    )
}

fn congruence_clause_group(
    clause: &[i32],
    cnf: &CnfProblem,
    arena: &TermArena,
    canonical_values: &HashSet<TermId>,
) -> Option<(TermId, i8)> {
    let is_noncanonical_application = |term: TermId| {
        !arena.terms[term].args.is_empty()
            && !arena.terms[term]
                .args
                .iter()
                .all(|argument| canonical_values.contains(argument))
    };

    for literal in clause {
        let var = literal.unsigned_abs() as usize;
        if let Some(BoolAtomKey::BoolTerm(term)) = cnf.var_atoms[var].as_ref() {
            if is_noncanonical_application(*term) {
                return Some((*term, if *literal > 0 { 1 } else { -1 }));
            }
        }
    }
    for &literal in clause {
        if literal <= 0 {
            continue;
        }
        let var = literal as usize;
        if let Some(BoolAtomKey::Eq(left, right)) = cnf.var_atoms[var].as_ref() {
            if is_noncanonical_application(*left) {
                return Some((*left, 0));
            }
            if is_noncanonical_application(*right) {
                return Some((*right, 0));
            }
        }
    }
    None
}

fn insert_nontautological_clause(clauses: &mut HashSet<Vec<i32>>, mut clause: Vec<i32>) {
    clause.sort_unstable();
    clause.dedup();
    if clause
        .iter()
        .any(|literal| clause.binary_search(&-*literal).is_ok())
    {
        return;
    }
    clauses.insert(clause);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CnfSearchResult {
    Sat,
    Unsat,
    Limit,
}

#[derive(Debug)]
struct DpllSolver<'a> {
    cnf: &'a CnfProblem,
    arena: &'a TermArena,
    true_term: TermId,
    false_term: TermId,
    nodes: usize,
    node_limit: usize,
    occurrence: Vec<usize>,
    clauses_by_var: Vec<Vec<usize>>,
}

impl<'a> DpllSolver<'a> {
    fn new(
        cnf: &'a CnfProblem,
        arena: &'a TermArena,
        true_term: TermId,
        false_term: TermId,
    ) -> Self {
        let mut occurrence = vec![0usize; cnf.var_count() + 1];
        let mut clauses_by_var = vec![Vec::new(); cnf.var_count() + 1];
        for (clause_id, clause) in cnf.clauses.iter().enumerate() {
            for &lit in clause {
                let var = lit.unsigned_abs() as usize;
                occurrence[var] += 1;
                clauses_by_var[var].push(clause_id);
            }
        }
        Self {
            cnf,
            arena,
            true_term,
            false_term,
            nodes: 0,
            node_limit: 1_000_000,
            occurrence,
            clauses_by_var,
        }
    }

    fn solve(&mut self) -> CnfSearchResult {
        let mut assignment = vec![0i8; self.cnf.var_count() + 1];
        let Some(pending) = self.initial_units(&mut assignment) else {
            return CnfSearchResult::Unsat;
        };
        self.search(&mut assignment, pending, true)
    }

    fn search(
        &mut self,
        assignment: &mut [i8],
        pending: Vec<usize>,
        theory_dirty: bool,
    ) -> CnfSearchResult {
        self.nodes += 1;
        if self.nodes > self.node_limit {
            return CnfSearchResult::Limit;
        }

        if !self.propagate(assignment, pending, theory_dirty) {
            return CnfSearchResult::Unsat;
        }
        let Some(var) = self.choose_var(assignment) else {
            return CnfSearchResult::Sat;
        };

        for value in self.preferred_values(var) {
            let mut branch = assignment.to_vec();
            branch[var] = value;
            let theory_dirty = self.cnf.var_atoms[var].is_some();
            match self.search(&mut branch, vec![var], theory_dirty) {
                CnfSearchResult::Sat => return CnfSearchResult::Sat,
                CnfSearchResult::Limit => return CnfSearchResult::Limit,
                CnfSearchResult::Unsat => {}
            }
        }
        CnfSearchResult::Unsat
    }

    fn initial_units(&self, assignment: &mut [i8]) -> Option<Vec<usize>> {
        let mut pending = Vec::new();
        for clause in &self.cnf.clauses {
            match clause {
                [] => return None,
                [lit] => {
                    let var = lit.unsigned_abs() as usize;
                    let value = if *lit > 0 { 1 } else { -1 };
                    if assignment[var] == 0 {
                        assignment[var] = value;
                        pending.push(var);
                    } else if assignment[var] != value {
                        return None;
                    }
                }
                _ => {}
            }
        }
        Some(pending)
    }

    fn propagate(
        &self,
        assignment: &mut [i8],
        mut pending: Vec<usize>,
        mut theory_dirty: bool,
    ) -> bool {
        loop {
            let Some(unit_theory_dirty) = self.propagate_pending_units(assignment, &mut pending)
            else {
                return false;
            };
            theory_dirty |= unit_theory_dirty;
            if !theory_dirty {
                return true;
            }
            let Some(theory_assignments) = self.propagate_theory(assignment) else {
                return false;
            };
            theory_dirty = false;
            if theory_assignments.is_empty() {
                return true;
            }
            pending.extend(theory_assignments);
        }
    }

    fn propagate_pending_units(
        &self,
        assignment: &mut [i8],
        pending: &mut Vec<usize>,
    ) -> Option<bool> {
        let mut theory_dirty = false;
        while let Some(changed_var) = pending.pop() {
            for &clause_id in &self.clauses_by_var[changed_var] {
                let clause = &self.cnf.clauses[clause_id];
                let mut unassigned = 0i32;
                let mut unassigned_count = 0usize;
                let mut satisfied = false;
                for &lit in clause {
                    match lit_status(lit, assignment) {
                        1 => {
                            satisfied = true;
                            break;
                        }
                        0 => {
                            unassigned = lit;
                            unassigned_count += 1;
                        }
                        _ => {}
                    }
                }
                if satisfied {
                    continue;
                }
                if unassigned_count == 0 {
                    return None;
                }
                if unassigned_count == 1 {
                    let var = unassigned.unsigned_abs() as usize;
                    let value = if unassigned > 0 { 1 } else { -1 };
                    if assignment[var] == 0 {
                        assignment[var] = value;
                        pending.push(var);
                        theory_dirty |= self.cnf.var_atoms[var].is_some();
                    } else if assignment[var] != value {
                        return None;
                    }
                }
            }
        }
        Some(theory_dirty)
    }

    fn propagate_theory(&self, assignment: &mut [i8]) -> Option<Vec<usize>> {
        let mut uf = UnionFind::new(self.arena.terms.len());
        let mut diseqs = Vec::new();
        for var in 1..assignment.len() {
            let Some(atom) = self.cnf.var_atoms[var].as_ref() else {
                continue;
            };
            match (assignment[var], atom) {
                (1, BoolAtomKey::Eq(a, b)) => {
                    uf.union(*a, *b);
                }
                (-1, BoolAtomKey::Eq(a, b)) => diseqs.push((*a, *b)),
                (1, BoolAtomKey::BoolTerm(term)) => {
                    uf.union(*term, self.true_term);
                }
                (-1, BoolAtomKey::BoolTerm(term)) => {
                    uf.union(*term, self.false_term);
                }
                _ => {}
            }
        }
        congruence_closure(self.arena, &mut uf);
        let true_root = uf.find(self.true_term);
        let false_root = uf.find(self.false_term);
        if true_root == false_root {
            return None;
        }
        let mut diseq_roots =
            HashSet::with_capacity_and_hasher(diseqs.len() * 2, Default::default());
        for (a, b) in diseqs {
            let ra = uf.find(a);
            let rb = uf.find(b);
            if ra == rb {
                return None;
            }
            diseq_roots.insert(normalized_pair(ra, rb));
        }

        let mut changed = Vec::new();
        for var in 1..assignment.len() {
            if assignment[var] != 0 {
                continue;
            }
            let value = match self.cnf.var_atoms[var].as_ref() {
                Some(BoolAtomKey::Eq(a, b)) => {
                    let ra = uf.find(*a);
                    let rb = uf.find(*b);
                    if ra == rb {
                        Some(1)
                    } else if diseq_roots.contains(&normalized_pair(ra, rb)) {
                        Some(-1)
                    } else {
                        None
                    }
                }
                Some(BoolAtomKey::BoolTerm(term)) => {
                    let root = uf.find(*term);
                    if root == true_root {
                        Some(1)
                    } else if root == false_root {
                        Some(-1)
                    } else {
                        None
                    }
                }
                None => None,
            };
            if let Some(value) = value {
                assignment[var] = value;
                changed.push(var);
            }
        }
        Some(changed)
    }

    fn choose_var(&self, assignment: &[i8]) -> Option<usize> {
        let mut best = None;
        let mut best_clause_len = usize::MAX;
        let mut best_occurrence = 0usize;
        for clause in &self.cnf.clauses {
            let mut satisfied = false;
            let mut open = 0usize;
            let mut clause_best = None;
            let mut clause_best_occurrence = 0usize;
            for &lit in clause {
                match lit_status(lit, assignment) {
                    1 => {
                        satisfied = true;
                        break;
                    }
                    0 => {
                        open += 1;
                        let var = lit.unsigned_abs() as usize;
                        let occurrence = self.occurrence[var];
                        if clause_best.is_none() || occurrence > clause_best_occurrence {
                            clause_best = Some(var);
                            clause_best_occurrence = occurrence;
                        }
                    }
                    _ => {}
                }
            }
            if satisfied {
                continue;
            }
            if open == 2 {
                return clause_best;
            }
            if open == 0 || open > best_clause_len {
                continue;
            }
            if open < best_clause_len || clause_best_occurrence > best_occurrence {
                best = clause_best;
                best_clause_len = open;
                best_occurrence = clause_best_occurrence;
            }
        }
        best.or_else(|| {
            (1..assignment.len())
                .find(|&var| assignment[var] == 0 && self.cnf.var_atoms[var].is_some())
        })
    }

    fn preferred_values(&self, var: usize) -> [i8; 2] {
        if matches!(self.cnf.var_atoms[var], Some(BoolAtomKey::Eq(_, _))) {
            [1, -1]
        } else {
            [1, -1]
        }
    }
}

fn complete_cnf_assignment(cnf: &CnfProblem, assignment: &mut [i8]) -> bool {
    if assignment.len() != cnf.var_count() + 1 || assignment.first() != Some(&0) {
        return false;
    }
    for value in assignment.iter_mut().skip(1) {
        match *value {
            -1 | 1 => {}
            0 => *value = -1,
            _ => return false,
        }
    }
    cnf.clauses.iter().all(|clause| {
        clause
            .iter()
            .any(|literal| lit_status(*literal, assignment) == 1)
    })
}

fn theory_conflict_clauses(
    cnf: &CnfProblem,
    arena: &TermArena,
    true_term: TermId,
    false_term: TermId,
    assignment: &[i8],
) -> Option<Vec<Vec<i32>>> {
    if assignment.len() != cnf.var_count() + 1
        || assignment.first() != Some(&0)
        || assignment
            .iter()
            .skip(1)
            .any(|value| !matches!(value, -1 | 1))
    {
        return None;
    }
    let mut theory = ExplainingTheory::new(arena);
    let mut false_equalities = Vec::new();
    for var in 1..assignment.len() {
        let Some(atom) = cnf.var_atoms[var].as_ref() else {
            continue;
        };
        let literal = if assignment[var] > 0 {
            var as i32
        } else {
            -(var as i32)
        };
        match (assignment[var], atom) {
            (1, BoolAtomKey::Eq(a, b)) => {
                theory.merge(*a, *b, EqualityReason::Literal(literal));
            }
            (-1, BoolAtomKey::Eq(a, b)) => false_equalities.push((var, *a, *b)),
            (1, BoolAtomKey::BoolTerm(term)) => {
                theory.merge(*term, true_term, EqualityReason::Literal(literal));
            }
            (-1, BoolAtomKey::BoolTerm(term)) => {
                theory.merge(*term, false_term, EqualityReason::Literal(literal));
            }
            _ => {}
        }
    }
    theory.close_congruence();

    let mut conflicts = Vec::new();
    if theory.equal(true_term, false_term) {
        let mut reasons = HashSet::default();
        theory.explain_equal(true_term, false_term, &mut reasons);
        conflicts.push(conflict_clause(reasons));
    }
    for (var, left, right) in false_equalities {
        if theory.equal(left, right) {
            let mut reasons = HashSet::default();
            reasons.insert(-(var as i32));
            theory.explain_equal(left, right, &mut reasons);
            conflicts.push(conflict_clause(reasons));
        }
    }
    conflicts.sort_by(|left, right| left.len().cmp(&right.len()).then_with(|| left.cmp(right)));
    conflicts.dedup();
    conflicts.truncate(32);
    Some(conflicts)
}

fn conflict_clause(reasons: HashSet<i32>) -> Vec<i32> {
    let mut clause = reasons
        .into_iter()
        .map(|literal| -literal)
        .collect::<Vec<_>>();
    clause.sort_unstable();
    clause.dedup();
    clause
}

fn use_eager_congruence_for_first_pass(
    finite_added: usize,
    cnf: &CnfProblem,
    arena: &TermArena,
) -> bool {
    match env::var("EUF_VIPER_EAGER_CONGRUENCE").as_deref() {
        Ok("0") => false,
        Ok("1") => true,
        _ => {
            finite_added == 0
                || (has_predicate_applications(cnf, arena)
                    && !cnf.finite_predicate_congruence_complete)
        }
    }
}

fn auto_prefers_cadical(app_count: usize, finite_added: usize, app_threshold: usize) -> bool {
    (app_threshold > 0 && app_count >= app_threshold)
        || (finite_added > 0 && !cfg!(all(target_os = "linux", target_arch = "x86_64")))
}

fn cadical_refine_after_invalid_model(setting: Option<&str>) -> bool {
    match setting {
        Some("cadical-refine") => true,
        Some("varisat") => false,
        _ => cfg!(all(target_os = "linux", target_arch = "x86_64")),
    }
}

fn use_cadical_refine_after_invalid_model() -> bool {
    let setting = env::var("EUF_VIPER_INVALID_MODEL_FALLBACK").ok();
    cadical_refine_after_invalid_model(setting.as_deref())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RefinementMode {
    Current,
    ModelCuts,
}

fn parse_refinement_mode(setting: Option<&str>) -> RefinementMode {
    match setting {
        Some("model-cuts") => RefinementMode::ModelCuts,
        _ => RefinementMode::Current,
    }
}

fn selected_refinement_mode() -> RefinementMode {
    let setting = env::var("EUF_VIPER_REFINEMENT_MODE").ok();
    parse_refinement_mode(setting.as_deref())
}

fn force_full_ackermann(setting: Option<&str>) -> bool {
    matches!(setting, Some("1" | "on"))
}

#[cold]
#[inline(never)]
fn dynamic_full_ackermann_for_shape(
    setting: Option<&str>,
    cnf_clauses: usize,
    app_count: usize,
    finite_added: usize,
) -> bool {
    match setting {
        Some("1" | "on" | "0" | "off") => false,
        _ => finite_added == 0 && cnf_clauses >= 100_000 && app_count <= 256,
    }
}

fn dynamic_full_ackermann_before_refinement(
    setting: Option<&str>,
    refinement_mode: RefinementMode,
    cnf_clauses: usize,
    app_count: usize,
    finite_added: usize,
) -> bool {
    !force_full_ackermann(setting)
        && refinement_mode == RefinementMode::Current
        && dynamic_full_ackermann_for_shape(setting, cnf_clauses, app_count, finite_added)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum EagerSolveOutcome {
    Solved(SolveResult),
    InvalidTheoryModel(usize),
    #[cfg_attr(all(target_os = "linux", target_arch = "x86_64"), allow(dead_code))]
    Unavailable,
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn configure_kissat(solver: &mut KissatSolver<'_>) -> Option<()> {
    let configuration = match env::var("EUF_VIPER_KISSAT_MODE").as_deref() {
        Ok("basic") => KissatConfig::Basic,
        Ok("plain") => KissatConfig::Plain,
        Ok("sat") => KissatConfig::Sat,
        Ok("unsat") => KissatConfig::Unsat,
        _ => KissatConfig::Default,
    };
    solver.set_configuration(configuration).ok()
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn solve_kissat_euf_once(
    cnf: &CnfProblem,
    arena: &TermArena,
    true_term: TermId,
    false_term: TermId,
    eager_congruence: bool,
) -> EagerSolveOutcome {
    let load_start = Instant::now();
    let mut solver = KissatSolver::new();
    let variables = (0..cnf.var_count())
        .map(|_| solver.var())
        .collect::<Vec<_>>();
    for clause in &cnf.clauses {
        solver.add(&kissat_clause(clause, &variables));
    }
    profile_phase("kissat_base_load", load_start, cnf.clauses.len());

    let transitivity_start = Instant::now();
    let transitivity = equality_transitivity_clauses(cnf, arena.terms.len());
    profile_phase("transitivity", transitivity_start, transitivity.len());
    let transitivity_load_start = Instant::now();
    for clause in transitivity {
        solver.add(&kissat_clause(&clause, &variables));
    }
    profile_phase("kissat_transitivity_load", transitivity_load_start, 0);

    let congruence_start = Instant::now();
    let congruence = if eager_congruence {
        congruence_axiom_clauses(cnf, arena)
    } else {
        Vec::new()
    };
    profile_phase("congruence", congruence_start, congruence.len());
    let congruence_load_start = Instant::now();
    for clause in congruence {
        solver.add(&kissat_clause(&clause, &variables));
    }
    profile_phase("kissat_congruence_load", congruence_load_start, 0);

    let sat_start = Instant::now();
    let result = solver.sat();
    profile_phase("kissat_solve", sat_start, 0);
    let Some(solution) = result else {
        return EagerSolveOutcome::Solved(SolveResult::Unsat);
    };

    let mut assignment = vec![0i8; cnf.var_count() + 1];
    for (index, variable) in variables.iter().enumerate() {
        assignment[index + 1] = match solution.get(*variable) {
            Some(true) => 1,
            Some(false) => -1,
            None => 0,
        };
    }
    if !complete_cnf_assignment(cnf, &mut assignment) {
        return EagerSolveOutcome::Unavailable;
    }
    let Some(conflicts) = theory_conflict_clauses(cnf, arena, true_term, false_term, &assignment)
    else {
        return EagerSolveOutcome::Unavailable;
    };
    if conflicts.is_empty() {
        EagerSolveOutcome::Solved(SolveResult::Sat)
    } else {
        EagerSolveOutcome::InvalidTheoryModel(conflicts.len())
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn kissat_clause(clause: &[i32], variables: &[KissatVar]) -> Vec<KissatVar> {
    clause
        .iter()
        .map(|literal| {
            let variable = variables[literal.unsigned_abs() as usize - 1];
            if *literal > 0 { variable } else { !variable }
        })
        .collect()
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn solve_kissat_euf_once(
    cnf: &CnfProblem,
    arena: &TermArena,
    true_term: TermId,
    false_term: TermId,
    eager_congruence: bool,
) -> EagerSolveOutcome {
    let load_start = Instant::now();
    let mut solver = KissatSolver::default();
    if configure_kissat(&mut solver).is_none() {
        return EagerSolveOutcome::Unavailable;
    }
    for clause in &cnf.clauses {
        if solver.add_clause(rustsat_clause(clause)).is_err() {
            return EagerSolveOutcome::Unavailable;
        }
    }
    profile_phase("kissat_base_load", load_start, cnf.clauses.len());

    let transitivity_start = Instant::now();
    let transitivity = equality_transitivity_clauses(cnf, arena.terms.len());
    profile_phase("transitivity", transitivity_start, transitivity.len());
    let transitivity_load_start = Instant::now();
    for clause in transitivity {
        if solver.add_clause(rustsat_clause(&clause)).is_err() {
            return EagerSolveOutcome::Unavailable;
        }
    }
    profile_phase("kissat_transitivity_load", transitivity_load_start, 0);

    let congruence_start = Instant::now();
    let congruence = if eager_congruence {
        congruence_axiom_clauses(cnf, arena)
    } else {
        Vec::new()
    };
    profile_phase("congruence", congruence_start, congruence.len());
    let congruence_load_start = Instant::now();
    for clause in congruence {
        if solver.add_clause(rustsat_clause(&clause)).is_err() {
            return EagerSolveOutcome::Unavailable;
        }
    }
    profile_phase("kissat_congruence_load", congruence_load_start, 0);

    let sat_start = Instant::now();
    let Ok(result) = solver.solve() else {
        return EagerSolveOutcome::Unavailable;
    };
    profile_phase("kissat_solve", sat_start, 0);
    match result {
        RustSatResult::Unsat => return EagerSolveOutcome::Solved(SolveResult::Unsat),
        RustSatResult::Interrupted => return EagerSolveOutcome::Unavailable,
        RustSatResult::Sat => {}
    }

    let mut assignment = vec![0i8; cnf.var_count() + 1];
    for (var, value) in assignment.iter_mut().enumerate().skip(1) {
        let Ok(literal) = RustSatLit::from_ipasir(var as i32) else {
            return EagerSolveOutcome::Unavailable;
        };
        let Ok(literal_value) = solver.lit_val(literal) else {
            return EagerSolveOutcome::Unavailable;
        };
        *value = match literal_value {
            TernaryVal::True => 1,
            TernaryVal::False => -1,
            TernaryVal::DontCare => 0,
        };
    }
    if !complete_cnf_assignment(cnf, &mut assignment) {
        return EagerSolveOutcome::Unavailable;
    }
    let Some(conflicts) = theory_conflict_clauses(cnf, arena, true_term, false_term, &assignment)
    else {
        return EagerSolveOutcome::Unavailable;
    };
    if conflicts.is_empty() {
        EagerSolveOutcome::Solved(SolveResult::Sat)
    } else {
        EagerSolveOutcome::InvalidTheoryModel(conflicts.len())
    }
}

fn rustsat_clause(clause: &[i32]) -> RustSatClause {
    clause
        .iter()
        .map(|literal| RustSatLit::from_ipasir(*literal).expect("valid DIMACS literal"))
        .collect()
}

fn configure_cadical(solver: &mut CadicalSolver<'_, '_>, prefer_unsat_search: bool) -> Option<()> {
    match env::var("EUF_VIPER_CADICAL_MODE").as_deref() {
        Ok("default-safe") => {
            solver.set_configuration(CadicalConfig::Default).ok()?;
            solver.set_option("sweep", 0).ok()?;
            solver.set_option("inprobing", 0).ok()?;
        }
        Ok("unsat-safe") => {
            solver.set_configuration(CadicalConfig::Unsat).ok()?;
            solver.set_option("sweep", 0).ok()?;
            solver.set_option("inprobing", 0).ok()?;
        }
        _ => solver.set_configuration(CadicalConfig::Plain).ok()?,
    }
    if prefer_unsat_search {
        solver.set_option("stabilize", 0).ok()?;
        solver.set_option("walk", 0).ok()?;
    }
    solver.set_option("backbone", 0).ok()?;
    if let Ok(options) = env::var("EUF_VIPER_CADICAL_OPTIONS") {
        for option in options.split(',').filter(|option| !option.is_empty()) {
            let (name, value) = option.split_once('=')?;
            solver.set_option(name, value.parse().ok()?).ok()?;
        }
    }
    Some(())
}

fn solve_cadical_euf_once(
    cnf: &CnfProblem,
    arena: &TermArena,
    true_term: TermId,
    false_term: TermId,
    eager_congruence: bool,
) -> Option<SolveResult> {
    let transitivity_start = Instant::now();
    let transitivity = equality_transitivity_clauses(cnf, arena.terms.len());
    profile_phase("transitivity", transitivity_start, transitivity.len());
    let congruence_start = Instant::now();
    let congruence = if eager_congruence {
        congruence_axiom_clauses(cnf, arena)
    } else {
        Vec::new()
    };
    profile_phase("congruence", congruence_start, congruence.len());

    let dense_congruence = congruence.len() > cnf.clauses.len().saturating_mul(4);
    let prefer_unsat_search = match env::var("EUF_VIPER_CADICAL_SEARCH_MODE").as_deref() {
        Ok("balanced") => false,
        Ok("unsat") => true,
        _ => dense_congruence,
    };
    let conflict_limit = env::var("EUF_VIPER_CADICAL_CONFLICT_LIMIT")
        .ok()
        .and_then(|limit| limit.parse().ok())
        .or(prefer_unsat_search.then_some(155_000u32));
    profile_measurement(
        "cadical_unsat_search",
        u128::from(prefer_unsat_search),
        conflict_limit.unwrap_or(0) as usize,
    );

    let load_start = Instant::now();
    let mut solver = CadicalSolver::default();
    configure_cadical(&mut solver, prefer_unsat_search)?;
    for clause in &cnf.clauses {
        solver.add_clause(rustsat_clause(clause)).ok()?;
    }
    profile_phase("cadical_base_load", load_start, cnf.clauses.len());

    let transitivity_load_start = Instant::now();
    for clause in transitivity {
        solver.add_clause(rustsat_clause(&clause)).ok()?;
    }
    profile_phase("cadical_transitivity_load", transitivity_load_start, 0);

    let congruence_load_start = Instant::now();
    for clause in congruence {
        solver.add_clause(rustsat_clause(&clause)).ok()?;
    }
    profile_phase("cadical_congruence_load", congruence_load_start, 0);

    if let Some(limit) = conflict_limit {
        solver.limit_conflicts(Some(limit)).ok()?;
    }

    let sat_start = Instant::now();
    let result = solver.solve().ok()?;
    profile_phase("cadical_solve", sat_start, 0);
    profile_measurement(
        "cadical_search",
        solver.conflicts() as u128,
        solver.decisions(),
    );
    match result {
        RustSatResult::Unsat => return Some(SolveResult::Unsat),
        RustSatResult::Interrupted => return None,
        RustSatResult::Sat => {}
    }

    let mut assignment = vec![0i8; cnf.var_count() + 1];
    for (var, value) in assignment.iter_mut().enumerate().skip(1) {
        let literal = RustSatLit::from_ipasir(var as i32).ok()?;
        *value = match solver.lit_val(literal).ok()? {
            TernaryVal::True => 1,
            TernaryVal::False => -1,
            TernaryVal::DontCare => 0,
        };
    }
    complete_cnf_assignment(cnf, &mut assignment).then_some(())?;
    theory_conflict_clauses(cnf, arena, true_term, false_term, &assignment)?
        .is_empty()
        .then_some(SolveResult::Sat)
}

#[derive(Debug, Default, PartialEq, Eq)]
struct CadicalRefinementTelemetry {
    rounds: usize,
    sat_calls: usize,
    sat_time_ns: u128,
    validation_calls: usize,
    validation_time_ns: u128,
    cuts_generated: usize,
    cuts_added: usize,
    cuts_duplicate: usize,
    cut_width_total: usize,
    cut_width_max: usize,
    candidate_clause_generation_avoided: bool,
    group_clause_loading_avoided: bool,
}

impl CadicalRefinementTelemetry {
    fn profile(&self) {
        profile_measurement("cadical_refine_solve", self.sat_time_ns, self.sat_calls);
        profile_measurement("cadical_refine_rounds", 0, self.rounds);
        profile_measurement("cadical_refine_sat_calls", 0, self.sat_calls);
        profile_measurement(
            "cadical_refine_validation",
            self.validation_time_ns,
            self.validation_calls,
        );
        profile_measurement("cadical_refine_cuts_generated", 0, self.cuts_generated);
        profile_measurement("cadical_refine_cuts_added", 0, self.cuts_added);
        profile_measurement("cadical_refine_cuts_duplicate", 0, self.cuts_duplicate);
        profile_measurement("cadical_refine_cut_width_total", 0, self.cut_width_total);
        profile_measurement("cadical_refine_cut_width_max", 0, self.cut_width_max);
        profile_measurement(
            "cadical_refine_candidate_clause_generation_avoided",
            0,
            usize::from(self.candidate_clause_generation_avoided),
        );
        profile_measurement(
            "cadical_refine_group_clause_loading_avoided",
            0,
            usize::from(self.group_clause_loading_avoided),
        );
    }
}

fn add_novel_theory_cuts(
    conflicts: &[Vec<i32>],
    learned_theory: &mut HashSet<Vec<i32>>,
    var_count: usize,
    telemetry: &mut CadicalRefinementTelemetry,
    mut add_clause: impl FnMut(&[i32]) -> bool,
) -> Option<usize> {
    telemetry.cuts_generated = telemetry.cuts_generated.saturating_add(conflicts.len());
    let mut added = 0usize;
    for conflict in conflicts {
        let mut clause = conflict.clone();
        clause.sort_unstable();
        clause.dedup();
        if clause
            .iter()
            .any(|literal| *literal == 0 || literal.unsigned_abs() as usize > var_count)
        {
            return None;
        }
        telemetry.cut_width_total = telemetry.cut_width_total.saturating_add(clause.len());
        telemetry.cut_width_max = telemetry.cut_width_max.max(clause.len());
        if !learned_theory.insert(clause.clone()) {
            telemetry.cuts_duplicate = telemetry.cuts_duplicate.saturating_add(1);
            continue;
        }
        if !add_clause(&clause) {
            learned_theory.remove(&clause);
            return None;
        }
        telemetry.cuts_added = telemetry.cuts_added.saturating_add(1);
        added += 1;
    }
    Some(added)
}

fn solve_cadical_euf_refining(
    cnf: &CnfProblem,
    arena: &TermArena,
    true_term: TermId,
    false_term: TermId,
    refinement_mode: RefinementMode,
) -> Option<(SolveResult, usize, usize)> {
    let max_rounds = env::var("EUF_VIPER_MAX_THEORY_ROUNDS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(10_000usize);
    let mut telemetry = CadicalRefinementTelemetry::default();
    let outcome = solve_cadical_euf_refining_with_limit(
        cnf,
        arena,
        true_term,
        false_term,
        refinement_mode,
        max_rounds,
        &mut telemetry,
    );
    telemetry.profile();
    outcome
}

fn solve_cadical_euf_refining_with_limit(
    cnf: &CnfProblem,
    arena: &TermArena,
    true_term: TermId,
    false_term: TermId,
    refinement_mode: RefinementMode,
    max_rounds: usize,
    telemetry: &mut CadicalRefinementTelemetry,
) -> Option<(SolveResult, usize, usize)> {
    let load_start = Instant::now();
    let mut solver = CadicalSolver::default();
    configure_cadical(&mut solver, false)?;
    for clause in &cnf.clauses {
        solver.add_clause(rustsat_clause(clause)).ok()?;
    }
    let transitivity = equality_transitivity_clauses(cnf, arena.terms.len());
    for clause in transitivity {
        solver.add_clause(rustsat_clause(&clause)).ok()?;
    }
    profile_phase("cadical_refine_base_load", load_start, cnf.clauses.len());

    let mut congruence = Vec::new();
    let mut congruence_groups = HashMap::<(TermId, i8), Vec<usize>>::default();
    let mut clause_groups = Vec::new();
    let mut loaded_congruence = Vec::new();
    match refinement_mode {
        RefinementMode::Current => {
            let congruence_start = Instant::now();
            congruence = congruence_axiom_clauses(cnf, arena);
            profile_phase(
                "cadical_refine_candidates",
                congruence_start,
                congruence.len(),
            );
            let canonical_values = canonical_value_terms(cnf, arena);
            clause_groups.reserve(congruence.len());
            for (index, clause) in congruence.iter().enumerate() {
                let group = congruence_clause_group(clause, cnf, arena, &canonical_values);
                if let Some(group) = group {
                    congruence_groups.entry(group).or_default().push(index);
                }
                clause_groups.push(group);
            }
            loaded_congruence.resize(congruence.len(), false);
        }
        RefinementMode::ModelCuts => {
            telemetry.candidate_clause_generation_avoided = true;
            telemetry.group_clause_loading_avoided = true;
            profile_measurement("cadical_refine_candidates", 0, 0);
        }
    }
    let mut learned_theory = HashSet::<Vec<i32>>::default();
    let mut lemma_count = 0usize;

    for round in 1..=max_rounds {
        telemetry.rounds = round;
        telemetry.sat_calls += 1;
        let sat_start = Instant::now();
        let result = solver.solve().ok()?;
        telemetry.sat_time_ns += sat_start.elapsed().as_nanos();
        match result {
            RustSatResult::Unsat => {
                return Some((SolveResult::Unsat, round, lemma_count));
            }
            RustSatResult::Interrupted => return None,
            RustSatResult::Sat => {}
        }

        let mut assignment = vec![0i8; cnf.var_count() + 1];
        for (var, value) in assignment.iter_mut().enumerate().skip(1) {
            let literal = RustSatLit::from_ipasir(var as i32).ok()?;
            *value = match solver.lit_val(literal).ok()? {
                TernaryVal::True => 1,
                TernaryVal::False => -1,
                TernaryVal::DontCare => 0,
            };
        }
        complete_cnf_assignment(cnf, &mut assignment).then_some(())?;

        let mut violated_groups = HashSet::default();
        let mut violated_ungrouped = Vec::new();
        for (index, clause) in congruence.iter().enumerate() {
            if !loaded_congruence[index]
                && clause
                    .iter()
                    .all(|literal| lit_status(*literal, &assignment) == -1)
            {
                if let Some(group) = clause_groups[index] {
                    violated_groups.insert(group);
                } else {
                    violated_ungrouped.push(index);
                }
            }
        }

        let mut added = 0usize;
        for group in violated_groups {
            for &index in &congruence_groups[&group] {
                if !loaded_congruence[index] {
                    solver.add_clause(rustsat_clause(&congruence[index])).ok()?;
                    loaded_congruence[index] = true;
                    lemma_count += 1;
                    added += 1;
                }
            }
        }
        for index in violated_ungrouped {
            solver.add_clause(rustsat_clause(&congruence[index])).ok()?;
            loaded_congruence[index] = true;
            lemma_count += 1;
            added += 1;
        }

        let validation_start = Instant::now();
        let conflicts = theory_conflict_clauses(cnf, arena, true_term, false_term, &assignment)?;
        telemetry.validation_time_ns += validation_start.elapsed().as_nanos();
        telemetry.validation_calls += 1;
        if conflicts.is_empty() && added == 0 {
            return Some((SolveResult::Sat, round, lemma_count));
        }
        let cut_count = add_novel_theory_cuts(
            &conflicts,
            &mut learned_theory,
            cnf.var_count(),
            telemetry,
            |clause| solver.add_clause(rustsat_clause(clause)).is_ok(),
        )?;
        lemma_count += cut_count;
        added += cut_count;
        if added == 0 {
            return None;
        }
    }

    None
}

fn solve_varisat_euf(
    cnf: &CnfProblem,
    arena: &TermArena,
    true_term: TermId,
    false_term: TermId,
) -> (SolveResult, usize, usize) {
    let load_start = Instant::now();
    let mut solver = VarisatSolver::new();
    for clause in &cnf.clauses {
        let lits = clause
            .iter()
            .map(|literal| Lit::from_dimacs(*literal as isize))
            .collect::<Vec<_>>();
        solver.add_clause(&lits);
    }
    profile_phase("varisat_base_load", load_start, cnf.clauses.len());

    let transitivity_start = Instant::now();
    let transitivity = equality_transitivity_clauses(cnf, arena.terms.len());
    profile_phase("transitivity", transitivity_start, transitivity.len());
    let transitivity_load_start = Instant::now();
    for clause in transitivity {
        let lits = clause
            .iter()
            .map(|literal| Lit::from_dimacs(*literal as isize))
            .collect::<Vec<_>>();
        solver.add_clause(&lits);
    }
    profile_phase("varisat_transitivity_load", transitivity_load_start, 0);

    let congruence_start = Instant::now();
    let congruence = if env::var("EUF_VIPER_EAGER_CONGRUENCE").as_deref() == Ok("0") {
        Vec::new()
    } else {
        congruence_axiom_clauses(cnf, arena)
    };
    profile_phase("congruence", congruence_start, congruence.len());
    let congruence_load_start = Instant::now();
    for clause in congruence {
        let lits = clause
            .iter()
            .map(|literal| Lit::from_dimacs(*literal as isize))
            .collect::<Vec<_>>();
        solver.add_clause(&lits);
    }
    profile_phase("varisat_congruence_load", congruence_load_start, 0);

    let mut learned = HashSet::<Vec<i32>>::default();
    let max_theory_rounds = env::var("EUF_VIPER_MAX_THEORY_ROUNDS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(100_000usize);
    let mut sat_time_ns = 0u128;
    for round in 1..=max_theory_rounds {
        let sat_start = Instant::now();
        let sat_result = solver.solve();
        sat_time_ns += sat_start.elapsed().as_nanos();
        match sat_result {
            Ok(false) => {
                profile_measurement("varisat_solve", sat_time_ns, round);
                return (SolveResult::Unsat, round, learned.len());
            }
            Err(error) => {
                profile_measurement("varisat_solve", sat_time_ns, round);
                return (
                    SolveResult::Unsupported(vec![format!("Varisat failed: {error}")]),
                    round,
                    learned.len(),
                );
            }
            Ok(true) => {}
        }

        let mut assignment = vec![0i8; cnf.var_count() + 1];
        for literal in solver.model().unwrap_or_default() {
            let dimacs = literal.to_dimacs() as i32;
            let var = dimacs.unsigned_abs() as usize;
            if var < assignment.len() {
                assignment[var] = if dimacs > 0 { 1 } else { -1 };
            }
        }
        if !complete_cnf_assignment(cnf, &mut assignment) {
            profile_measurement("varisat_solve", sat_time_ns, round);
            return (
                SolveResult::Unsupported(vec![
                    "Varisat returned an incomplete model that does not satisfy the base CNF"
                        .to_owned(),
                ]),
                round,
                learned.len(),
            );
        }
        let Some(conflicts) =
            theory_conflict_clauses(cnf, arena, true_term, false_term, &assignment)
        else {
            profile_measurement("varisat_solve", sat_time_ns, round);
            return (
                SolveResult::Unsupported(vec![
                    "Varisat model could not be completed for EUF validation".to_owned(),
                ]),
                round,
                learned.len(),
            );
        };
        if conflicts.is_empty() {
            profile_measurement("varisat_solve", sat_time_ns, round);
            return (SolveResult::Sat, round, learned.len());
        }

        let mut added = 0usize;
        for clause in conflicts {
            if learned.insert(clause.clone()) {
                let lits = clause
                    .iter()
                    .map(|literal| Lit::from_dimacs(*literal as isize))
                    .collect::<Vec<_>>();
                solver.add_clause(&lits);
                added += 1;
            }
        }
        if added == 0 {
            profile_measurement("varisat_solve", sat_time_ns, round);
            return (
                SolveResult::Unsupported(vec![
                    "Varisat repeated an existing EUF conflict clause".to_owned(),
                ]),
                round,
                learned.len(),
            );
        }
    }
    profile_measurement("varisat_solve", sat_time_ns, max_theory_rounds);
    (
        SolveResult::Unsupported(vec![format!(
            "Varisat reached the {max_theory_rounds}-round EUF lemma limit"
        )]),
        max_theory_rounds,
        learned.len(),
    )
}

#[cfg(feature = "certificates")]
#[derive(Debug, PartialEq, Eq)]
struct CertificateTheorySeeds {
    transitivity: Vec<Vec<i32>>,
    congruence: Vec<Vec<i32>>,
}

#[cfg(feature = "certificates")]
fn certificate_theory_seeds(cnf: &CnfProblem, arena: &TermArena) -> CertificateTheorySeeds {
    let mut transitivity = equality_transitivity_clauses(cnf, arena.terms.len());
    let mut congruence = congruence_axiom_clauses_with_mode(cnf, arena, "auto");
    transitivity.sort();
    congruence.sort();
    CertificateTheorySeeds {
        transitivity,
        congruence,
    }
}

#[cfg(feature = "certificates")]
fn certificate_theory_clause_key(cnf: &CnfProblem, clause: &[i32]) -> Result<Vec<i32>, String> {
    if clause.is_empty() {
        return Err("certificate EUF theory clause must not be empty".to_owned());
    }
    let mut key = clause.to_vec();
    key.sort_unstable();
    key.dedup();
    for &literal in &key {
        let variable = literal.unsigned_abs() as usize;
        if literal == 0 || !matches!(cnf.var_atoms.get(variable), Some(Some(_))) {
            return Err(format!(
                "certificate EUF theory clause contains non-theory literal {literal}"
            ));
        }
        if key.binary_search(&-literal).is_ok() {
            return Err("certificate EUF theory clause must not be tautological".to_owned());
        }
    }
    Ok(key)
}

#[cfg(feature = "certificates")]
fn discover_certificate_theory_conflicts(
    cnf: &mut CnfProblem,
    arena: &TermArena,
    true_term: TermId,
    false_term: TermId,
    theory_seed_start: usize,
    max_rounds: usize,
) -> Result<CertificateSaturation, String> {
    if theory_seed_start > cnf.clauses.len() {
        return Err("certificate EUF seed boundary exceeds the CNF".to_owned());
    }
    let mut known_theory_clauses = HashSet::<Vec<i32>>::default();
    for clause in cnf.clauses.iter().skip(theory_seed_start) {
        known_theory_clauses.insert(certificate_theory_clause_key(cnf, clause)?);
    }

    let mut solver = VarisatSolver::new();
    for clause in &cnf.clauses {
        let literals = clause
            .iter()
            .map(|literal| Lit::from_dimacs(*literal as isize))
            .collect::<Vec<_>>();
        solver.add_clause(&literals);
    }

    let mut dynamic_conflict_count = 0usize;
    for round in 1..=max_rounds {
        match solver.solve() {
            Ok(false) => {
                return Ok(CertificateSaturation::Unsat {
                    theory_rounds: round,
                    conflict_count: dynamic_conflict_count,
                });
            }
            Err(error) => return Err(format!("Varisat failed during certification: {error}")),
            Ok(true) => {}
        }

        let mut assignment = vec![-1i8; cnf.var_count() + 1];
        assignment[0] = 0;
        for literal in solver.model().unwrap_or_default() {
            let dimacs = literal.to_dimacs() as i32;
            let var = dimacs.unsigned_abs() as usize;
            if var < assignment.len() {
                assignment[var] = if dimacs > 0 { 1 } else { -1 };
            }
        }
        if !complete_cnf_assignment(cnf, &mut assignment) {
            return Err("certificate SAT model does not satisfy the reconstructed CNF".to_owned());
        }
        let conflicts = theory_conflict_clauses(cnf, arena, true_term, false_term, &assignment)
            .ok_or_else(|| "certificate SAT model is incomplete".to_owned())?;
        if conflicts.is_empty() {
            let assignment = assignment
                .iter()
                .enumerate()
                .skip(1)
                .map(|(variable, &value)| {
                    if value > 0 {
                        variable as i32
                    } else {
                        -(variable as i32)
                    }
                })
                .collect();
            return Ok(CertificateSaturation::Sat {
                theory_rounds: round,
                conflict_count: dynamic_conflict_count,
                assignment,
            });
        }

        let mut added = 0usize;
        for clause in conflicts {
            let clause = certificate_theory_clause_key(cnf, &clause)?;
            if known_theory_clauses.insert(clause.clone()) {
                let literals = clause
                    .iter()
                    .map(|literal| Lit::from_dimacs(*literal as isize))
                    .collect::<Vec<_>>();
                solver.add_clause(&literals);
                cnf.clauses.push(clause);
                added += 1;
                dynamic_conflict_count += 1;
            }
        }
        if added == 0 {
            return Err("certificate saturation repeated an EUF conflict clause".to_owned());
        }
    }
    Err(format!(
        "certificate saturation reached the {max_rounds}-round limit"
    ))
}

#[cfg(feature = "certificates")]
fn write_dimacs(path: &Path, cnf: &CnfProblem) -> Result<(), String> {
    let file = fs::File::create(path)
        .map_err(|error| format!("failed to create {}: {error}", path.display()))?;
    let mut writer = BufWriter::new(file);
    writeln!(writer, "p cnf {} {}", cnf.var_count(), cnf.clauses.len())
        .map_err(|error| format!("failed to write {}: {error}", path.display()))?;
    for clause in &cnf.clauses {
        for literal in clause {
            write!(writer, "{literal} ")
                .map_err(|error| format!("failed to write {}: {error}", path.display()))?;
        }
        writeln!(writer, "0")
            .map_err(|error| format!("failed to write {}: {error}", path.display()))?;
    }
    writer
        .flush()
        .map_err(|error| format!("failed to flush {}: {error}", path.display()))
}

#[cfg(feature = "certificates")]
fn write_cadical_drat(path: &Path, cnf: &CnfProblem) -> Result<(), String> {
    if path.exists() {
        fs::remove_file(path)
            .map_err(|error| format!("failed to replace {}: {error}", path.display()))?;
    }
    let result = {
        let mut solver = CadicalSolver::default();
        solver
            .set_configuration(CadicalConfig::Plain)
            .map_err(|error| format!("failed to configure proof solver: {error}"))?;
        solver
            .trace_proof(path, CadicalProofFormat::Drat { binary: false })
            .map_err(|error| format!("failed to open {}: {error}", path.display()))?;
        for clause in &cnf.clauses {
            solver
                .add_clause(rustsat_clause(clause))
                .map_err(|error| format!("failed to load certificate CNF: {error}"))?;
        }
        solver
            .solve()
            .map_err(|error| format!("CaDiCaL proof run failed: {error}"))?
    };
    if result != RustSatResult::Unsat {
        return Err(format!(
            "certificate CNF was expected UNSAT but CaDiCaL returned {result:?}"
        ));
    }
    Ok(())
}

#[cfg(feature = "certificates")]
fn dump_eager_cnf(path: &str, output: &str) -> Result<i32, String> {
    let input =
        fs::read_to_string(path).map_err(|error| format!("failed to read {path}: {error}"))?;
    let problem = parse_problem(&input)?;
    let bool_problem = problem
        .bool_problem
        .as_ref()
        .ok_or_else(|| "DIMACS export requires a Boolean QF_UF assertion".to_owned())?;
    if !bool_problem.unsupported.is_empty() {
        return Err(format!(
            "DIMACS export does not support: {}",
            bool_problem.unsupported.join("; ")
        ));
    }

    let mut cnf = CnfProblem::new();
    atomize_bool_data_terms(&mut cnf, bool_problem);
    for assertion in &bool_problem.assertions {
        cnf.add_assertion(assertion);
    }
    let finite_added = add_finite_domain_axioms(&mut cnf, &problem.arena, bool_problem);
    let eager_congruence = use_eager_congruence_for_first_pass(finite_added, &cnf, &problem.arena);
    let transitivity = equality_transitivity_clauses(&cnf, problem.arena.terms.len());
    let transitivity_count = transitivity.len();
    cnf.clauses.extend(transitivity);
    let congruence = if eager_congruence {
        congruence_axiom_clauses(&cnf, &problem.arena)
    } else {
        Vec::new()
    };
    let congruence_count = congruence.len();
    cnf.clauses.extend(congruence);
    write_dimacs(Path::new(output), &cnf)?;
    eprintln!("dimacs={output}");
    eprintln!("variables={}", cnf.var_count());
    eprintln!("clauses={}", cnf.clauses.len());
    eprintln!("finite_domain_axioms={finite_added}");
    eprintln!("transitivity_clauses={transitivity_count}");
    eprintln!("congruence_clauses={congruence_count}");
    Ok(0)
}

#[cfg(feature = "certificates")]
fn solve_dimacs_file(path: &str) -> Result<i32, String> {
    let input =
        fs::read_to_string(path).map_err(|error| format!("failed to read {path}: {error}"))?;
    let mut clauses = Vec::new();
    let mut current_clause = Vec::new();
    let mut max_variable = 0usize;
    for (line_index, line) in input.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('c') || line.starts_with('p') {
            continue;
        }
        for token in line.split_whitespace() {
            if token == "%" {
                break;
            }
            let literal = token.parse::<i32>().map_err(|error| {
                format!(
                    "invalid DIMACS token `{token}` on line {}: {error}",
                    line_index + 1
                )
            })?;
            if literal == 0 {
                clauses.push(std::mem::take(&mut current_clause));
            } else {
                max_variable = max_variable.max(literal.unsigned_abs() as usize);
                current_clause.push(literal);
            }
        }
    }
    if !current_clause.is_empty() {
        return Err("DIMACS input ends before a clause-terminating zero".to_owned());
    }

    let mut solver = CadicalSolver::default();
    configure_cadical(&mut solver, false)
        .ok_or_else(|| "failed to configure CaDiCaL".to_owned())?;
    for clause in &clauses {
        solver
            .add_clause(rustsat_clause(clause))
            .map_err(|error| format!("failed to load DIMACS clause: {error}"))?;
    }
    let start = Instant::now();
    let result = solver
        .solve()
        .map_err(|error| format!("CaDiCaL failed: {error}"))?;
    let elapsed = start.elapsed();
    let (status, exit_code) = match result {
        RustSatResult::Sat => ("sat", 0),
        RustSatResult::Unsat => ("unsat", 0),
        RustSatResult::Interrupted => ("unknown", 3),
    };
    println!("{status}");
    eprintln!("variables={max_variable}");
    eprintln!("clauses={}", clauses.len());
    eprintln!("elapsed_ns={}", elapsed.as_nanos());
    Ok(exit_code)
}

#[cfg(feature = "certificates")]
fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(feature = "certificates")]
fn sha256_file(path: &Path) -> Result<String, String> {
    let file = fs::File::open(path)
        .map_err(|error| format!("failed to hash {}: {error}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| format!("failed to hash {}: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let digest = hasher.finalize();
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[cfg(feature = "certificates")]
fn path_with_suffix(prefix: &Path, suffix: &str) -> PathBuf {
    let mut path = prefix.as_os_str().to_os_string();
    path.push(suffix);
    PathBuf::from(path)
}

#[cfg(feature = "certificates")]
fn certificate_atoms(cnf: &CnfProblem) -> Vec<CertificateAtom> {
    cnf.var_atoms
        .iter()
        .enumerate()
        .skip(1)
        .map(|(variable, atom)| match atom {
            None => CertificateAtom::Auxiliary { variable },
            Some(BoolAtomKey::Eq(left, right)) => CertificateAtom::Equality {
                variable,
                left: *left,
                right: *right,
            },
            Some(BoolAtomKey::BoolTerm(term)) => CertificateAtom::BoolTerm {
                variable,
                term: *term,
            },
        })
        .collect()
}

#[cfg(feature = "certificates")]
fn certify_file(path: &str, prefix: &str, max_rounds: usize) -> Result<i32, String> {
    if max_rounds == 0 {
        return Err("--max-theory-rounds must be at least 1".to_owned());
    }
    let source_path = Path::new(path);
    let source_bytes = fs::read(source_path)
        .map_err(|error| format!("failed to read {}: {error}", source_path.display()))?;
    let input = std::str::from_utf8(&source_bytes)
        .map_err(|error| format!("{} is not UTF-8: {error}", source_path.display()))?;
    let problem = parse_problem(input)?;
    let bool_problem = problem
        .bool_problem
        .as_ref()
        .ok_or_else(|| "certificate mode requires a Boolean QF_UF assertion".to_owned())?;
    if !bool_problem.unsupported.is_empty() {
        return Err(format!(
            "certificate mode does not support: {}",
            bool_problem.unsupported.join("; ")
        ));
    }

    let prefix = Path::new(prefix);
    let dimacs_path = path_with_suffix(prefix, ".cnf");
    let proof_path = path_with_suffix(prefix, ".drat");
    let manifest_path = path_with_suffix(prefix, ".euf.json");
    if let Some(parent) = dimacs_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create {}: {error}", parent.display()))?;
    }

    let mut cnf = CnfProblem::new();
    atomize_bool_data_terms(&mut cnf, bool_problem);
    for assertion in &bool_problem.assertions {
        cnf.add_assertion(assertion);
    }
    let base_count = cnf.clauses.len();
    let seeds = certificate_theory_seeds(&cnf, &problem.arena);
    let transitivity_count = seeds.transitivity.len();
    let congruence_count = seeds.congruence.len();
    cnf.clauses.extend(seeds.transitivity);
    cnf.clauses.extend(seeds.congruence);
    let saturation = discover_certificate_theory_conflicts(
        &mut cnf,
        &problem.arena,
        bool_problem.true_term,
        bool_problem.false_term,
        base_count,
        max_rounds,
    )?;
    let dynamic_conflict_count = match &saturation {
        CertificateSaturation::Sat { conflict_count, .. }
        | CertificateSaturation::Unsat { conflict_count, .. } => *conflict_count,
    };
    let accounted_clause_count = base_count
        .checked_add(transitivity_count)
        .and_then(|count| count.checked_add(congruence_count))
        .and_then(|count| count.checked_add(dynamic_conflict_count))
        .ok_or_else(|| "certificate clause accounting overflow".to_owned())?;
    if accounted_clause_count != cnf.clauses.len() {
        return Err(format!(
            "certificate clause accounting mismatch: expected {accounted_clause_count}, got {}",
            cnf.clauses.len()
        ));
    }
    let manifest_file = fs::File::create(&manifest_path)
        .map_err(|error| format!("failed to create {}: {error}", manifest_path.display()))?;
    let mut manifest_writer = BufWriter::new(manifest_file);
    match saturation {
        CertificateSaturation::Sat {
            theory_rounds,
            conflict_count,
            assignment,
        } => {
            let manifest = SatCertificateManifest {
                format: "euf-viper-euf-cnf-v2",
                result: "sat",
                encoding: "canonical-tseitin-v1",
                source: source_path.display().to_string(),
                source_sha256: sha256_hex(&source_bytes),
                variables: cnf.var_count(),
                assignment,
                theory_rounds,
                theory_conflicts: conflict_count,
            };
            serde_json::to_writer_pretty(&mut manifest_writer, &manifest)
                .map_err(|error| format!("failed to write {}: {error}", manifest_path.display()))?;
            writeln!(manifest_writer).map_err(|error| {
                format!("failed to finish {}: {error}", manifest_path.display())
            })?;
            println!("sat");
            eprintln!("manifest={}", manifest_path.display());
            eprintln!("cnf_vars={}", cnf.var_count());
            eprintln!("cnf_clauses={}", cnf.clauses.len());
            eprintln!("theory_rounds={theory_rounds}");
            eprintln!("theory_conflicts={conflict_count}");
            eprintln!("transitivity_clauses={transitivity_count}");
            eprintln!("congruence_clauses={congruence_count}");
            eprintln!("dynamic_theory_conflicts={conflict_count}");
            eprintln!("finite_domain_axioms=0");
        }
        CertificateSaturation::Unsat {
            theory_rounds,
            conflict_count,
        } => {
            write_dimacs(&dimacs_path, &cnf)?;
            write_cadical_drat(&proof_path, &cnf)?;
            let terms = problem
                .arena
                .terms
                .iter()
                .enumerate()
                .map(|(id, term)| CertificateTerm {
                    id,
                    function: term.fun,
                    args: term.args.clone(),
                })
                .collect();
            let manifest = CertificateManifest {
                format: "euf-viper-euf-cnf-v2",
                result: "unsat",
                encoding: "canonical-tseitin-v1",
                source: source_path.display().to_string(),
                source_sha256: sha256_hex(&source_bytes),
                dimacs: dimacs_path.display().to_string(),
                dimacs_sha256: sha256_file(&dimacs_path)?,
                proof: proof_path.display().to_string(),
                proof_sha256: sha256_file(&proof_path)?,
                variables: cnf.var_count(),
                true_term: bool_problem.true_term,
                false_term: bool_problem.false_term,
                terms,
                atoms: certificate_atoms(&cnf),
                clauses: CertificateClauseCounts {
                    base: base_count,
                    transitivity: transitivity_count,
                    congruence: congruence_count,
                    theory_conflicts: conflict_count,
                    total: cnf.clauses.len(),
                },
                theory_rounds,
                finite_domain_axioms: 0,
            };
            serde_json::to_writer_pretty(&mut manifest_writer, &manifest)
                .map_err(|error| format!("failed to write {}: {error}", manifest_path.display()))?;
            writeln!(manifest_writer).map_err(|error| {
                format!("failed to finish {}: {error}", manifest_path.display())
            })?;
            println!("unsat");
            eprintln!("dimacs={}", dimacs_path.display());
            eprintln!("proof={}", proof_path.display());
            eprintln!("manifest={}", manifest_path.display());
            eprintln!("cnf_vars={}", cnf.var_count());
            eprintln!("cnf_clauses={}", cnf.clauses.len());
            eprintln!("theory_rounds={theory_rounds}");
            eprintln!("theory_conflicts={conflict_count}");
            eprintln!("transitivity_clauses={transitivity_count}");
            eprintln!("congruence_clauses={congruence_count}");
            eprintln!("dynamic_theory_conflicts={conflict_count}");
            eprintln!("finite_domain_axioms=0");
        }
    }
    Ok(0)
}

fn profile_phase(label: &str, start: Instant, count: usize) {
    profile_measurement(label, start.elapsed().as_nanos(), count);
}

fn profile_measurement(label: &str, elapsed_ns: u128, count: usize) {
    if env::var_os("EUF_VIPER_PROFILE").is_some() {
        eprintln!("profile_{label}_ns={elapsed_ns} count={count}");
    }
}

fn profile_eq_facts_guarded_clauses(count: usize) {
    if env::var_os("EUF_VIPER_PROFILE").is_some() {
        eprintln!("profile_eq_facts_guarded_clauses={count}");
    }
}

fn lit_status(lit: i32, assignment: &[i8]) -> i8 {
    let var = lit.unsigned_abs() as usize;
    let value = assignment[var];
    if value == 0 {
        0
    } else if (lit > 0 && value > 0) || (lit < 0 && value < 0) {
        1
    } else {
        -1
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SolveResult {
    Sat,
    Unsat,
    Unsupported(Vec<String>),
}

#[derive(Debug)]
struct SolveStats {
    terms: usize,
    apps: usize,
    eqs: usize,
    diseqs: usize,
    closure_passes: usize,
    congruence_merges: usize,
    cnf_vars: usize,
    cnf_clauses: usize,
    search_nodes: usize,
    sat_calls: usize,
    theory_lemmas: usize,
}

#[derive(Debug)]
struct SolveReport {
    result: SolveResult,
    stats: SolveStats,
}

const DIRECT_ROOT_CNF_ENV: &str = "EUF_VIPER_DIRECT_ROOT_CNF";
const DIRECT_NEGATED_ROOT_ENV: &str = "EUF_VIPER_DIRECT_NEGATED_ROOT";
const SCOPED_LET_ENV: &str = "EUF_VIPER_SCOPED_LET";
const EQ_ABSTRACTION_ENV: &str = "EUF_VIPER_EQ_ABSTRACTION";
const EQ_ABSTRACTION_FRESH_ENV: &str = "EUF_VIPER_EQ_ABSTRACTION_FRESH";
const EQ_ABSTRACTION_MAX_FACTS_ENV: &str = "EUF_VIPER_EQ_ABSTRACTION_MAX_FACTS";
const EQ_ABSTRACTION_MAX_FRESH_FACTS_ENV: &str = "EUF_VIPER_EQ_ABSTRACTION_MAX_FRESH_FACTS";
const DEFAULT_EQ_ABSTRACTION_MAX_FACTS: usize = 4_096;
const DEFAULT_EQ_ABSTRACTION_MAX_FRESH_FACTS: usize = 256;
const SCOPED_LET_AUTO_THRESHOLD: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RootCnfOptions {
    direct_root_cnf: bool,
    direct_negated_root: bool,
}

impl RootCnfOptions {
    #[cfg(test)]
    fn existing_behavior(direct_root_cnf: bool) -> Self {
        Self {
            direct_root_cnf,
            direct_negated_root: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScopedLetMode {
    Off,
    Auto,
    On,
}

impl ScopedLetMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Auto => "auto",
            Self::On => "on",
        }
    }
}

fn parse_scoped_let_mode(value: Option<&str>) -> Result<ScopedLetMode, String> {
    match value {
        None | Some("auto") => Ok(ScopedLetMode::Auto),
        Some("off") => Ok(ScopedLetMode::Off),
        Some("on") => Ok(ScopedLetMode::On),
        Some(_) => Err(format!("{SCOPED_LET_ENV} must be off, auto, or on")),
    }
}

fn selected_scoped_let_mode() -> Result<ScopedLetMode, String> {
    match env::var(SCOPED_LET_ENV) {
        Ok(value) => parse_scoped_let_mode(Some(&value)),
        Err(env::VarError::NotPresent) => parse_scoped_let_mode(None),
        Err(env::VarError::NotUnicode(_)) => {
            Err(format!("{SCOPED_LET_ENV} must be off, auto, or on"))
        }
    }
}

fn bounded_lexical_let_count(input: &str) -> usize {
    input
        .match_indices("(let")
        .take(SCOPED_LET_AUTO_THRESHOLD)
        .count()
}

fn scoped_let_selected(mode: ScopedLetMode, bounded_let_count: usize) -> bool {
    match mode {
        ScopedLetMode::Off => false,
        ScopedLetMode::Auto => bounded_let_count >= SCOPED_LET_AUTO_THRESHOLD,
        ScopedLetMode::On => true,
    }
}

fn profile_scoped_let(mode: ScopedLetMode, bounded_let_count: usize, selected: bool) {
    if env::var_os("EUF_VIPER_PROFILE").is_some() {
        eprintln!(
            "profile_scoped_let_mode={} bounded_let_count={} selected={}",
            mode.as_str(),
            bounded_let_count,
            usize::from(selected),
        );
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EqAbstractionMode {
    Off,
    Shadow,
    Facts,
    GuardedFacts,
}

impl EqAbstractionMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Shadow => "shadow",
            Self::Facts => "facts",
            Self::GuardedFacts => "guarded-facts",
        }
    }
}

fn parse_eq_abstraction_mode(value: Option<&str>) -> EqAbstractionMode {
    match value {
        Some("shadow") => EqAbstractionMode::Shadow,
        Some("facts") => EqAbstractionMode::Facts,
        Some("guarded-facts") => EqAbstractionMode::GuardedFacts,
        None | Some("off") | Some(_) => EqAbstractionMode::Off,
    }
}

fn selected_eq_abstraction_mode() -> EqAbstractionMode {
    let setting = env::var(EQ_ABSTRACTION_ENV).ok();
    parse_eq_abstraction_mode(setting.as_deref())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EqAbstractionFactConfig {
    allow_fresh: bool,
    max_facts: usize,
    max_fresh_facts: usize,
}

impl Default for EqAbstractionFactConfig {
    fn default() -> Self {
        Self {
            allow_fresh: false,
            max_facts: DEFAULT_EQ_ABSTRACTION_MAX_FACTS,
            max_fresh_facts: DEFAULT_EQ_ABSTRACTION_MAX_FRESH_FACTS,
        }
    }
}

fn parse_eq_abstraction_fresh(value: Option<&str>) -> bool {
    value == Some("1")
}

fn parse_eq_abstraction_quota(value: Option<&str>, default: usize) -> usize {
    let Some(value) = value else {
        return default;
    };
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return default;
    }
    value.parse().unwrap_or(default)
}

fn selected_eq_abstraction_fact_config() -> EqAbstractionFactConfig {
    let fresh = env::var(EQ_ABSTRACTION_FRESH_ENV).ok();
    let max_facts = env::var(EQ_ABSTRACTION_MAX_FACTS_ENV).ok();
    let max_fresh_facts = env::var(EQ_ABSTRACTION_MAX_FRESH_FACTS_ENV).ok();
    EqAbstractionFactConfig {
        allow_fresh: parse_eq_abstraction_fresh(fresh.as_deref()),
        max_facts: parse_eq_abstraction_quota(
            max_facts.as_deref(),
            DEFAULT_EQ_ABSTRACTION_MAX_FACTS,
        ),
        max_fresh_facts: parse_eq_abstraction_quota(
            max_fresh_facts.as_deref(),
            DEFAULT_EQ_ABSTRACTION_MAX_FRESH_FACTS,
        ),
    }
}

fn eq_abstraction_fact_config_for_mode(
    mode: EqAbstractionMode,
    mut config: EqAbstractionFactConfig,
) -> EqAbstractionFactConfig {
    if mode == EqAbstractionMode::GuardedFacts {
        config.allow_fresh = false;
    }
    config
}

fn route_eq_abstraction_mode(
    requested: EqAbstractionMode,
    arena: &TermArena,
    bool_problem: &BoolProblem,
    finite_context: &mut finite_analysis::FiniteAnalysisContext,
) -> EqAbstractionMode {
    if requested != EqAbstractionMode::GuardedFacts {
        return requested;
    }

    let shape_start = Instant::now();
    let has_shape = finite_analysis::has_guarded_disequality_shape(bool_problem);
    profile_measurement(
        "eq_facts_guarded_shape",
        shape_start.elapsed().as_nanos(),
        usize::from(has_shape),
    );
    if !has_shape {
        profile_measurement("eq_facts_guarded_selector", 0, 0);
        profile_eq_facts_guarded_clauses(0);
        return EqAbstractionMode::Off;
    }

    let selector_start = Instant::now();
    let guarded_clauses = finite_context.guarded_disequality_clause_count(arena, bool_problem);
    let selected = guarded_clauses > 0;
    profile_measurement(
        "eq_facts_guarded_selector",
        selector_start.elapsed().as_nanos(),
        usize::from(selected),
    );
    profile_eq_facts_guarded_clauses(guarded_clauses);
    if selected {
        EqAbstractionMode::GuardedFacts
    } else {
        EqAbstractionMode::Off
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EqAbstractionIntegrationRollbackReason {
    MaxFacts,
    MaxFreshFacts,
}

impl EqAbstractionIntegrationRollbackReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::MaxFacts => "max_facts",
            Self::MaxFreshFacts => "max_fresh_facts",
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct EqAbstractionFactIntegration {
    duplicate_units: usize,
    accepted_existing_facts: usize,
    accepted_fresh_facts: usize,
    rollback_reason: Option<EqAbstractionIntegrationRollbackReason>,
    rollback_count: usize,
    accepted_edges: Vec<(TermId, TermId)>,
}

impl EqAbstractionFactIntegration {
    fn profile(&self) {
        profile_measurement("eq_abstraction_duplicate_units", 0, self.duplicate_units);
        profile_measurement(
            "eq_abstraction_accepted_existing_facts",
            0,
            self.accepted_existing_facts,
        );
        profile_measurement(
            "eq_abstraction_accepted_fresh_facts",
            0,
            self.accepted_fresh_facts,
        );
        profile_measurement(
            "eq_abstraction_integration_rollbacks",
            0,
            usize::from(self.rollback_reason.is_some()),
        );
        if env::var_os("EUF_VIPER_PROFILE").is_some() {
            eprintln!(
                "profile_eq_abstraction_integration_rollback_reason={} count={}",
                self.rollback_reason
                    .map_or("none", |reason| reason.as_str()),
                self.rollback_count,
            );
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum ClassifiedEqualityFact {
    Existing {
        edge: (TermId, TermId),
        literal: i32,
    },
    Fresh {
        edge: (TermId, TermId),
    },
}

fn integrate_equality_abstraction_facts(
    cnf: &mut CnfProblem,
    candidate_edges: &[(TermId, TermId)],
    config: EqAbstractionFactConfig,
) -> EqAbstractionFactIntegration {
    let unit_literals = cnf
        .clauses
        .iter()
        .filter_map(|clause| match clause {
            [literal] => Some(*literal),
            _ => None,
        })
        .collect::<HashSet<_>>();
    let mut integration = EqAbstractionFactIntegration::default();
    let mut selected = Vec::with_capacity(candidate_edges.len());
    let mut fresh_count = 0usize;

    for &(left, right) in candidate_edges {
        let edge = normalized_pair(left, right);
        let atom = BoolAtomKey::Eq(edge.0, edge.1);
        if let Some(&literal) = cnf.atom_vars.get(&atom) {
            if unit_literals.contains(&literal) {
                integration.duplicate_units += 1;
            } else {
                selected.push(ClassifiedEqualityFact::Existing { edge, literal });
            }
        } else if config.allow_fresh {
            selected.push(ClassifiedEqualityFact::Fresh { edge });
            fresh_count += 1;
        }
    }

    let rollback = if selected.len() > config.max_facts {
        Some((
            EqAbstractionIntegrationRollbackReason::MaxFacts,
            selected.len(),
        ))
    } else if fresh_count > config.max_fresh_facts {
        Some((
            EqAbstractionIntegrationRollbackReason::MaxFreshFacts,
            fresh_count,
        ))
    } else {
        None
    };
    if let Some((reason, count)) = rollback {
        integration.rollback_reason = Some(reason);
        integration.rollback_count = count;
        return integration;
    }

    integration.accepted_edges.reserve(selected.len());
    for fact in selected {
        match fact {
            ClassifiedEqualityFact::Existing { edge, literal } => {
                cnf.clauses.push(vec![literal]);
                integration.accepted_existing_facts += 1;
                integration.accepted_edges.push(edge);
            }
            ClassifiedEqualityFact::Fresh { edge } => {
                let literal = cnf.atom_lit(BoolAtomKey::Eq(edge.0, edge.1));
                cnf.clauses.push(vec![literal]);
                integration.accepted_fresh_facts += 1;
                integration.accepted_edges.push(edge);
            }
        }
    }
    integration
}

fn equality_abstraction_fact_candidates(
    assertions: &[BoolExpr],
    mode: EqAbstractionMode,
) -> Vec<(TermId, TermId)> {
    if mode == EqAbstractionMode::Off {
        return Vec::new();
    }

    let start = Instant::now();
    let outcome = eq_abstraction::analyze(assertions);
    profile_measurement(
        "eq_abstraction",
        start.elapsed().as_nanos(),
        outcome.star_edges.len(),
    );
    profile_measurement("eq_abstraction_nodes", 0, outcome.metrics.nodes);
    profile_measurement(
        "eq_abstraction_memo_entries",
        0,
        outcome.metrics.memo_entries,
    );
    profile_measurement("eq_abstraction_memo_hits", 0, outcome.metrics.memo_hits);
    profile_measurement("eq_abstraction_work", 0, outcome.metrics.work);
    profile_measurement("eq_abstraction_classes", 0, outcome.metrics.classes);
    profile_measurement(
        "eq_abstraction_partition_terms",
        0,
        outcome.metrics.partition_terms,
    );
    let mut seen_edges = HashSet::default();
    let normalized_edges = outcome
        .star_edges
        .iter()
        .map(|&(left, right)| normalized_pair(left, right))
        .filter(|edge| seen_edges.insert(*edge))
        .collect::<Vec<_>>();
    profile_measurement("eq_abstraction_candidate_edges", 0, normalized_edges.len());
    if env::var_os("EUF_VIPER_PROFILE").is_some() {
        eprintln!(
            "profile_eq_abstraction_mode={} cap_reason={} infeasible={}",
            mode.as_str(),
            outcome
                .cap_reason
                .map_or("none", eq_abstraction::CapReason::as_str),
            usize::from(outcome.infeasible),
        );
    }

    if !matches!(
        mode,
        EqAbstractionMode::Facts | EqAbstractionMode::GuardedFacts
    ) || outcome.cap_reason.is_some()
    {
        return Vec::new();
    }
    normalized_edges
}

fn parse_zero_one_setting_with_default(
    name: &str,
    value: Option<&str>,
    default: bool,
) -> Result<bool, String> {
    match value {
        None => Ok(default),
        Some("1") => Ok(true),
        Some("0") => Ok(false),
        Some(_) => Err(format!("{name} must be 0 or 1")),
    }
}

#[cfg(test)]
fn parse_zero_one_setting(name: &str, value: Option<&str>) -> Result<bool, String> {
    parse_zero_one_setting_with_default(name, value, true)
}

fn zero_one_env_setting(name: &str, default: bool) -> Result<bool, String> {
    match env::var(name) {
        Ok(value) => parse_zero_one_setting_with_default(name, Some(&value), default),
        Err(env::VarError::NotPresent) => parse_zero_one_setting_with_default(name, None, default),
        Err(env::VarError::NotUnicode(_)) => Err(format!("{name} must be 0 or 1")),
    }
}

fn direct_root_cnf_enabled() -> Result<bool, String> {
    zero_one_env_setting(DIRECT_ROOT_CNF_ENV, true)
}

fn direct_negated_root_enabled() -> Result<bool, String> {
    zero_one_env_setting(DIRECT_NEGATED_ROOT_ENV, false)
}

fn selected_root_cnf_options() -> Result<RootCnfOptions, String> {
    Ok(RootCnfOptions {
        direct_root_cnf: direct_root_cnf_enabled()?,
        direct_negated_root: direct_negated_root_enabled()?,
    })
}

#[cfg(test)]
fn solve_problem(problem: Problem, direct_root_cnf: bool) -> SolveReport {
    solve_problem_with_eq_abstraction(problem, direct_root_cnf, selected_eq_abstraction_mode())
}

fn solve_problem_with_root_cnf_options(
    problem: Problem,
    root_cnf_options: RootCnfOptions,
) -> SolveReport {
    solve_problem_with_options_and_eq_abstraction(
        problem,
        root_cnf_options,
        selected_eq_abstraction_mode(),
    )
}

#[cfg(test)]
fn solve_problem_with_eq_abstraction(
    problem: Problem,
    direct_root_cnf: bool,
    eq_abstraction_mode: EqAbstractionMode,
) -> SolveReport {
    solve_problem_with_options_and_eq_abstraction(
        problem,
        RootCnfOptions::existing_behavior(direct_root_cnf),
        eq_abstraction_mode,
    )
}

fn solve_problem_with_options_and_eq_abstraction(
    problem: Problem,
    root_cnf_options: RootCnfOptions,
    eq_abstraction_mode: EqAbstractionMode,
) -> SolveReport {
    debug_assert!(problem.terms_are_well_sorted());
    let stats_base = SolveStats {
        terms: problem.arena.terms.len(),
        apps: problem.arena.app_count(),
        eqs: problem.eqs.len(),
        diseqs: problem.diseqs.len(),
        closure_passes: 0,
        congruence_merges: 0,
        cnf_vars: 0,
        cnf_clauses: 0,
        search_nodes: 0,
        sat_calls: 0,
        theory_lemmas: 0,
    };

    if problem.contradiction {
        return SolveReport {
            result: SolveResult::Unsat,
            stats: stats_base,
        };
    }

    if let Some(bool_problem) = &problem.bool_problem {
        let mut finite_context = finite_analysis::FiniteAnalysisContext::default();
        finite_analysis::profile_if_enabled(&problem.arena, bool_problem, &mut finite_context);
        if bool_problem.unsupported.is_empty() {
            if let Some((result, cnf_vars, cnf_clauses, search_nodes, sat_calls, theory_lemmas)) =
                solve_bool_problem(
                    &problem.arena,
                    bool_problem,
                    root_cnf_options,
                    eq_abstraction_mode,
                    &mut finite_context,
                )
            {
                return SolveReport {
                    result,
                    stats: SolveStats {
                        cnf_vars,
                        cnf_clauses,
                        search_nodes,
                        sat_calls,
                        theory_lemmas,
                        ..stats_base
                    },
                };
            }
        }
    }

    let mut uf = UnionFind::new(problem.arena.terms.len());
    for &(a, b) in &problem.eqs {
        uf.union(a, b);
    }

    let (closure_passes, congruence_merges) = congruence_closure(&problem.arena, &mut uf);

    for &(a, b) in &problem.diseqs {
        if uf.find(a) == uf.find(b) {
            return SolveReport {
                result: SolveResult::Unsat,
                stats: SolveStats {
                    closure_passes,
                    congruence_merges,
                    ..stats_base
                },
            };
        }
    }

    if !problem.unsupported.is_empty() {
        return SolveReport {
            result: SolveResult::Unsupported(problem.unsupported),
            stats: SolveStats {
                closure_passes,
                congruence_merges,
                ..stats_base
            },
        };
    }

    SolveReport {
        result: SolveResult::Sat,
        stats: SolveStats {
            closure_passes,
            congruence_merges,
            ..stats_base
        },
    }
}

#[cfg(test)]
fn solve_dynamic_full_ackermann(
    arena: &TermArena,
    bool_problem: &BoolProblem,
    accepted_equality_facts: &[(TermId, TermId)],
) -> (CnfProblem, EagerSolveOutcome) {
    solve_dynamic_full_ackermann_with_negated_root(
        arena,
        bool_problem,
        accepted_equality_facts,
        false,
    )
}

#[cold]
#[inline(never)]
fn solve_dynamic_full_ackermann_with_negated_root(
    arena: &TermArena,
    bool_problem: &BoolProblem,
    accepted_equality_facts: &[(TermId, TermId)],
    direct_negated_root: bool,
) -> (CnfProblem, EagerSolveOutcome) {
    let direct_cnf_start = Instant::now();
    let mut completed = CnfProblem::new();
    atomize_bool_data_terms(&mut completed, bool_problem);
    for assertion in &bool_problem.assertions {
        completed.add_direct_assertion_with_negated_root(assertion, direct_negated_root);
    }
    for &(left, right) in accepted_equality_facts {
        let (left, right) = normalized_pair(left, right);
        let literal = completed.atom_lit(BoolAtomKey::Eq(left, right));
        completed.clauses.push(vec![literal]);
    }
    profile_phase(
        "dynamic_direct_cnf",
        direct_cnf_start,
        completed.clauses.len(),
    );
    add_full_ackermann_completion(&mut completed, arena);
    let outcome = solve_kissat_euf_once(
        &completed,
        arena,
        bool_problem.true_term,
        bool_problem.false_term,
        false,
    );
    (completed, outcome)
}

fn solve_bool_problem(
    arena: &TermArena,
    bool_problem: &BoolProblem,
    root_cnf_options: RootCnfOptions,
    requested_eq_abstraction_mode: EqAbstractionMode,
    finite_context: &mut finite_analysis::FiniteAnalysisContext,
) -> Option<(SolveResult, usize, usize, usize, usize, usize)> {
    let cnf_start = Instant::now();
    let mut cnf = CnfProblem::new();
    atomize_bool_data_terms(&mut cnf, bool_problem);
    if root_cnf_options.direct_root_cnf {
        for assertion in &bool_problem.assertions {
            cnf.add_direct_assertion_with_negated_root(
                assertion,
                root_cnf_options.direct_negated_root,
            );
        }
    } else {
        for assertion in &bool_problem.assertions {
            cnf.add_assertion(assertion);
        }
    }
    profile_phase("cnf", cnf_start, cnf.clauses.len());
    let eq_abstraction_mode = route_eq_abstraction_mode(
        requested_eq_abstraction_mode,
        arena,
        bool_problem,
        finite_context,
    );
    let candidate_edges =
        equality_abstraction_fact_candidates(&bool_problem.assertions, eq_abstraction_mode);
    let accepted_equality_facts = if matches!(
        eq_abstraction_mode,
        EqAbstractionMode::Facts | EqAbstractionMode::GuardedFacts
    ) {
        let integration = integrate_equality_abstraction_facts(
            &mut cnf,
            &candidate_edges,
            eq_abstraction_fact_config_for_mode(
                eq_abstraction_mode,
                selected_eq_abstraction_fact_config(),
            ),
        );
        integration.profile();
        integration.accepted_edges
    } else {
        Vec::new()
    };
    let backend = env::var("EUF_VIPER_BACKEND").unwrap_or_else(|_| "auto".to_owned());
    if matches!(
        backend.as_str(),
        "auto" | "varisat" | "kissat" | "cadical" | "cadical-refine"
    ) {
        let finite_added = if matches!(backend.as_str(), "auto" | "cadical" | "cadical-refine")
            || env::var("EUF_VIPER_FINITE_DOMAIN").as_deref() == Ok("1")
        {
            let finite_start = Instant::now();
            let added = add_finite_domain_axioms_with_context(
                &mut cnf,
                arena,
                bool_problem,
                finite_context,
            );
            profile_phase("finite_domain", finite_start, added);
            added
        } else {
            0
        };
        let refinement_mode = selected_refinement_mode();
        let full_ackermann_setting = env::var("EUF_VIPER_FULL_ACKERMANN").ok();
        let full_ackermann_forced = force_full_ackermann(full_ackermann_setting.as_deref());
        if full_ackermann_forced {
            add_full_ackermann_completion(&mut cnf, arena);
        } else if !cnf.finite_equalities_complete
            && matches!(
                env::var("EUF_VIPER_CHORDAL_TRANSITIVITY").as_deref(),
                Ok("1" | "on")
            )
        {
            let fill_start = Instant::now();
            let max_fill_edges = env::var("EUF_VIPER_CHORDAL_MAX_FILL")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(1_000_000usize);
            let fill_edges =
                add_sparse_transitivity_fill(&mut cnf, arena.terms.len(), max_fill_edges);
            profile_phase(
                "chordal_transitivity_fill",
                fill_start,
                fill_edges.unwrap_or(usize::MAX),
            );
        }
        let eager_congruence = !full_ackermann_forced
            && use_eager_congruence_for_first_pass(finite_added, &cnf, arena);
        profile_measurement(
            "eager_congruence_first_pass",
            u128::from(eager_congruence),
            finite_added,
        );
        let auto_cadical_threshold = env::var("EUF_VIPER_AUTO_CADICAL_APP_THRESHOLD")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(1_000usize);
        let auto_uses_cadical = backend == "auto"
            && auto_prefers_cadical(arena.apps.len(), finite_added, auto_cadical_threshold);
        if backend == "auto" && auto_uses_cadical {
            if let Some(result) = solve_cadical_euf_once(
                &cnf,
                arena,
                bool_problem.true_term,
                bool_problem.false_term,
                eager_congruence,
            ) {
                return Some((result, cnf.var_count(), cnf.clauses.len(), 0, 1, 0));
            }
        }
        if backend == "kissat" || (backend == "auto" && !auto_uses_cadical) {
            let outcome = solve_kissat_euf_once(
                &cnf,
                arena,
                bool_problem.true_term,
                bool_problem.false_term,
                eager_congruence,
            );
            match outcome {
                EagerSolveOutcome::Solved(result) => {
                    return Some((result, cnf.var_count(), cnf.clauses.len(), 0, 1, 0));
                }
                EagerSolveOutcome::InvalidTheoryModel(conflict_count) => {
                    let mut completed_cnf = None;
                    let mut prior_sat_calls = 1;
                    if dynamic_full_ackermann_before_refinement(
                        full_ackermann_setting.as_deref(),
                        refinement_mode,
                        cnf.clauses.len(),
                        arena.apps.len(),
                        finite_added,
                    ) {
                        profile_measurement("invalid_model_dynamic_ackermann", 1, conflict_count);
                        let (completed, completed_outcome) =
                            solve_dynamic_full_ackermann_with_negated_root(
                                arena,
                                bool_problem,
                                &accepted_equality_facts,
                                root_cnf_options.direct_negated_root,
                            );
                        prior_sat_calls += 1;
                        match completed_outcome {
                            EagerSolveOutcome::Solved(result) => {
                                return Some((
                                    result,
                                    completed.var_count(),
                                    completed.clauses.len(),
                                    0,
                                    prior_sat_calls,
                                    0,
                                ));
                            }
                            EagerSolveOutcome::InvalidTheoryModel(_) => {
                                completed_cnf = Some(completed);
                            }
                            EagerSolveOutcome::Unavailable => {}
                        }
                    }
                    if use_cadical_refine_after_invalid_model() {
                        profile_measurement("invalid_model_cadical_refine", 1, 0);
                        let fallback_cnf = completed_cnf.as_ref().unwrap_or(&cnf);
                        if let Some((result, sat_calls, theory_lemmas)) = solve_cadical_euf_refining(
                            fallback_cnf,
                            arena,
                            bool_problem.true_term,
                            bool_problem.false_term,
                            refinement_mode,
                        ) {
                            return Some((
                                result,
                                fallback_cnf.var_count(),
                                fallback_cnf.clauses.len(),
                                0,
                                sat_calls + prior_sat_calls,
                                theory_lemmas,
                            ));
                        }
                    }
                }
                EagerSolveOutcome::Unavailable => {}
            }
        }
        if backend == "cadical" {
            if let Some(result) = solve_cadical_euf_once(
                &cnf,
                arena,
                bool_problem.true_term,
                bool_problem.false_term,
                eager_congruence,
            ) {
                return Some((result, cnf.var_count(), cnf.clauses.len(), 0, 1, 0));
            }
        }
        if backend == "cadical-refine" {
            if let Some((result, sat_calls, theory_lemmas)) = solve_cadical_euf_refining(
                &cnf,
                arena,
                bool_problem.true_term,
                bool_problem.false_term,
                refinement_mode,
            ) {
                return Some((
                    result,
                    cnf.var_count(),
                    cnf.clauses.len(),
                    0,
                    sat_calls,
                    theory_lemmas,
                ));
            }
        }
        let (result, sat_calls, theory_lemmas) =
            solve_varisat_euf(&cnf, arena, bool_problem.true_term, bool_problem.false_term);
        return Some((
            result,
            cnf.var_count(),
            cnf.clauses.len(),
            0,
            sat_calls
                + usize::from(matches!(
                    backend.as_str(),
                    "auto" | "kissat" | "cadical" | "cadical-refine"
                )),
            theory_lemmas,
        ));
    }
    let mut solver = DpllSolver::new(&cnf, arena, bool_problem.true_term, bool_problem.false_term);
    let search_result = solver.solve();
    let result = match search_result {
        CnfSearchResult::Sat => SolveResult::Sat,
        CnfSearchResult::Unsat => SolveResult::Unsat,
        CnfSearchResult::Limit => SolveResult::Unsupported(vec![format!(
            "DPLL(T) node limit reached after {} nodes",
            solver.nodes
        )]),
    };
    Some((
        result,
        cnf.var_count(),
        cnf.clauses.len(),
        solver.nodes,
        0,
        0,
    ))
}

fn congruence_closure(arena: &TermArena, uf: &mut UnionFind) -> (usize, usize) {
    let mut passes = 0;
    let mut total_merges = 0;
    loop {
        passes += 1;
        let mut changed = false;
        let mut sigs: HashMap<Signature, TermId> =
            HashMap::with_capacity_and_hasher(arena.apps.len() * 2, Default::default());
        for &term_id in &arena.apps {
            let term = &arena.terms[term_id];
            let mut arg_roots = Vec::with_capacity(term.args.len());
            for &arg in &term.args {
                arg_roots.push(uf.root_const(arg));
            }
            let sig = Signature {
                fun: term.fun,
                arg_roots,
            };
            if let Some(&prev) = sigs.get(&sig) {
                if uf.union(prev, term_id) {
                    changed = true;
                    total_merges += 1;
                }
            } else {
                sigs.insert(sig, term_id);
            }
        }
        if !changed {
            break;
        }
    }
    (passes, total_merges)
}

fn atom_text(sexp: &Sexp) -> Option<&str> {
    match sexp {
        Sexp::Atom(text) | Sexp::QuotedAtom(text) => Some(text.as_str()),
        Sexp::List(_) => None,
    }
}

fn syntax_atom_text(sexp: &Sexp) -> Option<&str> {
    match sexp {
        Sexp::Atom(text) => Some(text.as_str()),
        Sexp::QuotedAtom(_) | Sexp::List(_) => None,
    }
}

fn is_positive_or(sexp: &Sexp) -> bool {
    matches!(sexp, Sexp::List(items) if items.first().and_then(syntax_atom_text) == Some("or"))
}

fn is_equality_path_branch(expr: &BoolExpr) -> bool {
    matches!(
        expr,
        BoolExpr::And(children)
            if children.len() >= 2
                && children
                    .iter()
                    .all(|child| matches!(child, BoolExpr::Atom(BoolAtomKey::Eq(_, _))))
    )
}

fn should_preprocess_branch_intersections(expr: &BoolExpr) -> bool {
    let BoolExpr::And(children) = expr else {
        return false;
    };
    let has_disequality = children.iter().any(has_mandatory_disequality);
    let has_path_disjunction = children.iter().any(|child| {
        matches!(
            child,
            BoolExpr::Or(branches)
                if branches.len() >= 2 && branches.iter().all(is_equality_path_branch)
        )
    });
    has_disequality && has_path_disjunction
}

fn has_mandatory_disequality(expr: &BoolExpr) -> bool {
    match expr {
        BoolExpr::Not(inner) => {
            matches!(inner.as_ref(), BoolExpr::Atom(BoolAtomKey::Eq(_, _)))
        }
        BoolExpr::And(children) => children.iter().any(has_mandatory_disequality),
        _ => false,
    }
}

fn normalized_pair(a: TermId, b: TermId) -> (TermId, TermId) {
    if a <= b { (a, b) } else { (b, a) }
}

fn tokenize(input: &str) -> Result<Vec<Tok>, String> {
    let mut toks = Vec::new();
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        match b {
            b' ' | b'\n' | b'\r' | b'\t' => i += 1,
            b';' => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'(' => {
                toks.push(Tok::LParen);
                i += 1;
            }
            b')' => {
                toks.push(Tok::RParen);
                i += 1;
            }
            b'|' => {
                i += 1;
                let mut atom = String::new();
                let mut closed = false;
                while i < bytes.len() {
                    match bytes[i] {
                        b'\\' if i + 1 < bytes.len() => {
                            i += 1;
                            atom.push(bytes[i] as char);
                            i += 1;
                        }
                        b'|' => {
                            i += 1;
                            closed = true;
                            break;
                        }
                        c => {
                            atom.push(c as char);
                            i += 1;
                        }
                    }
                }
                if !closed {
                    return Err("unterminated quoted symbol".to_owned());
                }
                toks.push(Tok::QuotedAtom(atom));
            }
            b'"' => {
                let start = i;
                i += 1;
                while i < bytes.len() {
                    if bytes[i] == b'"' {
                        i += 1;
                        break;
                    }
                    if bytes[i] == b'\\' && i + 1 < bytes.len() {
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                toks.push(Tok::Atom(input[start..i].to_owned()));
            }
            _ => {
                let start = i;
                while i < bytes.len()
                    && !matches!(bytes[i], b' ' | b'\n' | b'\r' | b'\t' | b'(' | b')' | b';')
                {
                    i += 1;
                }
                toks.push(Tok::Atom(input[start..i].to_owned()));
            }
        }
    }
    Ok(toks)
}

fn parse_sexps(input: &str) -> Result<Vec<Sexp>, String> {
    let mut toks = tokenize(input)?;
    let mut pos = 0;
    let mut sexps = Vec::new();
    while pos < toks.len() {
        sexps.push(parse_one(&mut toks, &mut pos)?);
    }
    Ok(sexps)
}

fn parse_one(toks: &mut [Tok], pos: &mut usize) -> Result<Sexp, String> {
    if *pos >= toks.len() {
        return Err("unexpected end of token stream".to_owned());
    }
    let token = std::mem::replace(&mut toks[*pos], Tok::RParen);
    match token {
        Tok::Atom(text) => {
            *pos += 1;
            Ok(Sexp::Atom(text))
        }
        Tok::QuotedAtom(text) => {
            *pos += 1;
            Ok(Sexp::QuotedAtom(text))
        }
        Tok::RParen => Err("unexpected ')'".to_owned()),
        Tok::LParen => {
            *pos += 1;
            let mut items = Vec::new();
            while *pos < toks.len() && toks[*pos] != Tok::RParen {
                items.push(parse_one(toks, pos)?);
            }
            if *pos >= toks.len() {
                return Err("unclosed '('".to_owned());
            }
            *pos += 1;
            Ok(Sexp::List(items))
        }
    }
}

fn parse_problem(input: &str) -> Result<Problem, String> {
    parse_problem_with_scoped_let_mode(input, selected_scoped_let_mode()?)
}

fn parse_problem_with_scoped_let_mode(
    input: &str,
    scoped_let_mode: ScopedLetMode,
) -> Result<Problem, String> {
    parse_context_with_scoped_let_mode(input, scoped_let_mode).map(ParseCtx::finish)
}

fn parse_problem_with_scoped_let_mode_and_symbols(
    input: &str,
    scoped_let_mode: ScopedLetMode,
) -> Result<(Problem, Vec<String>), String> {
    parse_context_with_scoped_let_mode(input, scoped_let_mode)
        .map(ParseCtx::finish_with_symbol_names)
}

fn parse_context_with_scoped_let_mode(
    input: &str,
    scoped_let_mode: ScopedLetMode,
) -> Result<ParseCtx, String> {
    let bounded_let_count = bounded_lexical_let_count(input);
    let scoped_let_selected = scoped_let_selected(scoped_let_mode, bounded_let_count);
    profile_scoped_let(scoped_let_mode, bounded_let_count, scoped_let_selected);

    let sexps = parse_sexps(input)?;
    let mut ctx = ParseCtx::new(scoped_let_selected);
    ctx.preprocess_branch_intersections = sexps
        .iter()
        .filter(|sexp| {
            matches!(
                sexp,
                Sexp::List(items)
                    if items.first().and_then(syntax_atom_text) == Some("assert")
            )
        })
        .take(2)
        .count()
        == 1;
    for sexp in &sexps {
        ctx.parse_command(sexp)?;
    }
    Ok(ctx)
}

fn status_text(result: &SolveResult) -> &'static str {
    match result {
        SolveResult::Sat => "sat",
        SolveResult::Unsat => "unsat",
        SolveResult::Unsupported(_) => "unsupported",
    }
}

fn print_report(report: &SolveReport, elapsed: std::time::Duration, with_stats: bool) {
    println!("{}", status_text(&report.result));
    if let SolveResult::Unsupported(items) = &report.result {
        for item in items.iter().take(12) {
            eprintln!("unsupported: {item}");
        }
        if items.len() > 12 {
            eprintln!("unsupported: ... {} more", items.len() - 12);
        }
    }
    if with_stats {
        eprintln!("terms={}", report.stats.terms);
        eprintln!("apps={}", report.stats.apps);
        eprintln!("eqs={}", report.stats.eqs);
        eprintln!("diseqs={}", report.stats.diseqs);
        eprintln!("closure_passes={}", report.stats.closure_passes);
        eprintln!("congruence_merges={}", report.stats.congruence_merges);
        eprintln!("cnf_vars={}", report.stats.cnf_vars);
        eprintln!("cnf_clauses={}", report.stats.cnf_clauses);
        eprintln!("search_nodes={}", report.stats.search_nodes);
        eprintln!("sat_calls={}", report.stats.sat_calls);
        eprintln!("theory_lemmas={}", report.stats.theory_lemmas);
        eprintln!("elapsed_ns={}", elapsed.as_nanos());
    }
}

fn solve_file(path: &str, with_stats: bool) -> Result<i32, String> {
    let root_cnf_options = selected_root_cnf_options()?;
    solve_file_with_root_cnf_options(path, with_stats, root_cnf_options)
}

fn solve_file_with_root_cnf_options(
    path: &str,
    with_stats: bool,
    root_cnf_options: RootCnfOptions,
) -> Result<i32, String> {
    let input = fs::read_to_string(path).map_err(|e| format!("failed to read {path}: {e}"))?;
    let start = Instant::now();
    let parse_start = Instant::now();
    let problem = parse_problem(&input)?;
    profile_phase("parse", parse_start, input.len());
    let report = solve_problem_with_root_cnf_options(problem, root_cnf_options);
    let elapsed = start.elapsed();
    print_report(&report, elapsed, with_stats);
    Ok(match report.result {
        SolveResult::Unsupported(_) => 3,
        _ => 0,
    })
}

// Frozen depth-3 candidate emitted by scripts/bench/train_structural_router.py.
const ROUTER_MAX_PARENS: usize = 1_912;
const ROUTER_MAX_NOTS: usize = 7;
const ROUTER_MAX_DECLARATIONS: usize = 18;

fn count_byte_up_to(input: &[u8], byte: u8, limit: usize) -> usize {
    input
        .iter()
        .filter(|&&candidate| candidate == byte)
        .take(limit + 1)
        .count()
}

fn count_pattern_up_to(input: &[u8], pattern: &[u8], limit: usize) -> usize {
    input
        .windows(pattern.len())
        .filter(|window| *window == pattern)
        .take(limit + 1)
        .count()
}

fn structural_router_prefers_euf(input: &[u8]) -> bool {
    count_byte_up_to(input, b'(', ROUTER_MAX_PARENS) <= ROUTER_MAX_PARENS
        && count_pattern_up_to(input, b"(not", ROUTER_MAX_NOTS) <= ROUTER_MAX_NOTS
        && count_pattern_up_to(input, b"(declare-fun", ROUTER_MAX_DECLARATIONS)
            <= ROUTER_MAX_DECLARATIONS
}

fn portfolio_file(path: &str, yices: &str, with_stats: bool) -> Result<i32, String> {
    let root_cnf_options = selected_root_cnf_options()?;
    let input = fs::read(path).map_err(|e| format!("failed to read {path}: {e}"))?;
    let use_euf = structural_router_prefers_euf(&input);
    if env::var_os("EUF_VIPER_PORTFOLIO_TRACE").is_some() {
        eprintln!(
            "portfolio_route={}",
            if use_euf { "euf-viper" } else { "yices2" }
        );
    }
    if use_euf {
        return solve_file_with_root_cnf_options(path, with_stats, root_cnf_options);
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let error = Command::new(yices).arg(path).exec();
        Err(format!("failed to exec Yices fallback `{yices}`: {error}"))
    }
    #[cfg(not(unix))]
    {
        let status = Command::new(yices)
            .arg(path)
            .status()
            .map_err(|e| format!("failed to run Yices fallback `{yices}`: {e}"))?;
        Ok(status.code().unwrap_or(1))
    }
}

fn parse_portfolio_args(args: &[String]) -> Result<(&str, &str, bool), String> {
    let mut yices = None;
    let mut file = None;
    let mut with_stats = false;
    let mut index = 2;
    while index < args.len() {
        match args[index].as_str() {
            "--yices" => {
                yices = args.get(index + 1).map(String::as_str);
                if yices.is_none() {
                    return Err("--yices requires a value".to_owned());
                }
                index += 2;
            }
            "--stats" => {
                with_stats = true;
                index += 1;
            }
            option if option.starts_with("--") => {
                return Err(format!("unknown portfolio option `{option}`"));
            }
            path if file.is_none() => {
                file = Some(path);
                index += 1;
            }
            path => return Err(format!("unexpected portfolio argument `{path}`")),
        }
    }
    Ok((
        file.ok_or_else(|| "portfolio input file is required".to_owned())?,
        yices.ok_or_else(|| "--yices is required".to_owned())?,
        with_stats,
    ))
}

fn stats_file(path: &str) -> Result<i32, String> {
    let input = fs::read_to_string(path).map_err(|e| format!("failed to read {path}: {e}"))?;
    let problem = parse_problem(&input)?;
    println!("terms {}", problem.arena.terms.len());
    println!("apps {}", problem.arena.app_count());
    println!("eqs {}", problem.eqs.len());
    println!("diseqs {}", problem.diseqs.len());
    println!("unsupported {}", problem.unsupported.len());
    if let Some(bool_problem) = &problem.bool_problem {
        println!("bool_assertions {}", bool_problem.assertions.len());
        println!("bool_unsupported {}", bool_problem.unsupported.len());
        println!(
            "finite_analysis {}",
            finite_analysis::analyze(&problem.arena, bool_problem)
        );
        for item in bool_problem.unsupported.iter().take(12) {
            println!("bool_unsupported_reason {item}");
        }
    } else {
        println!("bool_assertions 0");
        println!("bool_unsupported 0");
    }
    println!("contradiction {}", problem.contradiction);
    Ok(0)
}

fn read_parse_check_input<R: Read>(path: &str, stdin: &mut R) -> Result<String, String> {
    if path != "-" {
        return fs::read_to_string(path).map_err(|e| format!("failed to read {path}: {e}"));
    }
    let mut input = String::new();
    stdin
        .read_to_string(&mut input)
        .map_err(|e| format!("failed to read parse-check stdin: {e}"))?;
    Ok(input)
}

fn parse_check_file(path: &str) -> Result<i32, String> {
    let input = if path == "-" {
        read_parse_check_input(path, &mut io::stdin().lock())?
    } else {
        read_parse_check_input(path, &mut io::empty())?
    };
    smt2_stream::check_typed_parity(&input, selected_scoped_let_mode()?)?;
    Ok(0)
}

fn gen_chain(n: usize, unsat: bool) -> String {
    let mut out = String::new();
    out.push_str("(set-logic QF_UF)\n");
    out.push_str("(declare-sort U 0)\n");
    out.push_str("(declare-fun f (U) U)\n");
    for i in 0..=n {
        out.push_str(&format!("(declare-fun x{i} () U)\n"));
    }
    if !unsat {
        out.push_str("(declare-fun fresh_sat_marker () U)\n");
    }
    out.push_str("(assert (and\n");
    for i in 0..n {
        out.push_str(&format!("  (= x{i} x{})\n", i + 1));
    }
    if unsat {
        out.push_str(&format!("  (distinct (f x0) (f x{n}))\n"));
    } else {
        out.push_str("  (distinct (f x0) (f fresh_sat_marker))\n");
    }
    out.push_str("))\n(check-sat)\n");
    out
}

fn gen_grid(width: usize, depth: usize) -> String {
    let mut out = String::new();
    out.push_str("(set-logic QF_UF)\n");
    out.push_str("(declare-sort U 0)\n");
    for d in 0..depth {
        out.push_str(&format!("(declare-fun f{d} (U) U)\n"));
    }
    for i in 0..width {
        out.push_str(&format!("(declare-fun a{i} () U)\n"));
        out.push_str(&format!("(declare-fun b{i} () U)\n"));
    }
    out.push_str("(assert (and\n");
    for i in 0..width {
        out.push_str(&format!("  (= a{i} b{i})\n"));
    }
    if width > 0 && depth > 0 {
        let left = nested_term("a0", depth);
        let right = nested_term("b0", depth);
        out.push_str(&format!("  (distinct {left} {right})\n"));
    }
    out.push_str("))\n(check-sat)\n");
    out
}

fn gen_diamond(branches: usize, depth: usize) -> String {
    let mut out = String::new();
    out.push_str("(set-logic QF_UF)\n");
    out.push_str("(declare-sort U 0)\n");
    out.push_str("(declare-fun x0 () U)\n");
    out.push_str("(declare-fun x1 () U)\n");
    for branch in 0..branches {
        for step in 0..depth {
            out.push_str(&format!("(declare-fun d_{branch}_{step} () U)\n"));
        }
    }
    out.push_str("(assert (and\n");
    out.push_str("  (or\n");
    for branch in 0..branches {
        out.push_str("    (and");
        if depth == 0 {
            out.push_str(" (= x0 x1)");
        } else {
            out.push_str(&format!(" (= x0 d_{branch}_0)"));
            for step in 1..depth {
                out.push_str(&format!(" (= d_{branch}_{} d_{branch}_{step})", step - 1));
            }
            out.push_str(&format!(" (= d_{branch}_{} x1)", depth - 1));
        }
        out.push_str(")\n");
    }
    out.push_str("  )\n");
    out.push_str("  (distinct x0 x1)\n");
    out.push_str("))\n(check-sat)\n");
    out
}

fn gen_pruned_or(branches: usize) -> String {
    let mut out = String::new();
    out.push_str("(set-logic QF_UF)\n");
    out.push_str("(declare-sort U 0)\n");
    for branch in 0..branches {
        out.push_str(&format!("(declare-fun a_{branch} () U)\n"));
        out.push_str(&format!("(declare-fun b_{branch} () U)\n"));
    }
    out.push_str("(assert (and\n");
    for branch in 0..branches {
        out.push_str(&format!("  (distinct a_{branch} b_{branch})\n"));
    }
    out.push_str("  (or\n");
    for branch in 0..branches {
        out.push_str(&format!("    (= a_{branch} b_{branch})\n"));
    }
    out.push_str("  )\n");
    out.push_str("))\n(check-sat)\n");
    out
}

fn nested_term(base: &str, depth: usize) -> String {
    let mut text = base.to_owned();
    for d in 0..depth {
        text = format!("(f{d} {text})");
    }
    text
}

fn gen_cmd(args: &[String]) -> Result<i32, String> {
    if args.len() < 2 {
        return Err("usage: euf-viper gen <chain|grid|diamond|pruned-or> ...".to_owned());
    }
    match args[1].as_str() {
        "chain" => {
            let n = parse_usize(args.get(2), "chain length")?;
            let unsat = !args.iter().any(|arg| arg == "--sat");
            print!("{}", gen_chain(n, unsat));
        }
        "grid" => {
            let width = parse_usize(args.get(2), "grid width")?;
            let depth = parse_usize(args.get(3), "grid depth")?;
            print!("{}", gen_grid(width, depth));
        }
        "diamond" => {
            let branches = parse_usize(args.get(2), "diamond branches")?;
            let depth = parse_usize(args.get(3), "diamond depth")?;
            print!("{}", gen_diamond(branches, depth));
        }
        "pruned-or" => {
            let branches = parse_usize(args.get(2), "branch count")?;
            print!("{}", gen_pruned_or(branches));
        }
        other => return Err(format!("unknown generator `{other}`")),
    }
    Ok(0)
}

fn bench_cmd(args: &[String]) -> Result<i32, String> {
    let root_cnf_options = selected_root_cnf_options()?;
    let cases = parse_flag_usize(args, "--cases", 20)?;
    let size = parse_flag_usize(args, "--size", 10_000)?;
    let mut total_terms = 0usize;
    let start_all = Instant::now();
    for i in 0..cases {
        let input = if i % 2 == 0 {
            gen_chain(size, true)
        } else {
            gen_grid(size.min(5_000), 8)
        };
        let start = Instant::now();
        let problem = parse_problem(&input)?;
        total_terms += problem.arena.terms.len();
        let report = solve_problem_with_root_cnf_options(problem, root_cnf_options);
        let elapsed = start.elapsed();
        println!(
            "case={i} result={} elapsed_ns={} terms={} apps={} passes={} merges={}",
            status_text(&report.result),
            elapsed.as_nanos(),
            report.stats.terms,
            report.stats.apps,
            report.stats.closure_passes,
            report.stats.congruence_merges
        );
        if !matches!(report.result, SolveResult::Unsat) {
            return Err(format!(
                "internal benchmark case {i} did not solve to unsat"
            ));
        }
    }
    eprintln!(
        "bench_total_cases={cases} total_terms={total_terms} wall_ns={}",
        start_all.elapsed().as_nanos()
    );
    Ok(0)
}

fn bench_or_cmd(args: &[String]) -> Result<i32, String> {
    let root_cnf_options = selected_root_cnf_options()?;
    let cases = parse_flag_usize(args, "--cases", 8)?;
    let branches = parse_flag_usize(args, "--branches", 512)?;
    let depth = parse_flag_usize(args, "--depth", 4)?;
    let mut total_terms = 0usize;
    let start_all = Instant::now();
    for i in 0..cases {
        let input = if i % 2 == 0 {
            gen_diamond(branches, depth)
        } else {
            gen_pruned_or(branches)
        };
        let start = Instant::now();
        let problem = parse_problem(&input)?;
        total_terms += problem.arena.terms.len();
        let report = solve_problem_with_root_cnf_options(problem, root_cnf_options);
        let elapsed = start.elapsed();
        println!(
            "or_case={i} kind={} result={} elapsed_ns={} terms={} eqs={} diseqs={} passes={} merges={}",
            if i % 2 == 0 { "diamond" } else { "pruned-or" },
            status_text(&report.result),
            elapsed.as_nanos(),
            report.stats.terms,
            report.stats.eqs,
            report.stats.diseqs,
            report.stats.closure_passes,
            report.stats.congruence_merges
        );
        if !matches!(report.result, SolveResult::Unsat) {
            return Err(format!("or benchmark case {i} did not solve to unsat"));
        }
    }
    eprintln!(
        "or_bench_total_cases={cases} branches={branches} depth={depth} total_terms={total_terms} wall_ns={}",
        start_all.elapsed().as_nanos()
    );
    Ok(0)
}

fn parse_flag_usize(args: &[String], flag: &str, default: usize) -> Result<usize, String> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == flag {
            let value = iter
                .next()
                .ok_or_else(|| format!("{flag} requires a value"))?;
            return value
                .parse::<usize>()
                .map_err(|e| format!("invalid value for {flag}: {e}"));
        }
    }
    Ok(default)
}

#[cfg(feature = "certificates")]
fn parse_required_flag<'a>(args: &'a [String], flag: &str) -> Result<&'a str, String> {
    let position = args
        .iter()
        .position(|argument| argument == flag)
        .ok_or_else(|| format!("{flag} is required"))?;
    args.get(position + 1)
        .map(String::as_str)
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn parse_usize(value: Option<&String>, label: &str) -> Result<usize, String> {
    let value = value.ok_or_else(|| format!("missing {label}"))?;
    value
        .parse::<usize>()
        .map_err(|e| format!("invalid {label}: {e}"))
}

#[cfg(not(feature = "certificates"))]
fn usage() -> &'static str {
    "usage:
  euf-viper solve [--stats] FILE
  euf-viper portfolio --yices PATH [--stats] FILE
  euf-viper stats FILE
  euf-viper parse-check FILE|-
  euf-viper gen chain N [--sat]
  euf-viper gen grid WIDTH DEPTH
  euf-viper gen diamond BRANCHES DEPTH
  euf-viper gen pruned-or BRANCHES
  euf-viper bench [--cases N] [--size N]
  euf-viper bench-or [--cases N] [--branches N] [--depth N]"
}

#[cfg(feature = "certificates")]
fn usage() -> &'static str {
    "usage:
  euf-viper solve [--stats] FILE
  euf-viper portfolio --yices PATH [--stats] FILE
  euf-viper stats FILE
  euf-viper parse-check FILE|-
  euf-viper dump-eager-cnf FILE --out PATH
  euf-viper solve-dimacs FILE
  euf-viper certify FILE --out-prefix PATH [--max-theory-rounds N]
  euf-viper gen chain N [--sat]
  euf-viper gen grid WIDTH DEPTH
  euf-viper gen diamond BRANCHES DEPTH
  euf-viper gen pruned-or BRANCHES
  euf-viper bench [--cases N] [--size N]
  euf-viper bench-or [--cases N] [--branches N] [--depth N]"
}

fn run() -> Result<i32, String> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        return Err(usage().to_owned());
    }
    match args[1].as_str() {
        "solve" => {
            let with_stats = args.iter().any(|arg| arg == "--stats");
            let file = args
                .iter()
                .skip(2)
                .find(|arg| !arg.starts_with("--"))
                .ok_or_else(|| usage().to_owned())?;
            solve_file(file, with_stats)
        }
        "portfolio" => {
            let (file, yices, with_stats) = parse_portfolio_args(&args)?;
            portfolio_file(file, yices, with_stats)
        }
        "stats" => {
            let file = args.get(2).ok_or_else(|| usage().to_owned())?;
            stats_file(file)
        }
        "parse-check" => {
            let file = args.get(2).ok_or_else(|| usage().to_owned())?;
            if args.len() != 3 {
                return Err("usage: euf-viper parse-check FILE|-".to_owned());
            }
            parse_check_file(file)
        }
        #[cfg(feature = "certificates")]
        "dump-eager-cnf" => {
            let file = args.get(2).ok_or_else(|| usage().to_owned())?;
            let output = parse_required_flag(&args[3..], "--out")?;
            dump_eager_cnf(file, output)
        }
        #[cfg(feature = "certificates")]
        "solve-dimacs" => {
            let file = args.get(2).ok_or_else(|| usage().to_owned())?;
            solve_dimacs_file(file)
        }
        #[cfg(feature = "certificates")]
        "certify" => {
            let file = args.get(2).ok_or_else(|| usage().to_owned())?;
            let prefix = parse_required_flag(&args[3..], "--out-prefix")?;
            let max_rounds = parse_flag_usize(&args[3..], "--max-theory-rounds", 100_000)?;
            certify_file(file, prefix, max_rounds)
        }
        "gen" => gen_cmd(&args[1..]),
        "bench" => bench_cmd(&args[1..]),
        "bench-or" => bench_or_cmd(&args[1..]),
        "--version" | "-V" => {
            println!("euf-viper {}", env!("CARGO_PKG_VERSION"));
            Ok(0)
        }
        "--help" | "-h" | "help" => {
            println!("{}", usage());
            Ok(0)
        }
        other => Err(format!("unknown command `{other}`\n{}", usage())),
    }
}

fn main() {
    match run() {
        Ok(code) => process::exit(code),
        Err(err) => {
            eprintln!("{err}");
            process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "certificates")]
    struct CertificateTestDirectory(PathBuf);

    #[cfg(feature = "certificates")]
    impl CertificateTestDirectory {
        fn new(label: &str) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};

            static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);
            let nonce = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = env::temp_dir().join(format!("euf-viper-{label}-{}-{nonce}", process::id()));
            fs::create_dir_all(&path).expect("create certificate test directory");
            Self(path)
        }

        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    #[cfg(feature = "certificates")]
    impl Drop for CertificateTestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(feature = "certificates")]
    fn certificate_base_and_seeds(
        source: &str,
    ) -> (Problem, CnfProblem, usize, CertificateTheorySeeds) {
        let problem = parse_problem(source).expect("parse certificate test problem");
        let bool_problem = problem
            .bool_problem
            .as_ref()
            .expect("certificate test Boolean problem");
        let mut cnf = CnfProblem::new();
        atomize_bool_data_terms(&mut cnf, bool_problem);
        for assertion in &bool_problem.assertions {
            cnf.add_assertion(assertion);
        }
        let base_count = cnf.clauses.len();
        let seeds = certificate_theory_seeds(&cnf, &problem.arena);
        (problem, cnf, base_count, seeds)
    }

    #[cfg(feature = "certificates")]
    fn read_test_dimacs(path: &Path) -> (usize, Vec<Vec<i32>>) {
        let text = fs::read_to_string(path).expect("read certificate DIMACS");
        let mut variables = None;
        let mut clauses = Vec::new();
        let mut clause = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('c') {
                continue;
            }
            if line.starts_with('p') {
                let fields = line.split_whitespace().collect::<Vec<_>>();
                assert_eq!(fields.len(), 4);
                assert_eq!(&fields[..2], &["p", "cnf"]);
                variables = Some(fields[2].parse().expect("DIMACS variable count"));
                continue;
            }
            for token in line.split_whitespace() {
                let literal = token.parse::<i32>().expect("DIMACS literal");
                if literal == 0 {
                    clauses.push(std::mem::take(&mut clause));
                } else {
                    clause.push(literal);
                }
            }
        }
        assert!(clause.is_empty(), "unterminated DIMACS clause");
        (variables.expect("DIMACS header"), clauses)
    }

    #[test]
    fn flat_clauses_preserve_empty_and_unit_clauses() {
        let mut clauses = FlatClauses::new();
        assert!(clauses.is_empty());
        assert_eq!(clauses.len(), 0);
        assert_eq!(clauses.iter().next(), None);
        assert_eq!(clauses.last(), None);
        assert_eq!(clauses.end_offsets, vec![0]);

        clauses.push(vec![17]);
        assert!(!clauses.is_empty());
        assert_eq!(clauses.len(), 1);
        assert_eq!(&clauses[0], &[17]);
        assert_eq!(clauses.last(), Some(&[17][..]));
        assert_eq!(clauses.end_offsets, vec![0, 1]);
    }

    #[test]
    fn flat_clauses_preserve_wide_clause_literal_order() {
        let wide = (1..=70_000).collect::<Vec<i32>>();
        let mut clauses = FlatClauses::new();
        clauses.push(wide.clone());

        assert_eq!(clauses.len(), 1);
        assert_eq!(&clauses[0], wide.as_slice());
        assert_eq!(clauses.end_offsets, vec![0, 70_000]);
    }

    #[test]
    fn flat_clauses_preserve_duplicates_and_repeated_empty_clauses() {
        let expected = vec![
            Vec::new(),
            Vec::new(),
            vec![4, 4, -2],
            vec![4, 4, -2],
            Vec::new(),
        ];
        let mut clauses = FlatClauses::new();
        clauses.extend(expected.clone());

        assert_eq!(clauses, expected);
        assert_eq!(clauses.clone(), clauses);
        assert_eq!(clauses.end_offsets, vec![0, 0, 0, 3, 6, 6]);
        assert_eq!(format!("{clauses:?}"), format!("{expected:?}"));
    }

    #[test]
    fn flat_clauses_keep_indexed_lookup_stable_across_growth() {
        let mut clauses = FlatClauses::new();
        clauses.push(vec![11, -12]);
        clauses.push(Vec::new());
        clauses.push(vec![13]);

        for index in 0..2_048 {
            clauses.push(vec![index, -(index + 1)]);
        }

        assert_eq!(&clauses[0], &[11, -12]);
        assert_eq!(&clauses[1], &[] as &[i32]);
        assert_eq!(&clauses[2], &[13]);
        assert_eq!(&clauses[3], &[0, -1]);
        assert_eq!(&clauses[2_050], &[2_047, -2_048]);
    }

    #[test]
    fn flat_clauses_iterate_sequentially_in_exact_order() {
        let expected = vec![vec![3, 1, 3], Vec::new(), vec![-7], vec![9, 8]];
        let mut clauses = FlatClauses::new();
        clauses.extend(expected.clone());

        let mut iterator = clauses.iter();
        assert_eq!(iterator.len(), expected.len());
        assert_eq!(iterator.next(), Some(expected[0].as_slice()));
        assert_eq!(iterator.next(), Some(expected[1].as_slice()));
        assert_eq!(iterator.next(), Some(expected[2].as_slice()));
        assert_eq!(iterator.next(), Some(expected[3].as_slice()));
        assert_eq!(iterator.next(), None);
    }

    #[test]
    fn flat_clauses_grow_across_literal_and_offset_reallocations() {
        let expected = (0..4_096)
            .map(|clause_id| {
                (0..=clause_id % 19)
                    .map(|literal| clause_id * 100 + literal)
                    .collect::<Vec<i32>>()
            })
            .collect::<Vec<_>>();
        let expected_literal_count = expected.iter().map(Vec::len).sum::<usize>();
        let mut clauses = FlatClauses::new();
        clauses.extend(expected.clone());

        assert_eq!(clauses, expected);
        assert_eq!(clauses.literals.len(), expected_literal_count);
        assert_eq!(clauses.end_offsets.len(), expected.len() + 1);
        assert_eq!(clauses.end_offsets[0], 0);
        assert_eq!(
            clauses.end_offsets.last().copied(),
            Some(expected_literal_count as u32)
        );
    }

    #[test]
    fn flat_clauses_reject_offset_overflow_atomically() {
        let mut clauses = FlatClauses::new();
        clauses.push(vec![1, -2]);
        let before = clauses.clone();

        assert_eq!(
            clauses.try_push_with_max_end_offset(vec![3], 2),
            Err(FlatClauseStoreError::LiteralCapacityExceeded)
        );
        assert_eq!(clauses, before);
        assert_eq!(
            FlatClauses::checked_end_offset(u32::MAX as usize, 1, u32::MAX),
            Err(FlatClauseStoreError::LiteralCapacityExceeded)
        );
    }

    #[cfg(feature = "certificates")]
    #[test]
    fn flat_clauses_keep_dimacs_bytes_exact() {
        let mut cnf = CnfProblem::new();
        for _ in 0..3 {
            cnf.new_var(None);
        }
        cnf.clauses.push(vec![3, -1, 3]);
        cnf.clauses.push(Vec::new());
        cnf.clauses.push(vec![2]);
        cnf.clauses.push(Vec::new());

        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time after Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "euf-viper-flat-clauses-{}-{unique}.cnf",
            process::id()
        ));
        write_dimacs(&path, &cnf).expect("write flat clause DIMACS");
        let bytes = fs::read(&path).expect("read flat clause DIMACS");
        fs::remove_file(&path).expect("remove flat clause DIMACS");

        assert_eq!(bytes, b"p cnf 3 4\n3 -1 3 0\n0\n2 0\n0\n");
    }

    #[cfg(feature = "certificates")]
    const MIXED_CERTIFICATE_SOURCE: &str = r#"
        (set-logic QF_UF)
        (declare-sort U 0)
        (declare-fun a () U)
        (declare-fun b () U)
        (declare-fun c () U)
        (declare-fun d () U)
        (declare-fun e () U)
        (declare-fun g () U)
        (declare-fun h () U)
        (declare-fun f (U) U)
        (assert (= a b))
        (assert (= b c))
        (assert (= a c))
        (assert (= (f a) (f b)))
        (assert (= d e))
        (assert (= e g))
        (assert (= g h))
        (assert (distinct d h))
        (check-sat)
    "#;

    #[cfg(feature = "certificates")]
    #[test]
    fn certificate_seeds_preserve_base_and_append_only_ordered_pure_euf_lemmas() {
        let (problem, mut cnf, base_count, seeds) =
            certificate_base_and_seeds(MIXED_CERTIFICATE_SOURCE);
        let base_clauses = cnf.clauses.iter().map(<[_]>::to_vec).collect::<Vec<_>>();
        let variable_count = cnf.var_count();

        assert_eq!(seeds.transitivity.len(), 3);
        assert_eq!(seeds.congruence.len(), 1);
        assert!(seeds.transitivity.windows(2).all(|pair| pair[0] <= pair[1]));
        assert!(seeds.congruence.windows(2).all(|pair| pair[0] <= pair[1]));
        assert_eq!(
            certificate_theory_seeds(
                &cnf,
                &parse_problem(MIXED_CERTIFICATE_SOURCE).unwrap().arena
            ),
            seeds
        );

        for clause in seeds.transitivity.iter().chain(&seeds.congruence) {
            assert_eq!(
                certificate_theory_clause_key(&cnf, clause).unwrap().len(),
                clause.len()
            );
            assert!(clause.iter().all(|literal| matches!(
                cnf.var_atoms.get(literal.unsigned_abs() as usize),
                Some(Some(BoolAtomKey::Eq(_, _) | BoolAtomKey::BoolTerm(_)))
            )));

            let mut falsifying_assignment = vec![-1i8; cnf.var_count() + 1];
            falsifying_assignment[0] = 0;
            for &literal in clause {
                falsifying_assignment[literal.unsigned_abs() as usize] =
                    if literal > 0 { -1 } else { 1 };
            }
            let bool_problem = problem.bool_problem.as_ref().unwrap();
            assert!(
                !theory_conflict_clauses(
                    &cnf,
                    &problem.arena,
                    bool_problem.true_term,
                    bool_problem.false_term,
                    &falsifying_assignment,
                )
                .unwrap()
                .is_empty()
            );
        }

        let transitivity = seeds.transitivity.clone();
        let congruence = seeds.congruence.clone();
        cnf.clauses.extend(seeds.transitivity);
        cnf.clauses.extend(seeds.congruence);
        assert_eq!(cnf.var_count(), variable_count);
        assert!(!cnf.finite_equalities_complete);
        assert!(!cnf.finite_predicate_congruence_complete);
        assert_eq!(base_count, base_clauses.len());
        assert_eq!(
            cnf.clauses
                .iter()
                .take(base_count)
                .map(<[_]>::to_vec)
                .collect::<Vec<_>>(),
            base_clauses
        );
        assert_eq!(
            cnf.clauses
                .iter()
                .skip(base_count)
                .take(transitivity.len())
                .map(<[_]>::to_vec)
                .collect::<Vec<_>>(),
            transitivity
        );
        assert_eq!(
            cnf.clauses
                .iter()
                .skip(base_count + transitivity.len())
                .map(<[_]>::to_vec)
                .collect::<Vec<_>>(),
            congruence
        );
    }

    #[cfg(feature = "certificates")]
    #[test]
    fn certificate_clause_dedup_normalizes_seed_and_dynamic_literal_order() {
        let mut cnf = CnfProblem::new();
        let left = cnf.atom_lit(BoolAtomKey::Eq(0, 1));
        let right = cnf.atom_lit(BoolAtomKey::Eq(2, 3));
        let key = certificate_theory_clause_key(&cnf, &[-left, right]).unwrap();
        assert_eq!(
            certificate_theory_clause_key(&cnf, &[right, -left, right]).unwrap(),
            key
        );

        let mut known = HashSet::default();
        assert!(known.insert(key.clone()));
        assert!(!known.insert(certificate_theory_clause_key(&cnf, &[right, -left]).unwrap()));

        let auxiliary = cnf.new_var(None);
        assert!(certificate_theory_clause_key(&cnf, &[auxiliary]).is_err());
        assert!(certificate_theory_clause_key(&cnf, &[0]).is_err());
        assert!(certificate_theory_clause_key(&cnf, &[left, -left]).is_err());
        assert!(certificate_theory_clause_key(&cnf, &[]).is_err());
    }

    #[cfg(feature = "certificates")]
    #[test]
    fn sat_certificate_with_eager_seeds_is_sound_and_deterministic() {
        let source = r#"
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun a () U)
            (declare-fun b () U)
            (declare-fun f (U) U)
            (assert (= a b))
            (assert (= (f a) (f b)))
            (check-sat)
        "#;
        let directory = CertificateTestDirectory::new("sat-certificate-seeds");
        let source_path = directory.path("input.smt2");
        let first_prefix = directory.path("first");
        let second_prefix = directory.path("second");
        fs::write(&source_path, source).expect("write SAT certificate source");
        certify_file(
            source_path.to_str().unwrap(),
            first_prefix.to_str().unwrap(),
            8,
        )
        .expect("first SAT certification");
        certify_file(
            source_path.to_str().unwrap(),
            second_prefix.to_str().unwrap(),
            8,
        )
        .expect("second SAT certification");

        let first_manifest = fs::read(path_with_suffix(&first_prefix, ".euf.json"))
            .expect("read first SAT manifest");
        let second_manifest = fs::read(path_with_suffix(&second_prefix, ".euf.json"))
            .expect("read second SAT manifest");
        assert_eq!(first_manifest, second_manifest);
        assert!(!path_with_suffix(&first_prefix, ".cnf").exists());
        assert!(!path_with_suffix(&first_prefix, ".drat").exists());

        let manifest: serde_json::Value =
            serde_json::from_slice(&first_manifest).expect("parse SAT manifest");
        assert_eq!(manifest["result"], "sat");
        assert_eq!(manifest["theory_conflicts"], 0);

        let (problem, mut cnf, base_count, seeds) = certificate_base_and_seeds(source);
        assert_eq!(seeds.transitivity.len(), 0);
        assert_eq!(seeds.congruence.len(), 1);
        cnf.clauses.extend(seeds.transitivity);
        cnf.clauses.extend(seeds.congruence);
        assert_eq!(base_count + 1, cnf.clauses.len());
        let mut assignment = vec![0i8; cnf.var_count() + 1];
        for value in manifest["assignment"].as_array().unwrap() {
            let literal = value.as_i64().unwrap() as i32;
            let variable = literal.unsigned_abs() as usize;
            assert!((1..assignment.len()).contains(&variable));
            assert_eq!(assignment[variable], 0);
            assignment[variable] = if literal > 0 { 1 } else { -1 };
        }
        assert!(complete_cnf_assignment(&cnf, &mut assignment));
        let bool_problem = problem.bool_problem.as_ref().unwrap();
        assert!(
            theory_conflict_clauses(
                &cnf,
                &problem.arena,
                bool_problem.true_term,
                bool_problem.false_term,
                &assignment,
            )
            .unwrap()
            .is_empty()
        );
    }

    #[cfg(feature = "certificates")]
    #[test]
    fn unsat_certificate_orders_seeds_and_reports_dynamic_manifest_counts() {
        let directory = CertificateTestDirectory::new("unsat-certificate-seeds");
        let source_path = directory.path("input.smt2");
        let prefix = directory.path("certificate");
        fs::write(&source_path, MIXED_CERTIFICATE_SOURCE).expect("write UNSAT certificate source");
        certify_file(source_path.to_str().unwrap(), prefix.to_str().unwrap(), 8)
            .expect("UNSAT certification");

        let manifest: serde_json::Value = serde_json::from_slice(
            &fs::read(path_with_suffix(&prefix, ".euf.json"))
                .expect("read UNSAT certificate manifest"),
        )
        .expect("parse UNSAT certificate manifest");
        let (problem, cnf, base_count, seeds) =
            certificate_base_and_seeds(MIXED_CERTIFICATE_SOURCE);
        let (variables, clauses) = read_test_dimacs(&path_with_suffix(&prefix, ".cnf"));
        let base_clauses = cnf.clauses.iter().map(<[_]>::to_vec).collect::<Vec<_>>();

        assert_eq!(manifest["result"], "unsat");
        assert_eq!(manifest["finite_domain_axioms"], 0);
        assert_eq!(manifest["clauses"]["base"], base_count as u64);
        assert_eq!(
            manifest["clauses"]["transitivity"],
            seeds.transitivity.len() as u64
        );
        assert_eq!(
            manifest["clauses"]["congruence"],
            seeds.congruence.len() as u64
        );
        assert_eq!(manifest["clauses"]["theory_conflicts"], 1);
        assert_eq!(manifest["clauses"]["total"], clauses.len() as u64);
        assert_eq!(variables, cnf.var_count());
        assert_eq!(&clauses[..base_count], base_clauses.as_slice());
        let transitivity_end = base_count + seeds.transitivity.len();
        assert_eq!(
            &clauses[base_count..transitivity_end],
            seeds.transitivity.as_slice()
        );
        let congruence_end = transitivity_end + seeds.congruence.len();
        assert_eq!(
            &clauses[transitivity_end..congruence_end],
            seeds.congruence.as_slice()
        );
        assert_eq!(clauses.len(), congruence_end + 1);
        assert!(certificate_theory_clause_key(&cnf, &clauses[congruence_end]).is_ok());
        assert_eq!(
            clauses.len(),
            base_count
                + seeds.transitivity.len()
                + seeds.congruence.len()
                + manifest["clauses"]["theory_conflicts"].as_u64().unwrap() as usize
        );
        assert!(path_with_suffix(&prefix, ".drat").exists());
        assert_eq!(problem.bool_problem.as_ref().unwrap().unsupported.len(), 0);
    }

    #[test]
    fn structural_router_uses_only_bounded_lexical_features() {
        assert!(structural_router_prefers_euf(
            b"(set-logic QF_UF) (declare-fun a () Bool) (assert a)"
        ));
        assert!(!structural_router_prefers_euf(
            "(declare-fun a () Bool)".repeat(19).as_bytes()
        ));
        assert!(!structural_router_prefers_euf(
            "(not true)".repeat(8).as_bytes()
        ));
        assert!(!structural_router_prefers_euf("(".repeat(1_913).as_bytes()));
    }

    #[test]
    fn parses_explicit_portfolio_arguments() {
        let args = [
            "euf-viper".to_owned(),
            "portfolio".to_owned(),
            "--yices".to_owned(),
            "/solver/yices-smt2".to_owned(),
            "--stats".to_owned(),
            "input.smt2".to_owned(),
        ];
        assert_eq!(
            parse_portfolio_args(&args).unwrap(),
            ("input.smt2", "/solver/yices-smt2", true)
        );
    }

    #[test]
    fn direct_root_cnf_setting_is_strict_and_defaults_on() {
        assert_eq!(parse_zero_one_setting(DIRECT_ROOT_CNF_ENV, None), Ok(true));
        assert_eq!(
            parse_zero_one_setting(DIRECT_ROOT_CNF_ENV, Some("0")),
            Ok(false)
        );
        assert_eq!(
            parse_zero_one_setting(DIRECT_ROOT_CNF_ENV, Some("1")),
            Ok(true)
        );
        assert_eq!(
            parse_zero_one_setting(DIRECT_ROOT_CNF_ENV, Some("true")),
            Err(format!("{DIRECT_ROOT_CNF_ENV} must be 0 or 1"))
        );
        assert!(parse_zero_one_setting(DIRECT_ROOT_CNF_ENV, Some(" 1")).is_err());
    }

    #[test]
    fn direct_negated_root_setting_is_strict_and_defaults_off() {
        assert_eq!(
            parse_zero_one_setting_with_default(DIRECT_NEGATED_ROOT_ENV, None, false),
            Ok(false)
        );
        assert_eq!(
            parse_zero_one_setting_with_default(DIRECT_NEGATED_ROOT_ENV, Some("0"), false),
            Ok(false)
        );
        assert_eq!(
            parse_zero_one_setting_with_default(DIRECT_NEGATED_ROOT_ENV, Some("1"), false),
            Ok(true)
        );
        for invalid in [
            "", "true", "false", "on", "off", "2", "-1", "01", " 1", "1 ",
        ] {
            assert_eq!(
                parse_zero_one_setting_with_default(DIRECT_NEGATED_ROOT_ENV, Some(invalid), false,),
                Err(format!("{DIRECT_NEGATED_ROOT_ENV} must be 0 or 1"))
            );
        }
        assert_eq!(
            RootCnfOptions::existing_behavior(true),
            RootCnfOptions {
                direct_root_cnf: true,
                direct_negated_root: false,
            }
        );
    }

    #[test]
    fn scoped_let_mode_is_strict_and_defaults_auto() {
        assert_eq!(parse_scoped_let_mode(None), Ok(ScopedLetMode::Auto));
        assert_eq!(parse_scoped_let_mode(Some("off")), Ok(ScopedLetMode::Off));
        assert_eq!(parse_scoped_let_mode(Some("auto")), Ok(ScopedLetMode::Auto));
        assert_eq!(parse_scoped_let_mode(Some("on")), Ok(ScopedLetMode::On));

        // Invalid values are clear configuration errors, matching strict local settings.
        assert_eq!(
            parse_scoped_let_mode(Some("true")),
            Err(format!("{SCOPED_LET_ENV} must be off, auto, or on"))
        );
        assert!(parse_scoped_let_mode(Some(" on")).is_err());
    }

    #[test]
    fn scoped_let_auto_selection_has_an_exact_bounded_threshold() {
        let below = "(let ".repeat(SCOPED_LET_AUTO_THRESHOLD - 1);
        let at = "(let ".repeat(SCOPED_LET_AUTO_THRESHOLD);
        let above = "(let ".repeat(SCOPED_LET_AUTO_THRESHOLD + 1);

        assert_eq!(
            bounded_lexical_let_count(&below),
            SCOPED_LET_AUTO_THRESHOLD - 1
        );
        assert_eq!(bounded_lexical_let_count(&at), SCOPED_LET_AUTO_THRESHOLD);
        assert_eq!(bounded_lexical_let_count(&above), SCOPED_LET_AUTO_THRESHOLD);
        assert!(!scoped_let_selected(
            ScopedLetMode::Auto,
            bounded_lexical_let_count(&below)
        ));
        assert!(scoped_let_selected(
            ScopedLetMode::Auto,
            bounded_lexical_let_count(&at)
        ));
        assert!(!scoped_let_selected(
            ScopedLetMode::Off,
            SCOPED_LET_AUTO_THRESHOLD
        ));
        assert!(scoped_let_selected(ScopedLetMode::On, 0));
    }

    #[test]
    fn equality_abstraction_mode_defaults_off_and_is_conservative_on_unknown_values() {
        assert_eq!(parse_eq_abstraction_mode(None), EqAbstractionMode::Off);
        assert_eq!(
            parse_eq_abstraction_mode(Some("off")),
            EqAbstractionMode::Off
        );
        assert_eq!(
            parse_eq_abstraction_mode(Some("shadow")),
            EqAbstractionMode::Shadow
        );
        assert_eq!(
            parse_eq_abstraction_mode(Some("facts")),
            EqAbstractionMode::Facts
        );
        assert_eq!(
            parse_eq_abstraction_mode(Some("guarded-facts")),
            EqAbstractionMode::GuardedFacts
        );
        assert_eq!(
            parse_eq_abstraction_mode(Some("on")),
            EqAbstractionMode::Off
        );
        assert_eq!(
            parse_eq_abstraction_mode(Some(" guarded-facts")),
            EqAbstractionMode::Off
        );
        assert_eq!(
            parse_eq_abstraction_mode(Some("GUARDED-FACTS")),
            EqAbstractionMode::Off
        );
    }

    #[test]
    fn equality_abstraction_fact_settings_are_strict_and_bounded_by_default() {
        assert!(!parse_eq_abstraction_fresh(None));
        assert!(!parse_eq_abstraction_fresh(Some("0")));
        assert!(parse_eq_abstraction_fresh(Some("1")));
        assert!(!parse_eq_abstraction_fresh(Some("01")));
        assert!(!parse_eq_abstraction_fresh(Some("on")));

        assert_eq!(
            parse_eq_abstraction_quota(None, DEFAULT_EQ_ABSTRACTION_MAX_FACTS),
            DEFAULT_EQ_ABSTRACTION_MAX_FACTS
        );
        assert_eq!(parse_eq_abstraction_quota(Some("0"), 17), 0);
        assert_eq!(parse_eq_abstraction_quota(Some("23"), 17), 23);
        assert_eq!(parse_eq_abstraction_quota(Some(" 23"), 17), 17);
        assert_eq!(parse_eq_abstraction_quota(Some("+23"), 17), 17);
        assert_eq!(parse_eq_abstraction_quota(Some("invalid"), 17), 17);
        assert_eq!(
            EqAbstractionFactConfig::default(),
            EqAbstractionFactConfig {
                allow_fresh: false,
                max_facts: 4_096,
                max_fresh_facts: 256,
            }
        );

        let guarded = eq_abstraction_fact_config_for_mode(
            EqAbstractionMode::GuardedFacts,
            EqAbstractionFactConfig {
                allow_fresh: true,
                max_facts: 19,
                max_fresh_facts: 17,
            },
        );
        assert_eq!(
            guarded,
            EqAbstractionFactConfig {
                allow_fresh: false,
                max_facts: 19,
                max_fresh_facts: 17,
            }
        );
        assert!(
            eq_abstraction_fact_config_for_mode(
                EqAbstractionMode::Facts,
                EqAbstractionFactConfig {
                    allow_fresh: true,
                    ..EqAbstractionFactConfig::default()
                }
            )
            .allow_fresh
        );
    }

    #[test]
    fn equality_abstraction_suppresses_existing_positive_units() {
        let mut cnf = CnfProblem::new();
        let equality = cnf.atom_lit(BoolAtomKey::Eq(2, 7));
        cnf.clauses.push(vec![equality]);
        let clauses_before = cnf.clauses.clone();
        let vars_before = cnf.var_count();

        let integration = integrate_equality_abstraction_facts(
            &mut cnf,
            &[(7, 2)],
            EqAbstractionFactConfig::default(),
        );

        assert_eq!(integration.duplicate_units, 1);
        assert_eq!(integration.accepted_existing_facts, 0);
        assert_eq!(integration.accepted_fresh_facts, 0);
        assert!(integration.accepted_edges.is_empty());
        assert_eq!(integration.rollback_reason, None);
        assert_eq!(cnf.clauses, clauses_before);
        assert_eq!(cnf.var_count(), vars_before);
    }

    #[test]
    fn equality_abstraction_strengthens_a_materialized_equality_atom() {
        let mut cnf = CnfProblem::new();
        let equality = cnf.atom_lit(BoolAtomKey::Eq(2, 7));
        let guard = cnf.atom_lit(BoolAtomKey::BoolTerm(9));
        cnf.clauses.push(vec![-guard, equality]);
        let clauses_before = cnf.clauses.len();
        let vars_before = cnf.var_count();

        let integration = integrate_equality_abstraction_facts(
            &mut cnf,
            &[(7, 2)],
            EqAbstractionFactConfig::default(),
        );

        assert_eq!(integration.duplicate_units, 0);
        assert_eq!(integration.accepted_existing_facts, 1);
        assert_eq!(integration.accepted_fresh_facts, 0);
        assert_eq!(integration.accepted_edges, vec![(2, 7)]);
        assert_eq!(cnf.clauses.len(), clauses_before + 1);
        assert_eq!(cnf.clauses.last(), Some(&[equality][..]));
        assert_eq!(cnf.var_count(), vars_before);
    }

    #[test]
    fn equality_abstraction_fresh_atoms_require_exact_opt_in() {
        let mut default_cnf = CnfProblem::new();
        let default_integration = integrate_equality_abstraction_facts(
            &mut default_cnf,
            &[(7, 2)],
            EqAbstractionFactConfig::default(),
        );
        assert_eq!(default_integration.accepted_fresh_facts, 0);
        assert!(default_integration.accepted_edges.is_empty());
        assert_eq!(default_cnf.var_count(), 0);
        assert!(default_cnf.clauses.is_empty());

        let mut opted_in_cnf = CnfProblem::new();
        let opted_in = integrate_equality_abstraction_facts(
            &mut opted_in_cnf,
            &[(7, 2)],
            EqAbstractionFactConfig {
                allow_fresh: true,
                ..EqAbstractionFactConfig::default()
            },
        );
        let equality = opted_in_cnf.atom_vars[&BoolAtomKey::Eq(2, 7)];
        assert_eq!(opted_in.accepted_existing_facts, 0);
        assert_eq!(opted_in.accepted_fresh_facts, 1);
        assert_eq!(opted_in.accepted_edges, vec![(2, 7)]);
        assert_eq!(opted_in_cnf.var_count(), 1);
        assert_eq!(opted_in_cnf.clauses, vec![vec![equality]]);
    }

    #[test]
    fn equality_abstraction_total_cap_rolls_back_all_selected_facts() {
        let mut cnf = CnfProblem::new();
        let first = cnf.atom_lit(BoolAtomKey::Eq(0, 1));
        let second = cnf.atom_lit(BoolAtomKey::Eq(2, 3));
        cnf.clauses.push(vec![first, second]);
        let clauses_before = cnf.clauses.clone();
        let vars_before = cnf.var_count();

        let integration = integrate_equality_abstraction_facts(
            &mut cnf,
            &[(0, 1), (2, 3)],
            EqAbstractionFactConfig {
                max_facts: 1,
                ..EqAbstractionFactConfig::default()
            },
        );

        assert_eq!(
            integration.rollback_reason,
            Some(EqAbstractionIntegrationRollbackReason::MaxFacts)
        );
        assert_eq!(integration.rollback_count, 2);
        assert_eq!(integration.accepted_existing_facts, 0);
        assert!(integration.accepted_edges.is_empty());
        assert_eq!(cnf.clauses, clauses_before);
        assert_eq!(cnf.var_count(), vars_before);
    }

    #[test]
    fn guarded_equality_abstraction_preserves_total_quota_rollback() {
        let mut cnf = CnfProblem::new();
        let first = cnf.atom_lit(BoolAtomKey::Eq(0, 1));
        let second = cnf.atom_lit(BoolAtomKey::Eq(2, 3));
        cnf.clauses.push(vec![first, second]);
        let clauses_before = cnf.clauses.clone();

        let integration = integrate_equality_abstraction_facts(
            &mut cnf,
            &[(0, 1), (2, 3)],
            eq_abstraction_fact_config_for_mode(
                EqAbstractionMode::GuardedFacts,
                EqAbstractionFactConfig {
                    allow_fresh: true,
                    max_facts: 1,
                    max_fresh_facts: 0,
                },
            ),
        );

        assert_eq!(
            integration.rollback_reason,
            Some(EqAbstractionIntegrationRollbackReason::MaxFacts)
        );
        assert_eq!(integration.rollback_count, 2);
        assert!(integration.accepted_edges.is_empty());
        assert_eq!(cnf.clauses, clauses_before);
    }

    #[test]
    fn equality_abstraction_fresh_cap_rolls_back_without_materializing_atoms() {
        let mut cnf = CnfProblem::new();
        let existing = cnf.atom_lit(BoolAtomKey::Eq(0, 1));
        let guard = cnf.atom_lit(BoolAtomKey::BoolTerm(6));
        cnf.clauses.push(vec![existing, guard]);
        let clauses_before = cnf.clauses.clone();
        let vars_before = cnf.var_count();

        let integration = integrate_equality_abstraction_facts(
            &mut cnf,
            &[(0, 1), (2, 3), (4, 5)],
            EqAbstractionFactConfig {
                allow_fresh: true,
                max_facts: 3,
                max_fresh_facts: 1,
            },
        );

        assert_eq!(
            integration.rollback_reason,
            Some(EqAbstractionIntegrationRollbackReason::MaxFreshFacts)
        );
        assert_eq!(integration.rollback_count, 2);
        assert_eq!(integration.accepted_existing_facts, 0);
        assert_eq!(integration.accepted_fresh_facts, 0);
        assert!(integration.accepted_edges.is_empty());
        assert_eq!(cnf.clauses, clauses_before);
        assert_eq!(cnf.var_count(), vars_before);
        assert!(!cnf.atom_vars.contains_key(&BoolAtomKey::Eq(2, 3)));
        assert!(!cnf.atom_vars.contains_key(&BoolAtomKey::Eq(4, 5)));
    }

    fn cnf_is_satisfiable(cnf: &CnfProblem) -> bool {
        let mut solver = VarisatSolver::new();
        for clause in &cnf.clauses {
            solver.add_clause(
                &clause
                    .iter()
                    .map(|literal| Lit::from_dimacs(*literal as isize))
                    .collect::<Vec<_>>(),
            );
        }
        solver.solve().expect("Varisat should solve test CNF")
    }

    fn assertion_is_satisfiable(
        expression: &BoolExpr,
        direct_root_cnf: bool,
        atom_assignment: &[bool],
    ) -> bool {
        assertion_is_satisfiable_with_root_options(
            expression,
            RootCnfOptions::existing_behavior(direct_root_cnf),
            atom_assignment,
        )
    }

    fn assertion_is_satisfiable_with_root_options(
        expression: &BoolExpr,
        root_cnf_options: RootCnfOptions,
        atom_assignment: &[bool],
    ) -> bool {
        let mut cnf = CnfProblem::new();
        if root_cnf_options.direct_root_cnf {
            cnf.add_direct_assertion_with_negated_root(
                expression,
                root_cnf_options.direct_negated_root,
            );
        } else {
            cnf.add_assertion(expression);
        }
        for (term, value) in atom_assignment.iter().copied().enumerate() {
            let literal = cnf.atom_lit(BoolAtomKey::BoolTerm(term));
            cnf.clauses
                .push(vec![if value { literal } else { -literal }]);
        }
        cnf_is_satisfiable(&cnf)
    }

    fn assert_root_encodings_equivalent(expression: &BoolExpr, atom_count: usize) {
        for assignment_bits in 0..(1usize << atom_count) {
            let assignment = (0..atom_count)
                .map(|bit| assignment_bits & (1 << bit) != 0)
                .collect::<Vec<_>>();
            assert_eq!(
                assertion_is_satisfiable(expression, true, &assignment),
                assertion_is_satisfiable(expression, false, &assignment),
                "root encodings differ for {expression:?} under {assignment:?}"
            );
        }
    }

    fn evaluate_bool_expr(expression: &BoolExpr, atom_assignment: &[bool]) -> bool {
        match expression {
            BoolExpr::Const(value) => *value,
            BoolExpr::Atom(BoolAtomKey::BoolTerm(term)) => atom_assignment[*term],
            BoolExpr::Atom(BoolAtomKey::Eq(_, _)) => {
                panic!("truth-table tests use only independent Boolean atoms")
            }
            BoolExpr::Not(child) => !evaluate_bool_expr(child, atom_assignment),
            BoolExpr::And(children) => children
                .iter()
                .all(|child| evaluate_bool_expr(child, atom_assignment)),
            BoolExpr::Or(children) => children
                .iter()
                .any(|child| evaluate_bool_expr(child, atom_assignment)),
            BoolExpr::Iff(children) => children.split_first().is_none_or(|(first, rest)| {
                let first = evaluate_bool_expr(first, atom_assignment);
                rest.iter()
                    .all(|child| evaluate_bool_expr(child, atom_assignment) == first)
            }),
            BoolExpr::Ite(condition, then_expression, else_expression) => {
                if evaluate_bool_expr(condition, atom_assignment) {
                    evaluate_bool_expr(then_expression, atom_assignment)
                } else {
                    evaluate_bool_expr(else_expression, atom_assignment)
                }
            }
        }
    }

    fn assert_all_root_encodings_match_truth_table(expression: &BoolExpr, atom_count: usize) {
        let encodings = [
            RootCnfOptions {
                direct_root_cnf: false,
                direct_negated_root: false,
            },
            RootCnfOptions::existing_behavior(true),
            RootCnfOptions {
                direct_root_cnf: true,
                direct_negated_root: true,
            },
        ];
        for assignment_bits in 0..(1usize << atom_count) {
            let assignment = (0..atom_count)
                .map(|bit| assignment_bits & (1 << bit) != 0)
                .collect::<Vec<_>>();
            let expected = evaluate_bool_expr(expression, &assignment);
            for encoding in encodings {
                assert_eq!(
                    assertion_is_satisfiable_with_root_options(expression, encoding, &assignment,),
                    expected,
                    "encoding {encoding:?} disagrees for {expression:?} under {assignment:?}"
                );
            }
        }
    }

    #[test]
    fn direct_root_cnf_matches_tseitin_for_nested_boolean_formulas() {
        let atom = |term| BoolExpr::Atom(BoolAtomKey::BoolTerm(term));
        let formulas = vec![
            BoolExpr::And(vec![
                BoolExpr::Or(vec![atom(0), BoolExpr::Not(Box::new(atom(1)))]),
                BoolExpr::Iff(vec![
                    atom(2),
                    BoolExpr::Ite(
                        Box::new(atom(0)),
                        Box::new(atom(1)),
                        Box::new(BoolExpr::Not(Box::new(atom(2)))),
                    ),
                ]),
            ]),
            BoolExpr::Or(vec![
                BoolExpr::And(vec![
                    atom(0),
                    BoolExpr::Not(Box::new(BoolExpr::Or(vec![
                        atom(1),
                        BoolExpr::Const(false),
                    ]))),
                ]),
                BoolExpr::Ite(
                    Box::new(atom(2)),
                    Box::new(BoolExpr::Iff(vec![atom(0), atom(1)])),
                    Box::new(BoolExpr::Const(false)),
                ),
            ]),
            BoolExpr::Not(Box::new(BoolExpr::Iff(vec![
                BoolExpr::Or(vec![atom(0), atom(1)]),
                BoolExpr::Ite(
                    Box::new(atom(2)),
                    Box::new(BoolExpr::And(vec![atom(0), BoolExpr::Const(true)])),
                    Box::new(BoolExpr::Not(Box::new(atom(1)))),
                ),
            ]))),
            BoolExpr::Iff(vec![
                BoolExpr::And(vec![
                    atom(0),
                    BoolExpr::Or(vec![atom(1), BoolExpr::Not(Box::new(atom(2)))]),
                ]),
                BoolExpr::Ite(
                    Box::new(atom(1)),
                    Box::new(atom(0)),
                    Box::new(BoolExpr::Const(false)),
                ),
                BoolExpr::Not(Box::new(BoolExpr::Or(vec![
                    BoolExpr::Const(false),
                    atom(2),
                ]))),
            ]),
            BoolExpr::Ite(
                Box::new(BoolExpr::Or(vec![
                    atom(0),
                    BoolExpr::Not(Box::new(atom(1))),
                ])),
                Box::new(BoolExpr::Iff(vec![atom(1), atom(2)])),
                Box::new(BoolExpr::And(vec![
                    BoolExpr::Not(Box::new(atom(0))),
                    BoolExpr::Or(vec![atom(1), atom(2)]),
                ])),
            ),
        ];

        for formula in &formulas {
            assert_root_encodings_equivalent(formula, 3);
        }
    }

    #[test]
    fn direct_root_cnf_matches_tseitin_for_atom_free_constants() {
        let formulas = vec![
            BoolExpr::Const(true),
            BoolExpr::Const(false),
            BoolExpr::And(Vec::new()),
            BoolExpr::Or(Vec::new()),
            BoolExpr::Iff(Vec::new()),
            BoolExpr::Iff(vec![BoolExpr::Const(false)]),
            BoolExpr::Ite(
                Box::new(BoolExpr::Const(false)),
                Box::new(BoolExpr::Const(false)),
                Box::new(BoolExpr::Const(true)),
            ),
        ];

        for formula in &formulas {
            assert_root_encodings_equivalent(formula, 0);
        }
    }

    #[test]
    fn direct_negated_root_matches_truth_tables_and_existing_encodings() {
        let atom = |term| BoolExpr::Atom(BoolAtomKey::BoolTerm(term));
        let formulas = vec![
            BoolExpr::Not(Box::new(BoolExpr::Const(true))),
            BoolExpr::Not(Box::new(BoolExpr::Const(false))),
            BoolExpr::Not(Box::new(atom(0))),
            BoolExpr::Not(Box::new(BoolExpr::Not(Box::new(atom(0))))),
            BoolExpr::Not(Box::new(BoolExpr::And(Vec::new()))),
            BoolExpr::Not(Box::new(BoolExpr::And(vec![atom(0)]))),
            BoolExpr::Not(Box::new(BoolExpr::And(vec![
                atom(0),
                BoolExpr::Not(Box::new(atom(1))),
                BoolExpr::Const(true),
            ]))),
            BoolExpr::Not(Box::new(BoolExpr::And(vec![
                atom(0),
                BoolExpr::And(vec![atom(1), BoolExpr::Not(Box::new(atom(2)))]),
                BoolExpr::Or(vec![atom(0), atom(2)]),
            ]))),
            BoolExpr::Not(Box::new(BoolExpr::And(vec![
                BoolExpr::Iff(vec![atom(0), atom(1)]),
                BoolExpr::Ite(
                    Box::new(atom(2)),
                    Box::new(atom(0)),
                    Box::new(BoolExpr::Not(Box::new(atom(1)))),
                ),
            ]))),
            BoolExpr::Not(Box::new(BoolExpr::Or(Vec::new()))),
            BoolExpr::Not(Box::new(BoolExpr::Or(vec![atom(0)]))),
            BoolExpr::Not(Box::new(BoolExpr::Or(vec![
                atom(0),
                BoolExpr::Not(Box::new(BoolExpr::And(vec![atom(1), atom(2)]))),
                BoolExpr::Const(false),
            ]))),
            BoolExpr::And(vec![
                BoolExpr::Not(Box::new(BoolExpr::And(vec![atom(0), atom(1)]))),
                BoolExpr::Not(Box::new(BoolExpr::Or(vec![atom(1), atom(2)]))),
            ]),
        ];

        for formula in &formulas {
            assert_all_root_encodings_match_truth_table(formula, 3);
        }
    }

    #[test]
    fn direct_negated_root_reduces_every_complete_assignment_exactly() {
        let atom = |term| BoolExpr::Atom(BoolAtomKey::BoolTerm(term));
        const ATOM_COUNT: usize = 4;

        for complete_assignment_bits in 0..(1usize << ATOM_COUNT) {
            let children = (0..ATOM_COUNT)
                .map(|term| {
                    let atom = atom(term);
                    if complete_assignment_bits & (1 << term) != 0 {
                        atom
                    } else {
                        BoolExpr::Not(Box::new(atom))
                    }
                })
                .collect::<Vec<_>>();
            let expression = BoolExpr::Not(Box::new(BoolExpr::And(children)));

            let mut tseitin = CnfProblem::new();
            tseitin.add_assertion(&expression);
            let mut existing_direct = CnfProblem::new();
            existing_direct.add_direct_assertion(&expression);
            let mut direct_negated = CnfProblem::new();
            direct_negated.add_direct_assertion_with_negated_root(&expression, true);

            assert_eq!(tseitin.var_count(), ATOM_COUNT + 1);
            assert_eq!(tseitin.clauses.len(), ATOM_COUNT + 2);
            assert_eq!(existing_direct.var_count(), ATOM_COUNT + 1);
            assert_eq!(existing_direct.clauses.len(), ATOM_COUNT + 2);
            assert_eq!(direct_negated.var_count(), ATOM_COUNT);
            assert_eq!(direct_negated.clauses.len(), 1);

            let expected_clause = (0..ATOM_COUNT)
                .map(|term| {
                    let variable = term as i32 + 1;
                    if complete_assignment_bits & (1 << term) != 0 {
                        -variable
                    } else {
                        variable
                    }
                })
                .collect::<Vec<_>>();
            assert_eq!(direct_negated.clauses, vec![expected_clause]);
            assert_all_root_encodings_match_truth_table(&expression, ATOM_COUNT);
        }
    }

    #[test]
    fn direct_negated_root_handles_empty_singleton_nested_and_de_morgan_cases_exactly() {
        let atom = |term| BoolExpr::Atom(BoolAtomKey::BoolTerm(term));
        let encode = |expression: BoolExpr| {
            let mut cnf = CnfProblem::new();
            cnf.add_direct_assertion_with_negated_root(&expression, true);
            cnf
        };

        let empty_and = encode(BoolExpr::Not(Box::new(BoolExpr::And(Vec::new()))));
        assert_eq!(empty_and.var_count(), 0);
        assert_eq!(empty_and.clauses, vec![Vec::<i32>::new()]);

        let singleton_and = encode(BoolExpr::Not(Box::new(BoolExpr::And(vec![atom(0)]))));
        assert_eq!(singleton_and.var_count(), 1);
        assert_eq!(singleton_and.clauses, vec![vec![-1]]);

        let nested_and = encode(BoolExpr::Not(Box::new(BoolExpr::And(vec![
            atom(0),
            BoolExpr::And(vec![atom(1), BoolExpr::Not(Box::new(atom(2)))]),
        ]))));
        assert_eq!(nested_and.var_count(), 4);
        assert_eq!(
            nested_and.clauses,
            vec![vec![-4, 2], vec![-4, -3], vec![4, -2, 3], vec![-1, -4]]
        );

        let double_negation = encode(BoolExpr::Not(Box::new(BoolExpr::Not(Box::new(
            BoolExpr::And(vec![atom(0), atom(1)]),
        )))));
        assert_eq!(double_negation.var_count(), 2);
        assert_eq!(double_negation.clauses, vec![vec![1], vec![2]]);

        let de_morgan = encode(BoolExpr::Not(Box::new(BoolExpr::Or(vec![
            atom(0),
            BoolExpr::Not(Box::new(atom(1))),
            BoolExpr::Const(false),
        ]))));
        assert_eq!(de_morgan.var_count(), 2);
        assert_eq!(de_morgan.clauses, vec![vec![-1], vec![2]]);

        let empty_or = encode(BoolExpr::Not(Box::new(BoolExpr::Or(Vec::new()))));
        assert_eq!(empty_or.var_count(), 0);
        assert!(empty_or.clauses.is_empty());

        let not_true = encode(BoolExpr::Not(Box::new(BoolExpr::Const(true))));
        assert_eq!(not_true.var_count(), 0);
        assert_eq!(not_true.clauses, vec![Vec::<i32>::new()]);
        let not_false = encode(BoolExpr::Not(Box::new(BoolExpr::Const(false))));
        assert_eq!(not_false.var_count(), 0);
        assert!(not_false.clauses.is_empty());
    }

    #[test]
    fn guarded_equality_fact_integration_has_direct_root_tseitin_parity() {
        let input = "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun a () U)
            (declare-fun b () U)
            (declare-fun c () U)
            (declare-fun p () U)
            (declare-fun q () U)
            (declare-fun x () U)
            (declare-fun y () U)
            (assert (distinct a b c))
            (assert (or (= a b) (not (= x y))))
            (assert (= (= p q) true))
            (check-sat)
        ";
        let problem = parse_problem(input).unwrap();
        let bool_problem = problem.bool_problem.as_ref().unwrap();
        let mut context = finite_analysis::FiniteAnalysisContext::default();
        let mode = route_eq_abstraction_mode(
            EqAbstractionMode::GuardedFacts,
            &problem.arena,
            bool_problem,
            &mut context,
        );
        assert_eq!(mode, EqAbstractionMode::GuardedFacts);
        let candidates = equality_abstraction_fact_candidates(&bool_problem.assertions, mode);
        assert_eq!(candidates.len(), 1);
        let mut integrations = Vec::new();

        for direct_root_cnf in [false, true] {
            let mut cnf = CnfProblem::new();
            for assertion in &bool_problem.assertions {
                if direct_root_cnf {
                    cnf.add_direct_assertion(assertion);
                } else {
                    cnf.add_assertion(assertion);
                }
            }
            let integration = integrate_equality_abstraction_facts(
                &mut cnf,
                &candidates,
                eq_abstraction_fact_config_for_mode(
                    mode,
                    EqAbstractionFactConfig {
                        allow_fresh: true,
                        ..EqAbstractionFactConfig::default()
                    },
                ),
            );
            let equality = cnf.atom_vars[&BoolAtomKey::Eq(candidates[0].0, candidates[0].1)];

            assert_eq!(integration.accepted_existing_facts, 1);
            assert_eq!(integration.accepted_fresh_facts, 0);
            assert!(cnf.clauses.iter().any(|clause| clause == &[equality]));
            assert!(cnf_is_satisfiable(&cnf));
            cnf.clauses.push(vec![-equality]);
            assert!(!cnf_is_satisfiable(&cnf));
            integrations.push(integration);
        }

        assert_eq!(integrations[0], integrations[1]);
    }

    #[test]
    fn direct_root_initial_solve_does_not_create_false_unsat() {
        let input = "
            (set-logic QF_UF)
            (assert
              (and true
                   (or false (not false))
                   (= true (ite false false true))))
            (check-sat)
        ";
        for direct_root_cnf in [false, true] {
            assert_eq!(
                solve_problem(parse_problem(input).unwrap(), direct_root_cnf).result,
                SolveResult::Sat
            );
        }
    }

    #[test]
    fn emits_direct_constraints_for_assertion_roots() {
        let atom = |term| BoolExpr::Atom(BoolAtomKey::BoolTerm(term));

        let mut conjunction = CnfProblem::new();
        conjunction.add_direct_assertion(&BoolExpr::And(vec![
            atom(0),
            BoolExpr::Not(Box::new(atom(1))),
        ]));
        assert_eq!(conjunction.var_count(), 2);
        assert_eq!(conjunction.clauses, vec![vec![1], vec![-2]]);

        let mut equivalence = CnfProblem::new();
        equivalence.add_direct_assertion(&BoolExpr::Iff(vec![atom(0), atom(1), atom(2)]));
        assert_eq!(equivalence.var_count(), 3);
        assert_eq!(
            equivalence.clauses,
            vec![vec![-1, 2], vec![1, -2], vec![-1, 3], vec![1, -3]]
        );

        let mut conditional = CnfProblem::new();
        conditional.add_direct_assertion(&BoolExpr::Ite(
            Box::new(atom(0)),
            Box::new(atom(1)),
            Box::new(atom(2)),
        ));
        assert_eq!(conditional.var_count(), 3);
        assert_eq!(conditional.clauses, vec![vec![-1, 2], vec![1, 3]]);
    }

    #[test]
    fn chordal_fill_makes_triangle_transitivity_complete_on_a_four_cycle() {
        let mut cnf = CnfProblem::new();
        let edge_01 = cnf.atom_lit(BoolAtomKey::Eq(0, 1));
        let edge_12 = cnf.atom_lit(BoolAtomKey::Eq(1, 2));
        let edge_23 = cnf.atom_lit(BoolAtomKey::Eq(2, 3));
        let edge_03 = cnf.atom_lit(BoolAtomKey::Eq(0, 3));
        assert!(equality_transitivity_clauses(&cnf, 4).is_empty());
        assert_eq!(add_sparse_transitivity_fill(&mut cnf, 4, 1), Some(1));

        let transitivity = equality_transitivity_clauses(&cnf, 4);
        assert_eq!(transitivity.len(), 6);
        let mut solver = VarisatSolver::new();
        for clause in transitivity {
            solver.add_clause(
                &clause
                    .iter()
                    .map(|literal| Lit::from_dimacs(*literal as isize))
                    .collect::<Vec<_>>(),
            );
        }
        for literal in [edge_01, edge_12, edge_23, -edge_03] {
            solver.add_clause(&[Lit::from_dimacs(literal as isize)]);
        }
        assert!(matches!(solver.solve(), Ok(false)));

        let mut capped = CnfProblem::new();
        capped.atom_lit(BoolAtomKey::Eq(0, 1));
        capped.atom_lit(BoolAtomKey::Eq(1, 2));
        capped.atom_lit(BoolAtomKey::Eq(2, 3));
        capped.atom_lit(BoolAtomKey::Eq(0, 3));
        assert_eq!(add_sparse_transitivity_fill(&mut capped, 4, 0), None);
        assert_eq!(capped.var_count(), 4);
    }

    #[test]
    fn full_ackermann_axioms_make_function_congruence_propositional() {
        let input = "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun a () U)
            (declare-fun b () U)
            (declare-fun f (U) U)
            (assert (= a b))
            (assert (distinct (f a) (f b)))
            (check-sat)
        ";
        let problem = parse_problem(input).unwrap();
        let bool_problem = problem.bool_problem.as_ref().unwrap();
        let mut cnf = CnfProblem::new();
        for assertion in &bool_problem.assertions {
            cnf.add_assertion(assertion);
        }
        assert!(add_full_ackermann_axioms(&mut cnf, &problem.arena) > 0);

        let mut solver = VarisatSolver::new();
        for clause in &cnf.clauses {
            solver.add_clause(
                &clause
                    .iter()
                    .map(|literal| Lit::from_dimacs(*literal as isize))
                    .collect::<Vec<_>>(),
            );
        }
        for clause in equality_transitivity_clauses(&cnf, problem.arena.terms.len()) {
            solver.add_clause(
                &clause
                    .iter()
                    .map(|literal| Lit::from_dimacs(*literal as isize))
                    .collect::<Vec<_>>(),
            );
        }
        assert!(matches!(solver.solve(), Ok(false)));
    }

    #[test]
    fn full_ackermann_axioms_make_predicate_congruence_propositional() {
        let input = "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun a () U)
            (declare-fun b () U)
            (declare-fun p (U) Bool)
            (assert (= a b))
            (assert (p a))
            (assert (not (p b)))
            (check-sat)
        ";
        let problem = parse_problem(input).unwrap();
        let bool_problem = problem.bool_problem.as_ref().unwrap();
        let mut cnf = CnfProblem::new();
        for assertion in &bool_problem.assertions {
            cnf.add_assertion(assertion);
        }
        assert!(add_full_ackermann_axioms(&mut cnf, &problem.arena) > 0);

        let mut solver = VarisatSolver::new();
        for clause in &cnf.clauses {
            solver.add_clause(
                &clause
                    .iter()
                    .map(|literal| Lit::from_dimacs(*literal as isize))
                    .collect::<Vec<_>>(),
            );
        }
        assert!(matches!(solver.solve(), Ok(false)));
    }

    fn solve_text(input: &str) -> SolveResult {
        solve_problem(parse_problem(input).unwrap(), false).result
    }

    fn solve_text_with_scoped_let_mode(input: &str, mode: ScopedLetMode) -> SolveResult {
        solve_problem(
            parse_problem_with_scoped_let_mode(input, mode).unwrap(),
            false,
        )
        .result
    }

    fn parse_one_sexp(input: &str) -> Sexp {
        let mut sexps = parse_sexps(input).unwrap();
        assert_eq!(sexps.len(), 1);
        sexps.pop().unwrap()
    }

    fn parse_test_declarations(ctx: &mut ParseCtx, input: &str) {
        for sexp in parse_sexps(input).unwrap() {
            ctx.parse_command(&sexp).unwrap();
        }
    }

    fn solve_text_with_eq_abstraction(
        input: &str,
        direct_root_cnf: bool,
        mode: EqAbstractionMode,
    ) -> SolveResult {
        solve_problem_with_eq_abstraction(parse_problem(input).unwrap(), direct_root_cnf, mode)
            .result
    }

    fn equality_abstraction_fact_candidate_count(input: &str, mode: EqAbstractionMode) -> usize {
        let problem = parse_problem(input).unwrap();
        let bool_problem = problem.bool_problem.as_ref().unwrap();
        equality_abstraction_fact_candidates(&bool_problem.assertions, mode).len()
    }

    fn routed_eq_abstraction_mode(input: &str) -> (EqAbstractionMode, usize) {
        let problem = parse_problem(input).unwrap();
        let bool_problem = problem.bool_problem.as_ref().unwrap();
        let mut context = finite_analysis::FiniteAnalysisContext::default();
        let mode = route_eq_abstraction_mode(
            EqAbstractionMode::GuardedFacts,
            &problem.arena,
            bool_problem,
            &mut context,
        );
        let clauses = context
            .guarded
            .as_ref()
            .map_or(0, |summary| summary.clauses);
        (mode, clauses)
    }

    #[test]
    fn guarded_equality_route_selects_only_verified_guarded_clauses() {
        let declarations = "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun a () U)
            (declare-fun b () U)
            (declare-fun c () U)
            (declare-fun p () U)
            (declare-fun q () U)
            (declare-fun x () U)
            (declare-fun y () U)
        ";
        let selected = format!(
            "{declarations}
             (assert (distinct a b c))
             (assert (or (= a b) (not (= x y))))
             (assert (= (= p q) true))
             (check-sat)"
        );
        assert_eq!(
            routed_eq_abstraction_mode(&selected),
            (EqAbstractionMode::GuardedFacts, 1)
        );

        let plausible_unverified = format!(
            "{declarations}
             (assert (or (= a b) (not (= x y))))
             (assert (= (= p q) true))
             (check-sat)"
        );
        assert_eq!(
            equality_abstraction_fact_candidate_count(
                &plausible_unverified,
                EqAbstractionMode::Facts
            ),
            1
        );
        let problem = parse_problem(&plausible_unverified).unwrap();
        let bool_problem = problem.bool_problem.as_ref().unwrap();
        let mut context = finite_analysis::FiniteAnalysisContext::default();
        let routed = route_eq_abstraction_mode(
            EqAbstractionMode::GuardedFacts,
            &problem.arena,
            bool_problem,
            &mut context,
        );
        assert_eq!(routed, EqAbstractionMode::Off);
        assert!(equality_abstraction_fact_candidates(&bool_problem.assertions, routed).is_empty());

        let structural_negative = format!(
            "{declarations}
             (assert (distinct a b c))
             (assert (or (= a b) (= x y)))
             (assert (= (= p q) true))
             (check-sat)"
        );
        assert_eq!(
            routed_eq_abstraction_mode(&structural_negative),
            (EqAbstractionMode::Off, 0)
        );
    }

    #[test]
    fn dynamic_full_ackermann_rebuild_preserves_accepted_equality_facts() {
        let input = "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun a () U)
            (declare-fun b () U)
            (declare-fun c () U)
            (declare-fun p () U)
            (declare-fun q () U)
            (declare-fun x () U)
            (declare-fun y () U)
            (assert (distinct a b c))
            (assert (or (= a b) (not (= x y))))
            (assert (= (= p q) true))
            (check-sat)
        ";
        let problem = parse_problem(input).unwrap();
        let bool_problem = problem.bool_problem.as_ref().unwrap();
        let mut context = finite_analysis::FiniteAnalysisContext::default();
        let mode = route_eq_abstraction_mode(
            EqAbstractionMode::GuardedFacts,
            &problem.arena,
            bool_problem,
            &mut context,
        );
        assert_eq!(mode, EqAbstractionMode::GuardedFacts);
        let candidates = equality_abstraction_fact_candidates(&bool_problem.assertions, mode);
        assert_eq!(candidates.len(), 1);

        let mut initial_cnf = CnfProblem::new();
        for assertion in &bool_problem.assertions {
            initial_cnf.add_assertion(assertion);
        }
        let integration = integrate_equality_abstraction_facts(
            &mut initial_cnf,
            &candidates,
            eq_abstraction_fact_config_for_mode(
                mode,
                EqAbstractionFactConfig {
                    allow_fresh: true,
                    ..EqAbstractionFactConfig::default()
                },
            ),
        );
        assert_eq!(integration.accepted_existing_facts, 1);

        let (completed, _) =
            solve_dynamic_full_ackermann(&problem.arena, bool_problem, &integration.accepted_edges);
        let edge = integration.accepted_edges[0];
        let equality = completed.atom_vars[&BoolAtomKey::Eq(edge.0, edge.1)];
        assert!(completed.clauses.iter().any(|clause| clause == &[equality]));
    }

    #[test]
    fn dynamic_full_ackermann_rebuild_preserves_direct_negated_root_mode() {
        let input = "
            (set-logic QF_UF)
            (declare-fun p () Bool)
            (declare-fun q () Bool)
            (declare-fun r () Bool)
            (assert (not (and p (not q) r)))
            (check-sat)
        ";
        let problem = parse_problem(input).unwrap();
        let bool_problem = problem.bool_problem.as_ref().unwrap();

        let (existing, _) = solve_dynamic_full_ackermann(&problem.arena, bool_problem, &[]);
        let (direct_negated, _) =
            solve_dynamic_full_ackermann_with_negated_root(&problem.arena, bool_problem, &[], true);

        assert_eq!(existing.var_count(), 4);
        assert_eq!(existing.clauses.len(), 5);
        assert_eq!(direct_negated.var_count(), 3);
        assert_eq!(direct_negated.clauses, vec![vec![-1, 2, -3]]);
    }

    fn solve_text_varisat(input: &str) -> SolveResult {
        let problem = parse_problem(input).unwrap();
        let bool_problem = problem.bool_problem.as_ref().unwrap();
        assert!(bool_problem.unsupported.is_empty());
        let mut cnf = CnfProblem::new();
        atomize_bool_data_terms(&mut cnf, bool_problem);
        for assertion in &bool_problem.assertions {
            cnf.add_assertion(assertion);
        }
        solve_varisat_euf(
            &cnf,
            &problem.arena,
            bool_problem.true_term,
            bool_problem.false_term,
        )
        .0
    }

    fn solve_text_cadical_refinement(
        input: &str,
        refinement_mode: RefinementMode,
        max_rounds: usize,
    ) -> (
        Option<(SolveResult, usize, usize)>,
        CadicalRefinementTelemetry,
        usize,
        usize,
    ) {
        let problem = parse_problem(input).unwrap();
        let bool_problem = problem.bool_problem.as_ref().unwrap();
        assert!(bool_problem.unsupported.is_empty());
        let mut cnf = CnfProblem::new();
        atomize_bool_data_terms(&mut cnf, bool_problem);
        for assertion in &bool_problem.assertions {
            cnf.add_assertion(assertion);
        }
        let initial_vars = cnf.var_count();
        let mut telemetry = CadicalRefinementTelemetry::default();
        let outcome = solve_cadical_euf_refining_with_limit(
            &cnf,
            &problem.arena,
            bool_problem.true_term,
            bool_problem.false_term,
            refinement_mode,
            max_rounds,
            &mut telemetry,
        );
        (outcome, telemetry, initial_vars, cnf.var_count())
    }

    #[test]
    fn detects_direct_disequality_conflict() {
        let input = "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun a () U)
            (assert (= a a))
            (assert (distinct a a))
            (check-sat)
        ";
        assert_eq!(solve_text(input), SolveResult::Unsat);
        assert_eq!(solve_text_varisat(input), SolveResult::Unsat);
    }

    #[test]
    fn detects_unary_congruence_conflict() {
        let input = "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun a () U)
            (declare-fun b () U)
            (declare-fun f (U) U)
            (assert (= a b))
            (assert (distinct (f a) (f b)))
            (check-sat)
        ";
        assert_eq!(solve_text(input), SolveResult::Unsat);
        assert_eq!(solve_text_varisat(input), SolveResult::Unsat);
    }

    #[test]
    fn handles_let_bound_terms() {
        let input = "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun a () U)
            (declare-fun b () U)
            (declare-fun f (U) U)
            (assert (let ((x (f a)) (y (f b))) (and (= a b) (distinct x y))))
            (check-sat)
        ";
        assert_eq!(solve_text(input), SolveResult::Unsat);
    }

    #[test]
    fn clone_and_scoped_let_paths_preserve_sat_and_unsat_semantics() {
        let sat = "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun a () U)
            (assert (let ((x a)) (= x a)))
            (check-sat)
        ";
        let unsat = "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun a () U)
            (declare-fun b () U)
            (declare-fun f (U) U)
            (assert (let ((x (f a)) (y (f b))) (and (= a b) (distinct x y))))
            (check-sat)
        ";

        for mode in [ScopedLetMode::Off, ScopedLetMode::On] {
            assert_eq!(solve_text_with_scoped_let_mode(sat, mode), SolveResult::Sat);
            assert_eq!(
                solve_text_with_scoped_let_mode(unsat, mode),
                SolveResult::Unsat
            );
        }
    }

    #[test]
    fn preserves_sort_identity_and_full_zero_arity_signatures() {
        let mut ctx = ParseCtx::new(false);
        parse_test_declarations(
            &mut ctx,
            "(declare-sort U 0)
             (declare-sort V 0)
             (declare-fun a () U)
             (declare-const b V)
             (declare-fun p () Bool)
             (declare-fun f (U Bool) V)
             (declare-fun is-v (V) Bool)",
        );

        let u = ctx.sorts.get(ctx.symbols.ids["U"]).unwrap();
        let v = ctx.sorts.get(ctx.symbols.ids["V"]).unwrap();
        assert_ne!(u, v);
        assert_ne!(u, BOOL_SORT);
        assert_ne!(v, BOOL_SORT);

        let a_decl = ctx.fun_decls.get(ctx.symbols.ids["a"]).unwrap();
        assert!(a_decl.arg_sorts.is_empty());
        assert_eq!(a_decl.result_sort, u);
        let b_decl = ctx.fun_decls.get(ctx.symbols.ids["b"]).unwrap();
        assert!(b_decl.arg_sorts.is_empty());
        assert_eq!(b_decl.result_sort, v);
        let f_decl = ctx.fun_decls.get(ctx.symbols.ids["f"]).unwrap();
        assert_eq!(f_decl.arg_sorts, vec![u, BOOL_SORT]);
        assert_eq!(f_decl.result_sort, v);

        let mut env = HashMap::default();
        let a = ctx
            .parse_typed_term(&parse_one_sexp("a"), &mut env)
            .unwrap();
        let b = ctx
            .parse_typed_term(&parse_one_sexp("b"), &mut env)
            .unwrap();
        let f_a_p = ctx
            .parse_typed_term(&parse_one_sexp("(f a p)"), &mut env)
            .unwrap();
        ctx.parse_bool_expr(&parse_one_sexp("(is-v (f a p))"), &mut env)
            .unwrap();

        assert_eq!(ctx.arena.terms[a].sort, u);
        assert_eq!(ctx.arena.terms[b].sort, v);
        assert_eq!(ctx.arena.terms[f_a_p].sort, v);
        assert!(
            ctx.arena
                .terms
                .iter()
                .all(|term| matches!(term.sort, BOOL_SORT) || term.sort == u || term.sort == v)
        );
        let problem = ctx.finish();
        assert!(problem.terms_are_well_sorted());
        assert_eq!(problem.sorts.names, vec!["Bool", "U", "V"]);
        assert_eq!(
            problem
                .fun_decls
                .get(problem.arena.terms[a].fun)
                .unwrap()
                .result_sort,
            u
        );
    }

    #[test]
    fn dense_function_declarations_preserve_unset_symbol_slots() {
        let mut ctx = ParseCtx::new(false);
        let leading_gap = ctx.symbols.intern("leading-gap");
        let f = ctx.declare_function("f", Vec::new(), BOOL_SORT).unwrap();
        let interior_gap = ctx.symbols.intern("interior-gap");
        let g = ctx
            .declare_function("g", vec![BOOL_SORT], BOOL_SORT)
            .unwrap();

        assert!(ctx.fun_decls.get(leading_gap).is_none());
        assert!(ctx.fun_decls.get(interior_gap).is_none());
        assert_eq!(ctx.fun_decls.get(f).unwrap().arg_sorts, Vec::new());
        assert_eq!(ctx.fun_decls.get(g).unwrap().arg_sorts, vec![BOOL_SORT]);
        assert_eq!(ctx.fun_decls.slots.len(), g as usize + 1);
        assert_eq!(
            ctx.application_result_sort(interior_gap, "interior-gap", &[]),
            Err("undeclared function `interior-gap`".to_owned())
        );

        let problem = ctx.finish();
        assert!(problem.fun_decls.get(leading_gap).is_none());
        assert!(problem.fun_decls.get(interior_gap).is_none());
        assert_eq!(problem.fun_decls.get(f).unwrap().result_sort, BOOL_SORT);
        assert_eq!(problem.fun_decls.get(g).unwrap().result_sort, BOOL_SORT);
    }

    #[test]
    fn skips_diagnostic_sort_validation_for_valid_boolean_forms() {
        let mut ctx = ParseCtx::new(false);
        parse_test_declarations(
            &mut ctx,
            "(declare-sort U 0)
             (declare-fun a () U)
             (declare-fun b () U)
             (declare-fun p () Bool)
             (define-fun same () Bool (= a b))
             (assert (and p (same)))",
        );

        assert_eq!(ctx.assertion_sort_validations, 0);
    }

    #[test]
    fn rejects_cross_sort_equality_and_ite_branches() {
        let equality = "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-sort V 0)
            (declare-fun a () U)
            (declare-fun b () V)
            (assert (= a b))
            (check-sat)
        ";
        assert_eq!(
            parse_problem_with_scoped_let_mode(equality, ScopedLetMode::Off).unwrap_err(),
            "sort mismatch in equality: expected `U`, found `V`"
        );

        let ite = "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-sort V 0)
            (declare-fun p () Bool)
            (declare-fun a () U)
            (declare-fun b () V)
            (assert (= a (ite p a b)))
            (check-sat)
        ";
        assert_eq!(
            parse_problem_with_scoped_let_mode(ite, ScopedLetMode::Off).unwrap_err(),
            "sort mismatch in ite branches: expected `U`, found `V`"
        );
    }

    #[test]
    fn rejects_function_arity_and_argument_sort_mismatches() {
        let declarations = "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-sort V 0)
            (declare-fun a () U)
            (declare-fun b () V)
            (declare-fun p () Bool)
            (declare-fun f (U Bool) U)
        ";
        let cases = [
            (
                "(assert (= (f a) a))",
                "arity mismatch in application `f`: expected 2 arguments, found 1",
            ),
            (
                "(assert (= (f b p) a))",
                "sort mismatch in application `f` argument 1: expected `U`, found `V`",
            ),
            (
                "(assert (= (f a a) a))",
                "sort mismatch in application `f` argument 2: expected `Bool`, found `U`",
            ),
        ];

        for (assertion, expected) in cases {
            let input = format!("{declarations}\n{assertion}\n(check-sat)");
            assert_eq!(
                parse_problem_with_scoped_let_mode(&input, ScopedLetMode::Off).unwrap_err(),
                expected
            );
        }
    }

    #[test]
    fn typed_bool_arguments_preserve_let_and_ite_semantics() {
        let input = "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-sort V 0)
            (declare-fun p () Bool)
            (declare-fun q () Bool)
            (declare-fun a () U)
            (declare-fun f (Bool U) V)
            (declare-fun g (V) U)
            (assert p)
            (assert (not q))
            (assert (= (g (f (ite p true false) a)) a))
            (assert (distinct (g (f (let ((flag q)) flag) a)) a))
            (check-sat)
        ";

        for mode in [ScopedLetMode::Off, ScopedLetMode::On] {
            assert_eq!(
                solve_text_with_scoped_let_mode(input, mode),
                SolveResult::Sat
            );
        }
    }

    #[test]
    fn term_let_scopes_support_nested_shadowing() {
        for scoped_let_selected in [false, true] {
            let mut ctx = ParseCtx::new(scoped_let_selected);
            parse_test_declarations(
                &mut ctx,
                "(declare-sort U 0)
                 (declare-fun outer () U)
                 (declare-fun middle () U)
                 (declare-fun inner () U)
                 (declare-fun pair (U U) U)",
            );
            let mut env = HashMap::default();
            let outer = ctx.parse_term(&parse_one_sexp("outer"), &mut env).unwrap();
            let middle = ctx.parse_term(&parse_one_sexp("middle"), &mut env).unwrap();
            let inner = ctx.parse_term(&parse_one_sexp("inner"), &mut env).unwrap();
            env.insert("x".to_owned(), outer);

            let expression = parse_one_sexp("(let ((x middle)) (pair (let ((x inner)) x) x))");
            let result = ctx.parse_term(&expression, &mut env).unwrap();

            assert_eq!(ctx.arena.terms[result].args, vec![inner, middle]);
            assert_eq!(env.get("x"), Some(&outer));
            assert_eq!(env.len(), 1);
        }
    }

    #[test]
    fn term_let_rhs_values_use_the_pre_let_environment() {
        for scoped_let_selected in [false, true] {
            let mut ctx = ParseCtx::new(scoped_let_selected);
            parse_test_declarations(
                &mut ctx,
                "(declare-sort U 0)
                 (declare-fun outer () U)
                 (declare-fun replacement () U)",
            );
            let mut env = HashMap::default();
            let outer = ctx.parse_term(&parse_one_sexp("outer"), &mut env).unwrap();
            ctx.parse_term(&parse_one_sexp("replacement"), &mut env)
                .unwrap();
            env.insert("x".to_owned(), outer);

            let expression = parse_one_sexp("(let ((x replacement) (y x)) y)");
            assert_eq!(ctx.parse_term(&expression, &mut env).unwrap(), outer);
            assert_eq!(env.get("x"), Some(&outer));
            assert!(!env.contains_key("y"));
        }
    }

    #[test]
    fn mixed_let_scopes_bind_boolean_and_term_values() {
        for scoped_let_selected in [false, true] {
            let mut ctx = ParseCtx::new(scoped_let_selected);
            parse_test_declarations(
                &mut ctx,
                "(declare-sort U 0)
                 (declare-fun a () U)
                 (declare-fun b () U)",
            );
            let mut env = HashMap::default();
            let expression = parse_one_sexp("(let ((x a) (p (= a b))) (and (= x a) p))");

            let result = ctx.parse_bool_expr(&expression, &mut env).unwrap();
            let a = ctx
                .parse_typed_term(&parse_one_sexp("a"), &mut env)
                .unwrap();
            let b = ctx
                .parse_typed_term(&parse_one_sexp("b"), &mut env)
                .unwrap();

            assert_eq!(
                result,
                BoolExpr::And(vec![
                    BoolExpr::Atom(BoolAtomKey::Eq(a, a)),
                    BoolExpr::Atom(BoolAtomKey::Eq(a, b)),
                ])
            );
            assert!(env.is_empty());
        }
    }

    #[test]
    fn nested_let_errors_restore_term_and_mixed_environments() {
        for scoped_let_selected in [false, true] {
            let mut ctx = ParseCtx::new(scoped_let_selected);
            parse_test_declarations(
                &mut ctx,
                "(declare-sort U 0)
                 (declare-fun original () U)
                 (declare-fun shadow () U)
                 (declare-fun value () U)
                 (declare-fun inner () U)",
            );
            let mut term_env = HashMap::default();
            let original = ctx
                .parse_term(&parse_one_sexp("original"), &mut term_env)
                .unwrap();
            term_env.insert("x".to_owned(), original);

            let term_expression = parse_one_sexp(
                "(let ((x shadow) (outer_new value))
                   (let ((x inner) (inner_new value)) ()))",
            );
            assert_eq!(
                ctx.parse_term(&term_expression, &mut term_env),
                Err("empty term list".to_owned())
            );
            assert_eq!(term_env.get("x"), Some(&original));
            assert!(!term_env.contains_key("outer_new"));
            assert!(!term_env.contains_key("inner_new"));
            assert_eq!(term_env.len(), 1);

            let mut mixed_env = HashMap::default();
            mixed_env.insert("x".to_owned(), BindingValue::Term(original));
            mixed_env.insert(
                "keep".to_owned(),
                BindingValue::Bool(BoolExpr::Const(false)),
            );
            let mixed_expression = parse_one_sexp(
                "(let ((x shadow) (keep true) (outer_new true))
                   (let ((x inner) (inner_new false)) (not)))",
            );
            assert_eq!(
                ctx.parse_bool_expr(&mixed_expression, &mut mixed_env),
                Err("not with arity other than 1".to_owned())
            );
            assert!(matches!(
                mixed_env.get("x"),
                Some(BindingValue::Term(term)) if *term == original
            ));
            assert!(matches!(
                mixed_env.get("keep"),
                Some(BindingValue::Bool(BoolExpr::Const(false)))
            ));
            assert!(!mixed_env.contains_key("outer_new"));
            assert!(!mixed_env.contains_key("inner_new"));
            assert_eq!(mixed_env.len(), 2);
        }
    }

    #[test]
    fn solves_positive_disjunction_with_boolean_search() {
        let input = "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun a () U)
            (declare-fun b () U)
            (assert (or (= a b) (distinct a b)))
            (check-sat)
        ";
        assert_eq!(solve_text(input), SolveResult::Sat);
    }

    #[test]
    fn solves_boolean_let_aliases_over_euf_atoms() {
        let input = "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun a () U)
            (declare-fun b () U)
            (declare-fun c () U)
            (assert
              (let ((p (= a b)) (q (= b c)))
                (and (or p q) (not p) (not q))))
            (check-sat)
        ";
        assert_eq!(solve_text(input), SolveResult::Unsat);
    }

    #[test]
    fn solves_bool_constants_and_equivalence() {
        let input = "
            (set-logic QF_UF)
            (declare-fun p () Bool)
            (declare-fun q () Bool)
            (assert (= p (not q)))
            (assert p)
            (assert q)
            (check-sat)
        ";
        assert_eq!(solve_text(input), SolveResult::Unsat);
    }

    #[test]
    fn enforces_bool_predicate_congruence() {
        let input = "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun a () U)
            (declare-fun b () U)
            (declare-fun p (U) Bool)
            (assert (= a b))
            (assert (p a))
            (assert (not (p b)))
            (check-sat)
        ";
        assert_eq!(solve_text(input), SolveResult::Unsat);
    }

    #[cfg(feature = "finite-symmetry")]
    #[test]
    fn lex_leader_encoding_matches_boolean_vector_order() {
        const WIDTH: usize = 3;
        for negated in [false, true] {
            for left_mask in 0..(1usize << WIDTH) {
                for right_mask in 0..(1usize << WIDTH) {
                    let mut cnf = CnfProblem::new();
                    let left_variables = (0..WIDTH).map(|_| cnf.new_var(None)).collect::<Vec<_>>();
                    let right_variables = (0..WIDTH).map(|_| cnf.new_var(None)).collect::<Vec<_>>();
                    let comparison = left_variables
                        .iter()
                        .zip(&right_variables)
                        .map(|(&left, &right)| {
                            if negated {
                                (-left, -right)
                            } else {
                                (left, right)
                            }
                        })
                        .collect::<Vec<_>>();
                    assert!(add_lex_less_or_equal(&mut cnf, &comparison) > 0);

                    let left_bits = (0..WIDTH)
                        .map(|bit| (left_mask & (1 << bit)) != 0)
                        .collect::<Vec<_>>();
                    let right_bits = (0..WIDTH)
                        .map(|bit| (right_mask & (1 << bit)) != 0)
                        .collect::<Vec<_>>();
                    for (&variable, value) in left_variables.iter().zip(&left_bits) {
                        cnf.clauses
                            .push(vec![if *value { variable } else { -variable }]);
                    }
                    for (&variable, value) in right_variables.iter().zip(&right_bits) {
                        cnf.clauses
                            .push(vec![if *value { variable } else { -variable }]);
                    }

                    let mut solver = VarisatSolver::new();
                    for clause in &cnf.clauses {
                        solver.add_clause(
                            &clause
                                .iter()
                                .map(|literal| Lit::from_dimacs(*literal as isize))
                                .collect::<Vec<_>>(),
                        );
                    }
                    let logical_left = left_bits
                        .iter()
                        .map(|value| if negated { !value } else { *value })
                        .collect::<Vec<_>>();
                    let logical_right = right_bits
                        .iter()
                        .map(|value| if negated { !value } else { *value })
                        .collect::<Vec<_>>();
                    let expected = logical_left <= logical_right;
                    assert!(matches!(solver.solve(), Ok(value) if value == expected));
                }
            }
        }
    }

    #[cfg(feature = "finite-symmetry")]
    #[test]
    fn diagonal_ordered_range_uses_one_closed_function() {
        let input = "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun a () U)
            (declare-fun b () U)
            (declare-fun c () U)
            (declare-fun f (U U) U)
            (assert (distinct a b c))
            (assert (or (= (f a a) a) (= (f a a) b) (= (f a a) c)))
            (assert (or (= (f a b) a) (= (f a b) b) (= (f a b) c)))
            (assert (or (= (f a c) a) (= (f a c) b) (= (f a c) c)))
            (assert (or (= (f b a) a) (= (f b a) b) (= (f b a) c)))
            (assert (or (= (f b b) a) (= (f b b) b) (= (f b b) c)))
            (assert (or (= (f b c) a) (= (f b c) b) (= (f b c) c)))
            (assert (or (= (f c a) a) (= (f c a) b) (= (f c a) c)))
            (assert (or (= (f c b) a) (= (f c b) b) (= (f c b) c)))
            (assert (or (= (f c c) a) (= (f c c) b) (= (f c c) c)))
            (check-sat)
        ";
        let problem = parse_problem(input).unwrap();
        let bool_problem = problem.bool_problem.as_ref().unwrap();
        let mut edges = HashSet::default();
        for assertion in &bool_problem.assertions {
            collect_mandatory_disequalities(assertion, &mut edges);
        }
        let domain = largest_small_disequality_clique(&edges, &problem.arena);
        let domain_set = domain.iter().copied().collect::<HashSet<_>>();
        let mut covered = HashSet::default();
        for assertion in &bool_problem.assertions {
            collect_mandatory_coverages(assertion, &domain_set, &mut covered);
        }
        assert_eq!(domain.len(), 3);
        assert_eq!(covered.len(), 9);

        let function = problem.arena.terms[*covered.iter().next().unwrap()].fun;
        let closed_functions = [function].into_iter().collect::<HashSet<_>>();
        let mut cnf = CnfProblem::new();
        let mut membership = HashMap::default();
        for &term in &covered {
            for &value in &domain {
                let literal = cnf.atom_lit(BoolAtomKey::Eq(term, value));
                membership.insert((term, value), literal);
            }
        }
        let diagonal_zero = problem.arena.interned[&TermKey {
            fun: function,
            args: vec![domain[0], domain[0]],
        }];
        assert_eq!(
            add_finite_diagonal_ordered_range(
                &mut cnf,
                &problem.arena,
                &domain,
                &covered,
                &closed_functions,
                &membership,
                0,
            ),
            1
        );
        assert_eq!(
            cnf.clauses,
            vec![vec![-membership[&(diagonal_zero, domain[2])]]]
        );
        let diagonal =
            finite_diagonal_terms(&problem.arena, &domain, &covered, &closed_functions, 0).unwrap();
        let swap_maps = verified_domain_swap_maps(&problem.arena, bool_problem, &domain).unwrap();
        assert!(
            add_finite_table_lex_leaders(
                &mut cnf,
                &problem.arena,
                &domain,
                &covered,
                &membership,
                &diagonal,
                &swap_maps,
            ) > 0
        );
    }

    #[cfg(feature = "finite-symmetry")]
    #[test]
    fn lex_minimal_unary_conjugates_satisfy_ordered_range() {
        const PERMUTATIONS: [[usize; 3]; 6] = [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ];

        fn conjugate(function: &[usize; 3], permutation: &[usize; 3]) -> [usize; 3] {
            let mut inverse = [0usize; 3];
            for (value, image) in permutation.iter().copied().enumerate() {
                inverse[image] = value;
            }
            std::array::from_fn(|image| permutation[function[inverse[image]]])
        }

        fn negated_one_hot(function: &[usize; 3]) -> Vec<bool> {
            function
                .iter()
                .flat_map(|value| (0..3).map(move |candidate| candidate != *value))
                .collect()
        }

        for code in 0usize..27 {
            let mut quotient = code;
            let function = std::array::from_fn(|_| {
                let value = quotient % 3;
                quotient /= 3;
                value
            });
            let canonical = PERMUTATIONS
                .iter()
                .map(|permutation| conjugate(&function, permutation))
                .min_by_key(negated_one_hot)
                .unwrap();
            assert!(
                canonical
                    .iter()
                    .enumerate()
                    .all(|(input, output)| *output <= (input + 1).min(2))
            );
        }
    }

    #[cfg(feature = "finite-symmetry")]
    #[test]
    fn hybrid_diagonal_route_uses_only_the_measured_structure() {
        assert!(finite_hybrid_uses_diagonal("hybrid", 11, 3, false));
        assert!(!finite_hybrid_uses_diagonal("hybrid", 10, 3, false));
        assert!(!finite_hybrid_uses_diagonal("hybrid", 11, 4, false));
        assert!(!finite_hybrid_uses_diagonal("hybrid", 11, 3, true));
        assert!(!finite_hybrid_uses_diagonal("lex", 11, 3, false));
    }

    #[cfg(feature = "finite-symmetry")]
    #[test]
    fn negated_one_hot_lex_order_is_compatible_with_constant_restricted_growth() {
        const PERMUTATIONS: [[usize; 3]; 6] = [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ];
        const ADJACENT_SWAPS: [[usize; 3]; 2] = [[1, 0, 2], [0, 2, 1]];

        fn permuted(values: &[usize], permutation: &[usize; 3]) -> Vec<usize> {
            values.iter().map(|value| permutation[*value]).collect()
        }

        fn negated_one_hot(values: &[usize]) -> Vec<bool> {
            values
                .iter()
                .flat_map(|value| (0..3).map(move |candidate| candidate != *value))
                .collect()
        }

        for first in 0..3 {
            for second in 0..3 {
                for third in 0..3 {
                    let values = [first, second, third];
                    let canonical = PERMUTATIONS
                        .iter()
                        .map(|permutation| permuted(&values, permutation))
                        .min_by_key(|candidate| negated_one_hot(candidate))
                        .unwrap();
                    assert_eq!(canonical[0], 0);
                    for index in 1..canonical.len() {
                        assert!(canonical[index] <= index);
                        if canonical[index] > 0 {
                            assert!(canonical[..index].contains(&(canonical[index] - 1)));
                        }
                    }

                    let projection = negated_one_hot(&canonical);
                    for swap in ADJACENT_SWAPS {
                        let swapped = permuted(&canonical, &swap);
                        assert!(projection <= negated_one_hot(&swapped));
                    }
                }
            }
        }
    }

    #[cfg(feature = "finite-symmetry")]
    #[test]
    fn verifies_domain_automorphisms_before_breaking_constant_symmetry() {
        let symmetric = "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun a () U)
            (declare-fun b () U)
            (declare-fun c () U)
            (declare-fun x () U)
            (declare-fun y () U)
            (assert (distinct a b c))
            (assert (or (= x a) (= x b) (= x c)))
            (assert (or (= y a) (= y b) (= y c)))
            (check-sat)
        ";
        let problem = parse_problem(symmetric).unwrap();
        let bool_problem = problem.bool_problem.as_ref().unwrap();
        let mut edges = HashSet::default();
        let mut covered = HashSet::default();
        for assertion in &bool_problem.assertions {
            collect_mandatory_disequalities(assertion, &mut edges);
        }
        let domain = largest_small_disequality_clique(&edges, &problem.arena);
        let domain_set = domain.iter().copied().collect::<HashSet<_>>();
        for assertion in &bool_problem.assertions {
            collect_mandatory_coverages(assertion, &domain_set, &mut covered);
        }
        assert_eq!(domain.len(), 3);
        assert_eq!(covered.len(), 2);
        let swap_maps = verified_domain_swap_maps(&problem.arena, bool_problem, &domain).unwrap();
        assert_eq!(swap_maps.len(), domain.len() - 1);

        let mut cnf = CnfProblem::new();
        let mut membership = HashMap::default();
        for &term in &covered {
            for &value in &domain {
                let literal = cnf.atom_lit(BoolAtomKey::Eq(term, value));
                membership.insert((term, value), literal);
            }
        }
        assert_eq!(
            add_finite_constant_symmetry_breaking(
                &mut cnf,
                &problem.arena,
                &domain,
                &covered,
                &membership,
            ),
            5
        );
        assert!(
            add_finite_table_lex_leaders(
                &mut cnf,
                &problem.arena,
                &domain,
                &covered,
                &membership,
                &[],
                &swap_maps,
            ) > 0
        );

        let asymmetric = "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun a () U)
            (declare-fun b () U)
            (declare-fun c () U)
            (declare-fun x () U)
            (assert (distinct a b c))
            (assert (or (= x a) (= x b) (= x c)))
            (assert (= x a))
            (check-sat)
        ";
        let problem = parse_problem(asymmetric).unwrap();
        let bool_problem = problem.bool_problem.as_ref().unwrap();
        let mut edges = HashSet::default();
        for assertion in &bool_problem.assertions {
            collect_mandatory_disequalities(assertion, &mut edges);
        }
        let domain = largest_small_disequality_clique(&edges, &problem.arena);
        assert!(verified_domain_swap_maps(&problem.arena, bool_problem, &domain).is_none());
    }

    #[test]
    fn validates_finite_first_pass_models_with_full_euf_fallback() {
        let input = "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun a () U)
            (declare-fun b () U)
            (declare-fun c () U)
            (declare-fun x () U)
            (declare-fun y () U)
            (declare-fun f (U) U)
            (declare-fun g (U) U)
            (assert (distinct a b c))
            (assert (or (= (f a) a) (= (f a) b) (= (f a) c)))
            (assert (or (= (f b) a) (= (f b) b) (= (f b) c)))
            (assert (or (= (f c) a) (= (f c) b) (= (f c) c)))
            (assert (= x y))
            (assert (distinct (g x) (g y)))
            (check-sat)
        ";
        let problem = parse_problem(input).unwrap();
        let bool_problem = problem.bool_problem.as_ref().unwrap();
        let mut cnf = CnfProblem::new();
        for assertion in &bool_problem.assertions {
            cnf.add_assertion(assertion);
        }
        assert!(add_finite_domain_axioms(&mut cnf, &problem.arena, bool_problem) > 0);

        let report = solve_problem(problem, false);
        assert_eq!(report.result, SolveResult::Unsat);
        assert!(report.stats.sat_calls >= 2);
    }

    #[test]
    fn channels_finite_predicate_congruence_without_generic_euf_axioms() {
        let input = "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun a () U)
            (declare-fun b () U)
            (declare-fun c () U)
            (declare-fun f (U) U)
            (declare-fun p (U) Bool)
            (assert (distinct a b c))
            (assert (or (= (f a) a) (= (f a) b) (= (f a) c)))
            (assert (or (= (f b) a) (= (f b) b) (= (f b) c)))
            (assert (or (= (f c) a) (= (f c) b) (= (f c) c)))
            (assert (or (p a) (not (p a))))
            (assert (or (p b) (not (p b))))
            (assert (or (p c) (not (p c))))
            (assert (= (f a) a))
            (assert (p (f a)))
            (assert (not (p a)))
            (check-sat)
        ";
        let problem = parse_problem(input).unwrap();
        let bool_problem = problem.bool_problem.as_ref().unwrap();
        let mut cnf = CnfProblem::new();
        for assertion in &bool_problem.assertions {
            cnf.add_assertion(assertion);
        }
        assert!(
            add_finite_domain_axioms_with_options::<false>(
                &mut cnf,
                &problem.arena,
                bool_problem,
                FiniteEqualityChanneling::All,
                true,
            ) > 0
        );
        assert!(cnf.finite_equalities_complete);
        assert!(cnf.finite_predicate_congruence_complete);
        assert!(!use_eager_congruence_for_first_pass(
            1,
            &cnf,
            &problem.arena
        ));
        assert_eq!(
            solve_cadical_euf_once(
                &cnf,
                &problem.arena,
                bool_problem.true_term,
                bool_problem.false_term,
                false,
            ),
            Some(SolveResult::Unsat)
        );
    }

    #[test]
    fn routes_large_and_non_linux_finite_problems_to_cadical() {
        assert!(auto_prefers_cadical(1_000, 0, 1_000));
        assert!(!auto_prefers_cadical(10, 0, 1_000));
        assert_eq!(
            auto_prefers_cadical(10, 1, 1_000),
            !cfg!(all(target_os = "linux", target_arch = "x86_64"))
        );
    }

    #[test]
    fn configures_invalid_model_fallback_with_platform_default() {
        assert!(cadical_refine_after_invalid_model(Some("cadical-refine")));
        assert!(!cadical_refine_after_invalid_model(Some("varisat")));
        assert_eq!(
            cadical_refine_after_invalid_model(None),
            cfg!(all(target_os = "linux", target_arch = "x86_64"))
        );
        assert_eq!(
            cadical_refine_after_invalid_model(Some("unknown")),
            cfg!(all(target_os = "linux", target_arch = "x86_64"))
        );
    }

    #[test]
    fn routes_dynamic_full_ackermann_after_invalid_models() {
        assert!(!force_full_ackermann(None));
        assert!(force_full_ackermann(Some("on")));
        assert!(!force_full_ackermann(Some("off")));

        assert!(dynamic_full_ackermann_for_shape(None, 100_000, 256, 0));
        assert!(!dynamic_full_ackermann_for_shape(None, 99_999, 256, 0));
        assert!(!dynamic_full_ackermann_for_shape(None, 100_000, 257, 0));
        assert!(!dynamic_full_ackermann_for_shape(None, 100_000, 256, 1));
        assert!(!dynamic_full_ackermann_for_shape(
            Some("on"),
            1_000_000,
            1,
            0
        ));
        assert!(!dynamic_full_ackermann_for_shape(
            Some("off"),
            1_000_000,
            1,
            0
        ));
    }

    #[test]
    fn parses_refinement_mode_and_preserves_full_ackermann_precedence() {
        assert_eq!(parse_refinement_mode(None), RefinementMode::Current);
        assert_eq!(
            parse_refinement_mode(Some("current")),
            RefinementMode::Current
        );
        assert_eq!(
            parse_refinement_mode(Some("model-cuts")),
            RefinementMode::ModelCuts
        );
        assert_eq!(
            parse_refinement_mode(Some("unknown")),
            RefinementMode::Current
        );

        assert!(dynamic_full_ackermann_before_refinement(
            None,
            RefinementMode::Current,
            100_000,
            256,
            0,
        ));
        assert!(!dynamic_full_ackermann_before_refinement(
            None,
            RefinementMode::ModelCuts,
            100_000,
            256,
            0,
        ));
        assert!(force_full_ackermann(Some("on")));
        assert!(!dynamic_full_ackermann_before_refinement(
            Some("on"),
            RefinementMode::ModelCuts,
            1_000_000,
            1,
            0,
        ));
    }

    #[test]
    fn model_cut_validator_emits_exact_existing_atom_clause() {
        let mut arena = TermArena::default();
        let a = arena.intern(0, Vec::new());
        let b = arena.intern(1, Vec::new());
        let f_a = arena.intern(2, vec![a]);
        let f_b = arena.intern(2, vec![b]);
        let true_term = arena.intern(3, Vec::new());
        let false_term = arena.intern(4, Vec::new());
        let mut cnf = CnfProblem::new();
        let arguments_equal = cnf.atom_lit(BoolAtomKey::Eq(a, b));
        let results_equal = cnf.atom_lit(BoolAtomKey::Eq(f_a, f_b));
        let mut assignment = vec![0i8; cnf.var_count() + 1];
        assignment[arguments_equal as usize] = 1;
        assignment[results_equal as usize] = -1;

        let conflicts =
            theory_conflict_clauses(&cnf, &arena, true_term, false_term, &assignment).unwrap();
        assert_eq!(conflicts, vec![vec![-arguments_equal, results_equal]]);
        assert!(conflicts.iter().flatten().all(|literal| {
            *literal != 0 && literal.unsigned_abs() as usize <= cnf.var_count()
        }));

        let mut learned = HashSet::default();
        let mut telemetry = CadicalRefinementTelemetry::default();
        let mut added = Vec::new();
        assert_eq!(
            add_novel_theory_cuts(
                &conflicts,
                &mut learned,
                cnf.var_count(),
                &mut telemetry,
                |clause| {
                    added.push(clause.to_vec());
                    true
                },
            ),
            Some(1)
        );
        assert_eq!(added, conflicts);
        assert_eq!(telemetry.cuts_generated, 1);
        assert_eq!(telemetry.cuts_added, 1);
        assert_eq!(telemetry.cuts_duplicate, 0);
        assert_eq!(telemetry.cut_width_total, 2);
        assert_eq!(telemetry.cut_width_max, 2);
    }

    #[test]
    fn model_completion_fills_dont_care_values_and_checks_base_cnf() {
        let mut cnf = CnfProblem::new();
        let data = cnf.atom_lit(BoolAtomKey::BoolTerm(0));
        let required = cnf.new_var(None);
        cnf.clauses.push(vec![required]);
        let mut assignment = vec![0i8; cnf.var_count() + 1];
        assignment[required as usize] = 1;
        assert!(complete_cnf_assignment(&cnf, &mut assignment));
        assert_eq!(assignment[data as usize], -1);

        let mut invalid = vec![0i8; cnf.var_count() + 1];
        assert!(!complete_cnf_assignment(&cnf, &mut invalid));
        assert!(!complete_cnf_assignment(&cnf, &mut [0]));
    }

    #[test]
    fn theory_validator_rejects_partial_assignments() {
        let mut arena = TermArena::default();
        let value = arena.intern(0, Vec::new());
        let true_term = arena.intern(1, Vec::new());
        let false_term = arena.intern(2, Vec::new());
        let mut cnf = CnfProblem::new();
        cnf.atom_lit(BoolAtomKey::BoolTerm(value));
        assert!(theory_conflict_clauses(&cnf, &arena, true_term, false_term, &[0, 0],).is_none());
        assert!(theory_conflict_clauses(&cnf, &arena, true_term, false_term, &[0],).is_none());
    }

    #[test]
    fn model_cut_deduplication_detects_no_progress_and_rejects_fresh_variables() {
        let conflicts = vec![vec![2, -1], vec![-1, 2]];
        let mut learned = HashSet::default();
        let mut telemetry = CadicalRefinementTelemetry::default();
        let mut added = Vec::new();
        let first_add =
            add_novel_theory_cuts(&conflicts, &mut learned, 2, &mut telemetry, |clause| {
                added.push(clause.to_vec());
                true
            });
        assert_eq!(first_add, Some(1));
        assert_eq!(added, vec![vec![-1, 2]]);
        assert_eq!(telemetry.cuts_duplicate, 1);

        let duplicate_add =
            add_novel_theory_cuts(&[vec![-1, 2]], &mut learned, 2, &mut telemetry, |_| true);
        assert_eq!(duplicate_add, Some(0));
        assert_eq!(telemetry.cuts_generated, 3);
        assert_eq!(telemetry.cuts_added, 1);
        assert_eq!(telemetry.cuts_duplicate, 2);
        assert_eq!(telemetry.cut_width_total, 6);
        assert_eq!(telemetry.cut_width_max, 2);

        let fresh_variable =
            add_novel_theory_cuts(&[vec![3]], &mut learned, 2, &mut telemetry, |_| true);
        assert!(fresh_variable.is_none());
    }

    #[test]
    fn model_cuts_add_only_the_exact_conflict_without_fresh_variables() {
        let input = "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun a () U)
            (declare-fun b () U)
            (declare-fun f (U) U)
            (assert (= a b))
            (assert (distinct (f a) (f b)))
            (check-sat)
        ";
        let (outcome, telemetry, initial_vars, final_vars) =
            solve_text_cadical_refinement(input, RefinementMode::ModelCuts, 8);
        assert_eq!(outcome, Some((SolveResult::Unsat, 2, 1)));
        assert_eq!(initial_vars, final_vars);
        assert_eq!(telemetry.rounds, 2);
        assert_eq!(telemetry.sat_calls, 2);
        assert_eq!(telemetry.validation_calls, 1);
        assert_eq!(telemetry.cuts_generated, 1);
        assert_eq!(telemetry.cuts_added, 1);
        assert_eq!(telemetry.cuts_duplicate, 0);
        assert_eq!(telemetry.cut_width_total, 2);
        assert_eq!(telemetry.cut_width_max, 2);
        assert!(telemetry.candidate_clause_generation_avoided);
        assert!(telemetry.group_clause_loading_avoided);
    }

    #[test]
    fn model_cuts_return_none_at_theory_round_cap() {
        let input = "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun a () U)
            (assert (= a a))
            (check-sat)
        ";
        let (outcome, telemetry, _, _) =
            solve_text_cadical_refinement(input, RefinementMode::ModelCuts, 0);
        assert_eq!(outcome, None);
        assert_eq!(telemetry.rounds, 0);
        assert_eq!(telemetry.sat_calls, 0);
    }

    #[test]
    fn model_cuts_keep_pure_equality_cycles_sound() {
        let input = "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun a () U)
            (declare-fun b () U)
            (declare-fun c () U)
            (assert (= a b))
            (assert (= b c))
            (assert (distinct a c))
            (check-sat)
        ";
        let (outcome, telemetry, _, _) =
            solve_text_cadical_refinement(input, RefinementMode::ModelCuts, 8);
        assert_eq!(outcome, Some((SolveResult::Unsat, 1, 0)));
        assert_eq!(telemetry.sat_calls, 1);
        assert_eq!(telemetry.validation_calls, 0);
        assert_eq!(telemetry.cuts_added, 0);
    }

    #[test]
    fn model_cuts_accept_a_theory_valid_sat_model() {
        let input = "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun a () U)
            (declare-fun b () U)
            (declare-fun f (U) U)
            (assert (= a b))
            (assert (= (f a) (f b)))
            (check-sat)
        ";
        let (outcome, telemetry, _, _) =
            solve_text_cadical_refinement(input, RefinementMode::ModelCuts, 8);
        assert_eq!(outcome, Some((SolveResult::Sat, 1, 0)));
        assert_eq!(telemetry.validation_calls, 1);
        assert_eq!(telemetry.cuts_generated, 0);
        assert_eq!(telemetry.cuts_added, 0);
    }

    #[test]
    fn model_cuts_match_current_refinement_on_representative_euf_formulas() {
        let cases = [
            (
                "
                    (set-logic QF_UF)
                    (declare-sort U 0)
                    (declare-fun a () U)
                    (declare-fun b () U)
                    (declare-fun f (U) U)
                    (assert (= a b))
                    (assert (distinct (f a) (f b)))
                    (check-sat)
                ",
                SolveResult::Unsat,
            ),
            (
                "
                    (set-logic QF_UF)
                    (declare-sort U 0)
                    (declare-fun a () U)
                    (declare-fun b () U)
                    (declare-fun p (U) Bool)
                    (assert (= a b))
                    (assert (p a))
                    (assert (not (p b)))
                    (check-sat)
                ",
                SolveResult::Unsat,
            ),
            (
                "
                    (set-logic QF_UF)
                    (declare-sort U 0)
                    (declare-fun a () U)
                    (declare-fun b () U)
                    (declare-fun f (U) U)
                    (declare-fun g (U) U)
                    (assert (= a b))
                    (assert (distinct (g (f a)) (g (f b))))
                    (check-sat)
                ",
                SolveResult::Unsat,
            ),
            (
                "
                    (set-logic QF_UF)
                    (declare-sort U 0)
                    (declare-fun a () U)
                    (declare-fun b () U)
                    (declare-fun f (U) U)
                    (assert (distinct a b))
                    (assert (distinct (f a) (f b)))
                    (check-sat)
                ",
                SolveResult::Sat,
            ),
        ];

        for (input, expected) in cases {
            let (current, _, _, _) =
                solve_text_cadical_refinement(input, RefinementMode::Current, 64);
            let (model_cuts, _, _, _) =
                solve_text_cadical_refinement(input, RefinementMode::ModelCuts, 64);
            assert_eq!(current.as_ref().map(|outcome| &outcome.0), Some(&expected));
            assert_eq!(
                model_cuts.as_ref().map(|outcome| &outcome.0),
                current.as_ref().map(|outcome| &outcome.0)
            );
        }
    }

    #[test]
    fn supports_bool_values_as_uf_arguments() {
        let input = "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun p () Bool)
            (declare-fun q () Bool)
            (declare-fun f (Bool) U)
            (assert p)
            (assert q)
            (assert (distinct (f p) (f q)))
            (check-sat)
        ";
        assert_eq!(solve_text(input), SolveResult::Unsat);
        assert_eq!(solve_text_varisat(input), SolveResult::Unsat);
    }

    #[test]
    fn direct_negated_root_preserves_bool_as_data_atomization() {
        let input = "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun p () Bool)
            (declare-fun q () Bool)
            (declare-fun f (Bool) U)
            (assert (not (and p q)))
            (assert (distinct (f p) (f q)))
            (check-sat)
        ";
        let problem = parse_problem(input).unwrap();
        let bool_problem = problem.bool_problem.as_ref().unwrap();
        assert_eq!(bool_problem.data_terms.len(), 2);

        let build = |direct_negated_root| {
            let mut cnf = CnfProblem::new();
            atomize_bool_data_terms(&mut cnf, bool_problem);
            for assertion in &bool_problem.assertions {
                cnf.add_direct_assertion_with_negated_root(assertion, direct_negated_root);
            }
            cnf
        };
        let existing = build(false);
        let direct_negated = build(true);
        let data_variables = |cnf: &CnfProblem| {
            bool_problem
                .data_terms
                .iter()
                .map(|term| cnf.atom_vars[&BoolAtomKey::BoolTerm(*term)])
                .collect::<Vec<_>>()
        };

        assert_eq!(data_variables(&existing), vec![1, 2]);
        assert_eq!(data_variables(&direct_negated), vec![1, 2]);
        for (variable, term) in bool_problem.data_terms.iter().copied().enumerate() {
            assert_eq!(
                direct_negated.var_atoms[variable + 1],
                Some(BoolAtomKey::BoolTerm(term))
            );
        }
    }

    #[test]
    fn unasserted_bool_data_terms_obey_the_two_element_domain() {
        let input = "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun p () Bool)
            (declare-fun q () Bool)
            (declare-fun r () Bool)
            (declare-fun f (Bool) U)
            (assert (distinct (f p) (f q) (f r)))
            (check-sat)
        ";
        let problem = parse_problem(input).unwrap();
        let bool_problem = problem.bool_problem.as_ref().unwrap();
        assert_eq!(bool_problem.data_terms.len(), 3);
        assert_eq!(solve_text(input), SolveResult::Unsat);
        assert_eq!(solve_text_varisat(input), SolveResult::Unsat);
        for mode in [RefinementMode::Current, RefinementMode::ModelCuts] {
            let (outcome, _, _, _) = solve_text_cadical_refinement(input, mode, 64);
            assert_eq!(
                outcome.as_ref().map(|result| &result.0),
                Some(&SolveResult::Unsat)
            );
        }
    }

    #[test]
    fn unasserted_bool_data_terms_retain_satisfiable_completions() {
        let input = "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun p () Bool)
            (declare-fun q () Bool)
            (declare-fun f (Bool) U)
            (assert (distinct (f p) (f q)))
            (check-sat)
        ";
        assert_eq!(solve_text(input), SolveResult::Sat);
        assert_eq!(solve_text_varisat(input), SolveResult::Sat);
    }

    #[test]
    fn nested_bool_data_results_obey_the_two_element_domain() {
        let input = "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun p () Bool)
            (declare-fun q () Bool)
            (declare-fun r () Bool)
            (declare-fun h (Bool) Bool)
            (declare-fun f (Bool) U)
            (assert (distinct (f (h p)) (f (h q)) (f (h r))))
            (check-sat)
        ";
        assert_eq!(solve_text(input), SolveResult::Unsat);
        assert_eq!(solve_text_varisat(input), SolveResult::Unsat);
    }

    #[test]
    fn keeps_true_and_false_uf_arguments_distinct() {
        let input = "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun p () Bool)
            (declare-fun q () Bool)
            (declare-fun f (Bool) U)
            (assert p)
            (assert (not q))
            (assert (distinct (f p) (f q)))
            (check-sat)
        ";
        assert_eq!(solve_text(input), SolveResult::Sat);
        assert_eq!(solve_text_varisat(input), SolveResult::Sat);
    }

    #[test]
    fn eliminates_term_level_ite_with_guarded_equalities() {
        let input = "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun c () Bool)
            (declare-fun a () U)
            (declare-fun b () U)
            (declare-fun x () U)
            (assert (= x (ite c a b)))
            (assert (distinct x a))
            (assert (distinct x b))
            (check-sat)
        ";
        assert_eq!(solve_text(input), SolveResult::Unsat);
    }

    #[test]
    fn treats_smtlib_annotations_as_semantically_transparent() {
        let input = "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun a () U)
            (declare-fun b () U)
            (declare-fun f (U) U)
            (declare-fun p () Bool)
            (assert (! (= a b) :named same))
            (assert (! (distinct (! (f a) :named lhs) (f b)) :named different))
            (assert (! p :named positive))
            (assert (! (not p) :named negative))
            (check-sat)
        ";
        assert_eq!(solve_text(input), SolveResult::Unsat);
        assert_eq!(solve_text_varisat(input), SolveResult::Unsat);
    }

    #[test]
    fn expands_zero_arity_boolean_definitions() {
        let input = "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun a () U)
            (declare-fun b () U)
            (define-fun same () Bool (= a b))
            (define-fun conflict () Bool (and (same) (distinct a b)))
            (assert conflict)
            (check-sat)
        ";
        assert_eq!(solve_text(input), SolveResult::Unsat);
        assert_eq!(solve_text_varisat(input), SolveResult::Unsat);
    }

    #[test]
    fn extracts_common_or_equalities_for_diamond_unsat() {
        let input = "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun x0 () U)
            (declare-fun x1 () U)
            (declare-fun y0 () U)
            (declare-fun z0 () U)
            (assert
              (and
                (or (and (= x0 y0) (= y0 x1))
                    (and (= x0 z0) (= z0 x1)))
                (distinct x0 x1)))
            (check-sat)
        ";
        let problem = parse_problem(input).unwrap();
        assert!(problem.contradiction);
        assert_eq!(solve_problem(problem, false).result, SolveResult::Unsat);
    }

    #[test]
    fn skips_legacy_branch_preprocessing_for_multi_assert_problems() {
        let input = "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun a () U)
            (declare-fun b () U)
            (declare-fun c () U)
            (declare-fun d () U)
            (assert (= a a))
            (assert
              (and
                (or (and (= a c) (= c b))
                    (and (= a d) (= d b)))
                (distinct a b)))
            (check-sat)
        ";
        let problem = parse_problem(input).unwrap();
        assert!(problem.eqs.is_empty());
        assert!(problem.diseqs.is_empty());
        assert!(problem.unsupported.is_empty());
        assert!(!problem.contradiction);
        assert_eq!(solve_problem(problem, false).result, SolveResult::Unsat);
    }

    #[test]
    fn prunes_all_or_branches_against_surrounding_disequalities() {
        let input = "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun a () U)
            (declare-fun b () U)
            (declare-fun c () U)
            (declare-fun d () U)
            (assert
              (and
                (or (= a b) (= c d))
                (distinct a b)
                (distinct c d)))
            (check-sat)
        ";
        assert_eq!(solve_text(input), SolveResult::Unsat);
    }

    #[test]
    fn generated_diamond_and_pruned_or_are_unsat() {
        assert_eq!(solve_text(&gen_diamond(8, 4)), SolveResult::Unsat);
        assert_eq!(solve_text(&gen_pruned_or(8)), SolveResult::Unsat);
    }

    #[test]
    fn equality_abstraction_facts_preserve_representative_sat_answers() {
        let declarations = "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun a () U)
            (declare-fun b () U)
            (declare-fun c () U)
            (declare-fun d () U)
        ";
        let cases = [
            (
                format!(
                    "{declarations}
                    (assert (or (and (= a b) (= b c))
                                (and (= a d) (= d c))))
                    (assert (distinct a c))
                    (check-sat)"
                ),
                SolveResult::Unsat,
                1,
            ),
            (
                format!(
                    "{declarations}
                    (assert (= a b))
                    (assert (= b c))
                    (assert (distinct a c))
                    (check-sat)"
                ),
                SolveResult::Unsat,
                2,
            ),
            (
                format!(
                    "{declarations}
                    (assert (= (= a b) true))
                    (assert (distinct a b))
                    (check-sat)"
                ),
                SolveResult::Unsat,
                1,
            ),
            (
                format!(
                    "{declarations}
                    (assert (not (= (= a b) false)))
                    (assert (distinct a b))
                    (check-sat)"
                ),
                SolveResult::Unsat,
                1,
            ),
            (
                format!(
                    "{declarations}
                    (assert (ite (= a b) true false))
                    (assert (distinct a b))
                    (check-sat)"
                ),
                SolveResult::Unsat,
                1,
            ),
            (
                format!(
                    "{declarations}
                    (assert (not (ite (= a b) false true)))
                    (assert (distinct a b))
                    (check-sat)"
                ),
                SolveResult::Unsat,
                1,
            ),
            (
                format!(
                    "{declarations}
                    (assert (or (= a b) (= c d)))
                    (assert (distinct a b))
                    (check-sat)"
                ),
                SolveResult::Sat,
                0,
            ),
            (
                format!(
                    "{declarations}
                    (assert (= (= a b) false))
                    (assert (distinct a b))
                    (check-sat)"
                ),
                SolveResult::Sat,
                0,
            ),
        ];

        for (input, expected, expected_facts) in cases {
            assert_eq!(
                equality_abstraction_fact_candidate_count(&input, EqAbstractionMode::Shadow),
                0
            );
            assert_eq!(
                equality_abstraction_fact_candidate_count(&input, EqAbstractionMode::Facts),
                expected_facts
            );
            for direct_root_cnf in [false, true] {
                let off =
                    solve_text_with_eq_abstraction(&input, direct_root_cnf, EqAbstractionMode::Off);
                let shadow = solve_text_with_eq_abstraction(
                    &input,
                    direct_root_cnf,
                    EqAbstractionMode::Shadow,
                );
                let facts = solve_text_with_eq_abstraction(
                    &input,
                    direct_root_cnf,
                    EqAbstractionMode::Facts,
                );
                let guarded = solve_text_with_eq_abstraction(
                    &input,
                    direct_root_cnf,
                    EqAbstractionMode::GuardedFacts,
                );
                assert_eq!(off, expected);
                assert_eq!(shadow, off);
                assert_eq!(facts, off);
                assert_eq!(guarded, off);
            }
        }
    }

    #[test]
    fn quoted_reserved_identifiers_are_not_dispatched_as_builtins() {
        let quoted_true = r#"
            (set-logic QF_UF)
            (declare-fun |true| () Bool)
            (assert true)
            (assert (not |true|))
            (check-sat)
        "#;
        assert_eq!(solve_text(quoted_true), SolveResult::Sat);

        let quoted_not = r#"
            (set-logic QF_UF)
            (declare-fun |not| (Bool) Bool)
            (assert (|not| true))
            (check-sat)
        "#;
        assert_eq!(solve_text(quoted_not), SolveResult::Sat);
    }

    #[test]
    fn quoted_and_simple_spellings_share_user_symbol_identity() {
        let input = r#"
            (set-logic QF_UF)
            (declare-fun |p| () Bool)
            (assert p)
            (assert |p|)
            (check-sat)
        "#;
        assert_eq!(solve_text(input), SolveResult::Sat);
    }

    #[test]
    fn parser_rejects_mutating_commands_after_the_single_query() {
        let error = parse_problem(
            r#"
                (set-logic QF_UF)
                (check-sat)
                (assert false)
            "#,
        )
        .unwrap_err();
        assert!(error.contains("after `check-sat`"), "{error}");

        let repeated = parse_problem("(set-logic QF_UF) (check-sat) (check-sat)").unwrap_err();
        assert!(repeated.contains("after `check-sat`"), "{repeated}");
    }

    #[test]
    fn parser_allows_read_only_queries_and_exit_after_check_sat() {
        parse_problem(
            r#"
                (set-logic QF_UF)
                (declare-fun p () Bool)
                (assert p)
                (check-sat)
                (get-model)
                (get-value (p))
                (exit)
            "#,
        )
        .unwrap();
    }

    #[test]
    fn parse_check_dash_reads_the_supplied_stdin_bytes() {
        let source = b"(set-logic QF_UF)\n(assert true)\n(check-sat)\n";
        let mut stdin = std::io::Cursor::new(source);
        assert_eq!(
            read_parse_check_input("-", &mut stdin).unwrap().as_bytes(),
            source
        );
        assert_eq!(stdin.position(), source.len() as u64);
    }

    #[test]
    fn tokenizer_preserves_quotedness_and_rejects_unterminated_symbols() {
        assert_eq!(
            parse_sexps("|true| true").unwrap(),
            vec![
                Sexp::QuotedAtom("true".to_owned()),
                Sexp::Atom("true".to_owned()),
            ]
        );
        assert_eq!(
            parse_sexps("|unterminated"),
            Err("unterminated quoted symbol".to_owned())
        );
    }

    #[test]
    fn generated_chain_is_unsat() {
        let input = gen_chain(32, true);
        assert_eq!(solve_text(&input), SolveResult::Unsat);
    }
}
