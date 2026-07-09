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
#[cfg(feature = "certificates")]
use std::io::{BufReader, BufWriter, Read, Write};
#[cfg(feature = "certificates")]
use std::path::{Path, PathBuf};
use std::process::{self, Command};
use std::time::Instant;
use varisat::{ExtendFormula, Lit, Solver as VarisatSolver};

type SymId = u32;
type TermId = usize;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    LParen,
    RParen,
    Atom(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Sexp {
    Atom(String),
    List(Vec<Sexp>),
}

#[derive(Debug, Default)]
struct SymbolInterner {
    ids: HashMap<String, SymId>,
    names: Vec<String>,
}

impl SymbolInterner {
    fn intern(&mut self, text: &str) -> SymId {
        if let Some(&id) = self.ids.get(text) {
            return id;
        }
        let id = self.names.len() as SymId;
        self.ids.insert(text.to_owned(), id);
        self.names.push(text.to_owned());
        id
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
}

#[derive(Debug, Default)]
struct TermArena {
    terms: Vec<Term>,
    interned: HashMap<TermKey, TermId>,
    apps: Vec<TermId>,
}

impl TermArena {
    fn intern(&mut self, fun: SymId, args: Vec<TermId>) -> TermId {
        let key = TermKey { fun, args };
        if let Some(&id) = self.interned.get(&key) {
            return id;
        }
        let id = self.terms.len();
        if !key.args.is_empty() {
            self.apps.push(id);
        }
        self.terms.push(Term {
            fun: key.fun,
            args: key.args.clone(),
        });
        self.interned.insert(key, id);
        id
    }

    fn app_count(&self) -> usize {
        self.apps.len()
    }
}

#[derive(Debug)]
struct Problem {
    arena: TermArena,
    eqs: Vec<(TermId, TermId)>,
    diseqs: Vec<(TermId, TermId)>,
    unsupported: Vec<String>,
    bool_problem: Option<BoolProblem>,
    contradiction: bool,
}

#[derive(Debug, Default)]
struct BranchLiterals {
    eqs: Vec<(TermId, TermId)>,
    diseqs: Vec<(TermId, TermId)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FunDecl {
    result_is_bool: bool,
    arity: usize,
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

#[derive(Debug, Clone)]
struct BoolProblem {
    assertions: Vec<BoolExpr>,
    unsupported: Vec<String>,
    true_term: TermId,
    false_term: TermId,
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
    arena: TermArena,
    eqs: Vec<(TermId, TermId)>,
    diseqs: Vec<(TermId, TermId)>,
    unsupported: Vec<String>,
    bool_assertions: Vec<BoolExpr>,
    bool_unsupported: Vec<String>,
    fun_decls: HashMap<SymId, FunDecl>,
    bool_definitions: HashMap<SymId, BoolExpr>,
    bool_value_terms: Option<(TermId, TermId)>,
    fresh_internal_counter: usize,
    preprocess_branch_intersections: bool,
    contradiction: bool,
}

impl ParseCtx {
    fn finish(self) -> Problem {
        let bool_problem = (!self.bool_assertions.is_empty() || !self.bool_unsupported.is_empty())
            .then(|| {
                let (true_term, false_term) = self
                    .bool_value_terms
                    .expect("Boolean parsing initializes value terms");
                BoolProblem {
                    assertions: self.bool_assertions,
                    unsupported: self.bool_unsupported,
                    true_term,
                    false_term,
                }
            });
        Problem {
            arena: self.arena,
            eqs: self.eqs,
            diseqs: self.diseqs,
            unsupported: self.unsupported,
            bool_problem,
            contradiction: self.contradiction,
        }
    }

    fn add_unsupported(&mut self, msg: impl Into<String>) {
        self.unsupported.push(msg.into());
    }

    fn parse_command(&mut self, sexp: &Sexp) -> Result<(), String> {
        let Sexp::List(items) = sexp else {
            return Ok(());
        };
        if items.is_empty() {
            return Ok(());
        }
        let Some(head) = atom_text(&items[0]) else {
            return Ok(());
        };
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
                        self.bool_unsupported.push(err);
                        let mut env = HashMap::default();
                        self.collect_formula(&items[1], true, &mut env)?;
                    }
                }
            }
            "declare-fun" => {
                if let Some(name) = items.get(1).and_then(atom_text) {
                    let sym = self.symbols.intern(name);
                    let arity = items
                        .get(2)
                        .and_then(|arg_sorts| match arg_sorts {
                            Sexp::List(sorts) => Some(sorts.len()),
                            Sexp::Atom(_) => None,
                        })
                        .unwrap_or(0);
                    let result_is_bool = items.get(3).and_then(atom_text) == Some("Bool");
                    self.fun_decls.insert(
                        sym,
                        FunDecl {
                            result_is_bool,
                            arity,
                        },
                    );
                }
            }
            "declare-const" => {
                if let Some(name) = items.get(1).and_then(atom_text) {
                    let sym = self.symbols.intern(name);
                    let result_is_bool = items.get(2).and_then(atom_text) == Some("Bool");
                    self.fun_decls.insert(
                        sym,
                        FunDecl {
                            result_is_bool,
                            arity: 0,
                        },
                    );
                    if !result_is_bool {
                        self.arena.intern(sym, Vec::new());
                    }
                }
            }
            "set-logic" | "set-option" | "set-info" | "declare-sort" | "check-sat" | "exit"
            | "get-model" | "get-value" => {}
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
                if !parameters.is_empty() || items.get(3).and_then(atom_text) != Some("Bool") {
                    self.add_unsupported("only zero-arity Boolean define-fun macros are supported");
                    return Ok(());
                }

                self.ensure_bool_value_terms();
                let sym = self.symbols.intern(name);
                let mut env = HashMap::default();
                match self.parse_bool_expr(&items[4], &mut env) {
                    Ok(body) => {
                        self.fun_decls.insert(
                            sym,
                            FunDecl {
                                result_is_bool: true,
                                arity: 0,
                            },
                        );
                        self.bool_definitions.insert(sym, body);
                    }
                    Err(err) => {
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
            Sexp::Atom(atom) => match atom.as_str() {
                "true" if polarity => Ok(()),
                "false" if polarity => {
                    self.contradiction = true;
                    Ok(())
                }
                "true" => {
                    self.contradiction = true;
                    Ok(())
                }
                "false" => Ok(()),
                name => {
                    self.add_unsupported(format!(
                        "Boolean atom `{name}` is not handled without SAT search"
                    ));
                    Ok(())
                }
            },
            Sexp::List(items) => {
                if items.is_empty() {
                    self.add_unsupported("empty formula list");
                    return Ok(());
                }
                let Some(head) = atom_text(&items[0]) else {
                    self.add_unsupported("formula head is not a symbol");
                    return Ok(());
                };
                match head {
                    "!" => {
                        if items.len() < 2 {
                            self.add_unsupported("annotation without a payload");
                        } else {
                            self.collect_formula(&items[1], polarity, env)?;
                        }
                    }
                    "and" if polarity => {
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
                    "or" if !polarity => {
                        for child in &items[1..] {
                            self.collect_formula(child, false, env)?;
                        }
                    }
                    "not" => {
                        if items.len() != 2 {
                            self.add_unsupported("not with arity other than 1");
                        } else {
                            self.collect_formula(&items[1], !polarity, env)?;
                        }
                    }
                    "=" => self.collect_equality(&items[1..], polarity, env)?,
                    "distinct" => self.collect_distinct(&items[1..], polarity, env)?,
                    "let" => {
                        if items.len() != 3 {
                            self.add_unsupported("let formula with unexpected arity");
                        } else {
                            let mut local = self.extend_let_env(&items[1], env)?;
                            self.collect_formula(&items[2], polarity, &mut local)?;
                        }
                    }
                    "or" if polarity => {
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
                    "and" | "=>" | "xor" | "ite" => {
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
            Sexp::List(items) => {
                if items.is_empty() {
                    return Ok(false);
                }
                let Some(head) = atom_text(&items[0]) else {
                    return Ok(false);
                };
                match head {
                    "!" if items.len() >= 2 => {
                        self.collect_branch_literals_into(&items[1], polarity, env, lits)
                    }
                    "and" if polarity => {
                        for child in &items[1..] {
                            if !self.collect_branch_literals_into(child, true, env, lits)? {
                                return Ok(false);
                            }
                        }
                        Ok(true)
                    }
                    "or" if !polarity => {
                        for child in &items[1..] {
                            if !self.collect_branch_literals_into(child, false, env, lits)? {
                                return Ok(false);
                            }
                        }
                        Ok(true)
                    }
                    "not" if items.len() == 2 => {
                        self.collect_branch_literals_into(&items[1], !polarity, env, lits)
                    }
                    "=" if polarity => {
                        let terms = self.parse_terms(&items[1..], env)?;
                        if terms.len() < 2 {
                            return Ok(false);
                        }
                        let first = terms[0];
                        for &term in &terms[1..] {
                            lits.eqs.push((first, term));
                        }
                        Ok(true)
                    }
                    "=" if !polarity && items.len() == 3 => {
                        let terms = self.parse_terms(&items[1..], env)?;
                        lits.diseqs.push((terms[0], terms[1]));
                        Ok(true)
                    }
                    "distinct" if !polarity && items.len() == 3 => {
                        let terms = self.parse_terms(&items[1..], env)?;
                        lits.eqs.push((terms[0], terms[1]));
                        Ok(true)
                    }
                    "distinct" if polarity => {
                        let terms = self.parse_terms(&items[1..], env)?;
                        for i in 0..terms.len() {
                            for j in (i + 1)..terms.len() {
                                lits.diseqs.push((terms[i], terms[j]));
                            }
                        }
                        Ok(true)
                    }
                    "let" if items.len() == 3 => {
                        let mut local = self.extend_let_env(&items[1], env)?;
                        self.collect_branch_literals_into(&items[2], polarity, &mut local, lits)
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
            Sexp::Atom(atom) => match atom.as_str() {
                "true" => Ok(BoolExpr::Const(true)),
                "false" => Ok(BoolExpr::Const(false)),
                name => match env.get(name).cloned() {
                    Some(BindingValue::Bool(expr)) => Ok(expr),
                    Some(BindingValue::Term(_)) => {
                        Err(format!("term binding `{name}` used as a Boolean formula"))
                    }
                    None => {
                        let sym = self.symbols.intern(name);
                        if let Some(body) = self.bool_definitions.get(&sym).cloned() {
                            Ok(body)
                        } else if self.is_bool_symbol(sym, 0) {
                            Ok(self.bool_app_expr(sym, Vec::new()))
                        } else {
                            Err(format!("non-Boolean atom `{name}` used as a formula"))
                        }
                    }
                },
            },
            Sexp::List(items) => {
                if items.is_empty() {
                    return Err("empty Boolean formula list".to_owned());
                }
                let Some(head) = atom_text(&items[0]) else {
                    return Err("Boolean formula head is not a symbol".to_owned());
                };
                match head {
                    "!" => {
                        if items.len() < 2 {
                            Err("annotation without a payload".to_owned())
                        } else {
                            self.parse_bool_expr(&items[1], env)
                        }
                    }
                    "and" => {
                        let mut children = Vec::with_capacity(items.len().saturating_sub(1));
                        for child in &items[1..] {
                            children.push(self.parse_bool_expr(child, env)?);
                        }
                        Ok(BoolExpr::And(children))
                    }
                    "or" => {
                        let mut children = Vec::with_capacity(items.len().saturating_sub(1));
                        for child in &items[1..] {
                            children.push(self.parse_bool_expr(child, env)?);
                        }
                        Ok(BoolExpr::Or(children))
                    }
                    "not" => {
                        if items.len() != 2 {
                            Err("not with arity other than 1".to_owned())
                        } else {
                            Ok(BoolExpr::Not(Box::new(
                                self.parse_bool_expr(&items[1], env)?,
                            )))
                        }
                    }
                    "=>" => {
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
                    "xor" => {
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
                    "ite" => {
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
                    "=" => self.parse_bool_equality(&items[1..], env),
                    "distinct" => self.parse_bool_distinct(&items[1..], env),
                    "let" => {
                        if items.len() != 3 {
                            Err("let formula with unexpected arity".to_owned())
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
                            Ok(self.bool_app_expr(sym, args))
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
                        return Err("mixed Bool/data equality is not supported".to_owned());
                    };
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
                        return Err("mixed Bool/data equality is not supported".to_owned());
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
            BindingValue::Term(_) => {
                let mut terms = Vec::with_capacity(values.len());
                for value in values {
                    let BindingValue::Term(term) = value else {
                        return Err("mixed Bool/data distinct is not supported".to_owned());
                    };
                    terms.push(term);
                }
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
                        return Err("mixed Bool/data distinct is not supported".to_owned());
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
            Sexp::Atom(atom) => {
                if atom == "true" {
                    return Ok(BindingValue::Bool(BoolExpr::Const(true)));
                }
                if atom == "false" {
                    return Ok(BindingValue::Bool(BoolExpr::Const(false)));
                }
                if let Some(value) = env.get(atom).cloned() {
                    return Ok(value);
                }
                let sym = self.symbols.intern(atom);
                if let Some(body) = self.bool_definitions.get(&sym).cloned() {
                    Ok(BindingValue::Bool(body))
                } else if self.is_bool_symbol(sym, 0) {
                    Ok(BindingValue::Bool(self.bool_app_expr(sym, Vec::new())))
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
                if head == "!" {
                    if items.len() < 2 {
                        return Err("annotation without a payload".to_owned());
                    }
                    return self.parse_bool_or_term(&items[1], env);
                }
                if matches!(head, "and" | "or" | "not" | "=>" | "xor" | "=" | "distinct") {
                    return Ok(BindingValue::Bool(self.parse_bool_expr(sexp, env)?));
                }
                if head == "ite" {
                    if let Ok(expr) = self.parse_bool_expr(sexp, env) {
                        return Ok(BindingValue::Bool(expr));
                    }
                    return Ok(BindingValue::Term(self.parse_typed_term(sexp, env)?));
                }
                if head == "let" {
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
            Sexp::Atom(atom) => {
                if let Some(value) = env.get(atom).cloned() {
                    return match value {
                        BindingValue::Term(term) => Ok(term),
                        BindingValue::Bool(expr) => Ok(self.materialize_bool_expr(expr)),
                    };
                }
                let sym = self.symbols.intern(atom);
                if self.is_bool_symbol(sym, 0) {
                    return Ok(self.arena.intern(sym, Vec::new()));
                }
                Ok(self.arena.intern(sym, Vec::new()))
            }
            Sexp::List(items) => {
                if items.is_empty() {
                    return Err("empty term list".to_owned());
                }
                let Some(head) = atom_text(&items[0]) else {
                    return Err("term head is not a symbol".to_owned());
                };
                if head == "!" {
                    if items.len() < 2 {
                        return Err("annotation without a payload".to_owned());
                    }
                    return self.parse_typed_term(&items[1], env);
                }
                if head == "let" {
                    if items.len() != 3 {
                        return Err("let term with unexpected arity".to_owned());
                    }
                    let mut local = self.extend_mixed_let_env(&items[1], env)?;
                    return self.parse_typed_term(&items[2], &mut local);
                }
                if head == "ite" {
                    if items.len() != 4 {
                        return Err("term-level ite with arity other than 3".to_owned());
                    }
                    let cond = self.parse_bool_expr(&items[1], env)?;
                    let then_term = self.parse_typed_term(&items[2], env)?;
                    let else_term = self.parse_typed_term(&items[3], env)?;
                    if then_term == else_term {
                        return Ok(then_term);
                    }

                    let ite_term = self.fresh_internal_term("ite");
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
                Ok(self.arena.intern(fun, args))
            }
        }
    }

    fn extend_mixed_let_env(
        &mut self,
        bindings: &Sexp,
        env: &mut HashMap<String, BindingValue>,
    ) -> Result<HashMap<String, BindingValue>, String> {
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
        let mut local = env.clone();
        for (name, value) in parsed {
            local.insert(name, value);
        }
        Ok(local)
    }

    fn is_bool_symbol(&self, sym: SymId, arity: usize) -> bool {
        self.fun_decls
            .get(&sym)
            .is_some_and(|decl| decl.result_is_bool && decl.arity == arity)
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

    fn bool_app_expr(&mut self, fun: SymId, args: Vec<TermId>) -> BoolExpr {
        let term = self.arena.intern(fun, args);
        BoolExpr::Atom(BoolAtomKey::BoolTerm(term))
    }

    fn materialize_bool_expr(&mut self, expr: BoolExpr) -> TermId {
        match expr {
            BoolExpr::Const(value) => {
                let (true_term, false_term) = self.ensure_bool_value_terms();
                if value { true_term } else { false_term }
            }
            BoolExpr::Atom(BoolAtomKey::BoolTerm(term)) => term,
            expr => {
                let term = self.fresh_internal_term("bool_expr");
                self.bool_assertions.push(BoolExpr::Iff(vec![
                    BoolExpr::Atom(BoolAtomKey::BoolTerm(term)),
                    expr,
                ]));
                term
            }
        }
    }

    fn ensure_bool_value_terms(&mut self) -> (TermId, TermId) {
        if let Some(terms) = self.bool_value_terms {
            return terms;
        }
        let true_term = self.fresh_internal_term("true");
        let false_term = self.fresh_internal_term("false");
        self.bool_value_terms = Some((true_term, false_term));
        (true_term, false_term)
    }

    fn fresh_internal_term(&mut self, kind: &str) -> TermId {
        loop {
            let name = format!("@euf_viper_{kind}_{}", self.fresh_internal_counter);
            self.fresh_internal_counter += 1;
            if self.symbols.ids.contains_key(&name) {
                continue;
            }
            let sym = self.symbols.intern(&name);
            return self.arena.intern(sym, Vec::new());
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
        match sexp {
            Sexp::Atom(atom) => {
                if let Some(&id) = env.get(atom) {
                    return Ok(id);
                }
                let sym = self.symbols.intern(atom);
                Ok(self.arena.intern(sym, Vec::new()))
            }
            Sexp::List(items) => {
                if items.is_empty() {
                    return Err("empty term list".to_owned());
                }
                let Some(head) = atom_text(&items[0]) else {
                    return Err("term head is not a symbol".to_owned());
                };
                if head == "!" {
                    if items.len() < 2 {
                        return Err("annotation without a payload".to_owned());
                    }
                    return self.parse_term(&items[1], env);
                }
                if head == "let" {
                    if items.len() != 3 {
                        return Err("let term with unexpected arity".to_owned());
                    }
                    let mut local = self.extend_let_env(&items[1], env)?;
                    return self.parse_term(&items[2], &mut local);
                }
                let fun = self.symbols.intern(head);
                let mut args = Vec::with_capacity(items.len().saturating_sub(1));
                for child in &items[1..] {
                    args.push(self.parse_term(child, env)?);
                }
                Ok(self.arena.intern(fun, args))
            }
        }
    }

    fn extend_let_env(
        &mut self,
        bindings: &Sexp,
        env: &mut HashMap<String, TermId>,
    ) -> Result<HashMap<String, TermId>, String> {
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

#[derive(Debug)]
struct CnfProblem {
    clauses: Vec<Vec<i32>>,
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

impl CnfProblem {
    fn new() -> Self {
        Self {
            clauses: Vec::new(),
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

    #[cold]
    #[inline(never)]
    fn add_direct_assertion(&mut self, expr: &BoolExpr) {
        match expr {
            BoolExpr::Const(true) => {}
            BoolExpr::Const(false) => self.clauses.push(Vec::new()),
            BoolExpr::Atom(atom) => {
                let literal = self.atom_lit(atom.clone());
                self.clauses.push(vec![literal]);
            }
            BoolExpr::Not(child) => {
                let literal = self.encode_expr(child);
                self.clauses.push(vec![-literal]);
            }
            BoolExpr::And(children) => {
                for child in children {
                    self.add_direct_assertion(child);
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
    let equality_channeling = match env::var("EUF_VIPER_FINITE_EQUALITY_CHANNELING").as_deref() {
        Ok("0" | "off") => FiniteEqualityChanneling::Off,
        Ok("1" | "all") => FiniteEqualityChanneling::All,
        _ => FiniteEqualityChanneling::ValueOnly,
    };
    let predicate_channeling =
        env::var("EUF_VIPER_FINITE_PREDICATE_CHANNELING").as_deref() == Ok("1");
    add_finite_domain_axioms_with_options(
        cnf,
        arena,
        bool_problem,
        equality_channeling,
        predicate_channeling,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FiniteEqualityChanneling {
    Off,
    ValueOnly,
    All,
}

fn add_finite_domain_axioms_with_options(
    cnf: &mut CnfProblem,
    arena: &TermArena,
    bool_problem: &BoolProblem,
    equality_channeling: FiniteEqualityChanneling,
    predicate_channeling: bool,
) -> usize {
    let mut disequality_edges = HashSet::default();
    for assertion in &bool_problem.assertions {
        collect_mandatory_disequalities(assertion, &mut disequality_edges);
    }
    let domain = largest_small_disequality_clique(&disequality_edges, arena);
    if domain.len() < 3 || domain.len() > 8 {
        return 0;
    }
    let domain_set = domain.iter().copied().collect::<HashSet<_>>();

    let mut covered_terms = HashSet::default();
    for assertion in &bool_problem.assertions {
        collect_mandatory_coverages(assertion, &domain_set, &mut covered_terms);
    }

    let mut function_arities: HashMap<SymId, usize> = HashMap::default();
    for &term_id in &covered_terms {
        let term = &arena.terms[term_id];
        if !term.args.is_empty() && term.args.iter().all(|arg| domain_set.contains(arg)) {
            function_arities.insert(term.fun, term.args.len());
        }
    }
    let mut closed_functions = HashSet::default();
    for (function, arity) in function_arities {
        let Some(expected) = domain.len().checked_pow(arity as u32) else {
            continue;
        };
        let covered = covered_terms
            .iter()
            .filter(|&&term_id| {
                let term = &arena.terms[term_id];
                term.fun == function
                    && term.args.len() == arity
                    && term.args.iter().all(|arg| domain_set.contains(arg))
            })
            .count();
        if covered == expected {
            closed_functions.insert(function);
        }
    }
    if closed_functions.is_empty() {
        return 0;
    }

    let mut finite_terms = domain_set.clone();
    finite_terms.extend(covered_terms.iter().copied());
    loop {
        let mut changed = false;
        for &term_id in &arena.apps {
            let term = &arena.terms[term_id];
            if closed_functions.contains(&term.fun)
                && term.args.iter().all(|arg| finite_terms.contains(arg))
            {
                changed |= finite_terms.insert(term_id);
            }
        }
        if !changed {
            break;
        }
    }

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
        for &value in &domain {
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
            for &value in &domain {
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
            for &value in &domain {
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
            for &output in &domain {
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
    let mode = env::var("EUF_VIPER_CONGRUENCE_MODE").unwrap_or_else(|_| "auto".to_owned());
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
            match clause.as_slice() {
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
        best
    }

    fn preferred_values(&self, var: usize) -> [i8; 2] {
        if matches!(self.cnf.var_atoms[var], Some(BoolAtomKey::Eq(_, _))) {
            [1, -1]
        } else {
            [1, -1]
        }
    }
}

fn theory_conflict_clauses(
    cnf: &CnfProblem,
    arena: &TermArena,
    true_term: TermId,
    false_term: TermId,
    assignment: &[i8],
) -> Vec<Vec<i32>> {
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
    conflicts
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
    let conflicts = theory_conflict_clauses(cnf, arena, true_term, false_term, &assignment);
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
    let conflicts = theory_conflict_clauses(cnf, arena, true_term, false_term, &assignment);
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
    theory_conflict_clauses(cnf, arena, true_term, false_term, &assignment)
        .is_empty()
        .then_some(SolveResult::Sat)
}

fn solve_cadical_euf_refining(
    cnf: &CnfProblem,
    arena: &TermArena,
    true_term: TermId,
    false_term: TermId,
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

    let congruence_start = Instant::now();
    let congruence = congruence_axiom_clauses(cnf, arena);
    profile_phase(
        "cadical_refine_candidates",
        congruence_start,
        congruence.len(),
    );
    let canonical_values = canonical_value_terms(cnf, arena);
    let mut congruence_groups = HashMap::<(TermId, i8), Vec<usize>>::default();
    let mut clause_groups = Vec::with_capacity(congruence.len());
    for (index, clause) in congruence.iter().enumerate() {
        let group = congruence_clause_group(clause, cnf, arena, &canonical_values);
        if let Some(group) = group {
            congruence_groups.entry(group).or_default().push(index);
        }
        clause_groups.push(group);
    }
    let mut loaded_congruence = vec![false; congruence.len()];
    let mut learned_theory = HashSet::<Vec<i32>>::default();
    let max_rounds = env::var("EUF_VIPER_MAX_THEORY_ROUNDS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(10_000usize);
    let mut sat_time_ns = 0u128;
    let mut lemma_count = 0usize;

    for round in 1..=max_rounds {
        let sat_start = Instant::now();
        let result = solver.solve().ok()?;
        sat_time_ns += sat_start.elapsed().as_nanos();
        match result {
            RustSatResult::Unsat => {
                profile_measurement("cadical_refine_solve", sat_time_ns, round);
                return Some((SolveResult::Unsat, round, lemma_count));
            }
            RustSatResult::Interrupted => {
                profile_measurement("cadical_refine_solve", sat_time_ns, round);
                return None;
            }
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

        let conflicts = theory_conflict_clauses(cnf, arena, true_term, false_term, &assignment);
        if conflicts.is_empty() && added == 0 {
            profile_measurement("cadical_refine_solve", sat_time_ns, round);
            return Some((SolveResult::Sat, round, lemma_count));
        }
        for clause in conflicts {
            if learned_theory.insert(clause.clone()) {
                solver.add_clause(rustsat_clause(&clause)).ok()?;
                lemma_count += 1;
                added += 1;
            }
        }
        if added == 0 {
            profile_measurement("cadical_refine_solve", sat_time_ns, round);
            return None;
        }
    }

    profile_measurement("cadical_refine_solve", sat_time_ns, max_rounds);
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
        let conflicts = theory_conflict_clauses(cnf, arena, true_term, false_term, &assignment);
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
fn discover_certificate_theory_conflicts(
    cnf: &mut CnfProblem,
    arena: &TermArena,
    true_term: TermId,
    false_term: TermId,
    max_rounds: usize,
) -> Result<(usize, usize), String> {
    let mut solver = VarisatSolver::new();
    for clause in &cnf.clauses {
        let literals = clause
            .iter()
            .map(|literal| Lit::from_dimacs(*literal as isize))
            .collect::<Vec<_>>();
        solver.add_clause(&literals);
    }

    let mut learned = HashSet::<Vec<i32>>::default();
    for round in 1..=max_rounds {
        match solver.solve() {
            Ok(false) => return Ok((round, learned.len())),
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
        let conflicts = theory_conflict_clauses(cnf, arena, true_term, false_term, &assignment);
        if conflicts.is_empty() {
            return Err("input is satisfiable; no UNSAT certificate exists".to_owned());
        }

        let mut added = 0usize;
        for clause in conflicts {
            if learned.insert(clause.clone()) {
                let literals = clause
                    .iter()
                    .map(|literal| Lit::from_dimacs(*literal as isize))
                    .collect::<Vec<_>>();
                solver.add_clause(&literals);
                cnf.clauses.push(clause);
                added += 1;
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
    for assertion in &bool_problem.assertions {
        cnf.add_assertion(assertion);
    }
    let base_count = cnf.clauses.len();
    let transitivity = equality_transitivity_clauses(&cnf, problem.arena.terms.len());
    let transitivity_count = transitivity.len();
    cnf.clauses.extend(transitivity);
    let congruence = congruence_axiom_clauses(&cnf, &problem.arena);
    let congruence_count = congruence.len();
    cnf.clauses.extend(congruence);

    let (theory_rounds, conflict_count) = discover_certificate_theory_conflicts(
        &mut cnf,
        &problem.arena,
        bool_problem.true_term,
        bool_problem.false_term,
        max_rounds,
    )?;
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
        format: "euf-viper-euf-cnf-v1",
        result: "unsat",
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
    let manifest_file = fs::File::create(&manifest_path)
        .map_err(|error| format!("failed to create {}: {error}", manifest_path.display()))?;
    let mut manifest_writer = BufWriter::new(manifest_file);
    serde_json::to_writer_pretty(&mut manifest_writer, &manifest)
        .map_err(|error| format!("failed to write {}: {error}", manifest_path.display()))?;
    writeln!(manifest_writer)
        .map_err(|error| format!("failed to finish {}: {error}", manifest_path.display()))?;

    println!("unsat");
    eprintln!("dimacs={}", dimacs_path.display());
    eprintln!("proof={}", proof_path.display());
    eprintln!("manifest={}", manifest_path.display());
    eprintln!("cnf_vars={}", cnf.var_count());
    eprintln!("cnf_clauses={}", cnf.clauses.len());
    eprintln!("theory_rounds={theory_rounds}");
    eprintln!("theory_conflicts={conflict_count}");
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

fn solve_problem(problem: Problem) -> SolveReport {
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
        if bool_problem.unsupported.is_empty() {
            if let Some((result, cnf_vars, cnf_clauses, search_nodes, sat_calls, theory_lemmas)) =
                solve_bool_problem(&problem.arena, bool_problem)
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

#[cold]
#[inline(never)]
fn solve_dynamic_full_ackermann(
    arena: &TermArena,
    bool_problem: &BoolProblem,
) -> (CnfProblem, EagerSolveOutcome) {
    let direct_cnf_start = Instant::now();
    let mut completed = CnfProblem::new();
    for assertion in &bool_problem.assertions {
        completed.add_direct_assertion(assertion);
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
) -> Option<(SolveResult, usize, usize, usize, usize, usize)> {
    let cnf_start = Instant::now();
    let mut cnf = CnfProblem::new();
    for assertion in &bool_problem.assertions {
        cnf.add_assertion(assertion);
    }
    profile_phase("cnf", cnf_start, cnf.clauses.len());
    let backend = env::var("EUF_VIPER_BACKEND").unwrap_or_else(|_| "auto".to_owned());
    if matches!(
        backend.as_str(),
        "auto" | "varisat" | "kissat" | "cadical" | "cadical-refine"
    ) {
        let finite_added = if matches!(backend.as_str(), "auto" | "cadical" | "cadical-refine")
            || env::var("EUF_VIPER_FINITE_DOMAIN").as_deref() == Ok("1")
        {
            let finite_start = Instant::now();
            let added = add_finite_domain_axioms(&mut cnf, arena, bool_problem);
            profile_phase("finite_domain", finite_start, added);
            added
        } else {
            0
        };
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
                    if dynamic_full_ackermann_for_shape(
                        full_ackermann_setting.as_deref(),
                        cnf.clauses.len(),
                        arena.apps.len(),
                        finite_added,
                    ) {
                        profile_measurement("invalid_model_dynamic_ackermann", 1, conflict_count);
                        let (completed, completed_outcome) =
                            solve_dynamic_full_ackermann(arena, bool_problem);
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
        Sexp::Atom(text) => Some(text.as_str()),
        Sexp::List(_) => None,
    }
}

fn is_positive_or(sexp: &Sexp) -> bool {
    matches!(sexp, Sexp::List(items) if items.first().and_then(atom_text) == Some("or"))
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
                while i < bytes.len() {
                    match bytes[i] {
                        b'\\' if i + 1 < bytes.len() => {
                            i += 1;
                            atom.push(bytes[i] as char);
                            i += 1;
                        }
                        b'|' => {
                            i += 1;
                            break;
                        }
                        c => {
                            atom.push(c as char);
                            i += 1;
                        }
                    }
                }
                toks.push(Tok::Atom(atom));
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
    let toks = tokenize(input)?;
    let mut pos = 0;
    let mut sexps = Vec::new();
    while pos < toks.len() {
        sexps.push(parse_one(&toks, &mut pos)?);
    }
    Ok(sexps)
}

fn parse_one(toks: &[Tok], pos: &mut usize) -> Result<Sexp, String> {
    if *pos >= toks.len() {
        return Err("unexpected end of token stream".to_owned());
    }
    match &toks[*pos] {
        Tok::Atom(text) => {
            *pos += 1;
            Ok(Sexp::Atom(text.clone()))
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
    let sexps = parse_sexps(input)?;
    let mut ctx = ParseCtx::default();
    ctx.preprocess_branch_intersections = sexps
        .iter()
        .filter(|sexp| {
            matches!(
                sexp,
                Sexp::List(items) if items.first().and_then(atom_text) == Some("assert")
            )
        })
        .take(2)
        .count()
        == 1;
    for sexp in &sexps {
        ctx.parse_command(sexp)?;
    }
    Ok(ctx.finish())
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
    let input = fs::read_to_string(path).map_err(|e| format!("failed to read {path}: {e}"))?;
    let start = Instant::now();
    let parse_start = Instant::now();
    let problem = parse_problem(&input)?;
    profile_phase("parse", parse_start, input.len());
    let report = solve_problem(problem);
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
    let input = fs::read(path).map_err(|e| format!("failed to read {path}: {e}"))?;
    let use_euf = structural_router_prefers_euf(&input);
    if env::var_os("EUF_VIPER_PORTFOLIO_TRACE").is_some() {
        eprintln!(
            "portfolio_route={}",
            if use_euf { "euf-viper" } else { "yices2" }
        );
    }
    if use_euf {
        return solve_file(path, with_stats);
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
        let report = solve_problem(problem);
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
        let report = solve_problem(problem);
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
        solve_problem(parse_problem(input).unwrap()).result
    }

    fn solve_text_varisat(input: &str) -> SolveResult {
        let problem = parse_problem(input).unwrap();
        let bool_problem = problem.bool_problem.as_ref().unwrap();
        assert!(bool_problem.unsupported.is_empty());
        let mut cnf = CnfProblem::new();
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

        let report = solve_problem(problem);
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
            add_finite_domain_axioms_with_options(
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
        assert_eq!(solve_problem(problem).result, SolveResult::Unsat);
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
        assert_eq!(solve_problem(problem).result, SolveResult::Unsat);
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
    fn generated_chain_is_unsat() {
        let input = gen_chain(32, true);
        assert_eq!(solve_text(&input), SolveResult::Unsat);
    }
}
