use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::process;
use std::time::Instant;

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
    contradiction: bool,
}

#[derive(Debug, Default)]
struct ParseCtx {
    symbols: SymbolInterner,
    arena: TermArena,
    eqs: Vec<(TermId, TermId)>,
    diseqs: Vec<(TermId, TermId)>,
    unsupported: Vec<String>,
    contradiction: bool,
}

impl ParseCtx {
    fn finish(self) -> Problem {
        Problem {
            arena: self.arena,
            eqs: self.eqs,
            diseqs: self.diseqs,
            unsupported: self.unsupported,
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
                let mut env = HashMap::new();
                self.collect_formula(&items[1], true, &mut env)?;
            }
            "declare-fun" => {
                if let Some(name) = items.get(1).and_then(atom_text) {
                    self.symbols.intern(name);
                }
            }
            "declare-const" => {
                if let Some(name) = items.get(1).and_then(atom_text) {
                    let sym = self.symbols.intern(name);
                    self.arena.intern(sym, Vec::new());
                }
            }
            "set-logic" | "set-option" | "set-info" | "declare-sort" | "check-sat" | "exit"
            | "get-model" | "get-value" => {}
            "define-fun" | "define-fun-rec" | "define-funs-rec" => {
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
                    "and" if polarity => {
                        for child in &items[1..] {
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
                        let added = self.add_or_common_equalities(&items[1..], env)?;
                        self.add_unsupported(format!(
                            "positive or needs DPLL(T); extracted {added} common EUF equalities"
                        ));
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

    fn add_or_common_equalities(
        &mut self,
        branches: &[Sexp],
        env: &mut HashMap<String, TermId>,
    ) -> Result<usize, String> {
        if branches.is_empty() {
            return Ok(0);
        }

        let mut parsed_branches = Vec::with_capacity(branches.len());
        for branch in branches {
            let mut local = env.clone();
            let Some(eqs) = self.collect_branch_equalities(branch, true, &mut local)? else {
                return Ok(0);
            };
            parsed_branches.push(eqs);
        }

        let term_count = self.arena.terms.len();
        let mut branch_roots = Vec::with_capacity(parsed_branches.len());
        for eqs in &parsed_branches {
            let mut uf = UnionFind::new(term_count);
            for &(a, b) in &self.eqs {
                uf.union(a, b);
            }
            for &(a, b) in eqs {
                uf.union(a, b);
            }
            congruence_closure(&self.arena, &mut uf);
            branch_roots.push(
                (0..term_count)
                    .map(|term_id| uf.root_const(term_id))
                    .collect::<Vec<_>>(),
            );
        }

        let mut first_classes: HashMap<usize, Vec<TermId>> = HashMap::new();
        for term_id in 0..term_count {
            first_classes
                .entry(branch_roots[0][term_id])
                .or_default()
                .push(term_id);
        }

        let mut existing = HashSet::new();
        for &(a, b) in &self.eqs {
            existing.insert(normalized_pair(a, b));
        }

        let mut added = 0usize;
        const COMMON_PAIR_LIMIT: usize = 100_000;
        'classes: for class in first_classes.values() {
            for i in 0..class.len() {
                for j in (i + 1)..class.len() {
                    let a = class[i];
                    let b = class[j];
                    let common = branch_roots.iter().all(|roots| roots[a] == roots[b]);
                    if common && existing.insert(normalized_pair(a, b)) {
                        self.eqs.push((a, b));
                        added += 1;
                        if added >= COMMON_PAIR_LIMIT {
                            break 'classes;
                        }
                    }
                }
            }
        }
        Ok(added)
    }

    fn collect_branch_equalities(
        &mut self,
        sexp: &Sexp,
        polarity: bool,
        env: &mut HashMap<String, TermId>,
    ) -> Result<Option<Vec<(TermId, TermId)>>, String> {
        let mut eqs = Vec::new();
        let ok = self.collect_branch_equalities_into(sexp, polarity, env, &mut eqs)?;
        Ok(ok.then_some(eqs))
    }

    fn collect_branch_equalities_into(
        &mut self,
        sexp: &Sexp,
        polarity: bool,
        env: &mut HashMap<String, TermId>,
        eqs: &mut Vec<(TermId, TermId)>,
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
                    "and" if polarity => {
                        for child in &items[1..] {
                            if !self.collect_branch_equalities_into(child, true, env, eqs)? {
                                return Ok(false);
                            }
                        }
                        Ok(true)
                    }
                    "or" if !polarity => {
                        for child in &items[1..] {
                            if !self.collect_branch_equalities_into(child, false, env, eqs)? {
                                return Ok(false);
                            }
                        }
                        Ok(true)
                    }
                    "not" if items.len() == 2 => {
                        self.collect_branch_equalities_into(&items[1], !polarity, env, eqs)
                    }
                    "=" if polarity => {
                        let terms = self.parse_terms(&items[1..], env)?;
                        if terms.len() < 2 {
                            return Ok(false);
                        }
                        let first = terms[0];
                        for &term in &terms[1..] {
                            eqs.push((first, term));
                        }
                        Ok(true)
                    }
                    "distinct" if !polarity && items.len() == 3 => {
                        let terms = self.parse_terms(&items[1..], env)?;
                        eqs.push((terms[0], terms[1]));
                        Ok(true)
                    }
                    "distinct" if polarity => {
                        self.parse_terms(&items[1..], env)?;
                        Ok(true)
                    }
                    "let" if items.len() == 3 => {
                        let mut local = self.extend_let_env(&items[1], env)?;
                        self.collect_branch_equalities_into(&items[2], polarity, &mut local, eqs)
                    }
                    _ => Ok(false),
                }
            }
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
    };

    if problem.contradiction {
        return SolveReport {
            result: SolveResult::Unsat,
            stats: stats_base,
        };
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

fn congruence_closure(arena: &TermArena, uf: &mut UnionFind) -> (usize, usize) {
    let mut passes = 0;
    let mut total_merges = 0;
    loop {
        passes += 1;
        let mut changed = false;
        let mut sigs: HashMap<Signature, TermId> = HashMap::with_capacity(arena.apps.len() * 2);
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
        eprintln!("elapsed_ns={}", elapsed.as_nanos());
    }
}

fn solve_file(path: &str, with_stats: bool) -> Result<i32, String> {
    let input = fs::read_to_string(path).map_err(|e| format!("failed to read {path}: {e}"))?;
    let start = Instant::now();
    let problem = parse_problem(&input)?;
    let report = solve_problem(problem);
    let elapsed = start.elapsed();
    print_report(&report, elapsed, with_stats);
    Ok(match report.result {
        SolveResult::Unsupported(_) => 3,
        _ => 0,
    })
}

fn stats_file(path: &str) -> Result<i32, String> {
    let input = fs::read_to_string(path).map_err(|e| format!("failed to read {path}: {e}"))?;
    let problem = parse_problem(&input)?;
    println!("terms {}", problem.arena.terms.len());
    println!("apps {}", problem.arena.app_count());
    println!("eqs {}", problem.eqs.len());
    println!("diseqs {}", problem.diseqs.len());
    println!("unsupported {}", problem.unsupported.len());
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

fn nested_term(base: &str, depth: usize) -> String {
    let mut text = base.to_owned();
    for d in 0..depth {
        text = format!("(f{d} {text})");
    }
    text
}

fn gen_cmd(args: &[String]) -> Result<i32, String> {
    if args.len() < 2 {
        return Err("usage: euf-viper gen <chain|grid> ...".to_owned());
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

fn parse_usize(value: Option<&String>, label: &str) -> Result<usize, String> {
    let value = value.ok_or_else(|| format!("missing {label}"))?;
    value
        .parse::<usize>()
        .map_err(|e| format!("invalid {label}: {e}"))
}

fn usage() -> &'static str {
    "usage:
  euf-viper solve [--stats] FILE
  euf-viper stats FILE
  euf-viper gen chain N [--sat]
  euf-viper gen grid WIDTH DEPTH
  euf-viper bench [--cases N] [--size N]"
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
        "stats" => {
            let file = args.get(2).ok_or_else(|| usage().to_owned())?;
            stats_file(file)
        }
        "gen" => gen_cmd(&args[1..]),
        "bench" => bench_cmd(&args[1..]),
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

    fn solve_text(input: &str) -> SolveResult {
        solve_problem(parse_problem(input).unwrap()).result
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
    fn rejects_positive_disjunction() {
        let input = "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun a () U)
            (declare-fun b () U)
            (assert (or (= a b) (distinct a b)))
            (check-sat)
        ";
        assert!(matches!(solve_text(input), SolveResult::Unsupported(_)));
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
        assert_eq!(solve_text(input), SolveResult::Unsat);
    }

    #[test]
    fn generated_chain_is_unsat() {
        let input = gen_chain(32, true);
        assert_eq!(solve_text(&input), SolveResult::Unsat);
    }
}
