use super::{
    BOOL_SORT, BoolAtomKey, BoolExpr, ParseCtx, Problem, ScopedLetMode, Sexp, SortId, SymId, TermId,
};
use std::borrow::Cow;

const MAX_PARSE_NESTING: usize = 512;
const SNAPSHOT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy)]
enum RawEvent<'input> {
    Open,
    Close,
    Symbol(RawSymbol<'input>),
}

#[derive(Debug, Clone, Copy)]
struct RawSymbol<'input> {
    text: &'input str,
    quoted: bool,
    escaped: bool,
    string: bool,
}

#[derive(Clone)]
struct RawScanner<'input> {
    input: &'input str,
    pos: usize,
    depth: usize,
    finished: bool,
}

impl<'input> RawScanner<'input> {
    fn new(input: &'input str) -> Self {
        Self {
            input,
            pos: 0,
            depth: 0,
            finished: false,
        }
    }

    fn next_event(&mut self) -> Result<Option<RawEvent<'input>>, String> {
        if self.finished {
            return Ok(None);
        }
        let bytes = self.input.as_bytes();
        while self.pos < bytes.len() {
            match bytes[self.pos] {
                b' ' | b'\n' | b'\r' | b'\t' => self.pos += 1,
                b';' => {
                    while self.pos < bytes.len() && bytes[self.pos] != b'\n' {
                        self.pos += 1;
                    }
                }
                b'(' => {
                    self.pos += 1;
                    self.depth += 1;
                    if self.depth > MAX_PARSE_NESTING {
                        self.finished = true;
                        return Err(nesting_limit_error());
                    }
                    return Ok(Some(RawEvent::Open));
                }
                b')' => {
                    if self.depth == 0 {
                        self.finished = true;
                        return Err("unexpected ')'".to_owned());
                    }
                    self.pos += 1;
                    self.depth -= 1;
                    return Ok(Some(RawEvent::Close));
                }
                b'|' => return self.scan_quoted_symbol().map(Some),
                b'"' => return Ok(Some(self.scan_string())),
                _ => return Ok(Some(self.scan_simple_symbol())),
            }
        }

        self.finished = true;
        if self.depth == 0 {
            Ok(None)
        } else {
            Err("unclosed '('".to_owned())
        }
    }

    fn scan_quoted_symbol(&mut self) -> Result<RawEvent<'input>, String> {
        let bytes = self.input.as_bytes();
        let start = self.pos + 1;
        let mut escaped = false;
        self.pos = start;
        while self.pos < bytes.len() {
            match bytes[self.pos] {
                b'\\' => {
                    escaped = true;
                    self.pos += 1;
                    if self.pos >= bytes.len() {
                        self.finished = true;
                        return Err("unterminated quoted symbol".to_owned());
                    }
                    let escaped_char = self.input[self.pos..]
                        .chars()
                        .next()
                        .expect("scanner position is a UTF-8 boundary after an escape");
                    self.pos += escaped_char.len_utf8();
                }
                b'|' => {
                    let end = self.pos;
                    self.pos += 1;
                    return Ok(RawEvent::Symbol(RawSymbol {
                        text: &self.input[start..end],
                        quoted: true,
                        escaped,
                        string: false,
                    }));
                }
                _ => self.pos += 1,
            }
        }
        self.finished = true;
        Err("unterminated quoted symbol".to_owned())
    }

    fn scan_string(&mut self) -> RawEvent<'input> {
        let bytes = self.input.as_bytes();
        let start = self.pos;
        self.pos += 1;
        while self.pos < bytes.len() {
            match bytes[self.pos] {
                b'\\' if self.pos + 1 < bytes.len() => self.pos += 2,
                b'"' => {
                    self.pos += 1;
                    break;
                }
                _ => self.pos += 1,
            }
        }
        RawEvent::Symbol(RawSymbol {
            text: &self.input[start..self.pos],
            quoted: false,
            escaped: false,
            string: true,
        })
    }

    fn scan_simple_symbol(&mut self) -> RawEvent<'input> {
        let bytes = self.input.as_bytes();
        let start = self.pos;
        while self.pos < bytes.len()
            && !matches!(
                bytes[self.pos],
                b' ' | b'\n' | b'\r' | b'\t' | b'(' | b')' | b';'
            )
        {
            self.pos += 1;
        }
        RawEvent::Symbol(RawSymbol {
            text: &self.input[start..self.pos],
            quoted: false,
            escaped: false,
            string: false,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Event<'input> {
    Open,
    Close,
    Symbol(Symbol<'input>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Symbol<'input> {
    text: Cow<'input, str>,
    quoted: bool,
}

#[derive(Clone)]
struct Scanner<'input> {
    raw: RawScanner<'input>,
}

impl<'input> Scanner<'input> {
    fn new(input: &'input str) -> Self {
        Self {
            raw: RawScanner::new(input),
        }
    }

    fn next_event(&mut self) -> Result<Option<Event<'input>>, String> {
        self.raw.next_event().map(|event| {
            event.map(|event| match event {
                RawEvent::Open => Event::Open,
                RawEvent::Close => Event::Close,
                RawEvent::Symbol(symbol) => Event::Symbol(Symbol {
                    text: if symbol.quoted && (symbol.escaped || !symbol.text.is_ascii()) {
                        Cow::Owned(decode_tree_quoted_symbol(symbol.text))
                    } else {
                        Cow::Borrowed(symbol.text)
                    },
                    quoted: symbol.quoted && !symbol.string,
                }),
            })
        })
    }
}

fn decode_tree_quoted_symbol(raw: &str) -> String {
    let mut decoded = String::with_capacity(raw.len());
    let bytes = raw.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            index += 1;
            debug_assert!(index < bytes.len());
        }
        decoded.push(bytes[index] as char);
        index += 1;
    }
    decoded
}

fn nesting_limit_error() -> String {
    format!("SMT-LIB nesting exceeds parser safety limit of {MAX_PARSE_NESTING}")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Prepass {
    top_level_assertions: u8,
}

fn structural_prepass(input: &str) -> Result<Prepass, String> {
    let mut scanner = RawScanner::new(input);
    let mut depth = 0usize;
    let mut awaiting_top_level_head = false;
    let mut top_level_assertions = 0u8;

    while let Some(event) = scanner.next_event()? {
        match event {
            RawEvent::Open => {
                depth += 1;
                if depth == 1 {
                    awaiting_top_level_head = true;
                } else if awaiting_top_level_head {
                    awaiting_top_level_head = false;
                }
            }
            RawEvent::Close => {
                if depth == 1 {
                    awaiting_top_level_head = false;
                }
                depth -= 1;
            }
            RawEvent::Symbol(symbol) => {
                if depth == 1 && awaiting_top_level_head {
                    if !symbol.quoted && !symbol.string && symbol.text == "assert" {
                        top_level_assertions = top_level_assertions.saturating_add(1).min(2);
                    }
                    awaiting_top_level_head = false;
                }
            }
        }
    }

    Ok(Prepass {
        top_level_assertions,
    })
}

struct StreamingSexpParser<'input> {
    scanner: Scanner<'input>,
}

impl<'input> StreamingSexpParser<'input> {
    fn new(input: &'input str) -> Self {
        Self {
            scanner: Scanner::new(input),
        }
    }

    fn next_sexp(&mut self) -> Result<Option<Sexp>, String> {
        let Some(first) = self.scanner.next_event()? else {
            return Ok(None);
        };
        match first {
            Event::Symbol(symbol) => Ok(Some(symbol_to_sexp(symbol))),
            Event::Close => Err("unexpected ')'".to_owned()),
            Event::Open => self.parse_list().map(Some),
        }
    }

    fn parse_list(&mut self) -> Result<Sexp, String> {
        let mut stack = vec![Vec::new()];
        loop {
            match self.scanner.next_event()? {
                Some(Event::Open) => stack.push(Vec::new()),
                Some(Event::Symbol(symbol)) => {
                    stack
                        .last_mut()
                        .expect("the outer list remains on the stack")
                        .push(symbol_to_sexp(symbol));
                }
                Some(Event::Close) => {
                    let list = Sexp::List(stack.pop().expect("a close has a matching open"));
                    if let Some(parent) = stack.last_mut() {
                        parent.push(list);
                    } else {
                        return Ok(list);
                    }
                }
                None => return Err("unclosed '('".to_owned()),
            }
        }
    }
}

fn symbol_to_sexp(symbol: Symbol<'_>) -> Sexp {
    if symbol.quoted {
        Sexp::QuotedAtom(symbol.text.into_owned())
    } else {
        Sexp::Atom(symbol.text.into_owned())
    }
}

fn parse_stream_problem(
    input: &str,
    scoped_let_mode: ScopedLetMode,
) -> Result<(Problem, Vec<String>), String> {
    let prepass = structural_prepass(input)?;
    let bounded_let_count = super::bounded_lexical_let_count(input);
    let scoped_let_selected = super::scoped_let_selected(scoped_let_mode, bounded_let_count);
    super::profile_scoped_let(scoped_let_mode, bounded_let_count, scoped_let_selected);

    let mut parser = StreamingSexpParser::new(input);
    let mut ctx = ParseCtx::new(scoped_let_selected);
    ctx.preprocess_branch_intersections = prepass.top_level_assertions == 1;
    while let Some(sexp) = parser.next_sexp()? {
        ctx.parse_command(&sexp)?;
    }
    Ok(ctx.finish_with_symbol_names())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FunctionSnapshot {
    symbol: SymId,
    arg_sorts: Vec<SortId>,
    result_sort: SortId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BoolProblemSnapshot {
    assertions: Vec<BoolExpr>,
    unsupported: Vec<String>,
    true_term: TermId,
    false_term: TermId,
    data_terms: Vec<TermId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TypedSemanticSnapshot {
    schema_version: u32,
    symbol_names: Vec<String>,
    sort_names: Vec<String>,
    sort_bindings: Vec<(SymId, SortId)>,
    functions: Vec<FunctionSnapshot>,
    terms: Vec<(SymId, Vec<TermId>, SortId)>,
    applications: Vec<TermId>,
    interned: Vec<(SymId, Vec<TermId>, TermId)>,
    equalities: Vec<(TermId, TermId)>,
    disequalities: Vec<(TermId, TermId)>,
    unsupported: Vec<String>,
    bool_problem: Option<BoolProblemSnapshot>,
    contradiction: bool,
}

impl TypedSemanticSnapshot {
    fn from_problem(problem: &Problem, symbol_names: &[String]) -> Self {
        let mut sort_bindings = problem
            .sorts
            .ids
            .iter()
            .map(|(&symbol, &sort)| (symbol, sort))
            .collect::<Vec<_>>();
        sort_bindings.sort_unstable_by_key(|&(symbol, _)| symbol);

        let functions = problem
            .fun_decls
            .slots
            .iter()
            .enumerate()
            .filter_map(|(symbol, declaration)| {
                declaration.as_ref().map(|declaration| FunctionSnapshot {
                    symbol: symbol as SymId,
                    arg_sorts: declaration.arg_sorts.clone(),
                    result_sort: declaration.result_sort,
                })
            })
            .collect();

        let mut interned = problem
            .arena
            .interned
            .iter()
            .map(|(key, &term)| (key.fun, key.args.clone(), term))
            .collect::<Vec<_>>();
        interned.sort_unstable();

        Self {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            symbol_names: symbol_names.to_vec(),
            sort_names: problem.sorts.names.clone(),
            sort_bindings,
            functions,
            terms: problem
                .arena
                .terms
                .iter()
                .map(|term| (term.fun, term.args.clone(), term.sort))
                .collect(),
            applications: problem.arena.apps.clone(),
            interned,
            equalities: problem.eqs.clone(),
            disequalities: problem.diseqs.clone(),
            unsupported: problem.unsupported.clone(),
            bool_problem: problem
                .bool_problem
                .as_ref()
                .map(|bool_problem| BoolProblemSnapshot {
                    assertions: bool_problem.assertions.clone(),
                    unsupported: bool_problem.unsupported.clone(),
                    true_term: bool_problem.true_term,
                    false_term: bool_problem.false_term,
                    data_terms: bool_problem.data_terms.clone(),
                }),
            contradiction: problem.contradiction,
        }
    }

    fn fingerprint(&self) -> u64 {
        let rendered = format!("{self:?}");
        rendered.bytes().fold(0xcbf29ce484222325, |hash, byte| {
            (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3)
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParityReport {
    snapshot_fingerprint: u64,
    symbols: usize,
    sorts: usize,
    functions: usize,
    terms: usize,
    applications: usize,
    assertions: usize,
    bool_data_terms: usize,
    unsupported_diagnostics: usize,
}

impl ParityReport {
    fn from_snapshot(snapshot: &TypedSemanticSnapshot) -> Self {
        let (assertions, bool_data_terms, bool_unsupported) =
            snapshot.bool_problem.as_ref().map_or((0, 0, 0), |problem| {
                (
                    problem.assertions.len(),
                    problem.data_terms.len(),
                    problem.unsupported.len(),
                )
            });
        Self {
            snapshot_fingerprint: snapshot.fingerprint(),
            symbols: snapshot.symbol_names.len(),
            sorts: snapshot.sort_names.len(),
            functions: snapshot.functions.len(),
            terms: snapshot.terms.len(),
            applications: snapshot.applications.len(),
            assertions,
            bool_data_terms,
            unsupported_diagnostics: snapshot.unsupported.len() + bool_unsupported,
        }
    }

    fn json_line(&self) -> String {
        format!(
            "{{\"schema\":\"euf-viper.typed-parser-parity.v1\",\"status\":\"match\",\"tree_well_sorted\":true,\"stream_well_sorted\":true,\"fallback\":false,\"snapshot_fnv1a64\":\"{:016x}\",\"symbols\":{},\"sorts\":{},\"functions\":{},\"terms\":{},\"applications\":{},\"assertions\":{},\"bool_data_terms\":{},\"unsupported_diagnostics\":{}}}",
            self.snapshot_fingerprint,
            self.symbols,
            self.sorts,
            self.functions,
            self.terms,
            self.applications,
            self.assertions,
            self.bool_data_terms,
            self.unsupported_diagnostics,
        )
    }
}

pub(super) fn check_typed_parity(
    input: &str,
    scoped_let_mode: ScopedLetMode,
) -> Result<(), String> {
    let report = typed_parity_report(input, scoped_let_mode)?;
    println!("{}", report.json_line());
    Ok(())
}

fn typed_parity_report(
    input: &str,
    scoped_let_mode: ScopedLetMode,
) -> Result<ParityReport, String> {
    let (tree, tree_symbol_names) =
        super::parse_problem_with_scoped_let_mode_and_symbols(input, scoped_let_mode)
            .map_err(|error| format!("tree parser rejected input: {error}"))?;
    if !problem_is_well_sorted(&tree, &tree_symbol_names) {
        return Err("tree parser produced a non-well-sorted typed problem".to_owned());
    }

    let (stream, stream_symbol_names) = parse_stream_problem(input, scoped_let_mode)
        .map_err(|error| format!("stream parser rejected tree-accepted input: {error}"))?;
    if !problem_is_well_sorted(&stream, &stream_symbol_names) {
        return Err("stream parser produced a non-well-sorted typed problem".to_owned());
    }

    let tree_snapshot = TypedSemanticSnapshot::from_problem(&tree, &tree_symbol_names);
    let stream_snapshot = TypedSemanticSnapshot::from_problem(&stream, &stream_symbol_names);
    if tree_snapshot != stream_snapshot {
        return Err(format!(
            "typed parser semantic mismatch: tree={:016x}, stream={:016x}",
            tree_snapshot.fingerprint(),
            stream_snapshot.fingerprint()
        ));
    }
    Ok(ParityReport::from_snapshot(&tree_snapshot))
}

fn valid_term(problem: &Problem, term: TermId) -> bool {
    term < problem.arena.terms.len()
}

fn same_sort(problem: &Problem, left: TermId, right: TermId) -> bool {
    valid_term(problem, left)
        && valid_term(problem, right)
        && problem.arena.terms[left].sort == problem.arena.terms[right].sort
}

fn bool_expr_is_well_sorted(problem: &Problem, expression: &BoolExpr) -> bool {
    match expression {
        BoolExpr::Const(_) => true,
        BoolExpr::Atom(BoolAtomKey::Eq(left, right)) => same_sort(problem, *left, *right),
        BoolExpr::Atom(BoolAtomKey::BoolTerm(term)) => {
            valid_term(problem, *term) && problem.arena.terms[*term].sort == BOOL_SORT
        }
        BoolExpr::Not(child) => bool_expr_is_well_sorted(problem, child),
        BoolExpr::And(children) | BoolExpr::Or(children) | BoolExpr::Iff(children) => children
            .iter()
            .all(|child| bool_expr_is_well_sorted(problem, child)),
        BoolExpr::Ite(condition, then_expression, else_expression) => {
            bool_expr_is_well_sorted(problem, condition)
                && bool_expr_is_well_sorted(problem, then_expression)
                && bool_expr_is_well_sorted(problem, else_expression)
        }
    }
}

fn problem_is_well_sorted(problem: &Problem, symbol_names: &[String]) -> bool {
    let valid_sort = |sort: SortId| (sort.0 as usize) < problem.sorts.names.len();
    if symbol_names.len() < problem.fun_decls.slots.len()
        || problem.sorts.ids.iter().any(|(&symbol, &sort)| {
            !valid_sort(sort)
                || symbol as usize >= symbol_names.len()
                || problem.sorts.names[sort.0 as usize] != symbol_names[symbol as usize]
        })
        || problem.fun_decls.slots.iter().any(|declaration| {
            declaration.as_ref().is_some_and(|declaration| {
                !valid_sort(declaration.result_sort)
                    || declaration.arg_sorts.iter().any(|&sort| !valid_sort(sort))
            })
        })
    {
        return false;
    }

    for (term_id, term) in problem.arena.terms.iter().enumerate() {
        let Some(declaration) = problem.fun_decls.get(term.fun) else {
            return false;
        };
        if declaration.result_sort != term.sort
            || declaration.arg_sorts.len() != term.args.len()
            || term
                .args
                .iter()
                .zip(&declaration.arg_sorts)
                .any(|(&argument, &expected_sort)| {
                    !valid_term(problem, argument)
                        || problem.arena.terms[argument].sort != expected_sort
                })
            || problem.arena.interned.get(&super::TermKey {
                fun: term.fun,
                args: term.args.clone(),
            }) != Some(&term_id)
        {
            return false;
        }
    }

    let expected_applications = problem
        .arena
        .terms
        .iter()
        .enumerate()
        .filter_map(|(term, value)| (!value.args.is_empty()).then_some(term))
        .collect::<Vec<_>>();
    if problem.arena.interned.len() != problem.arena.terms.len()
        || problem.arena.apps != expected_applications
        || problem
            .eqs
            .iter()
            .chain(&problem.diseqs)
            .any(|&(left, right)| !same_sort(problem, left, right))
    {
        return false;
    }

    if let Some(bool_problem) = &problem.bool_problem {
        if !valid_term(problem, bool_problem.true_term)
            || !valid_term(problem, bool_problem.false_term)
            || problem.arena.terms[bool_problem.true_term].sort != BOOL_SORT
            || problem.arena.terms[bool_problem.false_term].sort != BOOL_SORT
            || bool_problem.data_terms.iter().any(|&term| {
                !valid_term(problem, term) || problem.arena.terms[term].sort != BOOL_SORT
            })
            || bool_problem
                .assertions
                .iter()
                .any(|assertion| !bool_expr_is_well_sorted(problem, assertion))
        {
            return false;
        }
    }

    problem.terms_are_well_sorted()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_parity(input: &str) -> ParityReport {
        for mode in [ScopedLetMode::Off, ScopedLetMode::On] {
            typed_parity_report(input, mode).unwrap();
        }
        typed_parity_report(input, ScopedLetMode::Off).unwrap()
    }

    fn assert_matching_error(input: &str) {
        for mode in [ScopedLetMode::Off, ScopedLetMode::On] {
            let tree = super::super::parse_problem_with_scoped_let_mode(input, mode).unwrap_err();
            let stream = parse_stream_problem(input, mode).unwrap_err();
            assert_eq!(stream, tree, "input: {input:?}");
        }
    }

    #[test]
    fn multiline_quoted_symbols_and_annotations_match() {
        assert_parity(include_str!(
            "../tests/fixtures/parser_parity/multiline_quoted_annotations.smt2"
        ));
    }

    #[test]
    fn simultaneous_and_nested_lets_match() {
        assert_parity(include_str!(
            "../tests/fixtures/parser_parity/nested_lets.smt2"
        ));
    }

    #[test]
    fn bool_as_data_and_mixed_sorts_match() {
        let report = assert_parity(include_str!(
            "../tests/fixtures/parser_parity/bool_data_mixed_sorts.smt2"
        ));
        assert!(report.bool_data_terms > 0);
        assert_eq!(report.sorts, 3);
    }

    #[test]
    fn snapshot_binds_sort_and_function_signatures() {
        let input = include_str!("../tests/fixtures/parser_parity/declarations_signatures.smt2");
        let (problem, symbol_names) = parse_stream_problem(input, ScopedLetMode::Off).unwrap();
        let snapshot = TypedSemanticSnapshot::from_problem(&problem, &symbol_names);
        assert_eq!(snapshot.sort_names, ["Bool", "A", "B"]);
        let g = snapshot
            .functions
            .iter()
            .find(|function| snapshot.symbol_names[function.symbol as usize] == "g")
            .unwrap();
        assert_eq!(g.arg_sorts, [SortId(1), SortId(2), BOOL_SORT]);
        assert_eq!(g.result_sort, SortId(2));
        assert!(problem_is_well_sorted(&problem, &symbol_names));
    }

    #[test]
    fn unsupported_diagnostics_are_not_a_fallback() {
        let report = assert_parity(include_str!(
            "../tests/fixtures/parser_parity/unsupported_command.smt2"
        ));
        assert_eq!(report.unsupported_diagnostics, 1);
        assert!(report.json_line().contains("\"fallback\":false"));
    }

    #[test]
    fn malformed_inputs_have_exact_error_parity() {
        for input in [
            ")",
            "(",
            "|unterminated",
            "(assert true))",
            "(declare-sort U 1)",
            "(check-sat 1)",
            include_str!("../tests/fixtures/parser_parity/malformed_unclosed.smt2"),
        ] {
            assert_matching_error(input);
        }
    }

    #[test]
    fn parity_report_is_deterministic() {
        let input = include_str!("../tests/fixtures/parser_parity/deterministic.smt2");
        let first = typed_parity_report(input, ScopedLetMode::Off).unwrap();
        let second = typed_parity_report(input, ScopedLetMode::Off).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.json_line(), second.json_line());
    }

    #[test]
    fn representative_existing_fixtures_match_without_fallback() {
        for input in [
            include_str!("../tests/fixtures/basic_sat.smt2"),
            include_str!("../tests/fixtures/basic_unsat.smt2"),
            include_str!("../tests/fixtures/bool_data_pigeonhole_unsat.smt2"),
            include_str!("../tests/fixtures/predicate_congruence_unsat.smt2"),
            include_str!("../tests/fixtures/quoted_not_sat.smt2"),
            include_str!("../tests/fixtures/transitivity_unsat.smt2"),
        ] {
            assert_parity(input);
        }
    }

    #[test]
    fn deep_stream_input_fails_closed() {
        let mut input = String::from("(assert ");
        for _ in 0..=MAX_PARSE_NESTING {
            input.push_str("(not ");
        }
        input.push_str("true");
        for _ in 0..=MAX_PARSE_NESTING {
            input.push(')');
        }
        input.push(')');
        assert_eq!(
            parse_stream_problem(&input, ScopedLetMode::Off).unwrap_err(),
            nesting_limit_error()
        );
    }
}
