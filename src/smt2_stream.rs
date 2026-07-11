use super::{
    BindingValue, BoolAtomKey, BoolExpr, FunDecl, HashMap, ParseCtx, Problem, ScopedBindings,
    ScopedLetMode, SymId, TermId, should_preprocess_branch_intersections,
};
use std::borrow::Cow;
use std::env;

pub(super) const PARSER_ENV: &str = "EUF_VIPER_PARSER";
const MAX_EXPRESSION_DEPTH: usize = 1_024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ParserMode {
    Tree,
    Shadow,
    Stream,
}

impl ParserMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Tree => "tree",
            Self::Shadow => "shadow",
            Self::Stream => "stream",
        }
    }
}

pub(super) fn parse_parser_mode(value: Option<&str>) -> Result<ParserMode, String> {
    match value {
        None | Some("tree") => Ok(ParserMode::Tree),
        Some("shadow") => Ok(ParserMode::Shadow),
        Some("stream") => Ok(ParserMode::Stream),
        Some(_) => Err(format!("{PARSER_ENV} must be tree, shadow, or stream")),
    }
}

fn selected_parser_mode() -> Result<ParserMode, String> {
    match env::var(PARSER_ENV) {
        Ok(value) => parse_parser_mode(Some(&value)),
        Err(env::VarError::NotPresent) => parse_parser_mode(None),
        Err(env::VarError::NotUnicode(_)) => {
            Err(format!("{PARSER_ENV} must be tree, shadow, or stream"))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FallbackReason {
    UnsupportedCommand,
    NoncanonicalCommand,
    UnsupportedExpression,
    SingleAssertionBranchIntersection,
    QuotedUnicodeNeedsLegacyOracle,
    ExpressionNestingLimit,
}

impl FallbackReason {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedCommand => "unsupported_command",
            Self::NoncanonicalCommand => "noncanonical_command",
            Self::UnsupportedExpression => "unsupported_expression",
            Self::SingleAssertionBranchIntersection => "single_assertion_branch_intersection",
            Self::QuotedUnicodeNeedsLegacyOracle => "quoted_unicode_needs_legacy_oracle",
            Self::ExpressionNestingLimit => "expression_nesting_limit",
        }
    }
}

#[derive(Debug)]
pub(super) enum StreamAttempt {
    Parsed(Problem),
    LegacyRequired(FallbackReason),
}

pub(super) fn parse_problem(
    input: &str,
    scoped_let_mode: ScopedLetMode,
) -> Result<Problem, String> {
    parse_problem_with_mode(input, scoped_let_mode, selected_parser_mode()?)
}

pub(super) fn parse_problem_with_mode(
    input: &str,
    scoped_let_mode: ScopedLetMode,
    mode: ParserMode,
) -> Result<Problem, String> {
    match mode {
        ParserMode::Tree => super::parse_problem_with_scoped_let_mode(input, scoped_let_mode),
        ParserMode::Stream => match parse_stream(input, scoped_let_mode)? {
            StreamAttempt::Parsed(problem) => {
                profile_parser_route(mode, "stream", None);
                Ok(problem)
            }
            StreamAttempt::LegacyRequired(reason) => {
                profile_parser_route(mode, "tree", Some(reason));
                super::parse_problem_with_scoped_let_mode(input, scoped_let_mode)
            }
        },
        ParserMode::Shadow => parse_shadow(input, scoped_let_mode),
    }
}

fn parse_shadow(input: &str, scoped_let_mode: ScopedLetMode) -> Result<Problem, String> {
    let stream = parse_stream(input, scoped_let_mode);
    let tree = super::parse_problem_with_scoped_let_mode(input, scoped_let_mode);

    match stream {
        Ok(StreamAttempt::LegacyRequired(reason)) => {
            profile_parser_route(ParserMode::Shadow, "tree-fallback", Some(reason));
            tree
        }
        Ok(StreamAttempt::Parsed(stream_problem)) => match tree {
            Ok(tree_problem) => {
                let stream_snapshot = SemanticSnapshot::from_problem(&stream_problem);
                let tree_snapshot = SemanticSnapshot::from_problem(&tree_problem);
                if stream_snapshot != tree_snapshot {
                    return Err(format!(
                        "{PARSER_ENV}=shadow mismatch: stream and tree semantic snapshots differ"
                    ));
                }
                profile_parser_route(ParserMode::Shadow, "matched", None);
                Ok(tree_problem)
            }
            Err(tree_error) => Err(format!(
                "{PARSER_ENV}=shadow mismatch: stream parsed successfully but tree failed: {tree_error}"
            )),
        },
        Err(stream_error) => match tree {
            Err(tree_error) if stream_error == tree_error => {
                profile_parser_route(ParserMode::Shadow, "matched-error", None);
                Err(tree_error)
            }
            Err(tree_error) => Err(format!(
                "{PARSER_ENV}=shadow mismatch: stream error `{stream_error}` != tree error `{tree_error}`"
            )),
            Ok(_) => Err(format!(
                "{PARSER_ENV}=shadow mismatch: stream failed `{stream_error}` but tree parsed successfully"
            )),
        },
    }
}

fn profile_parser_route(mode: ParserMode, route: &str, fallback: Option<FallbackReason>) {
    if env::var_os("EUF_VIPER_PROFILE").is_some() {
        eprintln!(
            "profile_parser_mode={} route={} fallback_reason={}",
            mode.as_str(),
            route,
            fallback.map_or("none", FallbackReason::as_str),
        );
    }
}

#[derive(Debug, PartialEq, Eq)]
struct SemanticSnapshot {
    terms: Vec<(SymId, Vec<TermId>)>,
    apps: Vec<TermId>,
    interned: Vec<(SymId, Vec<TermId>, TermId)>,
    eqs: Vec<(TermId, TermId)>,
    diseqs: Vec<(TermId, TermId)>,
    unsupported: Vec<String>,
    bool_problem: Option<BoolProblemSnapshot>,
    contradiction: bool,
}

#[derive(Debug, PartialEq, Eq)]
struct BoolProblemSnapshot {
    assertions: Vec<BoolExpr>,
    unsupported: Vec<String>,
    true_term: TermId,
    false_term: TermId,
    data_terms: Vec<TermId>,
}

impl SemanticSnapshot {
    fn from_problem(problem: &Problem) -> Self {
        let mut interned = problem
            .arena
            .interned
            .iter()
            .map(|(key, &term)| (key.fun, key.args.clone(), term))
            .collect::<Vec<_>>();
        interned.sort_unstable();
        Self {
            terms: problem
                .arena
                .terms
                .iter()
                .map(|term| (term.fun, term.args.clone()))
                .collect(),
            apps: problem.arena.apps.clone(),
            interned,
            eqs: problem.eqs.clone(),
            diseqs: problem.diseqs.clone(),
            unsupported: problem.unsupported.clone(),
            bool_problem: problem
                .bool_problem
                .as_ref()
                .map(|problem| BoolProblemSnapshot {
                    assertions: problem.assertions.clone(),
                    unsupported: problem.unsupported.clone(),
                    true_term: problem.true_term,
                    false_term: problem.false_term,
                    data_terms: problem.data_terms.clone(),
                }),
            contradiction: problem.contradiction,
        }
    }
}

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
                b'"' => return self.scan_string().map(Some),
                _ => return Ok(Some(self.scan_simple_symbol())),
            }
        }

        self.finished = true;
        if self.depth != 0 {
            Err("unclosed '('".to_owned())
        } else {
            Ok(None)
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
                        .expect("position is inside valid UTF-8 input");
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

    fn scan_string(&mut self) -> Result<RawEvent<'input>, String> {
        let bytes = self.input.as_bytes();
        let start = self.pos;
        self.pos += 1;
        while self.pos < bytes.len() {
            match bytes[self.pos] {
                b'\\' => {
                    self.pos += 1;
                    if self.pos >= bytes.len() {
                        self.finished = true;
                        return Err("unterminated string literal".to_owned());
                    }
                    let escaped_char = self.input[self.pos..]
                        .chars()
                        .next()
                        .expect("position is inside valid UTF-8 input");
                    self.pos += escaped_char.len_utf8();
                }
                b'"' if bytes.get(self.pos + 1) == Some(&b'"') => self.pos += 2,
                b'"' => {
                    self.pos += 1;
                    return Ok(RawEvent::Symbol(RawSymbol {
                        text: &self.input[start..self.pos],
                        quoted: false,
                        escaped: false,
                        string: true,
                    }));
                }
                _ => self.pos += 1,
            }
        }
        self.finished = true;
        Err("unterminated string literal".to_owned())
    }

    fn scan_simple_symbol(&mut self) -> RawEvent<'input> {
        let bytes = self.input.as_bytes();
        let start = self.pos;
        while self.pos < bytes.len()
            && !matches!(
                bytes[self.pos],
                b' ' | b'\n' | b'\r' | b'\t' | b'(' | b')' | b';' | b'|' | b'"'
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
    string: bool,
}

impl Symbol<'_> {
    fn is_syntax(&self, expected: &str) -> bool {
        !self.quoted && !self.string && self.text == expected
    }
}

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
                    text: if symbol.quoted && symbol.escaped {
                        Cow::Owned(decode_quoted_symbol(symbol.text))
                    } else {
                        Cow::Borrowed(symbol.text)
                    },
                    quoted: symbol.quoted,
                    string: symbol.string,
                }),
            })
        })
    }
}

fn decode_quoted_symbol(raw: &str) -> String {
    let mut decoded = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(character) = chars.next() {
        if character == '\\' {
            decoded.push(
                chars
                    .next()
                    .expect("the raw scanner validates quoted-symbol escapes"),
            );
        } else {
            decoded.push(character);
        }
    }
    decoded
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

struct EventCursor<'input> {
    scanner: Scanner<'input>,
    peeked: Option<Event<'input>>,
}

impl<'input> EventCursor<'input> {
    fn new(input: &'input str) -> Self {
        Self {
            scanner: Scanner::new(input),
            peeked: None,
        }
    }

    fn next(&mut self) -> Result<Option<Event<'input>>, String> {
        if self.peeked.is_some() {
            return Ok(self.peeked.take());
        }
        self.scanner.next_event()
    }

    fn peek(&mut self) -> Result<Option<&Event<'input>>, String> {
        if self.peeked.is_none() {
            self.peeked = self.scanner.next_event()?;
        }
        Ok(self.peeked.as_ref())
    }
}

#[derive(Debug)]
enum DirectError {
    LegacyRequired(FallbackReason),
    Parse(String),
}

type DirectResult<T> = Result<T, DirectError>;

fn legacy<T>(reason: FallbackReason) -> DirectResult<T> {
    Err(DirectError::LegacyRequired(reason))
}

struct DirectParser<'input> {
    cursor: EventCursor<'input>,
    ctx: ParseCtx,
    top_level_assertions: u8,
    expression_depth: usize,
}

fn parse_stream(input: &str, scoped_let_mode: ScopedLetMode) -> Result<StreamAttempt, String> {
    let prepass = structural_prepass(input)?;
    let bounded_let_count = super::bounded_lexical_let_count(input);
    let scoped_let_selected = super::scoped_let_selected(scoped_let_mode, bounded_let_count);
    super::profile_scoped_let(scoped_let_mode, bounded_let_count, scoped_let_selected);

    let parser = DirectParser {
        cursor: EventCursor::new(input),
        ctx: ParseCtx::new(scoped_let_selected),
        top_level_assertions: prepass.top_level_assertions,
        expression_depth: 0,
    };
    match parser.parse() {
        Ok(problem) => Ok(StreamAttempt::Parsed(problem)),
        Err(DirectError::LegacyRequired(reason)) => Ok(StreamAttempt::LegacyRequired(reason)),
        Err(DirectError::Parse(error)) => Err(error),
    }
}

impl<'input> DirectParser<'input> {
    fn parse(mut self) -> DirectResult<Problem> {
        while let Some(event) = self.next_event()? {
            match event {
                Event::Open => self.parse_command()?,
                Event::Symbol(_) => {}
                Event::Close => {
                    return Err(DirectError::Parse("unexpected ')'".to_owned()));
                }
            }
        }
        Ok(self.ctx.finish())
    }

    fn parse_command(&mut self) -> DirectResult<()> {
        if self.peek_is_close()? {
            self.take_close(FallbackReason::NoncanonicalCommand)?;
            return Ok(());
        }
        let head = match self.next_event()? {
            Some(Event::Symbol(symbol)) if !symbol.quoted => symbol,
            Some(Event::Symbol(_)) | Some(Event::Open) => {
                return Err(DirectError::Parse(
                    "top-level command head must be an unquoted symbol".to_owned(),
                ));
            }
            Some(Event::Close) | None => unreachable!("empty command was handled above"),
        };
        if head.string {
            return legacy(FallbackReason::UnsupportedCommand);
        }
        let command = head.text.as_ref();
        if self.ctx.exit_seen {
            return Err(DirectError::Parse(format!(
                "command `{command}` appears after `exit`"
            )));
        }
        if self.ctx.check_sat_seen && !matches!(command, "get-model" | "get-value" | "exit") {
            return Err(DirectError::Parse(format!(
                "command `{command}` after `check-sat` is unsupported in single-query mode"
            )));
        }

        match command {
            "set-logic" | "set-option" | "set-info" | "declare-sort" | "get-model"
            | "get-value" => self.skip_list_tail(),
            "declare-fun" => self.parse_declare_fun(),
            "declare-const" => self.parse_declare_const(),
            "define-fun" => self.parse_define_fun(),
            "assert" => self.parse_assert(),
            "check-sat" => self.parse_check_sat(),
            "exit" => self.parse_exit(),
            _ => legacy(FallbackReason::UnsupportedCommand),
        }
    }

    fn parse_declare_fun(&mut self) -> DirectResult<()> {
        let name = self.take_user_symbol(FallbackReason::NoncanonicalCommand)?;
        let sym = self.ctx.symbols.intern(name.text.as_ref());
        self.expect_open(FallbackReason::NoncanonicalCommand)?;
        let mut arity = 0usize;
        while !self.peek_is_close()? {
            self.skip_one(FallbackReason::NoncanonicalCommand)?;
            arity = arity.checked_add(1).ok_or(DirectError::LegacyRequired(
                FallbackReason::NoncanonicalCommand,
            ))?;
        }
        self.take_close(FallbackReason::NoncanonicalCommand)?;
        let result_is_bool = self.parse_sort(FallbackReason::NoncanonicalCommand)?;
        self.expect_close(FallbackReason::NoncanonicalCommand)?;
        self.ctx.fun_decls.insert(
            sym,
            FunDecl {
                result_is_bool,
                arity,
            },
        );
        Ok(())
    }

    fn parse_declare_const(&mut self) -> DirectResult<()> {
        let name = self.take_user_symbol(FallbackReason::NoncanonicalCommand)?;
        let sym = self.ctx.symbols.intern(name.text.as_ref());
        let result_is_bool = self.parse_sort(FallbackReason::NoncanonicalCommand)?;
        self.expect_close(FallbackReason::NoncanonicalCommand)?;
        self.ctx.fun_decls.insert(
            sym,
            FunDecl {
                result_is_bool,
                arity: 0,
            },
        );
        if !result_is_bool {
            self.ctx.arena.intern(sym, Vec::new());
        }
        Ok(())
    }

    fn parse_define_fun(&mut self) -> DirectResult<()> {
        let name = self.take_user_symbol(FallbackReason::NoncanonicalCommand)?;
        self.expect_open(FallbackReason::NoncanonicalCommand)?;
        if !self.peek_is_close()? {
            return legacy(FallbackReason::NoncanonicalCommand);
        }
        self.take_close(FallbackReason::NoncanonicalCommand)?;
        if !self.parse_sort(FallbackReason::NoncanonicalCommand)? {
            return legacy(FallbackReason::NoncanonicalCommand);
        }
        if self.peek_is_close()? {
            return legacy(FallbackReason::NoncanonicalCommand);
        }

        self.ctx.ensure_bool_value_terms();
        let sym = self.ctx.symbols.intern(name.text.as_ref());
        let mut environment = HashMap::default();
        let body = self.parse_bool_required(&mut environment)?;
        self.expect_close(FallbackReason::NoncanonicalCommand)?;
        self.ctx.fun_decls.insert(
            sym,
            FunDecl {
                result_is_bool: true,
                arity: 0,
            },
        );
        self.ctx.bool_definitions.insert(sym, body);
        Ok(())
    }

    fn parse_assert(&mut self) -> DirectResult<()> {
        if self.peek_is_close()? {
            return legacy(FallbackReason::NoncanonicalCommand);
        }
        self.ctx.ensure_bool_value_terms();
        let mut environment = HashMap::default();
        let assertion = self.parse_bool_required(&mut environment)?;
        self.expect_close(FallbackReason::NoncanonicalCommand)?;

        if self.top_level_assertions == 1
            && should_preprocess_branch_intersections(&assertion)
            && legacy_branch_preprocessing_enabled(self.ctx.arena.terms.len())
        {
            return legacy(FallbackReason::SingleAssertionBranchIntersection);
        }
        self.ctx.bool_assertions.push(assertion);
        Ok(())
    }

    fn parse_check_sat(&mut self) -> DirectResult<()> {
        if !self.peek_is_close()? {
            return Err(DirectError::Parse(
                "check-sat command must not have arguments".to_owned(),
            ));
        }
        self.take_close(FallbackReason::NoncanonicalCommand)?;
        self.ctx.check_sat_seen = true;
        Ok(())
    }

    fn parse_exit(&mut self) -> DirectResult<()> {
        if !self.peek_is_close()? {
            return Err(DirectError::Parse(
                "exit command must not have arguments".to_owned(),
            ));
        }
        self.take_close(FallbackReason::NoncanonicalCommand)?;
        self.ctx.exit_seen = true;
        Ok(())
    }

    fn parse_value(
        &mut self,
        environment: &mut HashMap<String, BindingValue>,
    ) -> DirectResult<BindingValue> {
        if self.expression_depth >= MAX_EXPRESSION_DEPTH {
            return legacy(FallbackReason::ExpressionNestingLimit);
        }
        self.expression_depth += 1;
        let result = self.parse_value_inner(environment);
        self.expression_depth -= 1;
        result
    }

    fn parse_value_inner(
        &mut self,
        environment: &mut HashMap<String, BindingValue>,
    ) -> DirectResult<BindingValue> {
        match self.next_event()? {
            Some(Event::Symbol(symbol)) => self.parse_symbol_value(symbol, environment),
            Some(Event::Open) => self.parse_list_value(environment),
            Some(Event::Close) | None => legacy(FallbackReason::UnsupportedExpression),
        }
    }

    fn parse_symbol_value(
        &mut self,
        symbol: Symbol<'input>,
        environment: &mut HashMap<String, BindingValue>,
    ) -> DirectResult<BindingValue> {
        self.ensure_direct_symbol(&symbol, FallbackReason::UnsupportedExpression)?;
        if symbol.is_syntax("true") {
            return Ok(BindingValue::Bool(BoolExpr::Const(true)));
        }
        if symbol.is_syntax("false") {
            return Ok(BindingValue::Bool(BoolExpr::Const(false)));
        }
        if let Some(value) = environment.get(symbol.text.as_ref()).cloned() {
            return Ok(value);
        }
        let sym = self.ctx.symbols.intern(symbol.text.as_ref());
        if let Some(body) = self.ctx.bool_definitions.get(&sym).cloned() {
            Ok(BindingValue::Bool(body))
        } else if self.ctx.is_bool_symbol(sym, 0) {
            Ok(BindingValue::Bool(self.ctx.bool_app_expr(sym, Vec::new())))
        } else {
            Ok(BindingValue::Term(self.ctx.arena.intern(sym, Vec::new())))
        }
    }

    fn parse_list_value(
        &mut self,
        environment: &mut HashMap<String, BindingValue>,
    ) -> DirectResult<BindingValue> {
        if self.peek_is_close()? {
            return legacy(FallbackReason::UnsupportedExpression);
        }
        let head = match self.next_event()? {
            Some(Event::Symbol(symbol)) => symbol,
            Some(Event::Open) | Some(Event::Close) | None => {
                return legacy(FallbackReason::UnsupportedExpression);
            }
        };
        self.ensure_direct_symbol(&head, FallbackReason::UnsupportedExpression)?;

        if head.is_syntax("!") {
            return self.parse_annotation(environment);
        }
        if head.is_syntax("and") {
            return self.parse_boolean_variadic(environment, true);
        }
        if head.is_syntax("or") {
            return self.parse_boolean_variadic(environment, false);
        }
        if head.is_syntax("not") {
            let child = self.parse_bool_required(environment)?;
            self.expect_close(FallbackReason::UnsupportedExpression)?;
            return Ok(BindingValue::Bool(BoolExpr::Not(Box::new(child))));
        }
        if head.is_syntax("=>") {
            return self.parse_implication(environment);
        }
        if head.is_syntax("xor") {
            return self.parse_xor(environment);
        }
        if head.is_syntax("ite") {
            return self.parse_ite(environment);
        }
        if head.is_syntax("=") {
            return self.parse_equality(environment);
        }
        if head.is_syntax("distinct") {
            return self.parse_distinct(environment);
        }
        if head.is_syntax("let") {
            return self.parse_let(environment);
        }
        self.parse_user_application(head, environment)
    }

    fn parse_annotation(
        &mut self,
        environment: &mut HashMap<String, BindingValue>,
    ) -> DirectResult<BindingValue> {
        if self.peek_is_close()? {
            return legacy(FallbackReason::UnsupportedExpression);
        }
        let value = self.parse_value(environment)?;
        self.skip_list_tail()?;
        Ok(value)
    }

    fn parse_boolean_variadic(
        &mut self,
        environment: &mut HashMap<String, BindingValue>,
        conjunction: bool,
    ) -> DirectResult<BindingValue> {
        let mut children = Vec::new();
        while !self.peek_is_close()? {
            children.push(self.parse_bool_required(environment)?);
        }
        self.take_close(FallbackReason::UnsupportedExpression)?;
        Ok(BindingValue::Bool(if conjunction {
            BoolExpr::And(children)
        } else {
            BoolExpr::Or(children)
        }))
    }

    fn parse_implication(
        &mut self,
        environment: &mut HashMap<String, BindingValue>,
    ) -> DirectResult<BindingValue> {
        let mut children = Vec::new();
        while !self.peek_is_close()? {
            children.push(self.parse_bool_required(environment)?);
        }
        self.take_close(FallbackReason::UnsupportedExpression)?;
        if children.len() < 2 {
            return legacy(FallbackReason::UnsupportedExpression);
        }
        let last = children.pop().expect("implication arity was checked");
        let premise = if children.len() == 1 {
            children.pop().expect("single implication premise")
        } else {
            BoolExpr::And(children)
        };
        Ok(BindingValue::Bool(BoolExpr::Or(vec![
            BoolExpr::Not(Box::new(premise)),
            last,
        ])))
    }

    fn parse_xor(
        &mut self,
        environment: &mut HashMap<String, BindingValue>,
    ) -> DirectResult<BindingValue> {
        let mut children = Vec::new();
        while !self.peek_is_close()? {
            children.push(self.parse_bool_required(environment)?);
        }
        self.take_close(FallbackReason::UnsupportedExpression)?;
        if children.len() < 2 {
            return legacy(FallbackReason::UnsupportedExpression);
        }
        let mut children = children.into_iter();
        let mut expression = children.next().expect("xor arity was checked");
        for rhs in children {
            expression = BoolExpr::Not(Box::new(BoolExpr::Iff(vec![expression, rhs])));
        }
        Ok(BindingValue::Bool(expression))
    }

    fn parse_ite(
        &mut self,
        environment: &mut HashMap<String, BindingValue>,
    ) -> DirectResult<BindingValue> {
        let condition = self.parse_bool_required(environment)?;
        let then_value = self.parse_value(environment)?;
        let else_value = self.parse_value(environment)?;
        self.expect_close(FallbackReason::UnsupportedExpression)?;
        match (then_value, else_value) {
            (BindingValue::Bool(then_expr), BindingValue::Bool(else_expr)) => {
                Ok(BindingValue::Bool(BoolExpr::Ite(
                    Box::new(condition),
                    Box::new(then_expr),
                    Box::new(else_expr),
                )))
            }
            (BindingValue::Term(then_term), BindingValue::Term(else_term)) => {
                if then_term == else_term {
                    return Ok(BindingValue::Term(then_term));
                }
                let ite_term = self.ctx.fresh_internal_term("ite");
                let then_eq = BoolExpr::Atom(BoolAtomKey::Eq(ite_term, then_term));
                let else_eq = BoolExpr::Atom(BoolAtomKey::Eq(ite_term, else_term));
                self.ctx.bool_assertions.push(BoolExpr::Or(vec![
                    BoolExpr::Not(Box::new(condition.clone())),
                    then_eq,
                ]));
                self.ctx
                    .bool_assertions
                    .push(BoolExpr::Or(vec![condition, else_eq]));
                Ok(BindingValue::Term(ite_term))
            }
            _ => legacy(FallbackReason::UnsupportedExpression),
        }
    }

    fn parse_equality(
        &mut self,
        environment: &mut HashMap<String, BindingValue>,
    ) -> DirectResult<BindingValue> {
        let values = self.parse_values_until_close(environment)?;
        if values.len() < 2 {
            return legacy(FallbackReason::UnsupportedExpression);
        }
        let expression = match &values[0] {
            BindingValue::Term(first) => {
                let mut conjuncts = Vec::with_capacity(values.len() - 1);
                for value in &values[1..] {
                    let BindingValue::Term(term) = value else {
                        return legacy(FallbackReason::UnsupportedExpression);
                    };
                    conjuncts.push(BoolExpr::Atom(BoolAtomKey::Eq(*first, *term)));
                }
                if conjuncts.len() == 1 {
                    conjuncts.pop().expect("single equality")
                } else {
                    BoolExpr::And(conjuncts)
                }
            }
            BindingValue::Bool(first) => {
                let mut expressions = Vec::with_capacity(values.len());
                expressions.push(first.clone());
                for value in &values[1..] {
                    let BindingValue::Bool(expression) = value else {
                        return legacy(FallbackReason::UnsupportedExpression);
                    };
                    expressions.push(expression.clone());
                }
                BoolExpr::Iff(expressions)
            }
        };
        Ok(BindingValue::Bool(expression))
    }

    fn parse_distinct(
        &mut self,
        environment: &mut HashMap<String, BindingValue>,
    ) -> DirectResult<BindingValue> {
        let values = self.parse_values_until_close(environment)?;
        if values.len() < 2 {
            return Ok(BindingValue::Bool(BoolExpr::Const(true)));
        }
        let expression = match &values[0] {
            BindingValue::Term(_) => {
                let mut terms = Vec::with_capacity(values.len());
                for value in values {
                    let BindingValue::Term(term) = value else {
                        return legacy(FallbackReason::UnsupportedExpression);
                    };
                    terms.push(term);
                }
                let mut conjuncts = Vec::new();
                for left in 0..terms.len() {
                    for right in (left + 1)..terms.len() {
                        conjuncts.push(BoolExpr::Not(Box::new(BoolExpr::Atom(BoolAtomKey::Eq(
                            terms[left],
                            terms[right],
                        )))));
                    }
                }
                BoolExpr::And(conjuncts)
            }
            BindingValue::Bool(_) => {
                let mut expressions = Vec::with_capacity(values.len());
                for value in values {
                    let BindingValue::Bool(expression) = value else {
                        return legacy(FallbackReason::UnsupportedExpression);
                    };
                    expressions.push(expression);
                }
                if expressions.len() == 2 {
                    BoolExpr::Not(Box::new(BoolExpr::Iff(expressions)))
                } else {
                    BoolExpr::Const(false)
                }
            }
        };
        Ok(BindingValue::Bool(expression))
    }

    fn parse_let(
        &mut self,
        environment: &mut HashMap<String, BindingValue>,
    ) -> DirectResult<BindingValue> {
        self.expect_open(FallbackReason::UnsupportedExpression)?;
        let mut bindings = Vec::new();
        while !self.peek_is_close()? {
            self.expect_open(FallbackReason::UnsupportedExpression)?;
            let name = self.take_user_symbol(FallbackReason::UnsupportedExpression)?;
            if self.peek_is_close()? {
                return legacy(FallbackReason::UnsupportedExpression);
            }
            let value = self.parse_value(environment)?;
            self.expect_close(FallbackReason::UnsupportedExpression)?;
            bindings.push((name.text.into_owned(), value));
        }
        self.take_close(FallbackReason::UnsupportedExpression)?;
        if self.peek_is_close()? {
            return legacy(FallbackReason::UnsupportedExpression);
        }

        let value = if self.ctx.scoped_let_selected {
            let mut scope = ScopedBindings::new(environment, bindings);
            self.parse_value(scope.env())?
        } else {
            let mut local = environment.clone();
            for (name, value) in bindings {
                local.insert(name, value);
            }
            self.parse_value(&mut local)?
        };
        self.expect_close(FallbackReason::UnsupportedExpression)?;
        Ok(value)
    }

    fn parse_user_application(
        &mut self,
        head: Symbol<'input>,
        environment: &mut HashMap<String, BindingValue>,
    ) -> DirectResult<BindingValue> {
        let sym = self.ctx.symbols.intern(head.text.as_ref());
        if self.peek_is_close()? {
            self.take_close(FallbackReason::UnsupportedExpression)?;
            if let Some(body) = self.ctx.bool_definitions.get(&sym).cloned() {
                return Ok(BindingValue::Bool(body));
            }
            if self.ctx.is_bool_symbol(sym, 0) {
                return Ok(BindingValue::Bool(self.ctx.bool_app_expr(sym, Vec::new())));
            }
            return Ok(BindingValue::Term(self.ctx.arena.intern(sym, Vec::new())));
        }

        let mut arguments = Vec::new();
        while !self.peek_is_close()? {
            arguments.push(self.parse_argument_term(environment)?);
        }
        self.take_close(FallbackReason::UnsupportedExpression)?;
        if self.ctx.is_bool_symbol(sym, arguments.len()) {
            Ok(BindingValue::Bool(self.ctx.bool_app_expr(sym, arguments)))
        } else {
            Ok(BindingValue::Term(self.ctx.arena.intern(sym, arguments)))
        }
    }

    fn parse_values_until_close(
        &mut self,
        environment: &mut HashMap<String, BindingValue>,
    ) -> DirectResult<Vec<BindingValue>> {
        let mut values = Vec::new();
        while !self.peek_is_close()? {
            values.push(self.parse_value(environment)?);
        }
        self.take_close(FallbackReason::UnsupportedExpression)?;
        Ok(values)
    }

    fn parse_bool_required(
        &mut self,
        environment: &mut HashMap<String, BindingValue>,
    ) -> DirectResult<BoolExpr> {
        match self.parse_value(environment)? {
            BindingValue::Bool(expression) => Ok(expression),
            BindingValue::Term(_) => legacy(FallbackReason::UnsupportedExpression),
        }
    }

    fn parse_argument_term(
        &mut self,
        environment: &mut HashMap<String, BindingValue>,
    ) -> DirectResult<TermId> {
        match self.parse_value(environment)? {
            BindingValue::Term(term) => Ok(term),
            BindingValue::Bool(expression) => Ok(self.ctx.materialize_bool_expr(expression)),
        }
    }

    fn parse_sort(&mut self, reason: FallbackReason) -> DirectResult<bool> {
        match self.next_event()? {
            Some(Event::Symbol(symbol)) => {
                self.ensure_direct_symbol(&symbol, reason)?;
                Ok(symbol.is_syntax("Bool"))
            }
            Some(Event::Open) => {
                self.skip_list_tail()?;
                Ok(false)
            }
            Some(Event::Close) | None => legacy(reason),
        }
    }

    fn take_user_symbol(&mut self, reason: FallbackReason) -> DirectResult<Symbol<'input>> {
        match self.next_event()? {
            Some(Event::Symbol(symbol)) => {
                self.ensure_direct_symbol(&symbol, reason)?;
                Ok(symbol)
            }
            Some(Event::Open) | Some(Event::Close) | None => legacy(reason),
        }
    }

    fn ensure_direct_symbol(
        &self,
        symbol: &Symbol<'_>,
        reason: FallbackReason,
    ) -> DirectResult<()> {
        if symbol.string {
            return legacy(reason);
        }
        if symbol.quoted && !symbol.text.is_ascii() {
            return legacy(FallbackReason::QuotedUnicodeNeedsLegacyOracle);
        }
        Ok(())
    }

    fn skip_one(&mut self, reason: FallbackReason) -> DirectResult<()> {
        match self.next_event()? {
            Some(Event::Symbol(_)) => Ok(()),
            Some(Event::Open) => self.skip_list_tail(),
            Some(Event::Close) | None => legacy(reason),
        }
    }

    fn skip_list_tail(&mut self) -> DirectResult<()> {
        let mut nested = 0usize;
        loop {
            match self.next_event()? {
                Some(Event::Open) => nested += 1,
                Some(Event::Close) if nested == 0 => return Ok(()),
                Some(Event::Close) => nested -= 1,
                Some(Event::Symbol(_)) => {}
                None => {
                    return Err(DirectError::Parse("unclosed '('".to_owned()));
                }
            }
        }
    }

    fn expect_open(&mut self, reason: FallbackReason) -> DirectResult<()> {
        match self.next_event()? {
            Some(Event::Open) => Ok(()),
            Some(Event::Close) | Some(Event::Symbol(_)) | None => legacy(reason),
        }
    }

    fn expect_close(&mut self, reason: FallbackReason) -> DirectResult<()> {
        match self.next_event()? {
            Some(Event::Close) => Ok(()),
            Some(Event::Open) | Some(Event::Symbol(_)) | None => legacy(reason),
        }
    }

    fn take_close(&mut self, reason: FallbackReason) -> DirectResult<()> {
        self.expect_close(reason)
    }

    fn peek_is_close(&mut self) -> DirectResult<bool> {
        self.cursor
            .peek()
            .map(|event| matches!(event, Some(Event::Close)))
            .map_err(DirectError::Parse)
    }

    fn next_event(&mut self) -> DirectResult<Option<Event<'input>>> {
        self.cursor.next().map_err(DirectError::Parse)
    }
}

fn legacy_branch_preprocessing_enabled(term_count: usize) -> bool {
    let term_limit = env::var("EUF_VIPER_LEGACY_PREPROCESS_TERM_LIMIT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1_024usize);
    term_limit > 0 && term_count <= term_limit
}

#[cfg(test)]
mod tests {
    use super::super::{SolveResult, solve_problem};
    use super::*;

    fn drain_scanner(input: &str) -> Result<Vec<Event<'_>>, String> {
        let mut scanner = Scanner::new(input);
        let mut events = Vec::new();
        while let Some(event) = scanner.next_event()? {
            events.push(event);
        }
        Ok(events)
    }

    fn assert_direct_parity(input: &str, mode: ScopedLetMode) {
        let tree = super::super::parse_problem_with_scoped_let_mode(input, mode).unwrap();
        let stream = match parse_stream(input, mode).unwrap() {
            StreamAttempt::Parsed(problem) => problem,
            StreamAttempt::LegacyRequired(reason) => {
                panic!("unexpected stream fallback {}", reason.as_str())
            }
        };
        assert_eq!(
            SemanticSnapshot::from_problem(&stream),
            SemanticSnapshot::from_problem(&tree)
        );
    }

    fn fallback_reason(input: &str) -> FallbackReason {
        match parse_stream(input, ScopedLetMode::Off).unwrap() {
            StreamAttempt::LegacyRequired(reason) => reason,
            StreamAttempt::Parsed(_) => panic!("input unexpectedly stayed on stream path"),
        }
    }

    #[test]
    fn scanner_borrows_plain_and_unescaped_symbols_and_only_owns_decoding() {
        let events = drain_scanner(
            r#"(plain |quoted lambda| |escaped\|bar| utf8_λ |quoted_λ| "string (;)")"#,
        )
        .unwrap();
        assert_eq!(events.len(), 8);
        assert!(matches!(events[0], Event::Open));
        assert!(matches!(events[7], Event::Close));
        assert!(matches!(
            &events[1],
            Event::Symbol(Symbol {
                text: Cow::Borrowed("plain"),
                quoted: false,
                string: false
            })
        ));
        assert!(matches!(
            &events[2],
            Event::Symbol(Symbol {
                text: Cow::Borrowed("quoted lambda"),
                quoted: true,
                string: false
            })
        ));
        assert!(matches!(
            &events[3],
            Event::Symbol(Symbol { text: Cow::Owned(text), quoted: true, string: false })
                if text == "escaped|bar"
        ));
        assert!(matches!(
            &events[4],
            Event::Symbol(Symbol {
                text: Cow::Borrowed("utf8_λ"),
                quoted: false,
                string: false
            })
        ));
        assert!(matches!(
            &events[5],
            Event::Symbol(Symbol {
                text: Cow::Borrowed("quoted_λ"),
                quoted: true,
                string: false
            })
        ));
        assert!(matches!(
            &events[6],
            Event::Symbol(Symbol {
                text: Cow::Borrowed("\"string (;)\""),
                quoted: false,
                string: true
            })
        ));
    }

    #[test]
    fn scanner_rejects_malformed_structure_and_unterminated_lexemes() {
        let cases = [
            (")", "unexpected ')'"),
            ("(", "unclosed '('"),
            ("|unterminated", "unterminated quoted symbol"),
            ("|trailing\\", "unterminated quoted symbol"),
            ("\"unterminated", "unterminated string literal"),
            ("\"trailing\\", "unterminated string literal"),
            ("(assert true))", "unexpected ')'"),
        ];
        for (input, expected) in cases {
            assert_eq!(
                structural_prepass(input),
                Err(expected.to_owned()),
                "{input:?}"
            );
            assert_eq!(drain_scanner(input), Err(expected.to_owned()), "{input:?}");
        }
    }

    #[test]
    fn prepass_validates_the_whole_input_and_counts_only_real_top_level_assertions() {
        let input = r#"
            ; (assert false) |unterminated "unterminated
            (set-info :source "(assert false)")
            (|assert| false)
            ((assert false))
            (assert true)
            ; another (assert false)
            (assert (! false :named counted))
            (assert true)
        "#;
        assert_eq!(
            structural_prepass(input).unwrap(),
            Prepass {
                top_level_assertions: 2
            }
        );
    }

    #[test]
    fn comments_and_escaped_bars_do_not_change_event_structure() {
        let events = drain_scanner(
            r#"
                ; ignored ( ) |bad
                (declare-fun |p\|q| () Bool) ; close ))
                (assert |p\|q|)
            "#,
        )
        .unwrap();
        let decoded = events
            .iter()
            .filter_map(|event| match event {
                Event::Symbol(symbol) => Some(symbol.text.as_ref()),
                Event::Open | Event::Close => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(decoded, ["declare-fun", "p|q", "Bool", "assert", "p|q"]);
    }

    #[test]
    fn parser_mode_is_strict_and_defaults_to_tree() {
        assert_eq!(parse_parser_mode(None), Ok(ParserMode::Tree));
        assert_eq!(parse_parser_mode(Some("tree")), Ok(ParserMode::Tree));
        assert_eq!(parse_parser_mode(Some("shadow")), Ok(ParserMode::Shadow));
        assert_eq!(parse_parser_mode(Some("stream")), Ok(ParserMode::Stream));
        for invalid in ["", "TREE", "off", "stream "] {
            assert_eq!(
                parse_parser_mode(Some(invalid)),
                Err(format!("{PARSER_ENV} must be tree, shadow, or stream"))
            );
        }
    }

    #[test]
    fn quoted_reserved_symbols_and_user_symbol_spellings_match_tree_semantics() {
        let input = r#"
            (set-logic QF_UF)
            (declare-fun |true| () Bool)
            (declare-fun |not| (Bool) Bool)
            (declare-fun p () Bool)
            (assert true)
            (assert (|not| |true|))
            (assert (= p |p|))
            (check-sat)
        "#;
        for mode in [ScopedLetMode::Off, ScopedLetMode::On] {
            assert_direct_parity(input, mode);
        }
    }

    #[test]
    fn annotations_are_transparent_for_boolean_and_term_payloads() {
        let input = r#"
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun a () U)
            (declare-fun b () U)
            (declare-fun f (U) U)
            (declare-fun p () Bool)
            (assert (! (= a b) :named same :weight 1))
            (assert (! (distinct (! (f a) :named lhs) (f b)) :named conflict))
            (assert (! p :named positive))
            (check-sat)
        "#;
        assert_direct_parity(input, ScopedLetMode::Off);
        assert_direct_parity(input, ScopedLetMode::On);
    }

    #[test]
    fn supported_command_surface_has_complete_snapshot_parity() {
        let input = r#"
            (set-logic QF_UF)
            (set-option :produce-models true)
            (set-info :source "stream parser command fixture")
            (declare-sort U 0)
            (declare-const a U)
            (declare-const p Bool)
            (declare-fun f (U) U)
            (define-fun enabled () Bool (or p (= (f a) a)))
            (assert enabled)
            (check-sat)
            (get-model)
            (get-value (a p))
            (exit)
        "#;
        assert_direct_parity(input, ScopedLetMode::Off);
        assert_direct_parity(input, ScopedLetMode::On);
    }

    #[test]
    fn simultaneous_and_nested_lets_match_in_both_scoped_modes() {
        let input = r#"
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun a () U)
            (declare-fun b () U)
            (assert
                (let ((x a))
                    (let ((x b) (y x))
                        (and (= x b) (= y a)))))
            (check-sat)
        "#;
        for mode in [ScopedLetMode::Off, ScopedLetMode::On] {
            assert_direct_parity(input, mode);
            let problem = parse_problem_with_mode(input, mode, ParserMode::Stream).unwrap();
            assert_eq!(solve_problem(problem, false).result, SolveResult::Sat);
        }
    }

    #[test]
    fn boolean_term_operators_and_zero_arity_definitions_match_tree() {
        let input = r#"
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun a () U)
            (declare-fun b () U)
            (declare-fun p () Bool)
            (declare-fun q () Bool)
            (declare-fun r () Bool)
            (declare-fun f (Bool) U)
            (define-fun same () Bool (= a b))
            (assert (and (or p q) (not r) (=> p q r) (xor p q r)))
            (assert (= (ite p a b) a))
            (assert (= (f (ite p q r)) (f q)))
            (assert (= (same) same))
            (assert (distinct p q))
            (check-sat)
        "#;
        assert_direct_parity(input, ScopedLetMode::Off);
        assert_direct_parity(input, ScopedLetMode::On);
    }

    #[test]
    fn query_ordering_matches_legacy_errors_and_allows_read_only_queries() {
        let accepted = r#"
            (set-logic QF_UF)
            (declare-fun p () Bool)
            (assert p)
            (check-sat)
            (get-model)
            (get-value (p))
            (exit)
        "#;
        assert_direct_parity(accepted, ScopedLetMode::Off);

        let after_query = "(check-sat) (assert false)";
        let expected = "command `assert` after `check-sat` is unsupported in single-query mode";
        assert_eq!(
            parse_stream(after_query, ScopedLetMode::Off).unwrap_err(),
            expected
        );
        assert_eq!(
            super::super::parse_problem_with_scoped_let_mode(after_query, ScopedLetMode::Off)
                .unwrap_err(),
            expected
        );

        let after_exit = "(exit) (get-model)";
        assert_eq!(
            parse_stream(after_exit, ScopedLetMode::Off).unwrap_err(),
            "command `get-model` appears after `exit`"
        );
    }

    #[test]
    fn fallback_reasons_are_explicit_and_single_assert_preprocessing_stays_legacy() {
        assert_eq!(
            fallback_reason("(set-logic QF_UF) (push 1)"),
            FallbackReason::UnsupportedCommand
        );
        assert_eq!(
            fallback_reason("(declare-fun f U U)"),
            FallbackReason::NoncanonicalCommand
        );
        assert_eq!(
            fallback_reason("(assert undeclared_data)"),
            FallbackReason::UnsupportedExpression
        );
        assert_eq!(
            fallback_reason(include_str!("../tests/fixtures/eq_diamond_unsat.smt2")),
            FallbackReason::SingleAssertionBranchIntersection
        );
        assert_eq!(
            fallback_reason("(declare-fun |λ| () Bool)"),
            FallbackReason::QuotedUnicodeNeedsLegacyOracle
        );
    }

    #[test]
    fn fallback_discards_partial_stream_state_before_legacy_restart() {
        let input = r#"
            (set-logic QF_UF)
            (declare-fun p () Bool)
            (assert p)
            (push 1)
            (assert (not p))
            (check-sat)
        "#;
        assert_eq!(fallback_reason(input), FallbackReason::UnsupportedCommand);
        let routed =
            parse_problem_with_mode(input, ScopedLetMode::Off, ParserMode::Stream).unwrap();
        let tree =
            super::super::parse_problem_with_scoped_let_mode(input, ScopedLetMode::Off).unwrap();
        assert_eq!(
            SemanticSnapshot::from_problem(&routed),
            SemanticSnapshot::from_problem(&tree)
        );
        assert_eq!(routed.bool_problem.unwrap().assertions.len(), 2);
    }

    #[test]
    fn shadow_requires_complete_snapshot_or_matching_error_parity() {
        let input = include_str!("../tests/fixtures/predicate_congruence_unsat.smt2");
        parse_problem_with_mode(input, ScopedLetMode::Off, ParserMode::Shadow).unwrap();

        let matching_error =
            parse_problem_with_mode("(set-logic QF_UF", ScopedLetMode::Off, ParserMode::Shadow)
                .unwrap_err();
        assert_eq!(matching_error, "unclosed '('");

        let mismatch = parse_problem_with_mode(
            "(set-info :source \"unterminated)",
            ScopedLetMode::Off,
            ParserMode::Shadow,
        )
        .unwrap_err();
        assert!(mismatch.contains("shadow mismatch"), "{mismatch}");
    }

    #[test]
    fn representative_fixtures_have_snapshot_parity_or_documented_fallback() {
        let direct = [
            include_str!("../tests/fixtures/basic_sat.smt2"),
            include_str!("../tests/fixtures/basic_unsat.smt2"),
            include_str!("../tests/fixtures/bool_data_pigeonhole_unsat.smt2"),
            include_str!("../tests/fixtures/predicate_congruence_unsat.smt2"),
            include_str!("../tests/fixtures/pruned_or_unsat.smt2"),
            include_str!("../tests/fixtures/quoted_not_sat.smt2"),
            include_str!("../tests/fixtures/quoted_true_sat.smt2"),
            include_str!("../tests/fixtures/transitivity_unsat.smt2"),
            include_str!("../tests/fixtures/unsupported_or.smt2"),
        ];
        for input in direct {
            assert_direct_parity(input, ScopedLetMode::Off);
            assert_direct_parity(input, ScopedLetMode::On);
        }

        assert_eq!(
            fallback_reason(include_str!("../tests/fixtures/eq_diamond_unsat.smt2")),
            FallbackReason::SingleAssertionBranchIntersection
        );

        let early_query = include_str!("../tests/fixtures/early_check_sat_rejected.smt2");
        let stream_error = parse_stream(early_query, ScopedLetMode::Off).unwrap_err();
        let tree_error =
            super::super::parse_problem_with_scoped_let_mode(early_query, ScopedLetMode::Off)
                .unwrap_err();
        assert_eq!(stream_error, tree_error);
    }
}
