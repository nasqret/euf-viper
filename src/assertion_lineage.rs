use super::{
    BoolAtomKey, BoolExpr, ParseCtx, Problem, ScopedLetMode, Sexp, SymId, TermArena, TermId,
    bounded_lexical_let_count, parse_sexps, profile_scoped_let, scoped_let_selected,
    syntax_atom_text,
};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
#[cfg(test)]
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

pub(crate) const SCHEMA: &str = "euf-viper.assertion-lineage.v1";
const BYTE_BINDING: &str = "no-follow-single-open-buffer.v1";
const SPAN_CONVENTION: &str = "zero-based-half-open-source-bytes.v1";
const RAW_AST_ENCODING: &str = "lossless-token-tree.v1";
const PARSER_ARCHITECTURE: &str = "authoritative-typed-tree.v1";

#[cfg(test)]
thread_local! {
    static RECORDER_CONSTRUCTIONS: Cell<usize> = const { Cell::new(0) };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) struct ByteSpan {
    pub(crate) end: usize,
    pub(crate) start: usize,
}

impl ByteSpan {
    fn new(start: usize, end: usize, source_len: usize) -> Result<Self, String> {
        if start >= end {
            return Err(format!(
                "invalid zero-length or reversed span [{start}, {end})"
            ));
        }
        if end > source_len {
            return Err(format!(
                "out-of-range span [{start}, {end}) for {source_len} source bytes"
            ));
        }
        Ok(Self { start, end })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RawNodeKind {
    Atom(Vec<u8>),
    Quoted(Vec<u8>),
    List(Vec<RawNode>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RawNode {
    kind: RawNodeKind,
    span: ByteSpan,
}

impl RawNode {
    fn canonical_bytes(&self) -> Vec<u8> {
        fn append(node: &RawNode, output: &mut Vec<u8>) {
            match &node.kind {
                RawNodeKind::Atom(raw) => {
                    output.push(b'A');
                    append_len(output, raw.len());
                    output.extend_from_slice(raw);
                }
                RawNodeKind::Quoted(raw) => {
                    output.push(b'Q');
                    append_len(output, raw.len());
                    output.extend_from_slice(raw);
                }
                RawNodeKind::List(children) => {
                    output.push(b'L');
                    append_len(output, children.len());
                    for child in children {
                        append(child, output);
                    }
                }
            }
        }

        let mut output = Vec::new();
        append(self, &mut output);
        output
    }

    fn syntax_head(&self) -> Option<&[u8]> {
        let RawNodeKind::List(children) = &self.kind else {
            return None;
        };
        match children.first().map(|child| &child.kind) {
            Some(RawNodeKind::Atom(raw)) if !raw.starts_with(b"\"") => Some(raw),
            _ => None,
        }
    }
}

fn append_len(output: &mut Vec<u8>, value: usize) {
    output.extend_from_slice(value.to_string().as_bytes());
    output.push(b':');
}

struct LosslessParser<'a> {
    source: &'a [u8],
    position: usize,
}

impl<'a> LosslessParser<'a> {
    fn new(source: &'a [u8]) -> Self {
        Self {
            source,
            position: 0,
        }
    }

    fn parse_all(mut self) -> Result<Vec<RawNode>, String> {
        let mut nodes = Vec::new();
        self.skip_layout();
        while self.position < self.source.len() {
            nodes.push(self.parse_one()?);
            self.skip_layout();
        }
        Ok(nodes)
    }

    fn skip_layout(&mut self) {
        loop {
            while self
                .source
                .get(self.position)
                .is_some_and(|byte| matches!(byte, b' ' | b'\n' | b'\r' | b'\t'))
            {
                self.position += 1;
            }
            if self.source.get(self.position) != Some(&b';') {
                return;
            }
            while self.position < self.source.len() && self.source[self.position] != b'\n' {
                self.position += 1;
            }
        }
    }

    fn parse_one(&mut self) -> Result<RawNode, String> {
        self.skip_layout();
        let start = self.position;
        let Some(&first) = self.source.get(self.position) else {
            return Err("unexpected end of source".to_owned());
        };
        match first {
            b'(' => self.parse_list(start),
            b')' => Err(format!("unexpected ')' at byte {start}")),
            b'|' => self.parse_quoted(start),
            b'\"' => self.parse_string(start),
            _ => self.parse_atom(start),
        }
    }

    fn parse_list(&mut self, start: usize) -> Result<RawNode, String> {
        self.position += 1;
        let mut children = Vec::new();
        loop {
            self.skip_layout();
            match self.source.get(self.position) {
                Some(b')') => {
                    self.position += 1;
                    return Ok(RawNode {
                        kind: RawNodeKind::List(children),
                        span: ByteSpan::new(start, self.position, self.source.len())?,
                    });
                }
                None => return Err(format!("unclosed '(' at byte {start}")),
                _ => children.push(self.parse_one()?),
            }
        }
    }

    fn parse_quoted(&mut self, start: usize) -> Result<RawNode, String> {
        self.position += 1;
        while self.position < self.source.len() {
            match self.source[self.position] {
                b'\\' if self.position + 1 < self.source.len() => self.position += 2,
                b'|' => {
                    self.position += 1;
                    return Ok(RawNode {
                        kind: RawNodeKind::Quoted(self.source[start..self.position].to_vec()),
                        span: ByteSpan::new(start, self.position, self.source.len())?,
                    });
                }
                _ => self.position += 1,
            }
        }
        Err(format!("unterminated quoted symbol at byte {start}"))
    }

    fn parse_string(&mut self, start: usize) -> Result<RawNode, String> {
        self.position += 1;
        while self.position < self.source.len() {
            match self.source[self.position] {
                b'\\' if self.position + 1 < self.source.len() => self.position += 2,
                b'\"' => {
                    self.position += 1;
                    return Ok(RawNode {
                        kind: RawNodeKind::Atom(self.source[start..self.position].to_vec()),
                        span: ByteSpan::new(start, self.position, self.source.len())?,
                    });
                }
                _ => self.position += 1,
            }
        }
        Err(format!("unterminated string at byte {start}"))
    }

    fn parse_atom(&mut self, start: usize) -> Result<RawNode, String> {
        while self.position < self.source.len()
            && !matches!(
                self.source[self.position],
                b' ' | b'\n' | b'\r' | b'\t' | b'(' | b')' | b';'
            )
        {
            self.position += 1;
        }
        if self.position == start {
            return Err(format!("empty atom at byte {start}"));
        }
        Ok(RawNode {
            kind: RawNodeKind::Atom(self.source[start..self.position].to_vec()),
            span: ByteSpan::new(start, self.position, self.source.len())?,
        })
    }
}

fn decode_quoted(raw: &[u8]) -> String {
    let mut decoded = String::new();
    let mut index = 1;
    while index + 1 < raw.len() {
        if raw[index] == b'\\' && index + 2 < raw.len() {
            index += 1;
        }
        decoded.push(raw[index] as char);
        index += 1;
    }
    decoded
}

fn raw_node_matches_typed(raw: &RawNode, typed: &Sexp) -> bool {
    match (&raw.kind, typed) {
        (RawNodeKind::Atom(bytes), Sexp::Atom(text)) => {
            std::str::from_utf8(bytes).is_ok_and(|raw_text| raw_text == text)
        }
        (RawNodeKind::Quoted(bytes), Sexp::QuotedAtom(text)) => decode_quoted(bytes) == *text,
        (RawNodeKind::List(raw_items), Sexp::List(typed_items)) => {
            raw_items.len() == typed_items.len()
                && raw_items
                    .iter()
                    .zip(typed_items)
                    .all(|(left, right)| raw_node_matches_typed(left, right))
        }
        _ => false,
    }
}

#[derive(Debug, Clone)]
struct AssertionIdentity {
    command_index: usize,
    id: String,
    ordinal: usize,
    raw_ast_sha256: String,
    source_slice_sha256: String,
    span: ByteSpan,
}

#[derive(Debug, Clone)]
struct CommandIdentity {
    assertion_ordinal: Option<usize>,
    head: Option<String>,
    id: String,
    ordinal: usize,
    raw_ast_sha256: String,
    source_slice_sha256: String,
    span: ByteSpan,
}

fn command_identities(source: &[u8], nodes: &[RawNode]) -> Result<Vec<CommandIdentity>, String> {
    let mut assertion_ordinal = 0usize;
    let mut previous_end = 0usize;
    let mut commands = Vec::with_capacity(nodes.len());
    for (ordinal, node) in nodes.iter().enumerate() {
        if node.span.start < previous_end {
            return Err(format!(
                "overlapping top-level command span at command {ordinal}"
            ));
        }
        previous_end = node.span.end;
        let head = node
            .syntax_head()
            .map(|bytes| String::from_utf8(bytes.to_vec()))
            .transpose()
            .map_err(|_| format!("command {ordinal} head is not UTF-8"))?;
        let assertion = (head.as_deref() == Some("assert")).then(|| {
            let current = assertion_ordinal;
            assertion_ordinal += 1;
            current
        });
        commands.push(CommandIdentity {
            assertion_ordinal: assertion,
            head,
            id: format!("command-{ordinal:06}"),
            ordinal,
            raw_ast_sha256: sha256_hex(&node.canonical_bytes()),
            source_slice_sha256: sha256_hex(&source[node.span.start..node.span.end]),
            span: node.span,
        });
    }
    Ok(commands)
}

fn assertion_identities(commands: &[CommandIdentity]) -> Vec<AssertionIdentity> {
    commands
        .iter()
        .filter_map(|command| {
            command.assertion_ordinal.map(|ordinal| AssertionIdentity {
                command_index: command.ordinal,
                id: format!("assertion-{ordinal:06}"),
                ordinal,
                raw_ast_sha256: command.raw_ast_sha256.clone(),
                source_slice_sha256: command.source_slice_sha256.clone(),
                span: command.span,
            })
        })
        .collect()
}

#[derive(Debug, Clone)]
struct PendingObject {
    actual_index: usize,
    category: &'static str,
    left: Option<TermId>,
    origins: BTreeSet<usize>,
    owner: Option<SymId>,
    right: Option<TermId>,
    transformation_kind: String,
}

#[derive(Debug, Clone)]
struct PendingDiagnostic {
    assertion: Option<usize>,
    category: &'static str,
    command: usize,
    message: String,
}

#[derive(Debug, Default)]
pub(crate) struct Recorder {
    bool_assertions: Vec<PendingObject>,
    contradictions: Vec<PendingObject>,
    current_assertion: Option<usize>,
    current_command: Option<usize>,
    current_definition: Option<SymId>,
    diagnostics: Vec<PendingDiagnostic>,
    euf_facts: Vec<PendingObject>,
    internal_terms: Vec<PendingObject>,
    internal_term_positions: BTreeMap<TermId, usize>,
    macro_dependencies: BTreeMap<SymId, BTreeSet<SymId>>,
    macro_uses: BTreeMap<usize, BTreeSet<SymId>>,
}

impl Recorder {
    pub(crate) fn new() -> Self {
        #[cfg(test)]
        RECORDER_CONSTRUCTIONS.set(RECORDER_CONSTRUCTIONS.get() + 1);
        Self::default()
    }

    pub(crate) fn begin_command(&mut self, command: usize, assertion: Option<usize>) {
        debug_assert!(self.current_command.is_none());
        debug_assert!(self.current_definition.is_none());
        self.current_command = Some(command);
        self.current_assertion = assertion;
    }

    pub(crate) fn end_command(&mut self) {
        self.current_definition = None;
        self.current_assertion = None;
        self.current_command = None;
    }

    pub(crate) fn begin_definition(&mut self, symbol: SymId) {
        debug_assert!(self.current_definition.is_none());
        self.current_definition = Some(symbol);
    }

    pub(crate) fn end_definition(&mut self) {
        self.current_definition = None;
    }

    fn current_origins(&self) -> BTreeSet<usize> {
        self.current_assertion.into_iter().collect()
    }

    pub(crate) fn record_bool_assertion(
        &mut self,
        index: usize,
        transformation_kind: &'static str,
    ) {
        debug_assert_eq!(self.bool_assertions.len(), index);
        self.bool_assertions.push(PendingObject {
            actual_index: index,
            category: "boolean_assertion",
            left: None,
            origins: self.current_origins(),
            owner: self.current_definition,
            right: None,
            transformation_kind: transformation_kind.to_owned(),
        });
    }

    pub(crate) fn truncate_bool_assertions(&mut self, len: usize) {
        self.bool_assertions.truncate(len);
    }

    pub(crate) fn record_internal_term(&mut self, term: TermId, kind: &str) {
        let position = self.internal_terms.len();
        let previous = self.internal_term_positions.insert(term, position);
        debug_assert!(previous.is_none());
        self.internal_terms.push(PendingObject {
            actual_index: term,
            category: "internal_term",
            left: Some(term),
            origins: self.current_origins(),
            owner: self.current_definition,
            right: None,
            transformation_kind: match kind {
                "true" => "internal_bool_true_term",
                "false" => "internal_bool_false_term",
                "ite" => "term_ite_result_term",
                "bool_expr" => "bool_materialization_term",
                other => other,
            }
            .to_owned(),
        });
    }

    pub(crate) fn add_current_origin_to_internal_term(&mut self, term: TermId) {
        let Some(origin) = self.current_assertion else {
            return;
        };
        if let Some(&position) = self.internal_term_positions.get(&term) {
            self.internal_terms[position].origins.insert(origin);
        }
    }

    pub(crate) fn record_euf_fact(
        &mut self,
        category: &'static str,
        index: usize,
        left: TermId,
        right: TermId,
        transformation_kind: &'static str,
    ) {
        self.euf_facts.push(PendingObject {
            actual_index: index,
            category,
            left: Some(left),
            origins: self.current_origins(),
            owner: self.current_definition,
            right: Some(right),
            transformation_kind: transformation_kind.to_owned(),
        });
    }

    pub(crate) fn record_contradiction(&mut self, transformation_kind: &'static str) {
        self.contradictions.push(PendingObject {
            actual_index: self.contradictions.len(),
            category: "contradiction",
            left: None,
            origins: self.current_origins(),
            owner: self.current_definition,
            right: None,
            transformation_kind: transformation_kind.to_owned(),
        });
    }

    pub(crate) fn record_diagnostic(&mut self, category: &'static str, message: &str) {
        let command = self
            .current_command
            .expect("parser diagnostics are emitted while parsing a command");
        self.diagnostics.push(PendingDiagnostic {
            assertion: self.current_assertion,
            category,
            command,
            message: message.to_owned(),
        });
    }

    pub(crate) fn record_macro_use(&mut self, symbol: SymId) {
        if let Some(assertion) = self.current_assertion {
            self.macro_uses.entry(assertion).or_default().insert(symbol);
        } else if let Some(owner) = self.current_definition
            && owner != symbol
        {
            self.macro_dependencies
                .entry(owner)
                .or_default()
                .insert(symbol);
        }
    }

    fn propagate_macro_origins(&mut self) {
        let mut macro_origins = BTreeMap::<SymId, BTreeSet<usize>>::new();
        for (&assertion, roots) in &self.macro_uses {
            let mut pending = roots.iter().copied().collect::<Vec<_>>();
            let mut seen = BTreeSet::new();
            while let Some(symbol) = pending.pop() {
                if !seen.insert(symbol) {
                    continue;
                }
                macro_origins.entry(symbol).or_default().insert(assertion);
                if let Some(dependencies) = self.macro_dependencies.get(&symbol) {
                    pending.extend(dependencies.iter().copied());
                }
            }
        }

        for object in self
            .bool_assertions
            .iter_mut()
            .chain(&mut self.internal_terms)
            .chain(&mut self.euf_facts)
            .chain(&mut self.contradictions)
        {
            if let Some(owner) = object.owner
                && let Some(origins) = macro_origins.get(&owner)
            {
                object.origins.extend(origins);
            }
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct OriginRecord {
    assertion_id: String,
    raw_ast_sha256: String,
    source_slice_sha256: String,
    span: ByteSpan,
}

#[derive(Debug, Clone, Serialize)]
struct CommandRecord {
    assertion_id: Option<String>,
    head: Option<String>,
    id: String,
    ordinal: usize,
    raw_ast_sha256: String,
    source_slice_sha256: String,
    span: ByteSpan,
}

#[derive(Debug, Clone, Serialize)]
struct AssertionRecord {
    command_id: String,
    id: String,
    ordinal: usize,
    raw_ast_sha256: String,
    source_slice_sha256: String,
    span: ByteSpan,
}

#[derive(Debug, Clone, Serialize)]
struct ObjectRecord {
    id: String,
    local_index: usize,
    object_kind: String,
    origins: Vec<OriginRecord>,
    transformation_kind: String,
    typed_object_sha256: String,
}

#[derive(Debug, Clone, Serialize)]
struct DiagnosticRecord {
    assertion_origins: Vec<OriginRecord>,
    category: String,
    command_id: String,
    id: String,
    message: String,
}

#[derive(Debug, Clone, Serialize)]
struct SourceBinding {
    byte_binding: &'static str,
    bytes: usize,
    device: u64,
    inode: u64,
    path: String,
    sha256: String,
}

#[derive(Debug, Clone, Serialize)]
struct BuildBinding {
    git_dirty: bool,
    git_revision: &'static str,
    package_version: &'static str,
    rustc: &'static str,
    source_revision_sha256: String,
}

#[derive(Debug, Clone, Serialize)]
struct ParserBinding {
    architecture: &'static str,
    bounded_let_count: usize,
    legacy_preprocess_term_limit: usize,
    raw_ast_encoding: &'static str,
    requested_scoped_let_mode: String,
    selected_scoped_let: bool,
    single_assertion_preprocessing: bool,
    source_revision_sha256: String,
    span_convention: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct ScopeBinding {
    boolean_euf_typed_ir_only: bool,
    sat_solving_performed: bool,
}

#[derive(Debug, Clone, Serialize)]
struct CountRecord {
    boolean_assertions: usize,
    commands: usize,
    contradiction_events: usize,
    diagnostics: usize,
    euf_disequalities: usize,
    euf_equalities: usize,
    internal_terms: usize,
    objects: usize,
    source_assertions: usize,
}

#[derive(Debug, Clone, Serialize)]
struct Ledger {
    active_check_sat: CommandRecord,
    assertions: Vec<AssertionRecord>,
    build: BuildBinding,
    commands: Vec<CommandRecord>,
    counts: CountRecord,
    diagnostics: Vec<DiagnosticRecord>,
    lineage_sha256: String,
    objects: Vec<ObjectRecord>,
    parser: ParserBinding,
    schema: &'static str,
    scope: ScopeBinding,
    source: SourceBinding,
    status: &'static str,
    unsupported_accounting_complete: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileFingerprint {
    changed_ns: i128,
    device: u64,
    inode: u64,
    mode: u32,
    modified_ns: i128,
    size: u64,
}

impl FileFingerprint {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            changed_ns: i128::from(metadata.ctime()) * 1_000_000_000
                + i128::from(metadata.ctime_nsec()),
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
            modified_ns: i128::from(metadata.mtime()) * 1_000_000_000
                + i128::from(metadata.mtime_nsec()),
            size: metadata.size(),
        }
    }
}

struct OpenedSource {
    bytes: Vec<u8>,
    canonical_path: PathBuf,
    file: File,
    fingerprint: FileFingerprint,
}

impl OpenedSource {
    fn open(path: &Path, expected_sha256: &str, expected_bytes: usize) -> Result<Self, String> {
        validate_sha256(expected_sha256)?;
        let file_name = path
            .file_name()
            .ok_or_else(|| format!("source path has no file name: {}", path.display()))?;
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let canonical_parent = parent
            .canonicalize()
            .map_err(|error| format!("cannot canonicalize source parent: {error}"))?;
        let canonical_path = canonical_parent.join(file_name);
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        let mut file = options.open(&canonical_path).map_err(|error| {
            format!(
                "cannot no-follow open {}: {error}",
                canonical_path.display()
            )
        })?;
        let before = file
            .metadata()
            .map_err(|error| format!("cannot stat opened source: {error}"))?;
        if !before.file_type().is_file() {
            return Err("opened source is not a regular file".to_owned());
        }
        let fingerprint = FileFingerprint::from_metadata(&before);
        if fingerprint.size != expected_bytes as u64 {
            return Err(format!(
                "stale-source: expected {expected_bytes} bytes, opened {}",
                fingerprint.size
            ));
        }
        let mut bytes = Vec::with_capacity(expected_bytes);
        file.read_to_end(&mut bytes)
            .map_err(|error| format!("cannot read opened source: {error}"))?;
        if bytes.len() != expected_bytes {
            return Err(format!(
                "stale-source: expected {expected_bytes} bytes, read {}",
                bytes.len()
            ));
        }
        let actual_sha256 = sha256_hex(&bytes);
        if actual_sha256 != expected_sha256 {
            return Err(format!(
                "stale-source: expected SHA-256 {expected_sha256}, opened {actual_sha256}"
            ));
        }
        let source = Self {
            bytes,
            canonical_path,
            file,
            fingerprint,
        };
        source.verify_unchanged()?;
        Ok(source)
    }

    fn verify_unchanged(&self) -> Result<(), String> {
        let descriptor = self
            .file
            .metadata()
            .map_err(|error| format!("cannot restat opened source: {error}"))?;
        if FileFingerprint::from_metadata(&descriptor) != self.fingerprint {
            return Err("stale-source: opened source changed after open".to_owned());
        }
        let path_metadata = fs::symlink_metadata(&self.canonical_path)
            .map_err(|error| format!("stale-source: source path vanished: {error}"))?;
        let path_fingerprint = FileFingerprint::from_metadata(&path_metadata);
        if path_fingerprint.device != self.fingerprint.device
            || path_fingerprint.inode != self.fingerprint.inode
            || !path_metadata.file_type().is_file()
        {
            return Err("stale-source: source path identity changed after open".to_owned());
        }

        let mut duplicate = self
            .file
            .try_clone()
            .map_err(|error| format!("cannot duplicate source descriptor: {error}"))?;
        duplicate
            .seek(SeekFrom::Start(0))
            .map_err(|error| format!("cannot rewind source descriptor: {error}"))?;
        let mut replay = Vec::with_capacity(self.bytes.len());
        duplicate
            .read_to_end(&mut replay)
            .map_err(|error| format!("cannot replay source descriptor: {error}"))?;
        if replay != self.bytes {
            return Err("stale-source: opened source bytes changed after snapshot".to_owned());
        }
        let replayed = self
            .file
            .metadata()
            .map_err(|error| format!("cannot restat replayed source: {error}"))?;
        if FileFingerprint::from_metadata(&replayed) != self.fingerprint {
            return Err("stale-source: opened source changed during replay".to_owned());
        }
        Ok(())
    }
}

fn validate_sha256(value: &str) -> Result<(), String> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err("expected source SHA-256 must be 64 lowercase hexadecimal digits".to_owned())
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn framed_source_revision(parts: &[(&str, &[u8])]) -> String {
    let mut digest = Sha256::new();
    for (name, bytes) in parts {
        digest.update(name.len().to_be_bytes());
        digest.update(name.as_bytes());
        digest.update(bytes.len().to_be_bytes());
        digest.update(bytes);
    }
    format!("{:x}", digest.finalize())
}

fn parser_source_revision() -> String {
    framed_source_revision(&[
        ("src/main.rs", include_bytes!("main.rs")),
        ("src/smt2_stream.rs", include_bytes!("smt2_stream.rs")),
    ])
}

fn build_source_revision() -> String {
    framed_source_revision(&[
        ("build.rs", include_bytes!("../build.rs")),
        ("Cargo.toml", include_bytes!("../Cargo.toml")),
        ("Cargo.lock", include_bytes!("../Cargo.lock")),
        ("src/main.rs", include_bytes!("main.rs")),
        ("src/smt2_stream.rs", include_bytes!("smt2_stream.rs")),
        (
            "src/assertion_lineage.rs",
            include_bytes!("assertion_lineage.rs"),
        ),
    ])
}

fn term_bytes(term: TermId, arena: &TermArena, symbols: &[String], output: &mut Vec<u8>) {
    output.push(b'T');
    append_len(output, term);
    let value = &arena.terms[term];
    let name = symbols
        .get(value.fun as usize)
        .map(String::as_bytes)
        .unwrap_or_default();
    append_len(output, name.len());
    output.extend_from_slice(name);
    append_len(output, value.sort.0 as usize);
    append_len(output, value.args.len());
    for &argument in &value.args {
        term_bytes(argument, arena, symbols, output);
    }
}

fn bool_expr_bytes(expr: &BoolExpr, arena: &TermArena, symbols: &[String], output: &mut Vec<u8>) {
    match expr {
        BoolExpr::Const(value) => output.extend_from_slice(if *value { b"C1" } else { b"C0" }),
        BoolExpr::Atom(BoolAtomKey::Eq(left, right)) => {
            output.push(b'E');
            term_bytes(*left, arena, symbols, output);
            term_bytes(*right, arena, symbols, output);
        }
        BoolExpr::Atom(BoolAtomKey::BoolTerm(term)) => {
            output.push(b'B');
            term_bytes(*term, arena, symbols, output);
        }
        BoolExpr::Not(child) => {
            output.push(b'N');
            bool_expr_bytes(child, arena, symbols, output);
        }
        BoolExpr::And(children) => bool_children_bytes(b'A', children, arena, symbols, output),
        BoolExpr::Or(children) => bool_children_bytes(b'O', children, arena, symbols, output),
        BoolExpr::Iff(children) => bool_children_bytes(b'F', children, arena, symbols, output),
        BoolExpr::Ite(condition, then_expr, else_expr) => {
            output.push(b'I');
            bool_expr_bytes(condition, arena, symbols, output);
            bool_expr_bytes(then_expr, arena, symbols, output);
            bool_expr_bytes(else_expr, arena, symbols, output);
        }
    }
}

fn bool_children_bytes(
    tag: u8,
    children: &[BoolExpr],
    arena: &TermArena,
    symbols: &[String],
    output: &mut Vec<u8>,
) {
    output.push(tag);
    append_len(output, children.len());
    for child in children {
        bool_expr_bytes(child, arena, symbols, output);
    }
}

fn pending_typed_hash(
    pending: &PendingObject,
    problem: &Problem,
    symbols: &[String],
) -> Result<String, String> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(pending.category.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(pending.transformation_kind.as_bytes());
    bytes.push(0);
    append_len(&mut bytes, pending.actual_index);
    match pending.category {
        "boolean_assertion" => {
            let bool_problem = problem
                .bool_problem
                .as_ref()
                .ok_or_else(|| "lineage has Boolean objects but Problem has none".to_owned())?;
            let expr = bool_problem
                .assertions
                .get(pending.actual_index)
                .ok_or_else(|| "Boolean lineage index is out of range".to_owned())?;
            bool_expr_bytes(expr, &problem.arena, symbols, &mut bytes);
        }
        "internal_term" => {
            let term = pending
                .left
                .ok_or_else(|| "internal term is missing".to_owned())?;
            if term >= problem.arena.terms.len() {
                return Err("internal term lineage index is out of range".to_owned());
            }
            term_bytes(term, &problem.arena, symbols, &mut bytes);
        }
        "equality" | "disequality" => {
            term_bytes(
                pending
                    .left
                    .ok_or_else(|| "EUF left term is missing".to_owned())?,
                &problem.arena,
                symbols,
                &mut bytes,
            );
            term_bytes(
                pending
                    .right
                    .ok_or_else(|| "EUF right term is missing".to_owned())?,
                &problem.arena,
                symbols,
                &mut bytes,
            );
        }
        "contradiction" => {}
        other => return Err(format!("unsupported lineage object category `{other}`")),
    }
    Ok(sha256_hex(&bytes))
}

fn origins_for(
    origins: &BTreeSet<usize>,
    assertions: &[AssertionIdentity],
) -> Result<Vec<OriginRecord>, String> {
    origins
        .iter()
        .map(|&ordinal| {
            let assertion = assertions
                .get(ordinal)
                .ok_or_else(|| format!("lineage origin {ordinal} is out of range"))?;
            Ok(OriginRecord {
                assertion_id: assertion.id.clone(),
                raw_ast_sha256: assertion.raw_ast_sha256.clone(),
                source_slice_sha256: assertion.source_slice_sha256.clone(),
                span: assertion.span,
            })
        })
        .collect()
}

fn finalize_objects(
    mut recorder: Recorder,
    problem: &Problem,
    symbols: &[String],
    assertions: &[AssertionIdentity],
) -> Result<(Vec<ObjectRecord>, Vec<DiagnosticRecord>), String> {
    recorder.propagate_macro_origins();
    let bool_count = problem
        .bool_problem
        .as_ref()
        .map_or(0, |boolean| boolean.assertions.len());
    if recorder.bool_assertions.len() != bool_count {
        return Err(format!(
            "lineage loss: recorded {} of {bool_count} Boolean assertions",
            recorder.bool_assertions.len()
        ));
    }
    let recorded_equalities = recorder
        .euf_facts
        .iter()
        .filter(|object| object.category == "equality")
        .count();
    let recorded_disequalities = recorder
        .euf_facts
        .iter()
        .filter(|object| object.category == "disequality")
        .count();
    if recorded_equalities != problem.eqs.len() || recorded_disequalities != problem.diseqs.len() {
        return Err("lineage loss: EUF fact counts do not match the typed Problem".to_owned());
    }
    if problem.contradiction != !recorder.contradictions.is_empty() {
        return Err("lineage loss: contradiction state is not accounted".to_owned());
    }
    let expected_diagnostics = problem.unsupported.len()
        + problem
            .bool_problem
            .as_ref()
            .map_or(0, |boolean| boolean.unsupported.len());
    if recorder.diagnostics.len() != expected_diagnostics {
        return Err(format!(
            "unsupported-accounting error: recorded {} of {expected_diagnostics} diagnostics",
            recorder.diagnostics.len()
        ));
    }

    let mut pending = Vec::new();
    pending.append(&mut recorder.bool_assertions);
    pending.append(&mut recorder.internal_terms);
    pending.append(&mut recorder.euf_facts);
    pending.append(&mut recorder.contradictions);
    let mut local_indices = BTreeMap::<String, usize>::new();
    let mut objects = Vec::with_capacity(pending.len());
    for (ordinal, object) in pending.iter().enumerate() {
        if object.origins.is_empty() {
            return Err(format!(
                "lineage loss: {} object {} has no source assertion origin",
                object.category, object.actual_index
            ));
        }
        let local_index = local_indices
            .entry(object.transformation_kind.clone())
            .or_default();
        let record = ObjectRecord {
            id: format!("object-{ordinal:06}"),
            local_index: *local_index,
            object_kind: object.category.to_owned(),
            origins: origins_for(&object.origins, assertions)?,
            transformation_kind: object.transformation_kind.clone(),
            typed_object_sha256: pending_typed_hash(object, problem, symbols)?,
        };
        *local_index += 1;
        objects.push(record);
    }

    let diagnostics = recorder
        .diagnostics
        .iter()
        .enumerate()
        .map(|(ordinal, diagnostic)| {
            let origins = diagnostic.assertion.into_iter().collect();
            Ok(DiagnosticRecord {
                assertion_origins: origins_for(&origins, assertions)?,
                category: diagnostic.category.to_owned(),
                command_id: format!("command-{:06}", diagnostic.command),
                id: format!("diagnostic-{ordinal:06}"),
                message: diagnostic.message.clone(),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok((objects, diagnostics))
}

fn command_record(command: &CommandIdentity) -> CommandRecord {
    CommandRecord {
        assertion_id: command
            .assertion_ordinal
            .map(|ordinal| format!("assertion-{ordinal:06}")),
        head: command.head.clone(),
        id: command.id.clone(),
        ordinal: command.ordinal,
        raw_ast_sha256: command.raw_ast_sha256.clone(),
        source_slice_sha256: command.source_slice_sha256.clone(),
        span: command.span,
    }
}

fn parse_lineaged_problem(
    input: &str,
    mode: ScopedLetMode,
    raw_nodes: &[RawNode],
    commands: &[CommandIdentity],
) -> Result<(Problem, Recorder, Vec<String>, bool, usize, bool), String> {
    let typed_nodes = parse_sexps(input)?;
    if typed_nodes.len() != raw_nodes.len() || typed_nodes.len() != commands.len() {
        return Err("ambiguous command mapping between lossless and typed parsers".to_owned());
    }
    for (ordinal, (raw, typed)) in raw_nodes.iter().zip(&typed_nodes).enumerate() {
        if !raw_node_matches_typed(raw, typed) {
            return Err(format!(
                "ambiguous raw-AST mapping at top-level command {ordinal}"
            ));
        }
    }

    let bounded_let_count = bounded_lexical_let_count(input);
    let selected = scoped_let_selected(mode, bounded_let_count);
    profile_scoped_let(mode, bounded_let_count, selected);
    let mut context = ParseCtx::new(selected);
    context.lineage = Some(Recorder::new());
    context.preprocess_branch_intersections = typed_nodes
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
    let single_assertion_preprocessing = context.preprocess_branch_intersections;
    for (command, sexp) in commands.iter().zip(&typed_nodes) {
        context
            .lineage
            .as_mut()
            .expect("lineage recorder exists")
            .begin_command(command.ordinal, command.assertion_ordinal);
        let parsed = context.parse_command(sexp);
        context
            .lineage
            .as_mut()
            .expect("lineage recorder exists")
            .end_command();
        parsed?;
    }
    let symbols = context.symbols.ordered_names();
    let recorder = context.lineage.take().expect("lineage recorder exists");
    Ok((
        context.finish(),
        recorder,
        symbols,
        selected,
        bounded_let_count,
        single_assertion_preprocessing,
    ))
}

fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, String> {
    fn write_value(value: &Value, output: &mut Vec<u8>) -> Result<(), String> {
        match value {
            Value::Null => output.extend_from_slice(b"null"),
            Value::Bool(value) => output.extend_from_slice(if *value { b"true" } else { b"false" }),
            Value::Number(number) => {
                if !number.is_i64() && !number.is_u64() {
                    return Err("non-finite or non-integral JSON number is forbidden".to_owned());
                }
                output.extend_from_slice(number.to_string().as_bytes());
            }
            Value::String(text) => {
                let encoded = serde_json::to_string(text)
                    .map_err(|error| format!("cannot encode JSON string: {error}"))?;
                output.extend_from_slice(encoded.as_bytes());
            }
            Value::Array(items) => {
                output.push(b'[');
                for (index, item) in items.iter().enumerate() {
                    if index != 0 {
                        output.push(b',');
                    }
                    write_value(item, output)?;
                }
                output.push(b']');
            }
            Value::Object(items) => {
                output.push(b'{');
                let mut entries = items.iter().collect::<Vec<_>>();
                entries.sort_unstable_by(|left, right| left.0.cmp(right.0));
                for (index, (key, item)) in entries.into_iter().enumerate() {
                    if index != 0 {
                        output.push(b',');
                    }
                    write_value(&Value::String(key.clone()), output)?;
                    output.push(b':');
                    write_value(item, output)?;
                }
                output.push(b'}');
            }
        }
        Ok(())
    }

    let mut output = Vec::new();
    write_value(value, &mut output)?;
    output.push(b'\n');
    Ok(output)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .map_err(|error| format!("cannot create output directory: {error}"))?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("lineage"),
        std::process::id()
    ));
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| format!("cannot create lineage temporary output: {error}"))?;
    let result = (|| {
        output
            .write_all(bytes)
            .map_err(|error| format!("cannot write lineage output: {error}"))?;
        output
            .sync_all()
            .map_err(|error| format!("cannot sync lineage output: {error}"))?;
        fs::rename(&temporary, path)
            .map_err(|error| format!("cannot install lineage output: {error}"))?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("cannot sync lineage output directory: {error}"))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

pub(crate) fn write_lineage(
    source_path: &Path,
    expected_sha256: &str,
    expected_bytes: usize,
    output_path: &Path,
    mode: ScopedLetMode,
) -> Result<(), String> {
    let source = OpenedSource::open(source_path, expected_sha256, expected_bytes)?;
    if let Some(output_name) = output_path.file_name() {
        let output_parent = output_path.parent().unwrap_or_else(|| Path::new("."));
        if let Ok(canonical_parent) = output_parent.canonicalize()
            && canonical_parent.join(output_name) == source.canonical_path
        {
            return Err("lineage output path must differ from the opened source".to_owned());
        }
    }
    let input = std::str::from_utf8(&source.bytes)
        .map_err(|error| format!("malformed UTF-8 source at byte {}", error.valid_up_to()))?;
    let raw_nodes = LosslessParser::new(&source.bytes).parse_all()?;
    let commands = command_identities(&source.bytes, &raw_nodes)?;
    let assertions = assertion_identities(&commands);
    let active = commands
        .iter()
        .filter(|command| command.head.as_deref() == Some("check-sat"))
        .collect::<Vec<_>>();
    let [active_check_sat] = active.as_slice() else {
        return Err(format!(
            "lineage requires exactly one active check-sat command, found {}",
            active.len()
        ));
    };
    let (problem, recorder, symbols, selected, bounded_let_count, single_assertion_preprocessing) =
        parse_lineaged_problem(input, mode, &raw_nodes, &commands)?;
    let legacy_preprocess_term_limit = std::env::var("EUF_VIPER_LEGACY_PREPROCESS_TERM_LIMIT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1_024usize);
    let (objects, diagnostics) = finalize_objects(recorder, &problem, &symbols, &assertions)?;
    let equality_count = objects
        .iter()
        .filter(|object| object.object_kind == "equality")
        .count();
    let disequality_count = objects
        .iter()
        .filter(|object| object.object_kind == "disequality")
        .count();
    let internal_count = objects
        .iter()
        .filter(|object| object.object_kind == "internal_term")
        .count();
    let boolean_count = objects
        .iter()
        .filter(|object| object.object_kind == "boolean_assertion")
        .count();
    let contradiction_count = objects
        .iter()
        .filter(|object| object.object_kind == "contradiction")
        .count();
    let source_path_text = source
        .canonical_path
        .to_str()
        .ok_or_else(|| "source path is not valid UTF-8".to_owned())?
        .to_owned();
    let mut ledger = Ledger {
        active_check_sat: command_record(active_check_sat),
        assertions: assertions
            .iter()
            .map(|assertion| AssertionRecord {
                command_id: format!("command-{:06}", assertion.command_index),
                id: assertion.id.clone(),
                ordinal: assertion.ordinal,
                raw_ast_sha256: assertion.raw_ast_sha256.clone(),
                source_slice_sha256: assertion.source_slice_sha256.clone(),
                span: assertion.span,
            })
            .collect(),
        build: BuildBinding {
            git_dirty: env!("EUF_VIPER_BUILD_GIT_DIRTY") == "true",
            git_revision: env!("EUF_VIPER_BUILD_GIT_REVISION"),
            package_version: env!("CARGO_PKG_VERSION"),
            rustc: env!("EUF_VIPER_BUILD_RUSTC"),
            source_revision_sha256: build_source_revision(),
        },
        commands: commands.iter().map(command_record).collect(),
        counts: CountRecord {
            boolean_assertions: boolean_count,
            commands: commands.len(),
            contradiction_events: contradiction_count,
            diagnostics: diagnostics.len(),
            euf_disequalities: disequality_count,
            euf_equalities: equality_count,
            internal_terms: internal_count,
            objects: objects.len(),
            source_assertions: assertions.len(),
        },
        diagnostics,
        lineage_sha256: String::new(),
        objects,
        parser: ParserBinding {
            architecture: PARSER_ARCHITECTURE,
            bounded_let_count,
            legacy_preprocess_term_limit,
            raw_ast_encoding: RAW_AST_ENCODING,
            requested_scoped_let_mode: mode.as_str().to_owned(),
            selected_scoped_let: selected,
            single_assertion_preprocessing,
            source_revision_sha256: parser_source_revision(),
            span_convention: SPAN_CONVENTION,
        },
        schema: SCHEMA,
        scope: ScopeBinding {
            boolean_euf_typed_ir_only: true,
            sat_solving_performed: false,
        },
        source: SourceBinding {
            byte_binding: BYTE_BINDING,
            bytes: source.bytes.len(),
            device: source.fingerprint.device,
            inode: source.fingerprint.inode,
            path: source_path_text,
            sha256: sha256_hex(&source.bytes),
        },
        status: "complete",
        unsupported_accounting_complete: true,
    };
    source.verify_unchanged()?;
    let mut commitment = serde_json::to_value(&ledger)
        .map_err(|error| format!("cannot construct lineage JSON: {error}"))?;
    commitment
        .as_object_mut()
        .expect("ledger serializes to an object")
        .remove("lineage_sha256");
    ledger.lineage_sha256 = sha256_hex(&canonical_json_bytes(&commitment)?);
    let value = serde_json::to_value(&ledger)
        .map_err(|error| format!("cannot construct lineage JSON: {error}"))?;
    let bytes = canonical_json_bytes(&value)?;
    source.verify_unchanged()?;
    atomic_write(output_path, &bytes)?;
    if let Err(error) = source.verify_unchanged() {
        fs::remove_file(output_path).map_err(|remove_error| {
            format!("{error}; additionally failed to remove stale lineage output: {remove_error}")
        })?;
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "euf-viper-lineage-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn lossless_parser_preserves_crlf_comments_and_repeated_spans() {
        let source = b"; lead\r\n(assert (= |x y| |x y|)) ; middle\r\n(assert (= |x y| |x y|))\r\n(check-sat)\r\n";
        let nodes = LosslessParser::new(source).parse_all().unwrap();
        let commands = command_identities(source, &nodes).unwrap();
        let assertions = assertion_identities(&commands);
        assert_eq!(assertions.len(), 2);
        assert_ne!(assertions[0].span, assertions[1].span);
        assert_eq!(assertions[0].raw_ast_sha256, assertions[1].raw_ast_sha256);
        assert_eq!(
            &source[assertions[0].span.start..assertions[0].span.end],
            b"(assert (= |x y| |x y|))"
        );
    }

    #[test]
    fn ordinary_parse_does_not_construct_a_lineage_recorder() {
        let before = RECORDER_CONSTRUCTIONS.get();
        let problem =
            super::super::parse_problem("(set-logic QF_UF)\n(assert true)\n(check-sat)\n").unwrap();
        assert!(problem.bool_problem.is_some());
        assert_eq!(RECORDER_CONSTRUCTIONS.get(), before);
    }

    #[test]
    fn opened_source_rejects_mutation_after_snapshot() {
        let path = temporary_path("mutation");
        fs::write(&path, b"(assert p)\n(check-sat)\n").unwrap();
        let original = fs::read(&path).unwrap();
        let source = OpenedSource::open(&path, &sha256_hex(&original), original.len()).unwrap();
        fs::write(&path, b"(assert q)\n(check-sat)\n").unwrap();
        let error = source.verify_unchanged().unwrap_err();
        assert!(error.contains("stale-source"), "{error}");
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn malformed_utf8_is_rejected_before_typed_parsing() {
        let source_path = temporary_path("utf8-source");
        let output_path = temporary_path("utf8-output");
        let bytes = b"(assert |\xff|)\n(check-sat)\n";
        fs::write(&source_path, bytes).unwrap();
        let error = write_lineage(
            &source_path,
            &sha256_hex(bytes),
            bytes.len(),
            &output_path,
            ScopedLetMode::On,
        )
        .unwrap_err();
        assert!(error.contains("malformed UTF-8"), "{error}");
        assert!(!output_path.exists());
        fs::remove_file(source_path).unwrap();
    }

    #[test]
    fn quoted_shadow_and_repeated_macro_roots_have_exact_shared_lineage() {
        let source_path = Path::new("tests/fixtures/assertion_lineage/adversarial.smt2");
        let output_path = temporary_path("adversarial-output");
        let bytes = fs::read(source_path).unwrap();
        write_lineage(
            source_path,
            &sha256_hex(&bytes),
            bytes.len(),
            &output_path,
            ScopedLetMode::On,
        )
        .unwrap();
        let ledger: Value = serde_json::from_slice(&fs::read(&output_path).unwrap()).unwrap();
        let assertions = ledger["assertions"].as_array().unwrap();
        assert_eq!(assertions.len(), 4);
        assert_eq!(
            assertions[1]["raw_ast_sha256"],
            assertions[2]["raw_ast_sha256"]
        );
        assert_ne!(assertions[1]["span"], assertions[2]["span"]);

        let shared = ledger["objects"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|object| {
                matches!(
                    object["transformation_kind"].as_str(),
                    Some("bool_materialization_axiom" | "bool_materialization_term")
                ) && object["origins"].as_array().unwrap().len() == 2
            })
            .count();
        assert_eq!(shared, 2);
        for object in ledger["objects"].as_array().unwrap() {
            let origins = object["origins"].as_array().unwrap();
            if matches!(
                object["transformation_kind"].as_str(),
                Some("bool_materialization_axiom" | "bool_materialization_term")
            ) && origins.len() == 2
            {
                assert_eq!(origins[0]["assertion_id"], "assertion-000001");
                assert_eq!(origins[1]["assertion_id"], "assertion-000002");
            }
        }
        fs::remove_file(output_path).unwrap();
    }

    #[test]
    fn lineaged_parse_and_ordinary_parse_have_solve_parity() {
        let input = include_str!("../tests/fixtures/assertion_lineage/adversarial.smt2");
        let raw = LosslessParser::new(input.as_bytes()).parse_all().unwrap();
        let commands = command_identities(input.as_bytes(), &raw).unwrap();
        let (lineaged, _, _, _, _, _) =
            parse_lineaged_problem(input, ScopedLetMode::On, &raw, &commands).unwrap();
        let ordinary =
            super::super::parse_problem_with_scoped_let_mode(input, ScopedLetMode::On).unwrap();

        assert_eq!(lineaged.eqs, ordinary.eqs);
        assert_eq!(lineaged.diseqs, ordinary.diseqs);
        assert_eq!(lineaged.unsupported, ordinary.unsupported);
        assert_eq!(lineaged.contradiction, ordinary.contradiction);
        assert_eq!(lineaged.arena.terms.len(), ordinary.arena.terms.len());
        assert_eq!(
            lineaged.bool_problem.as_ref().unwrap().assertions,
            ordinary.bool_problem.as_ref().unwrap().assertions
        );
        assert_eq!(
            super::super::solve_problem(lineaged, false).result,
            super::super::solve_problem(ordinary, false).result
        );
    }
}
