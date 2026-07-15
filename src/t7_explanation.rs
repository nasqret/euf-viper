//! Bounded SAT-impact explanation selection and experiment telemetry.

use std::{
    collections::BTreeSet,
    fs::OpenOptions,
    io::{BufWriter, Write},
    path::{Path, PathBuf},
};

use rustc_hash::FxHashMap as HashMap;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::rollback_euf::{ActiveFactRecord, ExplanationCandidate};

pub(crate) const T7_EXPLANATION_ENV: &str = "EUF_VIPER_T7_EXPLANATION";
pub(crate) const T7_TRANSCRIPT_ENV: &str = "EUF_VIPER_T7_TRANSCRIPT";
pub(crate) const T7_TRANSCRIPT_SCHEMA: &str = "euf-viper.t7-transcript.v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum T7ExplanationMode {
    Off,
    On,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct T7ExperimentConfig {
    pub(crate) mode: T7ExplanationMode,
    pub(crate) transcript_path: Option<PathBuf>,
    pub(crate) direct_root_cnf: bool,
    pub(crate) direct_negated_root: bool,
}

pub(crate) fn parse_explanation_mode(
    value: Option<&str>,
) -> Result<Option<T7ExplanationMode>, String> {
    match value {
        None => Ok(None),
        Some("off") => Ok(Some(T7ExplanationMode::Off)),
        Some("on") => Ok(Some(T7ExplanationMode::On)),
        Some(_) => Err(format!("{T7_EXPLANATION_ENV} must be off or on")),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct CandidateMetrics {
    pub(crate) lbd: usize,
    pub(crate) current_level_literals: usize,
    pub(crate) second_highest_level: usize,
    pub(crate) historical_reuse: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CandidateSelection {
    pub(crate) metrics: Vec<CandidateMetrics>,
    pub(crate) minimum_width: usize,
    pub(crate) off_index: usize,
    pub(crate) on_index: usize,
    pub(crate) selected_index: usize,
    pub(crate) disagreement: bool,
}

#[derive(Debug)]
pub(crate) struct T7Selector {
    mode: T7ExplanationMode,
    on_literal_reuse: HashMap<i32, u64>,
}

impl T7Selector {
    pub(crate) fn new(mode: T7ExplanationMode) -> Self {
        Self {
            mode,
            on_literal_reuse: HashMap::default(),
        }
    }

    pub(crate) fn select(
        &mut self,
        candidates: &[ExplanationCandidate],
        mut literal_level: impl FnMut(i32) -> Option<usize>,
        current_level: usize,
    ) -> Result<CandidateSelection, String> {
        if candidates.is_empty() {
            return Err("T7 explanation reconstruction produced no candidates".to_owned());
        }

        let minimum_width = candidates
            .iter()
            .map(|candidate| candidate.conflict().clause().len())
            .min()
            .expect("non-empty candidate pool");
        let mut metrics = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            let mut levels = BTreeSet::new();
            let mut current_level_literals = 0usize;
            for &literal in candidate.conflict().antecedents() {
                let level = literal_level(literal)
                    .ok_or_else(|| format!("T7 candidate references inactive literal {literal}"))?;
                levels.insert(level);
                if level == current_level {
                    current_level_literals = current_level_literals.saturating_add(1);
                }
            }
            let second_highest_level = levels.iter().rev().nth(1).copied().unwrap_or(0);
            let historical_reuse = candidate
                .conflict()
                .clause()
                .iter()
                .map(|literal| self.on_literal_reuse.get(literal).copied().unwrap_or(0))
                .try_fold(0u64, u64::checked_add)
                .ok_or_else(|| "T7 historical reuse counter overflowed".to_owned())?;
            metrics.push(CandidateMetrics {
                lbd: levels.len(),
                current_level_literals,
                second_highest_level,
                historical_reuse,
            });
        }

        let eligible: Vec<usize> = candidates
            .iter()
            .enumerate()
            .filter_map(|(index, candidate)| {
                (candidate.conflict().clause().len() == minimum_width).then_some(index)
            })
            .collect();
        let off_index = *eligible
            .iter()
            .min_by_key(|&&index| candidates[index].conflict().clause())
            .expect("minimum-width pool is non-empty");
        let on_index = *eligible
            .iter()
            .min_by(|&&left, &&right| {
                let left_metrics = &metrics[left];
                let right_metrics = &metrics[right];
                left_metrics
                    .lbd
                    .cmp(&right_metrics.lbd)
                    .then_with(|| {
                        left_metrics
                            .current_level_literals
                            .cmp(&right_metrics.current_level_literals)
                    })
                    .then_with(|| {
                        left_metrics
                            .second_highest_level
                            .cmp(&right_metrics.second_highest_level)
                    })
                    .then_with(|| {
                        right_metrics
                            .historical_reuse
                            .cmp(&left_metrics.historical_reuse)
                    })
                    .then_with(|| {
                        candidates[left]
                            .conflict()
                            .clause()
                            .cmp(candidates[right].conflict().clause())
                    })
            })
            .expect("minimum-width pool is non-empty");
        let selected_index = match self.mode {
            T7ExplanationMode::Off => off_index,
            T7ExplanationMode::On => on_index,
        };
        if candidates[selected_index].conflict().clause().len() != minimum_width
            || candidates[on_index].conflict().clause().len()
                > candidates[off_index].conflict().clause().len()
        {
            return Err("T7 selector escaped the minimum-width candidate pool".to_owned());
        }
        for &literal in candidates[on_index].conflict().clause() {
            let reuse = self.on_literal_reuse.entry(literal).or_insert(0);
            *reuse = reuse
                .checked_add(1)
                .ok_or_else(|| "T7 historical reuse counter overflowed".to_owned())?;
        }

        Ok(CandidateSelection {
            metrics,
            minimum_width,
            off_index,
            on_index,
            selected_index,
            disagreement: off_index != on_index,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct CandidateTelemetry {
    pub(crate) clause: Vec<i32>,
    pub(crate) antecedents: Vec<i32>,
    pub(crate) forests: Vec<&'static str>,
    pub(crate) metrics: CandidateMetrics,
    pub(crate) replay_valid: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct ConflictTelemetry {
    pub(crate) event: usize,
    pub(crate) decision_level: usize,
    pub(crate) trail_sha256: String,
    pub(crate) active_facts: Vec<ActiveFactRecord>,
    pub(crate) candidates: Vec<CandidateTelemetry>,
    pub(crate) minimum_width: usize,
    pub(crate) off_index: usize,
    pub(crate) on_index: usize,
    pub(crate) selected_index: usize,
    pub(crate) disagreement: bool,
    pub(crate) candidate_duplicates: usize,
    pub(crate) build_ns: u128,
    pub(crate) score_ns: u128,
    pub(crate) replay_ns: u128,
    pub(crate) disposition: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct T7RunSummary {
    pub(crate) result: &'static str,
    pub(crate) decisions: u64,
    pub(crate) propagations: u64,
    pub(crate) sat_conflicts: u64,
    pub(crate) backtracks: usize,
    pub(crate) theory_conflicts: usize,
    pub(crate) model_checks: usize,
    pub(crate) validations: usize,
    pub(crate) persistent_duplicates: usize,
    pub(crate) fallbacks: usize,
    pub(crate) final_model: Option<Vec<i32>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TranscriptReceipt {
    pub(crate) path: PathBuf,
    pub(crate) chain_sha256: String,
}

#[derive(Debug)]
pub(crate) struct T7Telemetry {
    mode: T7ExplanationMode,
    transcript_path: Option<PathBuf>,
    direct_root_cnf: bool,
    direct_negated_root: bool,
    base_variables: usize,
    base_clauses: usize,
    base_cnf_sha256: String,
    events: Vec<ConflictTelemetry>,
}

impl T7Telemetry {
    pub(crate) fn new(
        config: &T7ExperimentConfig,
        variables: usize,
        clauses: &[Vec<i32>],
    ) -> Result<Self, String> {
        let base_cnf_sha256 = hash_json(&json!({
            "clauses": clauses,
            "variables": variables,
        }))?;
        Ok(Self {
            mode: config.mode,
            transcript_path: config.transcript_path.clone(),
            direct_root_cnf: config.direct_root_cnf,
            direct_negated_root: config.direct_negated_root,
            base_variables: variables,
            base_clauses: clauses.len(),
            base_cnf_sha256,
            events: Vec::new(),
        })
    }

    pub(crate) fn record_conflict(
        &mut self,
        facts: &[ActiveFactRecord],
        decision_level: usize,
        candidates: &[ExplanationCandidate],
        replay_valid: &[bool],
        selection: &CandidateSelection,
        candidate_duplicates: usize,
        build_ns: u128,
        score_ns: u128,
        replay_ns: u128,
    ) -> Result<usize, String> {
        if candidates.len() != replay_valid.len() || candidates.len() != selection.metrics.len() {
            return Err("T7 telemetry candidate vectors have inconsistent lengths".to_owned());
        }
        let event = self.events.len();
        let trail_sha256 = hash_json(&facts)?;
        let candidates = candidates
            .iter()
            .zip(replay_valid)
            .zip(&selection.metrics)
            .map(|((candidate, &replay_valid), metrics)| CandidateTelemetry {
                clause: candidate.conflict().clause().to_vec(),
                antecedents: candidate.conflict().antecedents().to_vec(),
                forests: candidate
                    .forests()
                    .iter()
                    .map(|forest| forest.as_str())
                    .collect(),
                metrics: metrics.clone(),
                replay_valid,
            })
            .collect();
        self.events.push(ConflictTelemetry {
            event,
            decision_level,
            trail_sha256,
            active_facts: facts.to_vec(),
            candidates,
            minimum_width: selection.minimum_width,
            off_index: selection.off_index,
            on_index: selection.on_index,
            selected_index: selection.selected_index,
            disagreement: selection.disagreement,
            candidate_duplicates,
            build_ns,
            score_ns,
            replay_ns,
            disposition: "selected",
        });
        Ok(event)
    }

    pub(crate) fn set_disposition(
        &mut self,
        event: usize,
        disposition: &'static str,
    ) -> Result<(), String> {
        let record = self
            .events
            .get_mut(event)
            .ok_or_else(|| format!("T7 telemetry event {event} is out of range"))?;
        record.disposition = disposition;
        Ok(())
    }

    pub(crate) fn finish(
        &self,
        summary: &T7RunSummary,
    ) -> Result<Option<TranscriptReceipt>, String> {
        let Some(path) = &self.transcript_path else {
            return Ok(None);
        };
        let emitted_suffix = self.distinct_emitted_suffix();
        let suffix_sha256 = hash_json(&emitted_suffix)?;
        let checked_total = |field: &'static str, values: Vec<u128>| {
            values.into_iter().try_fold(0u128, |total, value| {
                total
                    .checked_add(value)
                    .ok_or_else(|| format!("T7 {field} total overflow"))
            })
        };
        let build_ns = checked_total(
            "candidate-build time",
            self.events.iter().map(|event| event.build_ns).collect(),
        )?;
        let score_ns = checked_total(
            "candidate-score time",
            self.events.iter().map(|event| event.score_ns).collect(),
        )?;
        let replay_ns = checked_total(
            "candidate-replay time",
            self.events.iter().map(|event| event.replay_ns).collect(),
        )?;
        let disagreements = self
            .events
            .iter()
            .filter(|event| event.disagreement)
            .count();
        let candidate_duplicates = self
            .events
            .iter()
            .map(|event| event.candidate_duplicates)
            .sum::<usize>();
        let replay_failures = self
            .events
            .iter()
            .flat_map(|event| &event.candidates)
            .filter(|candidate| !candidate.replay_valid)
            .count();

        let mut records = Vec::with_capacity(self.events.len() + 2);
        records.push(json!({
            "backend": "cadical-rollback",
            "base_clauses": self.base_clauses,
            "base_cnf_sha256": self.base_cnf_sha256,
            "base_variables": self.base_variables,
            "direct_negated_root": self.direct_negated_root,
            "direct_root_cnf": self.direct_root_cnf,
            "kind": "header",
            "mode": self.mode,
            "schema": T7_TRANSCRIPT_SCHEMA,
        }));
        for event in &self.events {
            let mut value = serde_json::to_value(event)
                .map_err(|error| format!("failed to encode T7 conflict telemetry: {error}"))?;
            let object = value
                .as_object_mut()
                .ok_or_else(|| "T7 conflict telemetry did not encode as an object".to_owned())?;
            object.insert("kind".to_owned(), Value::String("conflict".to_owned()));
            object.insert(
                "schema".to_owned(),
                Value::String(T7_TRANSCRIPT_SCHEMA.to_owned()),
            );
            records.push(value);
        }
        records.push(json!({
            "backtracks": summary.backtracks,
            "build_ns": build_ns,
            "candidate_duplicates": candidate_duplicates,
            "decisions": summary.decisions,
            "disagreements": disagreements,
            "fallbacks": summary.fallbacks,
            "final_model": summary.final_model,
            "kind": "summary",
            "mode": self.mode,
            "model_checks": summary.model_checks,
            "persistent_duplicates": summary.persistent_duplicates,
            "propagations": summary.propagations,
            "replay_failures": replay_failures,
            "replay_ns": replay_ns,
            "result": summary.result,
            "sat_conflicts": summary.sat_conflicts,
            "schema": T7_TRANSCRIPT_SCHEMA,
            "score_ns": score_ns,
            "selected_suffix": emitted_suffix,
            "selected_suffix_sha256": suffix_sha256,
            "theory_conflicts": summary.theory_conflicts,
            "validations": summary.validations,
        }));
        write_chain(path, records)
    }

    fn distinct_emitted_suffix(&self) -> Vec<Vec<i32>> {
        let mut seen = BTreeSet::new();
        let mut suffix = Vec::new();
        for event in &self.events {
            if event.disposition != "emitted" {
                continue;
            }
            let clause = event.candidates[event.selected_index].clause.clone();
            if seen.insert(clause.clone()) {
                suffix.push(clause);
            }
        }
        suffix
    }
}

fn canonical_json(value: &Value) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec(value)
        .map_err(|error| format!("failed to encode canonical T7 JSON: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn hash_json(value: &impl Serialize) -> Result<String, String> {
    let value = serde_json::to_value(value)
        .map_err(|error| format!("failed to encode T7 hash input: {error}"))?;
    Ok(hex_digest(&Sha256::digest(canonical_json(&value)?)))
}

fn write_chain(path: &Path, records: Vec<Value>) -> Result<Option<TranscriptReceipt>, String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create {}: {error}", parent.display()))?;
    }
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("failed to create T7 transcript {}: {error}", path.display()))?;
    let mut writer = BufWriter::new(file);
    let mut previous = [0u8; 32];
    let mut previous_hex = "0".repeat(64);
    for (sequence, value) in records.into_iter().enumerate() {
        let mut payload = value
            .as_object()
            .cloned()
            .ok_or_else(|| "T7 transcript record must be an object".to_owned())?;
        payload.insert("sequence".to_owned(), json!(sequence));
        payload.insert(
            "previous_sha256".to_owned(),
            Value::String(previous_hex.clone()),
        );
        let payload_value = Value::Object(payload.clone());
        let encoded = canonical_json(&payload_value)?;
        let mut hasher = Sha256::new();
        hasher.update(previous);
        hasher.update(&encoded);
        previous.copy_from_slice(&hasher.finalize());
        previous_hex = hex_digest(&previous);
        payload.insert(
            "record_sha256".to_owned(),
            Value::String(previous_hex.clone()),
        );
        writer
            .write_all(&canonical_json(&Value::Object(payload))?)
            .map_err(|error| {
                format!("failed to write T7 transcript {}: {error}", path.display())
            })?;
    }
    writer
        .flush()
        .map_err(|error| format!("failed to flush T7 transcript {}: {error}", path.display()))?;
    Ok(Some(TranscriptReceipt {
        path: path.to_path_buf(),
        chain_sha256: previous_hex,
    }))
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::rollback_euf::{EufConflict, ExplanationCandidate, ExplanationForestOrder};

    fn candidate(clause: &[i32], antecedents: &[i32]) -> ExplanationCandidate {
        ExplanationCandidate::for_test(
            EufConflict::for_test(antecedents.to_vec(), clause.to_vec()),
            ExplanationForestOrder::Trail,
        )
    }

    #[test]
    fn strict_mode_parser_rejects_every_non_contract_value() {
        assert_eq!(parse_explanation_mode(None), Ok(None));
        assert_eq!(
            parse_explanation_mode(Some("off")),
            Ok(Some(T7ExplanationMode::Off))
        );
        assert_eq!(
            parse_explanation_mode(Some("on")),
            Ok(Some(T7ExplanationMode::On))
        );
        for value in ["", "OFF", "true", "shadow", " on", "on ", "unknown"] {
            assert!(parse_explanation_mode(Some(value)).is_err(), "{value:?}");
        }
    }

    #[test]
    fn selectors_share_the_minimum_width_pool_and_apply_all_ties() {
        let candidates = vec![
            candidate(&[-5, -4], &[4, 5]),
            candidate(&[-3, -2], &[2, 3]),
            candidate(&[-6, -2, -1], &[1, 2, 6]),
        ];
        let levels = BTreeMap::from([(1, 0), (2, 1), (3, 1), (4, 2), (5, 1), (6, 2)]);
        let mut off = T7Selector::new(T7ExplanationMode::Off);
        let first = off
            .select(&candidates, |literal| levels.get(&literal).copied(), 2)
            .unwrap();
        assert_eq!(first.minimum_width, 2);
        assert_eq!(first.off_index, 0);
        assert_eq!(first.on_index, 1);
        assert_eq!(first.selected_index, 0);
        assert!(first.disagreement);
        assert_eq!(first.metrics[1].lbd, 1);
        assert_eq!(first.metrics[0].lbd, 2);

        let mut on = T7Selector::new(T7ExplanationMode::On);
        let selected = on
            .select(&candidates, |literal| levels.get(&literal).copied(), 2)
            .unwrap();
        assert_eq!(selected.selected_index, 1);
        assert_eq!(
            candidates[selected.selected_index]
                .conflict()
                .clause()
                .len(),
            2
        );
    }

    #[test]
    fn historical_reuse_is_scored_in_both_modes() {
        let candidates = vec![candidate(&[-5, -4], &[4, 5]), candidate(&[-3, -2], &[2, 3])];
        let first_levels = BTreeMap::from([(2, 1), (3, 1), (4, 2), (5, 1)]);
        for mode in [T7ExplanationMode::Off, T7ExplanationMode::On] {
            let mut selector = T7Selector::new(mode);
            let first = selector
                .select(
                    &candidates,
                    |literal| first_levels.get(&literal).copied(),
                    2,
                )
                .unwrap();
            assert_eq!(first.off_index, 0);
            assert_eq!(first.on_index, 1);
            let second = selector.select(&candidates, |_| Some(1), 1).unwrap();
            assert_eq!(second.metrics[0].historical_reuse, 0);
            assert_eq!(second.metrics[1].historical_reuse, 2);
            assert_eq!(second.on_index, 1);
        }
    }

    #[test]
    fn on_selector_applies_current_level_then_second_highest_ties() {
        let current_count_candidates =
            vec![candidate(&[-4, -3], &[3, 4]), candidate(&[-2, -1], &[1, 2])];
        let current_count_levels = BTreeMap::from([(1, 2), (2, 1), (3, 3), (4, 1)]);
        let mut selector = T7Selector::new(T7ExplanationMode::On);
        let selection = selector
            .select(
                &current_count_candidates,
                |literal| current_count_levels.get(&literal).copied(),
                3,
            )
            .unwrap();
        assert_eq!(selection.metrics[0].lbd, selection.metrics[1].lbd);
        assert_eq!(selection.metrics[0].current_level_literals, 1);
        assert_eq!(selection.metrics[1].current_level_literals, 0);
        assert_eq!(selection.on_index, 1);

        let second_highest_candidates =
            vec![candidate(&[-8, -7], &[7, 8]), candidate(&[-6, -5], &[5, 6])];
        let second_highest_levels = BTreeMap::from([(5, 3), (6, 1), (7, 3), (8, 2)]);
        let selection = T7Selector::new(T7ExplanationMode::On)
            .select(
                &second_highest_candidates,
                |literal| second_highest_levels.get(&literal).copied(),
                3,
            )
            .unwrap();
        assert_eq!(selection.metrics[0].lbd, selection.metrics[1].lbd);
        assert_eq!(selection.metrics[0].current_level_literals, 1);
        assert_eq!(selection.metrics[1].current_level_literals, 1);
        assert_eq!(selection.metrics[0].second_highest_level, 2);
        assert_eq!(selection.metrics[1].second_highest_level, 1);
        assert_eq!(selection.on_index, 1);
    }

    #[test]
    fn selector_results_are_invariant_under_generated_candidate_permutations() {
        let candidates = [
            candidate(&[-6, -5], &[5, 6]),
            candidate(&[-4, -3], &[3, 4]),
            candidate(&[-2, -1], &[1, 2]),
        ];
        let levels = BTreeMap::from([(1, 1), (2, 1), (3, 1), (4, 2), (5, 1), (6, 3)]);
        for permutation in [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ] {
            let permuted = permutation
                .into_iter()
                .map(|index| candidates[index].clone())
                .collect::<Vec<_>>();
            let off = T7Selector::new(T7ExplanationMode::Off)
                .select(&permuted, |literal| levels.get(&literal).copied(), 3)
                .unwrap();
            let on = T7Selector::new(T7ExplanationMode::On)
                .select(&permuted, |literal| levels.get(&literal).copied(), 3)
                .unwrap();
            assert_eq!(permuted[off.off_index].conflict().clause(), [-6, -5]);
            assert_eq!(permuted[on.on_index].conflict().clause(), [-2, -1]);
        }
    }

    #[test]
    fn both_arms_emit_equivalent_chain_hashed_candidate_telemetry() {
        let candidates = vec![candidate(&[-5, -4], &[4, 5]), candidate(&[-3, -2], &[2, 3])];
        let facts = vec![
            ActiveFactRecord::for_test(2, 1, 0),
            ActiveFactRecord::for_test(3, 1, 1),
            ActiveFactRecord::for_test(4, 2, 2),
            ActiveFactRecord::for_test(5, 1, 3),
        ];
        let levels = BTreeMap::from([(2, 1), (3, 1), (4, 2), (5, 1)]);
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut conflict_records = Vec::new();
        for mode in [T7ExplanationMode::Off, T7ExplanationMode::On] {
            let path = std::env::temp_dir().join(format!(
                "euf-viper-t7-telemetry-{}-{nonce}-{}.jsonl",
                std::process::id(),
                mode.as_str_for_test()
            ));
            let config = T7ExperimentConfig {
                mode,
                transcript_path: Some(path.clone()),
                direct_root_cnf: true,
                direct_negated_root: false,
            };
            let mut telemetry = T7Telemetry::new(&config, 5, &[vec![1]]).unwrap();
            let mut selector = T7Selector::new(mode);
            let selection = selector
                .select(&candidates, |literal| levels.get(&literal).copied(), 2)
                .unwrap();
            let event = telemetry
                .record_conflict(
                    &facts,
                    2,
                    &candidates,
                    &[true, true],
                    &selection,
                    2,
                    11,
                    13,
                    17,
                )
                .unwrap();
            telemetry.set_disposition(event, "emitted").unwrap();
            let receipt = telemetry
                .finish(&T7RunSummary {
                    result: "unsat",
                    decisions: 19,
                    propagations: 23,
                    sat_conflicts: 29,
                    backtracks: 1,
                    theory_conflicts: 1,
                    model_checks: 0,
                    validations: 0,
                    persistent_duplicates: 0,
                    fallbacks: 0,
                    final_model: None,
                })
                .unwrap()
                .unwrap();
            assert_eq!(receipt.path, path);
            assert_eq!(receipt.chain_sha256.len(), 64);
            let lines: Vec<Value> = std::fs::read_to_string(&path)
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
            assert_eq!(lines.len(), 3);
            assert_eq!(lines[0]["kind"], "header");
            assert_eq!(lines[1]["kind"], "conflict");
            assert_eq!(lines[2]["kind"], "summary");
            assert_eq!(lines[2]["record_sha256"], receipt.chain_sha256);
            assert_eq!(lines[1]["candidates"].as_array().unwrap().len(), 2);
            assert_eq!(lines[1]["off_index"], 0);
            assert_eq!(lines[1]["on_index"], 1);
            conflict_records.push(lines[1].clone());
            std::fs::remove_file(path).unwrap();
        }
        for key in [
            "active_facts",
            "candidate_duplicates",
            "candidates",
            "decision_level",
            "disagreement",
            "minimum_width",
            "off_index",
            "on_index",
            "trail_sha256",
        ] {
            assert_eq!(conflict_records[0][key], conflict_records[1][key], "{key}");
        }
        assert_eq!(conflict_records[0]["selected_index"], 0);
        assert_eq!(conflict_records[1]["selected_index"], 1);
    }

    impl T7ExplanationMode {
        fn as_str_for_test(self) -> &'static str {
            match self {
                Self::Off => "off",
                Self::On => "on",
            }
        }
    }
}
