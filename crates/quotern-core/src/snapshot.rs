use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::domain::{
    FailureCode, OPENCODE_SOURCE_CONVENTION, ObservationStatus, OriginUncertainty, PassCounters,
    PassOutcome, ProjectionConsistency, Provenance, SourceReportedObservation, TokenObservation,
    bounded, is_valid_id_component, parse_tuple_record_id, required_nullable, tuple_record_id,
};
use crate::limits::{
    MAX_OBSERVATION_PAGE, MAX_REPORTED_SOURCES, MAX_SELECTED_PART_IDS, MAX_SOURCE_TIMESTAMP_MS,
    MAX_TOKEN_COUNT,
};

/// Bounded per-source projection of durable source-reported numeric records.
///
/// Each component is the checked sum over the source's records. A component that is missing
/// from some records is `partial`; one missing from every record is `unavailable` with no value.
/// Raw records stay in the store and are reached only through [`ObservationPage`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SourceProjection {
    pub records: u64,
    pub input: TokenObservation,
    pub output: TokenObservation,
    pub reasoning: TokenObservation,
    pub cache_read: TokenObservation,
    pub cache_write: TokenObservation,
    pub total: TokenObservation,
    #[serde(deserialize_with = "bounded::convention")]
    pub source_convention: Option<String>,
    /// Acquisition methods of the represented records; `None` iff there are none. Never a claim
    /// of one simultaneous source-wide snapshot.
    #[serde(deserialize_with = "required_nullable")]
    pub acquisition_consistency: Option<ProjectionConsistency>,
    pub origin_uncertainty: OriginUncertainty,
    pub total_mismatch: bool,
    pub mirror_conflict: bool,
    pub pending_partial: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SourceSnapshot {
    #[serde(deserialize_with = "bounded::source_id")]
    pub source_id: String,
    pub outcome: PassOutcome,
    #[serde(deserialize_with = "required_nullable")]
    pub failure: Option<FailureCode>,
    pub counters: PassCounters,
    #[serde(deserialize_with = "required_nullable")]
    pub last_good_ms: Option<i64>,
    pub projection: SourceProjection,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Snapshot {
    #[serde(deserialize_with = "sources")]
    pub source_reported: Vec<SourceSnapshot>,
}

fn sources<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<SourceSnapshot>, D::Error> {
    bounded::sequence(deserializer, MAX_REPORTED_SOURCES)
}

/// Position after the last returned record in `(occurred_at_ms, record_id)` order.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ObservationCursor {
    pub occurred_at_ms: i64,
    #[serde(deserialize_with = "bounded::record_id")]
    pub record_id: String,
}

impl ObservationCursor {
    /// A cursor names a calendar-valid instant and a canonical bounded tuple record ID.
    pub fn is_valid(&self) -> bool {
        (0..=MAX_SOURCE_TIMESTAMP_MS).contains(&self.occurred_at_ms)
            && parse_tuple_record_id(&self.record_id).is_some()
    }
}

/// One bounded page of raw durable records.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ObservationPage {
    #[serde(deserialize_with = "page_observations")]
    pub observations: Vec<SourceReportedObservation>,
    #[serde(deserialize_with = "required_nullable")]
    pub next: Option<ObservationCursor>,
}

fn page_observations<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<SourceReportedObservation>, D::Error> {
    bounded::sequence(deserializer, MAX_OBSERVATION_PAGE)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SnapshotError {
    TooManySources,
    DuplicateSource,
}

impl Snapshot {
    pub fn new(mut source_reported: Vec<SourceSnapshot>) -> Result<Self, SnapshotError> {
        if source_reported.len() > MAX_REPORTED_SOURCES {
            return Err(SnapshotError::TooManySources);
        }
        source_reported
            .sort_by(|left, right| left.source_id.as_bytes().cmp(right.source_id.as_bytes()));
        let mut seen = HashSet::with_capacity(source_reported.len());
        if source_reported
            .iter()
            .any(|source| !seen.insert(source.source_id.as_str()))
        {
            return Err(SnapshotError::DuplicateSource);
        }
        Ok(Self { source_reported })
    }
}

impl SourceSnapshot {
    pub fn new(
        source_id: String,
        outcome: PassOutcome,
        failure: Option<FailureCode>,
        counters: PassCounters,
        last_good_ms: Option<i64>,
        projection: SourceProjection,
    ) -> Self {
        Self {
            source_id,
            outcome,
            failure,
            counters,
            last_good_ms,
            projection,
        }
    }
}

fn invalid(message: &str) -> serde_json::Error {
    serde::de::Error::custom(message)
}

/// Shape of one numeric observation: absent exactly together with its provenance and
/// `Unavailable` status; present values carry provenance and a present status. `ceiling` is the
/// largest value the observation may hold (the raw-record ceiling, or an aggregate bound).
fn validate_observation(
    observation: &TokenObservation,
    ceiling: u128,
) -> Result<(), serde_json::Error> {
    let shape_ok = matches!(
        (
            observation.value,
            observation.provenance,
            observation.status
        ),
        (None, None, ObservationStatus::Unavailable)
            | (
                Some(_),
                Some(_),
                ObservationStatus::Current | ObservationStatus::Partial
            )
    );
    if !shape_ok {
        return Err(invalid("numeric observation mixes null and present fields"));
    }
    if observation
        .value
        .is_some_and(|value| u128::from(value) > ceiling)
    {
        return Err(invalid("numeric observation exceeds its ceiling"));
    }
    Ok(())
}

/// A component is only ever source-reported; never derived or invented.
fn validate_component(
    observation: &TokenObservation,
    ceiling: u128,
) -> Result<(), serde_json::Error> {
    validate_observation(observation, ceiling)?;
    if observation.provenance == Some(Provenance::Derived) {
        return Err(invalid("a component is never derived"));
    }
    Ok(())
}

fn validate_total(
    total: &TokenObservation,
    convention: Option<&str>,
    ceiling: u128,
) -> Result<(), serde_json::Error> {
    validate_observation(total, ceiling)?;
    let derived = total.provenance == Some(Provenance::Derived);
    match convention {
        Some(convention) if derived && convention == OPENCODE_SOURCE_CONVENTION => Ok(()),
        None if !derived => Ok(()),
        _ => Err(invalid("source convention contradicts total provenance")),
    }
}

impl SourceProjection {
    /// Relational contract of a projection; derive-`Deserialize` alone cannot express it. Each
    /// component is a checked sum of up to `records` raw values, so its ceiling is that many
    /// raw-record ceilings, not one.
    pub fn validate(&self) -> Result<(), serde_json::Error> {
        let ceiling = u128::from(self.records) * u128::from(MAX_TOKEN_COUNT);
        let components = [
            &self.input,
            &self.output,
            &self.reasoning,
            &self.cache_read,
            &self.cache_write,
        ];
        for observation in components {
            validate_component(observation, ceiling)?;
        }
        validate_total(&self.total, self.source_convention.as_deref(), ceiling)?;
        if (self.records == 0) != self.acquisition_consistency.is_none() {
            return Err(invalid(
                "consistency is absent exactly when there are no records",
            ));
        }
        let observations = [
            &self.input,
            &self.output,
            &self.reasoning,
            &self.cache_read,
            &self.cache_write,
            &self.total,
        ];
        if self.records == 0
            && (observations
                .iter()
                .any(|observation| observation.value.is_some())
                || self.total_mismatch
                || self.mirror_conflict)
        {
            return Err(invalid("an empty projection carries numbers or flags"));
        }
        if self.pending_partial
            && observations
                .iter()
                .any(|observation| observation.status == ObservationStatus::Current)
        {
            return Err(invalid("a pending projection holds a current value"));
        }
        Ok(())
    }
}

impl SourceReportedObservation {
    /// Relational contract of one raw record: identity, calendar range, per-record numeric
    /// ceiling, reported-only components, status/pending relation and selected-part membership.
    pub fn validate(&self) -> Result<(), serde_json::Error> {
        if self.source_id.is_empty() {
            return Err(invalid("record has no source"));
        }
        let ceiling = u128::from(MAX_TOKEN_COUNT);
        let components = [
            &self.input,
            &self.output,
            &self.reasoning,
            &self.cache_read,
            &self.cache_write,
        ];
        for observation in components {
            validate_component(observation, ceiling)?;
        }
        validate_total(&self.total, self.source_convention.as_deref(), ceiling)?;
        if !is_valid_id_component(&self.session_id)
            || !is_valid_id_component(&self.message_id)
            || self.record_id != tuple_record_id(&self.session_id, &self.message_id)
            || parse_tuple_record_id(&self.record_id).is_none()
        {
            return Err(invalid("record identity is not a canonical tuple"));
        }
        if !(0..=MAX_SOURCE_TIMESTAMP_MS).contains(&self.occurred_at_ms) {
            return Err(invalid("record time is outside the calendar range"));
        }
        if self.revision == 0 || (self.pending_reason.is_some() && !self.pending_partial) {
            return Err(invalid("revision or pending state is inconsistent"));
        }
        let expected = if self.pending_partial {
            ObservationStatus::Partial
        } else {
            ObservationStatus::Current
        };
        if components
            .into_iter()
            .chain([&self.total])
            .any(|observation| observation.value.is_some() && observation.status != expected)
        {
            return Err(invalid("status contradicts the pending state"));
        }
        if self.selected_part_ids.len() > MAX_SELECTED_PART_IDS
            || self
                .selected_part_ids
                .iter()
                .any(|part| !is_valid_id_component(part))
            || self.selected_part_ids.iter().collect::<HashSet<_>>().len()
                != self.selected_part_ids.len()
        {
            return Err(invalid("selected part identifiers are invalid"));
        }
        let mismatch = match (self.total.value, complete_sum(components)) {
            (Some(total), Some(sum)) => total != sum,
            _ => false,
        };
        if mismatch != self.total_mismatch {
            return Err(invalid("mismatch flag contradicts the numbers"));
        }
        Ok(())
    }
}

/// Checked sum of five components, `None` unless every one is present and the sum fits.
fn complete_sum(components: [&TokenObservation; 5]) -> Option<u64> {
    components.into_iter().try_fold(0_u64, |sum, observation| {
        sum.checked_add(observation.value?)
    })
}

impl SourceSnapshot {
    pub fn decode(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        let snapshot: Self = serde_json::from_slice(bytes)?;
        snapshot.projection.validate()?;
        Ok(snapshot)
    }
}

impl Snapshot {
    /// Decodes the serialized envelope and rejects any relational contradiction.
    pub fn decode(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        let snapshot: Self = serde_json::from_slice(bytes)?;
        let mut seen = HashSet::new();
        for source in &snapshot.source_reported {
            if !seen.insert(source.source_id.as_str()) {
                return Err(invalid("duplicate source"));
            }
            source.projection.validate()?;
        }
        Ok(snapshot)
    }
}

impl ObservationPage {
    pub fn decode(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        let page: Self = serde_json::from_slice(bytes)?;
        for observation in &page.observations {
            observation.validate()?;
        }
        let key = |observation: &SourceReportedObservation| {
            (observation.occurred_at_ms, observation.record_id.clone())
        };
        if page
            .observations
            .windows(2)
            .any(|pair| key(&pair[0]) >= key(&pair[1]))
        {
            return Err(invalid("records are not strictly ascending"));
        }
        if let Some(first) = page.observations.first()
            && page
                .observations
                .iter()
                .any(|observation| observation.source_id != first.source_id)
        {
            return Err(invalid("a page mixes sources"));
        }
        if let Some(next) = &page.next {
            let last = page.observations.last();
            if !next.is_valid()
                || last.map(|last| (last.occurred_at_ms, last.record_id.as_str()))
                    != Some((next.occurred_at_ms, next.record_id.as_str()))
            {
                return Err(invalid("next cursor does not follow the last record"));
            }
        }
        Ok(page)
    }
}
