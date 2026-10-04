use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub const OPENCODE_SOURCE_CONVENTION: &str = "codexbar-3239175f-disjoint";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentState {
    Undecided,
    Enabled,
    Denied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceAuthorization {
    pub selected: bool,
    pub consent: ConsentState,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    Builtin,
    Environment,
    Custom,
}

impl SourceKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Builtin => "builtin",
            Self::Environment => "env",
            Self::Custom => "custom",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PassOutcome {
    Consistent,
    CatchingUp,
    Partial,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureCode {
    Denied,
    Unselected,
    RootInvalid,
    RootOverlap,
    SourceIdle,
    HotJournal,
    NotSqlite,
    Busy,
    Corrupt,
    SourceChanging,
    UnsupportedSchema,
    RecordTooLarge,
    InvalidRecord,
    LimitExceeded,
    Io,
    Sqlite,
    Store,
}

impl FailureCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Denied => "denied",
            Self::Unselected => "unselected",
            Self::RootInvalid => "root_invalid",
            Self::RootOverlap => "source_overlap_conflict",
            Self::SourceIdle => "source_idle",
            Self::HotJournal => "hot_journal",
            Self::NotSqlite => "not_sqlite",
            Self::Busy => "busy",
            Self::Corrupt => "corrupt",
            Self::SourceChanging => "source_changing",
            Self::UnsupportedSchema => "unsupported_schema",
            Self::RecordTooLarge => "record_too_large",
            Self::InvalidRecord => "invalid_record",
            Self::LimitExceeded => "limit_exceeded",
            Self::Io => "io",
            Self::Sqlite => "sqlite",
            Self::Store => "store",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        [
            Self::Denied,
            Self::Unselected,
            Self::RootInvalid,
            Self::RootOverlap,
            Self::SourceIdle,
            Self::HotJournal,
            Self::NotSqlite,
            Self::Busy,
            Self::Corrupt,
            Self::SourceChanging,
            Self::UnsupportedSchema,
            Self::RecordTooLarge,
            Self::InvalidRecord,
            Self::LimitExceeded,
            Self::Io,
            Self::Sqlite,
            Self::Store,
        ]
        .into_iter()
        .find(|code| code.as_str() == value)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Provenance {
    Reported,
    Derived,
}

/// How one record's numbers were acquired from its source.
///
/// A SQLite label binds one message group read inside one read transaction; it never claims a
/// common transaction across records. JSON files are read one by one and validated before and
/// after, which is best effort only.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AcquisitionConsistency {
    SqliteReadTransaction,
    FileByFileBestEffort,
}

impl AcquisitionConsistency {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SqliteReadTransaction => "sqlite_read_transaction",
            Self::FileByFileBestEffort => "file_by_file_best_effort",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "sqlite_read_transaction" => Some(Self::SqliteReadTransaction),
            "file_by_file_best_effort" => Some(Self::FileByFileBestEffort),
            _ => None,
        }
    }
}

/// Acquisition methods represented by a projection's records, never a source-wide transaction.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionConsistency {
    SqliteReadTransaction,
    FileByFileBestEffort,
    Mixed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationStatus {
    Current,
    Partial,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenUnit {
    Tokens,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TokenObservation {
    #[serde(deserialize_with = "required_nullable")]
    pub value: Option<u64>,
    pub unit: TokenUnit,
    #[serde(deserialize_with = "required_nullable")]
    pub provenance: Option<Provenance>,
    pub status: ObservationStatus,
}

/// Serde adapter for a nullable field that must still be written: omission is an error, an
/// explicit `null` is `None`. Plain `Option` fields would silently accept omission.
pub fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

/// One record-ID component (session or message ID): non-empty, bounded, free of control bytes.
pub fn is_valid_id_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= crate::limits::MAX_RECORD_ID_COMPONENT_BYTES
        && !value.chars().any(char::is_control)
}

/// The `(session, message)` pair of a canonical length-delimited OpenCode tuple record ID, or
/// `None` for any prefix, length, component or trailing-byte deviation.
pub fn parse_tuple_record_id(record_id: &str) -> Option<(&str, &str)> {
    let rest = record_id.strip_prefix("opencode:")?;
    let (length, rest) = rest.split_once(':')?;
    let session_len: usize = length.parse().ok()?;
    let session = rest.get(..session_len)?;
    let rest = rest.get(session_len..)?.strip_prefix(':')?;
    let (length, rest) = rest.split_once(':')?;
    let message_len: usize = length.parse().ok()?;
    if rest.len() != message_len {
        return None;
    }
    let valid = is_valid_id_component(session)
        && is_valid_id_component(rest)
        && session.len() + rest.len() <= crate::limits::MAX_RECORD_ID_BYTES;
    (valid && tuple_record_id(session, rest) == record_id).then_some((session, rest))
}

/// Bounded wire decoding: sequences and strings are rejected while they are read, before any
/// storage beyond the cap is allocated.
pub(crate) mod bounded {
    use std::fmt;
    use std::marker::PhantomData;

    use serde::Deserialize;
    use serde::de::{self, Deserializer, IgnoredAny, SeqAccess, Visitor};

    struct Text(usize);

    impl Visitor<'_> for Text {
        type Value = String;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "a string of at most {} bytes", self.0)
        }

        fn visit_str<E: de::Error>(self, value: &str) -> Result<String, E> {
            if value.len() > self.0 {
                return Err(E::custom("string exceeds its byte limit"));
            }
            Ok(value.to_owned())
        }
    }

    struct OptionalText(usize);

    impl<'de> Visitor<'de> for OptionalText {
        type Value = Option<String>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "null or a string of at most {} bytes", self.0)
        }

        fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_some<D: Deserializer<'de>>(
            self,
            deserializer: D,
        ) -> Result<Self::Value, D::Error> {
            deserializer.deserialize_str(Text(self.0)).map(Some)
        }
    }

    struct Elements<T> {
        max: usize,
        marker: PhantomData<T>,
    }

    impl<'de, T: Deserialize<'de>> Visitor<'de> for Elements<T> {
        type Value = Vec<T>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "a sequence of at most {} elements", self.max)
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<T>, A::Error> {
            let mut items = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(self.max).min(64));
            while items.len() < self.max {
                match seq.next_element::<T>()? {
                    Some(item) => items.push(item),
                    None => return Ok(items),
                }
            }
            // One more element means the cap is exceeded; it is skipped, never stored.
            if seq.next_element::<IgnoredAny>()?.is_some() {
                return Err(de::Error::custom("sequence exceeds its element limit"));
            }
            Ok(items)
        }
    }

    pub fn text<'de, D: Deserializer<'de>>(
        deserializer: D,
        max: usize,
    ) -> Result<String, D::Error> {
        deserializer.deserialize_str(Text(max))
    }

    pub fn optional_text<'de, D: Deserializer<'de>>(
        deserializer: D,
        max: usize,
    ) -> Result<Option<String>, D::Error> {
        deserializer.deserialize_option(OptionalText(max))
    }

    pub fn sequence<'de, D, T>(deserializer: D, max: usize) -> Result<Vec<T>, D::Error>
    where
        D: Deserializer<'de>,
        T: Deserialize<'de>,
    {
        deserializer.deserialize_seq(Elements {
            max,
            marker: PhantomData,
        })
    }

    /// A string element of a bounded identifier list.
    pub struct Component(pub String);

    impl<'de> Deserialize<'de> for Component {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            text(deserializer, crate::limits::MAX_RECORD_ID_COMPONENT_BYTES).map(Self)
        }
    }

    pub fn source_id<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
        text(deserializer, 64)
    }

    pub fn record_id<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
        text(deserializer, crate::limits::MAX_RECORD_ID_BYTES + 32)
    }

    pub fn component<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
        text(deserializer, crate::limits::MAX_RECORD_ID_COMPONENT_BYTES)
    }

    pub fn convention<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<String>, D::Error> {
        optional_text(deserializer, 128)
    }

    pub fn part_ids<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<String>, D::Error> {
        let parts: Vec<Component> = sequence(deserializer, crate::limits::MAX_SELECTED_PART_IDS)?;
        Ok(parts.into_iter().map(|part| part.0).collect())
    }
}

impl TokenObservation {
    pub fn reported(value: Option<u64>, partial: bool) -> Self {
        Self {
            value,
            unit: TokenUnit::Tokens,
            provenance: value.map(|_| Provenance::Reported),
            status: match (value, partial) {
                (Some(_), false) => ObservationStatus::Current,
                (Some(_), true) => ObservationStatus::Partial,
                (None, _) => ObservationStatus::Unavailable,
            },
        }
    }

    pub fn derived(value: Option<u64>, partial: bool) -> Self {
        Self {
            value,
            unit: TokenUnit::Tokens,
            provenance: value.map(|_| Provenance::Derived),
            status: match (value, partial) {
                (Some(_), false) => ObservationStatus::Current,
                (Some(_), true) => ObservationStatus::Partial,
                (None, _) => ObservationStatus::Unavailable,
            },
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct TokenComponents {
    #[serde(deserialize_with = "required_nullable")]
    pub input: Option<u64>,
    #[serde(deserialize_with = "required_nullable")]
    pub output: Option<u64>,
    #[serde(deserialize_with = "required_nullable")]
    pub reasoning: Option<u64>,
    #[serde(deserialize_with = "required_nullable")]
    pub cache_read: Option<u64>,
    #[serde(deserialize_with = "required_nullable")]
    pub cache_write: Option<u64>,
}

impl TokenComponents {
    pub fn checked_total(&self) -> Option<u64> {
        [
            self.input?,
            self.output?,
            self.reasoning?,
            self.cache_read?,
            self.cache_write?,
        ]
        .into_iter()
        .try_fold(0_u64, u64::checked_add)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OriginUncertainty {
    UnverifiedOrigin,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SourceReportedObservation {
    #[serde(deserialize_with = "bounded::source_id")]
    pub source_id: String,
    #[serde(deserialize_with = "bounded::record_id")]
    pub record_id: String,
    #[serde(deserialize_with = "bounded::component")]
    pub session_id: String,
    #[serde(deserialize_with = "bounded::component")]
    pub message_id: String,
    pub occurred_at_ms: i64,
    pub input: TokenObservation,
    pub output: TokenObservation,
    pub reasoning: TokenObservation,
    pub cache_read: TokenObservation,
    pub cache_write: TokenObservation,
    pub total: TokenObservation,
    #[serde(deserialize_with = "bounded::convention")]
    pub source_convention: Option<String>,
    pub acquisition_consistency: AcquisitionConsistency,
    pub origin_uncertainty: OriginUncertainty,
    pub total_mismatch: bool,
    pub mirror_conflict: bool,
    #[serde(deserialize_with = "bounded::part_ids")]
    pub selected_part_ids: Vec<String>,
    pub revision: u64,
    pub pending_partial: bool,
    #[serde(deserialize_with = "required_nullable")]
    pub pending_reason: Option<FailureCode>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordCandidate {
    pub session_id: String,
    pub message_id: String,
    pub occurred_at_ms: i64,
    pub components: TokenComponents,
    /// Resolved numeric total: the explicit source total, or the permitted derived total.
    pub total: Option<u64>,
    /// `None` iff `total` is `None`.
    pub total_provenance: Option<Provenance>,
    /// `Some(OPENCODE_SOURCE_CONVENTION)` iff the total is derived.
    pub source_convention: Option<String>,
    pub acquisition_consistency: AcquisitionConsistency,
    pub selected_part_ids: Vec<String>,
    pub pending_partial: bool,
    pub canonical_path: PathBuf,
    pub format_rank: u8,
    pub fingerprint: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedCandidate {
    pub record: RecordCandidate,
    pub mirror_conflict: bool,
}

/// The resolved total of one counter set: an explicit total is reported; otherwise a complete
/// five-component sum is derived under the pinned convention; otherwise the total is absent.
pub fn resolve_total(
    components: &TokenComponents,
    explicit_total: Option<u64>,
) -> (Option<u64>, Option<Provenance>, Option<String>) {
    if let Some(total) = explicit_total {
        return (Some(total), Some(Provenance::Reported), None);
    }
    match components.checked_total() {
        Some(total) => (
            Some(total),
            Some(Provenance::Derived),
            Some(OPENCODE_SOURCE_CONVENTION.to_owned()),
        ),
        None => (None, None, None),
    }
}

/// Whether total, provenance and convention agree: absent exactly together, a derived total
/// carries the pinned convention, a reported one carries none.
pub fn total_metadata_is_valid(
    total: Option<u64>,
    provenance: Option<Provenance>,
    convention: Option<&str>,
) -> bool {
    match (total, provenance, convention) {
        (None, None, None) => true,
        (Some(_), Some(Provenance::Reported), None) => true,
        (Some(_), Some(Provenance::Derived), Some(convention)) => {
            convention == OPENCODE_SOURCE_CONVENTION
        }
        _ => false,
    }
}

impl RecordCandidate {
    pub fn record_id(&self) -> String {
        tuple_record_id(&self.session_id, &self.message_id)
    }

    /// A source total that disagrees with its complete components; the total still wins.
    pub fn total_mismatch(&self) -> bool {
        matches!(
            (self.total, self.components.checked_total()),
            (Some(total), Some(sum)) if total != sum
        )
    }
}

pub fn tuple_record_id(session_id: &str, message_id: &str) -> String {
    format!(
        "opencode:{}:{session_id}:{}:{message_id}",
        session_id.len(),
        message_id.len()
    )
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct PassCounters {
    pub entries: u32,
    pub stat_calls: u32,
    pub header_reads: u32,
    pub directory_opens: u32,
    pub source_opens: u32,
    pub rows_read: u32,
    pub bytes_read: u64,
    pub rejected_records: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PassReport {
    pub outcome: PassOutcome,
    pub failure: Option<FailureCode>,
    pub counters: PassCounters,
    pub records_committed: u32,
    pub last_good_ms: Option<i64>,
}

impl PassReport {
    pub fn unavailable(failure: FailureCode, counters: PassCounters) -> Self {
        Self {
            outcome: PassOutcome::Unavailable,
            failure: Some(failure),
            counters,
            records_committed: 0,
            last_good_ms: None,
        }
    }
}
