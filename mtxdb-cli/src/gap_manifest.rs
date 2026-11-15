//! Durable record of a room's unresolved `prev_events`.
//!
//! Three facts stay separate so a policy decision can never masquerade as
//! evidence:
//!
//! - availability: what the queried servers said, or that nothing was asked;
//! - waiver: an operator chose not to chase a gap;
//! - anchor: a trusted state reference from outside the DAG.
//!
//! A waiver never makes state authoritative. An anchor always names whether it
//! supplies the state before or after its event, because `/state_ids` for an
//! event returns the state *before* it.
//!
//! Availability answers are scoped to one assessment and to the servers it
//! asked: `not_found` means "not found on these named servers in that
//! assessment", never "nobody has it". Older assessments are kept as history,
//! but the current status reads only the newest one, so a later all-404
//! assessment can supersede an earlier timeout. A gap-fill report that omits
//! an id because it found the event is not evidence of anything here. Only the
//! event arriving (in the import batch or already stored in the room) closes a
//! gap.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use mtxdb::interop::{
    event_record_id, gap_manifest_collection_id, gap_manifest_node_id, room_event_collection_id,
    EVENT_POOL, SERVER_INFO_POOL,
};
use mtxdb::{Database, NodeData, StorageEngine};
use rezzy::json::Value as OwnedValue;

/// Layout version. No compatibility is kept: an older record is refused.
const VERSION: u8 = 1;

/// Guards against a corrupt count turning a read into an allocation.
const MAX_GAPS: usize = 1_000_000;
const MAX_ANSWERS: usize = 1_024;

/// What one server said when asked for the missing event by id.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AnswerKind {
    /// A definite 404 from that server.
    NotFound,
    /// A 4xx other than 404. The server would not answer, so this says
    /// nothing about whether it holds the event.
    Refused,
    /// A timeout, 408, 429, 5xx, or network failure.
    Transient,
    /// The id was never requested by itself.
    Unanswered,
}

impl AnswerKind {
    const fn code(self) -> u8 {
        match self {
            Self::NotFound => 0,
            Self::Refused => 1,
            Self::Transient => 2,
            Self::Unanswered => 3,
        }
    }

    const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::NotFound),
            1 => Some(Self::Refused),
            2 => Some(Self::Transient),
            3 => Some(Self::Unanswered),
            _ => None,
        }
    }

    /// Whether this answer says the event is not held here.
    const fn is_definite_absence(self) -> bool {
        matches!(self, Self::NotFound)
    }
}

/// One server's answer about one gap, kept with the request outcome so a
/// refusal is not mistaken for absence.
///
/// Answers are evidence from a named server in a named assessment. They are
/// kept across assessments as history rather than overwritten, but the
/// *current* status reads only the latest assessment: what a server said last
/// year does not overrule what it said in the run being judged.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ServerAnswer {
    pub(crate) server: String,
    /// Label for the gap-fill run that produced this answer. Re-reading the
    /// same report replaces that assessment's answer for the server; a new
    /// assessment adds another record.
    pub(crate) run: String,
    /// When this answer was recorded, so the newest assessment and the
    /// status's `as_of` can be named without trusting vector order.
    pub(crate) recorded_at_ms: u64,
    pub(crate) kind: AnswerKind,
    pub(crate) status: Option<u16>,
    pub(crate) errcode: Option<String>,
}

/// What the queried servers said about a gap.
///
/// Absence is derived from the latest assessment, never stored as an
/// independent claim: it requires a definite 404 from every server that
/// assessment covered. A refusal, transient failure or unanswered query in
/// that assessment leaves the gap open. Earlier assessments stay here as
/// history and do not block a later all-404 assessment.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct Availability {
    pub(crate) answers: Vec<ServerAnswer>,
}

impl Availability {
    /// The run label of the newest answer. Ties go to the answer recorded
    /// later, which is the one `record_answer` appended last.
    fn latest_run(&self) -> Option<&str> {
        let mut newest: Option<&ServerAnswer> = None;
        for answer in &self.answers {
            if newest.is_none_or(|current| answer.recorded_at_ms >= current.recorded_at_ms) {
                newest = Some(answer);
            }
        }
        newest.map(|answer| answer.run.as_str())
    }

    /// The servers this assessment covered, taken from its answers.
    ///
    /// The ingest records one answer per gap for every entry in the report's
    /// `queried_servers`, using `Unanswered` when the report did not name the
    /// id. That keeps this set equal to `queried_servers`: a server the latest
    /// run named but never answered still counts and keeps the gap open, while
    /// a server dropped from that run stops counting.
    fn servers_in_run(&self, run: &str) -> BTreeSet<String> {
        self.answers
            .iter()
            .filter(|answer| answer.run == run)
            .map(|answer| answer.server.clone())
            .collect()
    }

    /// One server's answer in one assessment.
    fn answer_in_run(&self, server: &str, run: &str) -> Option<&ServerAnswer> {
        self.answers
            .iter()
            .find(|answer| answer.server == server && answer.run == run)
    }
}

/// An operator decision not to chase a gap. It never claims the gap is closed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Waiver {
    pub(crate) by: String,
    pub(crate) reason: String,
    pub(crate) recorded_at_ms: u64,
}

/// Whether an anchor supplies the state before or after its event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AnchorBoundary {
    Before,
    After,
}

impl AnchorBoundary {
    const fn code(self) -> u8 {
        match self {
            Self::Before => 1,
            Self::After => 2,
        }
    }

    const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Before),
            2 => Some(Self::After),
            _ => None,
        }
    }
}

/// A trusted state reference from outside the DAG.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Anchor {
    pub(crate) event_id: String,
    pub(crate) boundary: AnchorBoundary,
    pub(crate) source: String,
    pub(crate) recorded_at_ms: u64,
}

/// Everything known about one unresolved prev.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct GapRecord {
    pub(crate) availability: Availability,
    pub(crate) waiver: Option<Waiver>,
    pub(crate) anchor: Option<Anchor>,
}

/// A gap's state, derived from its records. Never stored: a new answer, a
/// waiver or an anchor changes it without rewriting a status field.
///
/// Order matters. An anchor is the only fact that can complete state past a
/// gap, so it outranks everything. A waiver is an operator decision, so it
/// outranks mere evidence. `AbsentAmong` reads the latest assessment only; it
/// is still a gap and never closes one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum GapStatus {
    Anchored,
    Waived,
    /// Every server in this one assessment answered a definite 404.
    ///
    /// The set names exactly the servers that assessment covered, and
    /// `as_of_ms` is the newest answer in it. It is not a claim that nobody
    /// holds the event, and it does not speak for servers the assessment did
    /// not ask. A later assessment replaces it; an earlier timeout in another
    /// assessment is history.
    AbsentAmong {
        servers: BTreeSet<String>,
        as_of_ms: u64,
    },
    Open,
}

impl GapRecord {
    fn open() -> Self {
        Self::default()
    }

    /// Derive the status from the latest assessment.
    ///
    /// See [`GapStatus`]. Use [`Self::status_for`] to judge a named
    /// assessment and server set instead.
    #[allow(
        dead_code,
        reason = "read by the strict-import gap check, which is not wired yet"
    )]
    pub(crate) fn status(&self) -> GapStatus {
        if self.anchor.is_some() {
            return GapStatus::Anchored;
        }
        if self.waiver.is_some() {
            return GapStatus::Waived;
        }
        let Some(run) = self.availability.latest_run() else {
            return GapStatus::Open;
        };
        let servers = self.availability.servers_in_run(run);
        self.status_for(run, &servers)
    }

    /// Derive the status from one assessment over an explicit server set.
    ///
    /// A server in the set with no answer in this assessment, or with any
    /// answer other than a definite 404, leaves the gap open. The set is
    /// explicit because "not found" is only meaningful for the sources that
    /// were actually asked.
    #[allow(
        dead_code,
        reason = "read by the strict-import gap check, which is not wired yet"
    )]
    pub(crate) fn status_for(&self, run: &str, servers: &BTreeSet<String>) -> GapStatus {
        if self.anchor.is_some() {
            return GapStatus::Anchored;
        }
        if self.waiver.is_some() {
            return GapStatus::Waived;
        }
        if servers.is_empty() {
            return GapStatus::Open;
        }
        let mut as_of_ms = 0;
        for server in servers {
            let Some(answer) = self.availability.answer_in_run(server, run) else {
                return GapStatus::Open;
            };
            if !answer.kind.is_definite_absence() {
                return GapStatus::Open;
            }
            as_of_ms = as_of_ms.max(answer.recorded_at_ms);
        }
        GapStatus::AbsentAmong {
            servers: servers.clone(),
            as_of_ms,
        }
    }
}

/// A room's gaps, keyed by the missing event id.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct GapManifest {
    pub(crate) gaps: BTreeMap<String, GapRecord>,
}

impl GapManifest {
    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.gaps.is_empty()
    }

    /// Record a server answer. Evidence is kept per `(server, run)`.
    ///
    /// Re-reading the same assessment's report replaces that assessment's
    /// answer for the server, so duplicate ingestion does not pile up. A
    /// different assessment is appended: older answers stay as history, while
    /// the status reads only the newest assessment.
    #[allow(
        dead_code,
        reason = "used by the gap-evidence command, which is not wired yet"
    )]
    pub(crate) fn record_answer(&mut self, gap: &str, answer: ServerAnswer) {
        let record = self.gaps.entry(gap.to_owned()).or_default();
        record
            .availability
            .answers
            .retain(|existing| !(existing.server == answer.server && existing.run == answer.run));
        record.availability.answers.push(answer);
    }
}

/// Read a room's manifest, or an empty one if none is stored.
///
/// # Errors
/// Propagates storage errors and refuses a malformed record.
pub(crate) fn read(db: &Database, room_id: &str) -> Result<GapManifest> {
    let record = db
        .pool(SERVER_INFO_POOL)
        .get(
            &gap_manifest_collection_id(room_id.as_bytes()),
            &gap_manifest_node_id(),
        )
        .context("reading the gap manifest")?;
    match record {
        Some(data) => decode(&data.bytes),
        None => Ok(GapManifest::default()),
    }
}

/// Write a room's manifest, removing the record when no gaps remain.
///
/// # Errors
/// Propagates encoding, staging and commit errors.
pub(crate) fn write(db: &Database, room_id: &str, manifest: &GapManifest) -> Result<()> {
    let collection = gap_manifest_collection_id(room_id.as_bytes());
    let node_id = gap_manifest_node_id();
    let tx = db.begin_transaction();
    if manifest.is_empty() {
        tx.remove(SERVER_INFO_POOL, collection, node_id)
            .context("removing the gap manifest")?;
    } else {
        tx.put(
            SERVER_INFO_POOL,
            collection,
            node_id,
            &NodeData::new(bytes::Bytes::from(encode(manifest)?)),
        )
        .context("writing the gap manifest")?;
    }
    tx.commit().context("committing the gap manifest")?;
    Ok(())
}

/// Record the gaps visible in `events` and clear gaps that are now resolved.
///
/// Existing records keep their answers, waiver and anchor; only newly seen
/// gaps start open. A gap is resolved only when its event is in this batch or
/// already stored in the room: a report that says the event was found, or
/// omits it from a missing list, does not close the gap. Presence in the store
/// is what lets the state walk resolve the prev.
///
/// # Errors
/// Propagates storage errors from the read, resolution check and write.
pub(crate) fn record_import_gaps(
    db: &Database,
    room_id: &str,
    events: &[OwnedValue],
    auth_chain: &[OwnedValue],
) -> Result<()> {
    let mut manifest = read(db, room_id)?;
    let known: HashSet<String> = events
        .iter()
        .chain(auth_chain)
        .filter_map(event_id)
        .map(str::to_owned)
        .collect();
    let mut missing = BTreeSet::new();
    for event in events {
        for parent in prev_ids(event) {
            if !known.contains(parent) {
                missing.insert(parent.to_owned());
            }
        }
    }
    let mut resolved = BTreeSet::new();
    for id in manifest.gaps.keys() {
        if known.contains(id) || room_holds(db, room_id, id)? {
            resolved.insert(id.clone());
        }
    }
    manifest.gaps.retain(|id, _| !resolved.contains(id));
    for id in missing {
        // A prev absent from this batch may already be stored in the room
        // (an export re-import); that is not a gap.
        if room_holds(db, room_id, &id)? {
            continue;
        }
        manifest.gaps.entry(id).or_insert_with(GapRecord::open);
    }
    write(db, room_id, &manifest)
}

/// Timestamp for a waiver or anchor recorded now.
#[must_use]
#[allow(
    dead_code,
    reason = "used by the gap waiver and anchor commands, which are not wired yet"
)]
pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

/// Whether the room's event collection already holds `event_id`.
fn room_holds(db: &Database, room_id: &str, event_id: &str) -> Result<bool> {
    // A failed lookup must not read as "not held": that would record a false
    // gap, or keep a resolved one.
    Ok(db
        .pool(EVENT_POOL)
        .get(
            &room_event_collection_id(room_id.as_bytes()),
            &event_record_id(event_id.as_bytes()),
        )?
        .is_some())
}

fn event_id(event: &OwnedValue) -> Option<&str> {
    event
        .get("event_id")
        .and_then(OwnedValue::as_str)
        .filter(|id| !id.is_empty())
}

fn prev_ids(event: &OwnedValue) -> Vec<&str> {
    event
        .get("prev_events")
        .and_then(OwnedValue::as_array)
        .map(|references| {
            references
                .iter()
                .filter_map(|reference| match reference {
                    OwnedValue::String(id) => Some(id.as_str()),
                    OwnedValue::Array(parts) => parts.first().and_then(OwnedValue::as_str),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Encode a manifest as `GVM1`.
///
/// # Errors
/// Returns an error for a field or count that does not fit its prefix.
pub(crate) fn encode(manifest: &GapManifest) -> Result<Vec<u8>> {
    let too_large = || anyhow::anyhow!("gap manifest field is too large");
    let mut out = vec![VERSION];
    out.extend_from_slice(
        &u32::try_from(manifest.gaps.len())
            .map_err(|_| too_large())?
            .to_le_bytes(),
    );
    for (id, record) in &manifest.gaps {
        put_str(&mut out, id)?;
        out.extend_from_slice(
            &u32::try_from(record.availability.answers.len())
                .map_err(|_| too_large())?
                .to_le_bytes(),
        );
        for answer in &record.availability.answers {
            put_str(&mut out, &answer.server)?;
            put_str(&mut out, &answer.run)?;
            out.extend_from_slice(&answer.recorded_at_ms.to_le_bytes());
            out.push(answer.kind.code());
            match answer.status {
                Some(status) => {
                    out.push(1);
                    out.extend_from_slice(&status.to_le_bytes());
                }
                None => out.push(0),
            }
            put_opt_str(&mut out, answer.errcode.as_deref())?;
        }
        match &record.waiver {
            Some(waiver) => {
                out.push(1);
                put_str(&mut out, &waiver.by)?;
                put_str(&mut out, &waiver.reason)?;
                out.extend_from_slice(&waiver.recorded_at_ms.to_le_bytes());
            }
            None => out.push(0),
        }
        match &record.anchor {
            Some(anchor) => {
                out.push(anchor.boundary.code());
                put_str(&mut out, &anchor.event_id)?;
                put_str(&mut out, &anchor.source)?;
                out.extend_from_slice(&anchor.recorded_at_ms.to_le_bytes());
            }
            None => out.push(0),
        }
    }
    Ok(out)
}

/// Decode a `GVM1` record. Trailing bytes are corrupt, not ignored.
///
/// # Errors
/// Returns an error for a truncated record, an unknown version or answer code,
/// a count over the guard, or trailing bytes.
pub(crate) fn decode(bytes: &[u8]) -> Result<GapManifest> {
    let mut reader = Reader::new(bytes);
    let version = reader.u8()?;
    if version != VERSION {
        bail!("unknown gap manifest version {version}");
    }
    let count = reader.len_prefixed(MAX_GAPS, "gap count")?;
    let mut gaps = BTreeMap::new();
    for _ in 0..count {
        let id = reader.string()?;
        let answers = reader.len_prefixed(MAX_ANSWERS, "answer count")?;
        let mut record = GapRecord::default();
        for _ in 0..answers {
            let server = reader.string()?;
            let run = reader.string()?;
            let recorded_at_ms = reader.u64()?;
            let kind = AnswerKind::from_code(reader.u8()?)
                .ok_or_else(|| anyhow::anyhow!("unknown gap answer code"))?;
            let status = match reader.u8()? {
                0 => None,
                1 => Some(reader.u16()?),
                _ => bail!("invalid gap answer status flag"),
            };
            let errcode = reader.opt_string()?;
            record.availability.answers.push(ServerAnswer {
                server,
                run,
                recorded_at_ms,
                kind,
                status,
                errcode,
            });
        }
        if reader.u8()? == 1 {
            record.waiver = Some(Waiver {
                by: reader.string()?,
                reason: reader.string()?,
                recorded_at_ms: reader.u64()?,
            });
        }
        let boundary = reader.u8()?;
        if boundary != 0 {
            record.anchor = Some(Anchor {
                boundary: AnchorBoundary::from_code(boundary)
                    .ok_or_else(|| anyhow::anyhow!("unknown anchor boundary"))?,
                event_id: reader.string()?,
                source: reader.string()?,
                recorded_at_ms: reader.u64()?,
            });
        }
        gaps.insert(id, record);
    }
    if !reader.is_empty() {
        bail!("gap manifest has trailing bytes");
    }
    Ok(GapManifest { gaps })
}

fn put_str(out: &mut Vec<u8>, value: &str) -> Result<()> {
    out.extend_from_slice(
        &u32::try_from(value.len())
            .map_err(|_| anyhow::anyhow!("gap manifest field is too large"))?
            .to_le_bytes(),
    );
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn put_opt_str(out: &mut Vec<u8>, value: Option<&str>) -> Result<()> {
    if let Some(value) = value {
        out.push(1);
        put_str(out, value)
    } else {
        out.push(0);
        Ok(())
    }
}

/// Bounds-checked cursor over a manifest record.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .at
            .checked_add(len)
            .ok_or_else(|| anyhow::anyhow!("gap manifest length overflow"))?;
        let slice = self
            .bytes
            .get(self.at..end)
            .ok_or_else(|| anyhow::anyhow!("gap manifest is truncated"))?;
        self.at = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        let bytes = self.take(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Result<u32> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn u64(&mut self) -> Result<u64> {
        let bytes = self.take(8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn len_prefixed(&mut self, max: usize, what: &str) -> Result<usize> {
        let count = usize::try_from(self.u32()?).unwrap_or(usize::MAX);
        if count > max {
            bail!("gap manifest {what} {count} exceeds {max}");
        }
        Ok(count)
    }

    fn string(&mut self) -> Result<String> {
        let len = self.len_prefixed(self.bytes.len(), "string length")?;
        let bytes = self.take(len)?;
        String::from_utf8(bytes.to_vec()).context("gap manifest string is not UTF-8")
    }

    fn opt_string(&mut self) -> Result<Option<String>> {
        match self.u8()? {
            0 => Ok(None),
            1 => self.string().map(Some),
            _ => bail!("invalid gap manifest optional flag"),
        }
    }

    fn is_empty(&self) -> bool {
        self.at == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answer_at(server: &str, run: &str, at_ms: u64, kind: AnswerKind) -> ServerAnswer {
        ServerAnswer {
            server: server.to_owned(),
            run: run.to_owned(),
            recorded_at_ms: at_ms,
            kind,
            status: match kind {
                AnswerKind::Unanswered => None,
                _ => Some(404),
            },
            errcode: None,
        }
    }

    fn answer(server: &str, run: &str, kind: AnswerKind) -> ServerAnswer {
        answer_at(server, run, 1, kind)
    }

    fn absent(servers: &[&str], as_of_ms: u64) -> GapStatus {
        GapStatus::AbsentAmong {
            servers: servers.iter().map(|server| (*server).to_owned()).collect(),
            as_of_ms,
        }
    }

    fn sample() -> GapManifest {
        let mut manifest = GapManifest::default();
        manifest.record_answer(
            "$absent",
            answer("matrix.example", "run-1", AnswerKind::NotFound),
        );
        manifest.record_answer(
            "$waived",
            answer("a.example", "run-1", AnswerKind::NotFound),
        );
        manifest.gaps.get_mut("$waived").unwrap().waiver = Some(Waiver {
            by: "operator".to_owned(),
            reason: "no source has it".to_owned(),
            recorded_at_ms: 7,
        });
        let mut open = GapRecord::open();
        open.availability.answers = vec![
            answer("a.example", "run-1", AnswerKind::NotFound),
            answer("b.example", "run-1", AnswerKind::Transient),
        ];
        open.anchor = Some(Anchor {
            event_id: "$later".to_owned(),
            boundary: AnchorBoundary::Before,
            source: "snapshot".to_owned(),
            recorded_at_ms: 9,
        });
        manifest.gaps.insert("$open".to_owned(), open);
        manifest
    }

    #[test]
    fn a_manifest_round_trips_every_separate_fact() {
        let manifest = sample();
        let decoded = decode(&encode(&manifest).unwrap()).unwrap();
        assert_eq!(decoded, manifest);
        assert_eq!(
            decoded.gaps["$absent"].status(),
            absent(&["matrix.example"], 1)
        );
        assert_eq!(decoded.gaps["$waived"].status(), GapStatus::Waived);
        assert_eq!(decoded.gaps["$open"].status(), GapStatus::Anchored);
    }

    #[test]
    fn absence_reads_only_the_latest_assessment() {
        let mut gap = GapRecord::open();
        assert_eq!(
            gap.status(),
            GapStatus::Open,
            "nothing asked is not absence"
        );

        gap.availability.answers = vec![answer("a", "run-1", AnswerKind::NotFound)];
        assert_eq!(gap.status(), absent(&["a"], 1));

        gap.availability
            .answers
            .push(answer("b", "run-1", AnswerKind::Refused));
        assert_eq!(gap.status(), GapStatus::Open, "a refusal is not absence");

        gap.availability.answers = vec![
            answer("a", "run-1", AnswerKind::NotFound),
            answer("b", "run-1", AnswerKind::Transient),
        ];
        assert_eq!(gap.status(), GapStatus::Open, "a 5xx is not absence");

        gap.availability.answers = vec![answer("a", "run-1", AnswerKind::Unanswered)];
        assert_eq!(
            gap.status(),
            GapStatus::Open,
            "an unsent query is not absence"
        );
    }

    #[test]
    fn a_gap_status_is_derived_from_its_facts_in_priority_order() {
        let mut gap = GapRecord::open();
        assert_eq!(gap.status(), GapStatus::Open, "no facts is open");

        gap.availability.answers = vec![answer("a", "run-1", AnswerKind::NotFound)];
        assert_eq!(
            gap.status(),
            absent(&["a"], 1),
            "an answer and only definite 404s is absent among those servers"
        );

        gap.availability
            .answers
            .push(answer("b", "run-1", AnswerKind::Transient));
        assert_eq!(
            gap.status(),
            GapStatus::Open,
            "one non-404 leaves the gap open"
        );

        gap.waiver = Some(Waiver {
            by: "operator".to_owned(),
            reason: "accepted".to_owned(),
            recorded_at_ms: 1,
        });
        assert_eq!(
            gap.status(),
            GapStatus::Waived,
            "a waiver outranks availability"
        );

        gap.anchor = Some(Anchor {
            event_id: "$later".to_owned(),
            boundary: AnchorBoundary::Before,
            source: "snapshot".to_owned(),
            recorded_at_ms: 2,
        });
        assert_eq!(
            gap.status(),
            GapStatus::Anchored,
            "an anchor outranks a waiver"
        );
    }

    #[test]
    fn a_later_all_not_found_assessment_restores_absence_but_history_survives() {
        let mut manifest = GapManifest::default();
        manifest.record_answer("$gap", answer_at("a", "run-1", 1, AnswerKind::NotFound));
        manifest.record_answer("$gap", answer_at("b", "run-1", 1, AnswerKind::Transient));
        assert_eq!(manifest.gaps["$gap"].status(), GapStatus::Open);

        // A later assessment asks both servers again and both answer 404.
        manifest.record_answer("$gap", answer_at("a", "run-2", 2, AnswerKind::NotFound));
        manifest.record_answer("$gap", answer_at("b", "run-2", 2, AnswerKind::NotFound));
        assert_eq!(manifest.gaps["$gap"].status(), absent(&["a", "b"], 2));
        assert_eq!(
            manifest.gaps["$gap"].availability.answers.len(),
            4,
            "earlier assessments are kept as history"
        );

        // A newer assessment with one timeout is open again.
        manifest.record_answer("$gap", answer_at("a", "run-3", 3, AnswerKind::Transient));
        manifest.record_answer("$gap", answer_at("b", "run-3", 3, AnswerKind::NotFound));
        assert_eq!(manifest.gaps["$gap"].status(), GapStatus::Open);
    }

    #[test]
    fn status_is_scoped_to_the_servers_the_assessment_asked() {
        let mut gap = GapRecord::open();
        gap.availability.answers = vec![
            answer_at("a", "run-1", 1, AnswerKind::NotFound),
            answer_at("b", "run-1", 1, AnswerKind::Transient),
        ];
        assert_eq!(gap.status(), GapStatus::Open);
        assert_eq!(
            gap.status_for("run-1", &BTreeSet::from(["a".to_owned()])),
            absent(&["a"], 1),
            "absence is only claimed for the servers actually asked"
        );
        assert_eq!(
            gap.status_for("run-2", &BTreeSet::from(["a".to_owned()])),
            GapStatus::Open,
            "an answer from another assessment does not count for this one"
        );
        assert_eq!(
            gap.status_for("run-1", &BTreeSet::from(["a".to_owned(), "b".to_owned()])),
            GapStatus::Open
        );
        assert_eq!(
            gap.status_for("run-1", &BTreeSet::from(["c".to_owned()])),
            GapStatus::Open,
            "a server with no answer in this assessment is not absent"
        );
        assert_eq!(
            gap.status_for("run-1", &BTreeSet::new()),
            GapStatus::Open,
            "an empty assessment decides nothing"
        );
    }

    #[test]
    fn the_newest_timestamp_picks_the_assessment_not_vector_order() {
        let mut manifest = GapManifest::default();
        manifest.record_answer("$gap", answer_at("a", "run-2", 2, AnswerKind::NotFound));
        // An older assessment ingested later must not become current.
        manifest.record_answer("$gap", answer_at("a", "run-1", 1, AnswerKind::Transient));
        assert_eq!(
            manifest.gaps["$gap"].status(),
            absent(&["a"], 2),
            "the timestamp, not insertion order, names the latest assessment"
        );
    }

    #[test]
    fn re_reading_one_assessment_replaces_that_servers_answer() {
        let mut manifest = GapManifest::default();
        manifest.record_answer("$gap", answer_at("a", "run-1", 1, AnswerKind::NotFound));
        manifest.record_answer("$gap", answer_at("a", "run-1", 1, AnswerKind::Transient));
        assert_eq!(manifest.gaps["$gap"].availability.answers.len(), 1);
        assert_eq!(manifest.gaps["$gap"].status(), GapStatus::Open);

        manifest.record_answer("$gap", answer_at("a", "run-2", 2, AnswerKind::NotFound));
        assert_eq!(manifest.gaps["$gap"].status(), absent(&["a"], 2));
        assert_eq!(manifest.gaps["$gap"].availability.answers.len(), 2);
    }

    #[test]
    fn a_server_dropped_from_the_latest_run_stops_counting() {
        let mut manifest = GapManifest::default();
        manifest.record_answer("$gap", answer_at("a", "run-1", 1, AnswerKind::NotFound));
        manifest.record_answer("$gap", answer_at("b", "run-1", 1, AnswerKind::NotFound));
        assert_eq!(manifest.gaps["$gap"].status(), absent(&["a", "b"], 1));

        // The newest run asks only `a`; `b`'s stale 404 no longer carries.
        manifest.record_answer("$gap", answer_at("a", "run-2", 2, AnswerKind::NotFound));
        assert_eq!(manifest.gaps["$gap"].status(), absent(&["a"], 2));
    }

    #[test]
    fn a_server_named_but_unanswered_in_the_latest_run_keeps_the_gap_open() {
        let mut gap = GapRecord::open();
        gap.availability.answers = vec![
            answer_at("a", "run-1", 1, AnswerKind::NotFound),
            answer_at("b", "run-1", 1, AnswerKind::Unanswered),
        ];
        assert_eq!(
            gap.status(),
            GapStatus::Open,
            "a queried server with no answer is not a 404"
        );
    }

    #[test]
    fn truncated_or_trailing_bytes_are_corrupt() {
        let bytes = encode(&sample()).unwrap();
        assert!(decode(&bytes[..bytes.len() - 1]).is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(decode(&trailing).is_err());
        trailing[0] = 2;
        assert!(decode(&trailing).is_err());
    }

    #[test]
    fn an_empty_manifest_writes_no_record() {
        let encoded = encode(&GapManifest::default()).unwrap();
        assert!(decode(&encoded).unwrap().is_empty());
    }
}
