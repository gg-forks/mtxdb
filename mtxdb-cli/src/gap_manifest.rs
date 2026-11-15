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
    #[allow(
        dead_code,
        reason = "read by the strict-import gap check, which is not wired yet"
    )]
    const fn is_definite_absence(self) -> bool {
        matches!(self, Self::NotFound)
    }
}

/// One server's answer about one gap, kept with the request outcome so a
/// refusal is not mistaken for absence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ServerAnswer {
    pub(crate) server: String,
    pub(crate) kind: AnswerKind,
    pub(crate) status: Option<u16>,
    pub(crate) errcode: Option<String>,
}

/// What the queried servers said about a gap.
///
/// `Absent` is derived, never stored as an independent claim: it requires at
/// least one answer and a definite 404 from every server asked. Any refusal,
/// transient failure or unanswered query leaves the gap open.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct Availability {
    pub(crate) answers: Vec<ServerAnswer>,
}

impl Availability {
    #[must_use]
    #[allow(
        dead_code,
        reason = "read by the strict-import gap check, which is not wired yet"
    )]
    pub(crate) fn is_absent(&self) -> bool {
        !self.answers.is_empty()
            && self
                .answers
                .iter()
                .all(|answer| answer.kind.is_definite_absence())
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

impl GapRecord {
    fn open() -> Self {
        Self::default()
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

    /// Record a server answer, replacing any earlier answer from that server.
    ///
    /// Evidence arrives per run, so the latest answer wins. Only `not_found`
    /// can make the gap absent; a later refusal or transient failure opens it
    /// again.
    #[allow(
        dead_code,
        reason = "used by the gap-evidence command, which is not wired yet"
    )]
    pub(crate) fn record_answer(&mut self, gap: &str, answer: ServerAnswer) {
        let record = self.gaps.entry(gap.to_owned()).or_default();
        record
            .availability
            .answers
            .retain(|existing| existing.server != answer.server);
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
/// gaps start open. A gap is resolved when its event is in this batch or
/// already stored in the room.
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
    manifest
        .gaps
        .retain(|id, _| !known.contains(id) && !room_holds(db, room_id, id));
    for id in missing {
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
fn room_holds(db: &Database, room_id: &str, event_id: &str) -> bool {
    db.pool(EVENT_POOL)
        .get(
            &room_event_collection_id(room_id.as_bytes()),
            &event_record_id(event_id.as_bytes()),
        )
        .map(|record| record.is_some())
        .unwrap_or(false)
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

    fn answer(server: &str, kind: AnswerKind) -> ServerAnswer {
        ServerAnswer {
            server: server.to_owned(),
            kind,
            status: Some(404),
            errcode: Some("M_NOT_FOUND".to_owned()),
        }
    }

    fn sample() -> GapManifest {
        let mut manifest = GapManifest::default();
        manifest.record_answer("$absent", answer("matrix.example", AnswerKind::NotFound));
        let absent = manifest.gaps.get_mut("$absent").unwrap();
        absent.waiver = Some(Waiver {
            by: "operator".to_owned(),
            reason: "no source has it".to_owned(),
            recorded_at_ms: 7,
        });
        let mut open = GapRecord::open();
        open.availability.answers = vec![
            answer("a.example", AnswerKind::NotFound),
            answer("b.example", AnswerKind::Transient),
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
        assert!(decoded.gaps["$absent"].availability.is_absent());
        assert!(!decoded.gaps["$open"].availability.is_absent());
    }

    #[test]
    fn absence_requires_a_definite_answer_from_every_server() {
        let mut availability = Availability::default();
        assert!(!availability.is_absent(), "nothing asked is not absence");
        availability.answers = vec![answer("a", AnswerKind::NotFound)];
        assert!(availability.is_absent());
        availability.answers.push(answer("b", AnswerKind::Refused));
        assert!(!availability.is_absent(), "a refusal is not absence");
        availability.answers = vec![
            answer("a", AnswerKind::NotFound),
            answer("b", AnswerKind::Transient),
        ];
        assert!(!availability.is_absent(), "a 5xx is not absence");
        availability.answers = vec![answer("a", AnswerKind::Unanswered)];
        assert!(!availability.is_absent(), "an unsent query is not absence");
    }

    #[test]
    fn the_latest_answer_from_one_server_wins() {
        let mut manifest = GapManifest::default();
        manifest.record_answer("$gap", answer("a", AnswerKind::NotFound));
        assert!(manifest.gaps["$gap"].availability.is_absent());
        manifest.record_answer("$gap", answer("a", AnswerKind::Transient));
        assert!(!manifest.gaps["$gap"].availability.is_absent());
        assert_eq!(manifest.gaps["$gap"].availability.answers.len(), 1);
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
