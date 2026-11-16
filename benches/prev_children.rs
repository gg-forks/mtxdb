//! Write cost of the maintained `PREV_CHILDREN` reverse family, and bounded
//! `children_of` reads against the whole-room `reverse_family` derive.
//!
//! Run twice and compare the record time:
//!
//! ```text
//! cargo +1.90.0 bench --manifest-path benches/Cargo.toml --bench prev_children
//! cargo +1.90.0 bench --manifest-path benches/Cargo.toml --bench prev_children \
//!   --features prev-children
//! ```
//!
//! Knobs: `MTXDB_PC_SIZES` (default `10000,100000`), `MTXDB_PC_FANOUT` (extra
//! children added to one hot parent per 1000 events, default 0; raise it to
//! see the cost of wide fan-out), `MTXDB_PC_LOOKUPS` (default 1000),
//! `MTXDB_BENCH_ROOT`. Event ids are spread so the hash index does not cluster.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use mtxdb::csr_adjacency::{CsrAdjacency, EventRecord, PREV};
use mtxdb::Database;

const BATCH: usize = 256;

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn id(n: usize) -> String {
    // Spread ids: a constant prefix clusters the short-id hash index.
    format!(
        "${:016x}{n}",
        (n as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)
    )
}

fn per(total: Duration, n: usize) -> Duration {
    total
        .checked_div(u32::try_from(n.max(1)).unwrap_or(u32::MAX))
        .unwrap_or(Duration::ZERO)
}

fn run(base: &std::path::Path, events: usize, fanout: usize, lookups: usize) {
    let root = base.join(format!(
        "mtxdb-prevchildren-{}-{events}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let db = Database::open(root.clone()).expect("open database");
    let adj = CsrAdjacency::new("!bench:example.org");
    let ids: Vec<String> = (0..events).map(id).collect();
    let hot = id(0);

    let started = Instant::now();
    let mut n = 0;
    while n < events {
        let end = n.saturating_add(BATCH).min(events);
        let prevs: Vec<Vec<&str>> = (n..end)
            .map(|i| {
                let mut prev: Vec<&str> = Vec::new();
                if i > 0 {
                    let parent_index = i.checked_sub(1).expect("i is positive");
                    prev.push(ids.get(parent_index).expect("parent id exists"));
                }
                if fanout > 0 && i > 1 && i % 1000 < fanout {
                    prev.push(&hot);
                }
                prev
            })
            .collect();
        let batch: Vec<EventRecord<'_>> = (n..end)
            .zip(&prevs)
            .map(|(i, prev)| EventRecord {
                event_id: &ids[i],
                prev,
                auth: &[],
                relation: None,
            })
            .collect();
        adj.record_events(&db, &batch).expect("record");
        n = end;
    }
    let record = started.elapsed();

    let (derive, derived) = {
        let started = Instant::now();
        let reverse = adj.reverse_family(&db, PREV).expect("reverse_family");
        (started.elapsed(), reverse)
    };
    let parents = derived.parents().to_vec();
    let shorts = &parents;

    println!(
        "events {events:>8} fanout/1000 {fanout}: record {record:>10.2?} ({:?}/event) | reverse_family derive {derive:>10.2?}",
        per(record, events)
    );
    #[cfg(feature = "prev-children")]
    {
        let started = Instant::now();
        let mut children = 0usize;
        if !shorts.is_empty() {
            for i in 0..lookups {
                let slot = i
                    .checked_mul(7919)
                    .expect("lookup index multiplication overflow")
                    .checked_rem(shorts.len())
                    .expect("parent list is nonempty");
                let parent = shorts[slot];
                children = children
                    .checked_add(
                        adj.children_of(&db, parent)
                            .expect("children_of")
                            .map_or(0, |c| c.len()),
                    )
                    .expect("child count overflow");
            }
        }
        let read = started.elapsed();
        println!(
            "{:>44} children_of x{lookups}: {:?}/lookup ({children} children)",
            "",
            per(read, lookups)
        );
    }
    #[cfg(not(feature = "prev-children"))]
    let _ = (shorts, lookups);
    let _ = std::fs::remove_dir_all(&root);
}

fn main() {
    let fanout = env_usize("MTXDB_PC_FANOUT", 0);
    let lookups = env_usize("MTXDB_PC_LOOKUPS", 1000);
    let base = std::env::var_os("MTXDB_BENCH_ROOT").map_or_else(std::env::temp_dir, PathBuf::from);
    std::fs::create_dir_all(&base).expect("bench root");
    let sizes = std::env::var("MTXDB_PC_SIZES").unwrap_or_else(|_| "10000,100000".to_owned());
    for events in sizes
        .split(',')
        .filter_map(|s| s.trim().parse::<usize>().ok())
    {
        run(&base, events, fanout, lookups);
    }
}
