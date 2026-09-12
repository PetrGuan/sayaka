// SPDX-License-Identifier: MPL-2.0

use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use sayaka_engine::history::{self, Query};
use sayaka_engine::journal::{ItemState, Store};
use serde::Serialize;
use std::io::{self, Write};
use std::path::PathBuf;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub fn command() -> Command {
    Command::new("history").about("Query complete operation records without retrying or changing history")
        .arg(Arg::new("id").long("id").value_name("OPERATION_ID").help("Exact operation ID, not a path or prefix"))
        .arg(Arg::new("state").long("state").action(ArgAction::Append)
            .value_parser(["succeeded", "skipped", "failed", "unknown"])
            .help("Match operations with any matching item; retain the entire operation"))
        .arg(Arg::new("since").long("since").value_name("RFC3339").help("Inclusive creation-time boundary with explicit UTC offset"))
        .arg(Arg::new("until").long("until").value_name("RFC3339").help("Exclusive creation-time boundary with explicit UTC offset"))
        .arg(Arg::new("limit").long("limit").default_value("20").value_parser(value_parser!(u64).range(1..=1024)))
        .arg(Arg::new("offset").long("offset").default_value("0").value_parser(value_parser!(u64).range(0..=1024)))
        .arg(Arg::new("state-dir").long("state-dir").value_parser(value_parser!(PathBuf)).help("Existing private journal directory"))
        .arg(Arg::new("json").long("json").action(ArgAction::SetTrue))
        .after_help("Newest first, stable operation-ID tie order. Pagination applies to one read snapshot.\nGlobal pending warnings are never filtered out. Unknown is not success; no automatic replay.")
}

pub fn run(args: &ArgMatches) -> io::Result<u8> {
    let result: io::Result<u8> = (|| {
        let query = Query {
            operation_id: args.get_one::<String>("id").cloned(),
            states: args
                .get_many::<String>("state")
                .into_iter()
                .flatten()
                .map(|state| match state.as_str() {
                    "succeeded" => Ok(ItemState::Succeeded),
                    "skipped" => Ok(ItemState::Skipped),
                    "failed" => Ok(ItemState::Failed),
                    "unknown" => Ok(ItemState::Unknown),
                    _ => Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "invalid history state",
                    )),
                })
                .collect::<io::Result<Vec<_>>>()?,
            since_unix_ms: args
                .get_one::<String>("since")
                .map(|value| timestamp(value))
                .transpose()?,
            until_unix_ms: args
                .get_one::<String>("until")
                .map(|value| timestamp(value))
                .transpose()?,
            offset: usize::try_from(
                *args
                    .get_one::<u64>("offset")
                    .ok_or_else(|| io::Error::other("offset missing"))?,
            )
            .map_err(io::Error::other)?,
            limit: usize::try_from(
                *args
                    .get_one::<u64>("limit")
                    .ok_or_else(|| io::Error::other("limit missing"))?,
            )
            .map_err(io::Error::other)?,
        };
        query.validate()?;
        let store = Store::open(&crate::trash::state_directory(args)?, false)?;
        let page = history::query(store.records()?, &query)?;
        if args.get_flag("json") {
            #[derive(Serialize)]
            struct Envelope<'a> {
                schema_version: u32,
                kind: &'static str,
                history: &'a history::Page,
            }
            write_json(&Envelope {
                schema_version: 1,
                kind: "history",
                history: &page,
            })?;
        } else {
            let mut out = io::stdout().lock();
            writeln!(
                out,
                "History: {} matching / {} total operations; offset {}, limit {}",
                page.matched_records, page.total_records, page.offset, page.limit
            )?;
            if page.records.is_empty() {
                writeln!(out, "No operations match this page.")?;
            }
            for record in &page.records {
                writeln!(
                    out,
                    "Created: {}",
                    display_timestamp(record.created_unix_ms)
                )?;
                crate::trash::write_record(&mut out, record)?;
            }
            for pending in &page.uncommitted_snapshots {
                writeln!(
                    out,
                    "Store-wide uncommitted evidence {pending:?}; preserved, never replayed."
                )?;
            }
            out.flush()?;
        }
        Ok(if page.uncommitted_snapshots.is_empty() {
            0
        } else {
            3
        })
    })();
    match result {
        Ok(code) => Ok(code),
        Err(error) => {
            if args.get_flag("json") && error.kind() != io::ErrorKind::BrokenPipe {
                write_json(
                    &serde_json::json!({"schema_version":1,"kind":"history","status":"failed",
                    "error":{"code":format!("{:?}",error.kind()),"message":error.to_string()}}),
                )?;
            }
            writeln!(
                io::stderr().lock(),
                "history failed: {:?}",
                error.to_string()
            )?;
            Ok(if error.kind() == io::ErrorKind::InvalidInput {
                2
            } else {
                1
            })
        }
    }
}

fn timestamp(value: &str) -> io::Result<u64> {
    let time = OffsetDateTime::parse(value, &Rfc3339).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("expected RFC3339 time with UTC offset: {error}"),
        )
    })?;
    let nanos = time.unix_timestamp_nanos();
    if nanos < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "history boundaries must be on or after the Unix epoch",
        ));
    }
    // The parser truncates fractions beyond nanoseconds. Inspect the validated
    // input so even a nonzero digit past that precision affects the ms ceiling.
    let remainder = nanos % 1_000_000 != 0
        || value.split_once('.').is_some_and(|(_, fraction)| {
            fraction
                .bytes()
                .take_while(u8::is_ascii_digit)
                .skip(3)
                .any(|digit| digit != b'0')
        });
    u64::try_from(nanos / 1_000_000 + i128::from(remainder))
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
}

fn display_timestamp(millis: u64) -> String {
    match OffsetDateTime::from_unix_timestamp_nanos(i128::from(millis) * 1_000_000)
        .map_err(|error| error.to_string())
        .and_then(|time| time.format(&Rfc3339).map_err(|error| error.to_string()))
    {
        Ok(value) => value,
        Err(error) => format!("epoch_ms={millis} (calendar formatting unavailable: {error})"),
    }
}

fn write_json(value: &impl Serialize) -> io::Result<()> {
    let mut out = io::stdout().lock();
    serde_json::to_writer(&mut out, value).map_err(|error| {
        io::Error::new(
            error.io_error_kind().unwrap_or(io::ErrorKind::InvalidData),
            error,
        )
    })?;
    writeln!(out)?;
    out.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn offset_times_and_submillisecond_boundaries_preserve_comparisons() {
        assert_eq!(timestamp("1970-01-01T08:00:00+08:00").unwrap(), 0);
        assert_eq!(timestamp("1970-01-01T00:00:00.000000001Z").unwrap(), 1);
        assert_eq!(timestamp("1970-01-01T00:00:00.001Z").unwrap(), 1);
        assert_eq!(timestamp("1970-01-01T00:00:00.0010000001Z").unwrap(), 2);
        assert_eq!(timestamp("1970-01-01T00:00:00.0010000000000Z").unwrap(), 1);
        assert_eq!(timestamp("1970-01-01T00:00:00.0000000001Z").unwrap(), 1);
        assert_eq!(
            timestamp("1970-01-01T08:00:00.1230000001+08:00").unwrap(),
            124
        );
        assert!(timestamp("2026-09-12").is_err());
        assert!(timestamp("1969-12-31T23:59:59Z").is_err());
    }
    #[test]
    fn unrepresentable_calendar_values_keep_exact_numeric_time() {
        assert!(display_timestamp(u64::MAX).contains(&u64::MAX.to_string()));
        assert_eq!(display_timestamp(0), "1970-01-01T00:00:00Z");
    }
}
