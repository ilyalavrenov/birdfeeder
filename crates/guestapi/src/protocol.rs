//! The vsock API's request and status lines, minus their newlines. The wire format can't change, since restored
//! snapshots keep running whatever birdfeeder-init they were taken with.
//!
//! - `STATS 1` gets one JSON line of [`Stats`](crate::stats::Stats).
//! - `CLOCK 1 <unix nanos>` sets the guest's wall clock and gets [`Reply::Ok`].
//! - `LOGS <container> <seq>` streams that container's records after `seq` until the client hangs up.
//!
//! A request the guest can't serve gets [`Reply::Refused`].

use std::fmt;
use std::str::FromStr;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    Stats,
    /// The host's wall clock, as time since the Unix epoch.
    Clock(Duration),
    Logs {
        container: String,
        after: u64,
    },
}

/// The answer to a request with no reply of its own: `CLOCK`, or anything the guest refuses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    Ok,
    Refused(String),
}

/// Why the guest refused a request line. Its message is what the guest sends back as the reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseRequestError {
    #[error("malformed request")]
    Malformed,
    #[error("bad seq")]
    BadSeq,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("malformed reply {0:?}")]
pub struct ParseReplyError(String);

impl fmt::Display for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stats => f.write_str("STATS 1"),
            Self::Clock(since_epoch) => write!(f, "CLOCK 1 {}", since_epoch.as_nanos()),
            Self::Logs { container, after } => write!(f, "LOGS {container} {after}"),
        }
    }
}

impl FromStr for Request {
    type Err = ParseRequestError;

    fn from_str(line: &str) -> Result<Self, Self::Err> {
        if line == "STATS 1" {
            return Ok(Self::Stats);
        }
        if let Some(nanos) = line.strip_prefix("CLOCK 1 ") {
            // positive and fits in i64, which is the range every snapshotted guest accepts.
            let nanos = nanos.parse::<i64>().ok().and_then(|n| u64::try_from(n).ok()).filter(|&n| n > 0);
            return nanos.map(|n| Self::Clock(Duration::from_nanos(n))).ok_or(ParseRequestError::Malformed);
        }
        let ["LOGS", container, after] = line.split_whitespace().collect::<Vec<_>>()[..] else {
            return Err(ParseRequestError::Malformed);
        };
        // u64's parser accepts a leading `+`, but the wire never has one.
        let after = Some(after).filter(|s| s.bytes().all(|b| b.is_ascii_digit())).and_then(|s| s.parse().ok());
        Ok(Self::Logs { container: container.to_owned(), after: after.ok_or(ParseRequestError::BadSeq)? })
    }
}

impl fmt::Display for Reply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ok => f.write_str("OK"),
            Self::Refused(reason) => write!(f, "ERR {reason}"),
        }
    }
}

impl FromStr for Reply {
    type Err = ParseReplyError;

    fn from_str(line: &str) -> Result<Self, Self::Err> {
        match line {
            "OK" => Ok(Self::Ok),
            _ => line.strip_prefix("ERR ").map(|reason| Self::Refused(reason.to_owned())).ok_or_else(|| ParseReplyError(line.to_owned())),
        }
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case::stats(Request::Stats, "STATS 1")]
    #[case::clock(Request::Clock(Duration::from_nanos(1_700_000_000_123_456_789)), "CLOCK 1 1700000000123456789")]
    #[case::logs(Request::Logs { container: "web".into(), after: 7 }, "LOGS web 7")]
    fn requests_round_trip(#[case] request: Request, #[case] line: &str) {
        assert_eq!(request.to_string(), line);
        assert_eq!(line.parse::<Request>(), Ok(request));
    }

    #[rstest]
    #[case::unknown_verb("HELLO", ParseRequestError::Malformed)]
    #[case::stats_version("STATS 2", ParseRequestError::Malformed)]
    #[case::stats_trailing_space("STATS 1 ", ParseRequestError::Malformed)]
    #[case::clock_version("CLOCK 2 1", ParseRequestError::Malformed)]
    #[case::clock_negative("CLOCK 1 -5", ParseRequestError::Malformed)]
    #[case::clock_epoch("CLOCK 1 0", ParseRequestError::Malformed)]
    #[case::clock_words("CLOCK 1 soon", ParseRequestError::Malformed)]
    #[case::clock_double_space("CLOCK 1  1", ParseRequestError::Malformed)]
    #[case::clock_past_i64("CLOCK 1 9223372036854775808", ParseRequestError::Malformed)]
    #[case::logs_extra_field("LOGS web 0 1", ParseRequestError::Malformed)]
    #[case::logs_word_seq("LOGS web abc", ParseRequestError::BadSeq)]
    #[case::logs_signed_seq("LOGS web +1", ParseRequestError::BadSeq)]
    fn refuses_malformed_requests(#[case] line: &str, #[case] want: ParseRequestError) {
        assert_eq!(line.parse::<Request>(), Err(want));
    }

    #[test]
    fn logs_fields_split_on_any_whitespace() {
        assert_eq!("LOGS  web\t3\r".parse(), Ok(Request::Logs { container: "web".into(), after: 3 }));
    }

    #[rstest]
    #[case::ok(Reply::Ok, "OK")]
    #[case::refused(Reply::Refused("set clock failed".into()), "ERR set clock failed")]
    fn replies_round_trip(#[case] reply: Reply, #[case] line: &str) {
        assert_eq!(reply.to_string(), line);
        assert_eq!(line.parse::<Reply>(), Ok(reply));
    }

    #[test]
    fn refuses_unknown_replies() {
        assert!("OK 1".parse::<Reply>().is_err());
        assert!("ERR".parse::<Reply>().is_err());
    }
}
