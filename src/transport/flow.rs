use super::{
    Error, MAX_BODY, MAX_CHUNK, MAX_REQUESTS, Result, WINDOW,
    wire::{self, record::Kind},
};
use evidence_sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// Party that emitted a record; authenticated by the directional Oak channel.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// User's device.
    Client,
    /// Accepted proxy.
    Server,
}
#[derive(Default)]
struct Body {
    hash: Sha256,
    length: u64,
    index: u64,
    ended: bool,
}
impl Body {
    fn data(&mut self, data: &wire::Data, credit: &mut u32) -> Result<()> {
        let count = u32::try_from(data.body.len()).map_err(|_| Error::Limit)?;
        if self.ended
            || data.index != self.index
            || count == 0
            || data.body.len() > MAX_CHUNK
            || count > *credit
            || self.length + u64::from(count) > MAX_BODY
        {
            return Err(Error::Limit);
        }
        self.hash.update(&data.body);
        self.length += u64::from(count);
        self.index += 1;
        *credit -= count;
        Ok(())
    }
    fn end(&mut self, end: &wire::End) -> Result<()> {
        if self.ended || self.length != end.length || self.hash.clone().finalize()[..] != end.sha256
        {
            return Err(Error::Protocol);
        }
        self.ended = true;
        Ok(())
    }
    fn summary(&self) -> wire::End {
        wire::End {
            length: self.length,
            sha256: self.hash.clone().finalize().to_vec(),
        }
    }
}
struct Active {
    id: Vec<u8>,
    request: Body,
    response: Body,
    started: bool,
    cancelled: bool,
    inference: bool,
    upload_credit: u32,
    response_credit: u32,
}
/// Bounded, identical application lifecycle validation on both endpoints.
/// Version 1 permits one active operation per connection, including streaming.
#[derive(Default)]
pub struct Flow {
    seen: BTreeSet<Vec<u8>>,
    active: Option<Active>,
    terminal: bool,
}
impl Flow {
    /// Check sequencing, totals, IDs, direction and receive credit.
    /// After any error the owning session must be discarded.
    /// # Errors
    /// Rejects replay, truncation, unexpected records, route injection and limits.
    #[allow(
        clippy::too_many_lines,
        reason = "single exhaustive wire-state transition table"
    )]
    pub fn accept(&mut self, side: Side, record: &wire::Record) -> Result<()> {
        if record.version != 1 || record.id.len() != 16 {
            return Err(Error::Protocol);
        }
        let kind = record.kind.as_ref().ok_or(Error::Protocol)?;
        if let Kind::RequestStart(start) = kind {
            if side != Side::Client
                || self.active.is_some()
                || self.seen.len() >= MAX_REQUESTS
                || !self.seen.insert(record.id.clone())
            {
                return Err(Error::State);
            }
            validate_start(start)?;
            self.active = Some(Active {
                id: record.id.clone(),
                request: Body::default(),
                response: Body::default(),
                started: false,
                cancelled: false,
                inference: inference_route(&start.path),
                upload_credit: WINDOW,
                response_credit: WINDOW,
            });
            return Ok(());
        }
        let active = self.active.as_mut().ok_or(Error::State)?;
        if active.id != record.id {
            return Err(Error::Protocol);
        }
        if self.terminal {
            match (side, kind) {
                (Side::Client, Kind::TerminalAck(_)) => {
                    self.active = None;
                    self.terminal = false;
                    return Ok(());
                }
                (Side::Client, Kind::ResponseCredit(c)) => {
                    return add_credit(&mut active.response_credit, c.bytes);
                }
                // Cancellation can race authenticated completion. The already-issued
                // terminal outcome wins; acknowledgement still retires the ID.
                (Side::Client, Kind::Cancel(_)) if !active.cancelled => {
                    active.cancelled = true;
                    return Ok(());
                }
                _ => return Err(Error::Protocol),
            }
        }
        let mut terminal = false;
        match (side, kind) {
            (Side::Client, Kind::RequestData(data)) if !active.cancelled => {
                active.request.data(data, &mut active.upload_credit)?;
            }
            (Side::Client, Kind::RequestEnd(end)) if !active.cancelled => {
                active.request.end(end)?;
            }
            (Side::Server, Kind::ResponseStart(start))
                if active.request.ended && !active.started =>
            {
                if !(100..=599).contains(&start.status) {
                    return Err(Error::Protocol);
                }
                validate_headers(&start.headers, false)?;
                active.started = true;
            }
            (Side::Server, Kind::ResponseData(data)) if active.started => {
                active.response.data(data, &mut active.response_credit)?;
            }
            (Side::Server, Kind::ResponseEnd(end)) if active.started => {
                active
                    .response
                    .end(end.body.as_ref().ok_or(Error::Protocol)?)?;
                if active.inference
                    && (end.receipt_id.is_empty()
                        || end.receipt.is_empty()
                        || end.session.is_empty())
                {
                    return Err(Error::Protocol);
                }
                if end.receipt_id.len() > 256
                    || end.receipt.len() > 256 * 1024
                    || end.session.len() > 4 * 1024 * 1024
                {
                    return Err(Error::Limit);
                }
                if !active.inference
                    && (!end.receipt.is_empty()
                        || !end.session.is_empty()
                        || !end.receipt_id.is_empty())
                {
                    return Err(Error::Protocol);
                }
                terminal = true;
            }
            (Side::Client, Kind::Cancel(_)) if !active.cancelled => {
                active.cancelled = true;
            }
            (Side::Server, Kind::Cancelled(_)) if active.cancelled => {
                terminal = true;
            }
            (Side::Server, Kind::Failure(failure))
                if matches!(
                    failure.code.as_str(),
                    "upstream_failed" | "request_rejected" | "deadline" | "receipt_unavailable"
                ) =>
            {
                terminal = true;
            }
            (Side::Server, Kind::UploadCredit(c)) => {
                add_credit(&mut active.upload_credit, c.bytes)?;
            }
            (Side::Client, Kind::ResponseCredit(c)) => {
                add_credit(&mut active.response_credit, c.bytes)?;
            }
            _ => return Err(Error::Protocol),
        }
        if terminal {
            self.terminal = true;
        }
        Ok(())
    }
    /// Current body totals used to produce authenticated terminal records.
    /// # Errors
    /// Rejects absent requests.
    pub fn end(&self, side: Side) -> Result<wire::End> {
        let active = self.active.as_ref().ok_or(Error::State)?;
        Ok(if side == Side::Client {
            active.request.summary()
        } else {
            active.response.summary()
        })
    }
    /// Next body chunk index.
    /// # Errors
    /// Rejects absent requests.
    pub fn index(&self, side: Side) -> Result<u64> {
        let a = self.active.as_ref().ok_or(Error::State)?;
        Ok(if side == Side::Client {
            a.request.index
        } else {
            a.response.index
        })
    }
    /// Remaining peer credit. A host should wait for credit instead of exceeding it.
    #[must_use]
    pub fn credit(&self, side: Side) -> u32 {
        self.active.as_ref().map_or(0, |a| {
            if side == Side::Client {
                a.upload_credit
            } else {
                a.response_credit
            }
        })
    }
    /// Whether an operation may have an unknown server outcome on disconnect.
    #[must_use]
    pub fn active(&self) -> bool {
        self.active.is_some()
    }
}
fn add_credit(credit: &mut u32, count: u32) -> Result<()> {
    if count == 0 || count > WINDOW || *credit > WINDOW - count {
        return Err(Error::Limit);
    }
    *credit += count;
    Ok(())
}
/// Whether a route requires a signed inference receipt and upstream session.
#[must_use]
pub fn inference_route(path: &str) -> bool {
    matches!(
        path,
        "/v1/chat/completions"
            | "/v1/completions"
            | "/v1/embeddings"
            | "/v1/messages"
            | "/v1/responses"
            | "/v3/chat/completions"
            | "/v3/chat/title"
    )
}
/// Strict routing boundary shared by both ends; no arbitrary URLs/providers.
/// # Errors
/// Rejects unknown methods/routes and unsafe headers.
pub fn validate_start(start: &wire::Start) -> Result<()> {
    if start.path.len() > 2048 || !start.path.is_ascii() {
        return Err(Error::Protocol);
    }
    let (path, query) = start
        .path
        .split_once('?')
        .map_or((start.path.as_str(), None), |(p, q)| (p, Some(q)));
    let pieces: Vec<_> = path.split('/').collect();
    let method = start.method.as_str();
    let uuid = |s: &str| {
        s.len() == 36
            && s.bytes().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_hexdigit()
                }
            })
    };
    let allowed = match pieces.as_slice() {
        ["", "v1", "chats"] => matches!(method, "GET" | "PUT" | "DELETE"),
        ["", "v1", "chats", id] if uuid(id) => matches!(method, "GET" | "PUT" | "PATCH" | "DELETE"),
        ["", "v1", "chats", id, "messages"] if uuid(id) => matches!(method, "GET" | "PUT"),
        ["", "v1", "chats", id, "messages", "batch"] if uuid(id) => method == "PUT",
        ["", "v1", "attachments"] => method == "POST",
        ["", "v1", "attachments", "link"] => method == "PUT",
        ["", "v1", "attachments", id] if uuid(id) => matches!(method, "GET" | "DELETE"),
        ["", "v1", "attachments", id, "complete" | "upload"] if uuid(id) => method == "POST",
        ["", "v1", "attachments", id, "link"] if uuid(id) => method == "PUT",
        ["", "v3", "credentials" | "preferences"] => matches!(method, "GET" | "PUT"),
        _ => {
            method == "POST"
                && (inference_route(path)
                    || matches!(
                        path,
                        "/v1/convert/file" | "/v3/documents/process" | "/v3/web/favicons"
                    ))
        }
    };
    let valid_query = query.is_none_or(|q| {
        method == "GET"
            && matches!(pieces.as_slice(), ["", "v1", "chats", id, "messages"] if uuid(id))
            && q.strip_prefix("since=").is_some_and(|value| {
                !value.is_empty()
                    && value.len() <= 256
                    && value
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"%-_.:+".contains(&b))
            })
    });
    if !allowed || !valid_query {
        return Err(Error::Protocol);
    }
    validate_headers(&start.headers, true)
}
fn validate_headers(headers: &[wire::Header], request: bool) -> Result<()> {
    if headers.len() > 16 {
        return Err(Error::Limit);
    }
    let mut seen = BTreeSet::new();
    let mut size = 0;
    for h in headers {
        size += h.name.len() + h.value.len();
        let allowed = if request {
            matches!(
                h.name.as_str(),
                "authorization" | "content-type" | "accept" | "anthropic-version"
            )
        } else {
            matches!(
                h.name.as_str(),
                "content-type"
                    | "x-aci-receipt-id"
                    | "x-request-id"
                    | "retry-after"
                    | "cache-control"
            )
        };
        if !allowed
            || !seen.insert(&h.name)
            || h.value.len() > 8192
            || h.value.bytes().any(|b| b < 32 || b == 127)
            || size > 16 * 1024
        {
            return Err(Error::Protocol);
        }
    }
    Ok(())
}
