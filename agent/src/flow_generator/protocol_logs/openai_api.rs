/*
 * Copyright (c) 2024 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! OpenAI API business sub-protocol enhancement layer.
//!
//! This module implements incremental recognition, field extraction, SSE state machine,
//! and metric calculation (TTFT/TPOT/tokens) on top of the existing HTTP1/HTTP2 parser.
//! It does NOT introduce a new L7Protocol; the `biz_protocol` in the final log is set
//! to "openai-api" while the native L7 protocol remains HTTP1 or HTTP2.

use std::sync::atomic::{AtomicU32, Ordering};

use serde_json::Value;

use crate::config::config::OpenAIUsageFieldPaths;
use crate::config::handler::LogParserConfig;
use crate::flow_generator::protocol_logs::pb_adapter::{KeyVal, MetricKeyVal};

// ─── synthetic stream-id counter (per-process, wraps around) ───────────────
static OPENAI_SESSION_COUNTER: AtomicU32 = AtomicU32::new(1);

fn next_openai_session_id() -> u32 {
    OPENAI_SESSION_COUNTER.fetch_add(1, Ordering::Relaxed)
}

// ─── Public constants ───────────────────────────────────────────────────────
pub const BIZ_PROTOCOL: &str = "openai-api";

// Attribute names
pub const ATTR_API_KIND: &str = "openai_api_kind";
pub const ATTR_STREAM: &str = "openai_stream";
pub const ATTR_USAGE_STATUS: &str = "openai_usage_status";
pub const ATTR_STREAM_COMPLETE: &str = "llm_stream_complete";
pub const ATTR_ABORT_REASON: &str = "llm_abort_reason";
pub const ATTR_BIZ_ORG_PATH: &str = "biz_org_path";
pub const ATTR_BIZ_USER_ID: &str = "biz_user_id";
pub const ATTR_BIZ_APP_ID: &str = "biz_app_id";

// Metric names
pub const METRIC_REQUEST: &str = "llm_request";
pub const METRIC_STREAM_REQUEST: &str = "llm_stream_request";
pub const METRIC_TTFT_US: &str = "llm_ttft_us";
pub const METRIC_TPOT_US: &str = "llm_tpot_us";
pub const METRIC_INPUT_TOKENS: &str = "llm_input_tokens";
pub const METRIC_OUTPUT_TOKENS: &str = "llm_output_tokens";
pub const METRIC_TOTAL_TOKENS: &str = "llm_total_tokens";
pub const METRIC_CACHED_TOKENS: &str = "llm_cached_tokens";
pub const METRIC_STREAM_EVENT_COUNT: &str = "llm_stream_event_count";
pub const METRIC_TOTAL_STREAM_US: &str = "llm_total_stream_us";

// ─── Enumerations ──────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OpenAIKind {
    #[default]
    Unknown,
    ChatCompletions,
    Responses,
}

impl OpenAIKind {
    pub fn as_str(self) -> &'static str {
        match self {
            OpenAIKind::ChatCompletions => "chat_completions",
            OpenAIKind::Responses => "responses",
            OpenAIKind::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum UsageStatus {
    #[default]
    Unknown,
    Available,
    Missing,
    NotRequested,
    StreamInterrupted,
}

impl UsageStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            UsageStatus::Available => "available",
            UsageStatus::Missing => "missing",
            UsageStatus::NotRequested => "not_requested",
            UsageStatus::StreamInterrupted => "stream_interrupted",
            UsageStatus::Unknown => "unknown",
        }
    }
}

// ─── Token usage ─────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default)]
pub struct OpenAIUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub total_tokens: u64,
    pub cached_tokens: Option<u64>,
}

// ─── Pre-compiled usage path pointers ────────────────────────────────────

/// Dot-separated paths compiled once into JSON Pointer strings (`/a/b/c`).
/// Stored in `OpenAISession` so the hot SSE path does zero allocation.
#[derive(Clone, Debug)]
pub struct CompiledUsagePaths {
    pub input_tokens: Vec<String>,
    pub output_tokens: Vec<String>,
    pub total_tokens: Vec<String>,
    pub cached_tokens: Vec<String>,
}

impl CompiledUsagePaths {
    pub fn from_config(cfg: &OpenAIUsageFieldPaths) -> Self {
        let compile = |paths: &[String]| -> Vec<String> {
            paths.iter().map(|p| dot_path_to_pointer(p)).collect()
        };
        Self {
            input_tokens: compile(&cfg.input_tokens),
            output_tokens: compile(&cfg.output_tokens),
            total_tokens: compile(&cfg.total_tokens),
            cached_tokens: compile(&cfg.cached_tokens),
        }
    }
}

/// Compile a dot-separated path into a JSON Pointer string (`/a/b/c`).
/// Escapes `~` → `~0` and `/` → `~1` as required by RFC 6901.
fn dot_path_to_pointer(path: &str) -> String {
    let mut ptr = String::with_capacity(path.len() + 1);
    ptr.push('/');
    for ch in path.chars() {
        match ch {
            '.' => ptr.push('/'),
            '~' => ptr.push_str("~0"),
            '/' => ptr.push_str("~1"),
            c => ptr.push(c),
        }
    }
    ptr
}

/// Lookup a u64 using pre-compiled JSON Pointer strings. Zero allocation.
#[inline]
fn extract_u64_by_ptrs(json: &Value, ptrs: &[String]) -> Option<u64> {
    for ptr in ptrs {
        if let Some(n) = json.pointer(ptr.as_str()).and_then(|v| v.as_u64()) {
            return Some(n);
        }
    }
    None
}

/// Parse token usage from the top-level JSON using pre-compiled pointers.
pub fn parse_usage_from_json(json: &Value, ptrs: &CompiledUsagePaths) -> Option<OpenAIUsage> {
    let input_tokens = extract_u64_by_ptrs(json, &ptrs.input_tokens)?;
    let output_tokens = extract_u64_by_ptrs(json, &ptrs.output_tokens)?;
    let total_tokens =
        extract_u64_by_ptrs(json, &ptrs.total_tokens).unwrap_or(input_tokens + output_tokens);
    let cached_tokens = extract_u64_by_ptrs(json, &ptrs.cached_tokens);
    Some(OpenAIUsage {
        input_tokens,
        output_tokens,
        total_tokens,
        cached_tokens,
    })
}

/// Best-effort extraction of usage field values from raw (potentially truncated)
/// response bytes without full JSON parsing.
///
/// Searches for patterns like `"prompt_tokens":18` in the raw byte slice.
/// Returns `None` if any required field is absent (e.g., body is truncated
/// before those bytes).  Only supports simple leaf paths (the last path
/// component is the field name to search for).
fn extract_usage_raw(data: &[u8], ptrs: &CompiledUsagePaths) -> Option<OpenAIUsage> {
    // Max field name length we expect (e.g., "completion_tokens" = 17 chars).
    // Pattern is `"<field>":` so max pattern len = 1 + 17 + 2 = 20 bytes.
    const MAX_PATTERN: usize = 32;
    let find_field = |field: &[u8]| -> Option<u64> {
        let pattern_len = field.len() + 3; // '"' + field + '":'
        if pattern_len > MAX_PATTERN {
            return None;
        }
        let mut pattern = [0u8; MAX_PATTERN];
        pattern[0] = b'"';
        pattern[1..1 + field.len()].copy_from_slice(field);
        pattern[1 + field.len()] = b'"';
        pattern[2 + field.len()] = b':';
        let pattern_slice = &pattern[..pattern_len];

        let pos = data.windows(pattern_len).position(|w| w == pattern_slice)?;
        let rest = &data[pos + pattern_len..];
        // Skip optional whitespace.
        let start = rest
            .iter()
            .position(|&b| !b.is_ascii_whitespace())
            .unwrap_or(0);
        let digits = &rest[start..];
        let end = digits
            .iter()
            .position(|b| !b.is_ascii_digit())
            .unwrap_or(digits.len());
        if end == 0 {
            return None;
        }
        std::str::from_utf8(&digits[..end])
            .ok()?
            .parse::<u64>()
            .ok()
    };

    // Extract the leaf field name from the last configured path (e.g.,
    // "usage.prompt_tokens" → "prompt_tokens").
    let leaf = |paths: &[String]| -> Option<u64> {
        for path in paths {
            let field = path.rsplit('.').next().unwrap_or(path.as_str());
            if let Some(v) = find_field(field.as_bytes()) {
                return Some(v);
            }
        }
        None
    };

    let input_tokens = leaf(&ptrs.input_tokens)?;
    let output_tokens = leaf(&ptrs.output_tokens)?;
    let total_tokens = leaf(&ptrs.total_tokens).unwrap_or(input_tokens + output_tokens);
    Some(OpenAIUsage {
        input_tokens,
        output_tokens,
        total_tokens,
        cached_tokens: None,
    })
}

// ─── Per-session state (lives in HttpLog) ────────────────────────────────

/// State accumulated across multiple packets for one OpenAI streaming session.
#[derive(Clone, Debug)]
pub struct OpenAISession {
    pub kind: OpenAIKind,
    pub is_stream: bool,
    /// True when the HTTP response uses `Transfer-Encoding: chunked`.
    /// SSE data is then wrapped in chunk framing and must be decoded before
    /// the SSE state machine can parse events.
    pub is_chunked_transfer: bool,
    /// Synthetic stream-id assigned to the session for multi-merge matching.
    pub stream_id: u32,

    /// Request packet timestamp (microseconds).
    pub request_ts_us: u64,
    /// Timestamp when the SSE stream ended (microseconds).
    /// `None` until the terminal event ([DONE] / response.completed) is received,
    /// or until the non-streaming JSON response is parsed.
    pub stream_end_ts_us: Option<u64>,
    /// Timestamp of the first SSE output event (microseconds).
    pub first_output_ts_us: Option<u64>,
    /// Timestamp of the most recent SSE output event (microseconds).
    pub last_output_ts_us: Option<u64>,

    pub stream_event_count: u32,
    pub stream_completed: bool,

    pub usage: Option<OpenAIUsage>,
    pub usage_status: UsageStatus,

    pub biz_org_path: Option<String>,
    pub biz_user_id: Option<String>,
    pub biz_app_id: Option<String>,

    /// Partial SSE bytes not yet forming a complete event (any supported separator).
    pub sse_buf: Vec<u8>,
    pub sse_buf_overflowed: bool,

    pub abort_reason: Option<String>,

    pub config_sse_max: usize,
    /// Pre-compiled JSON Pointer strings for token extraction. Computed once at
    /// session creation so the SSE hot path does zero allocation.
    pub usage_ptrs: CompiledUsagePaths,
    /// Scratch buffer reused across calls to decode HTTP chunked framing.
    /// Avoids a fresh heap allocation per SSE continuation packet for chunked streams.
    pub chunked_decode_buf: Vec<u8>,
}

impl OpenAISession {
    pub fn new(
        kind: OpenAIKind,
        is_stream: bool,
        request_ts_us: u64,
        sse_buffer_max_bytes: usize,
        usage_paths: &OpenAIUsageFieldPaths,
    ) -> Self {
        Self {
            kind,
            is_stream,
            is_chunked_transfer: false,
            stream_id: next_openai_session_id(),
            request_ts_us,
            stream_end_ts_us: None,
            first_output_ts_us: None,
            last_output_ts_us: None,
            stream_event_count: 0,
            stream_completed: false,
            usage: None,
            usage_status: if is_stream {
                UsageStatus::Missing
            } else {
                UsageStatus::Unknown
            },
            biz_org_path: None,
            biz_user_id: None,
            biz_app_id: None,
            sse_buf: Vec::new(),
            sse_buf_overflowed: false,
            abort_reason: None,
            config_sse_max: sse_buffer_max_bytes,
            usage_ptrs: CompiledUsagePaths::from_config(usage_paths),
            chunked_decode_buf: Vec::new(),
        }
    }

    /// Feed raw bytes (from a streaming HTTP response chunk) into the SSE buffer
    /// and process complete events. Returns `true` when the stream has ended.
    pub fn feed_sse(&mut self, data: &[u8], packet_ts_us: u64) -> bool {
        // Append to SSE buffer with overflow protection.
        let available = self.config_sse_max.saturating_sub(self.sse_buf.len());
        let done = if available == 0 {
            if !self.sse_buf_overflowed {
                self.sse_buf_overflowed = true;
                self.abort_reason = Some("sse_buffer_overflow".to_string());
            }
            // Still try to scan for terminal events in the new data.
            self.has_terminal_in(data)
        } else {
            let to_append = available.min(data.len());
            self.sse_buf.extend_from_slice(&data[..to_append]);
            if to_append < data.len() {
                self.sse_buf_overflowed = true;
                self.abort_reason = Some("sse_buffer_overflow".to_string());
            }
            self.drain_events(packet_ts_us)
        };
        if done {
            self.stream_end_ts_us.get_or_insert(packet_ts_us);
        }
        done
    }

    /// Returns true if the stream has ended (terminal marker found in raw bytes).
    /// Operates directly on bytes to avoid any allocation.
    fn has_terminal_in(&self, data: &[u8]) -> bool {
        // Both `data:[DONE]` (no space) and `data: [DONE]` (with space) are valid.
        contains_bytes(data, b"data:[DONE]")
            || contains_bytes(data, b"data: [DONE]")
            || contains_bytes(data, b"\"response.completed\"")
    }

    /// Drain all complete SSE events from the buffer.
    /// Handles all four separator forms (`\n\n`, `\n\r\n`, `\r\n\n`, `\r\n\r\n`).
    /// Returns `true` when the stream has ended.
    fn drain_events(&mut self, packet_ts_us: u64) -> bool {
        // Temporarily take the buffer so we can borrow slices from it while
        // mutating the rest of `self` inside `process_sse_event`. This avoids
        // per-event Vec allocations and reduces drain() calls to one.
        let mut buf = std::mem::take(&mut self.sse_buf);
        let mut cursor = 0;
        let mut done = false;

        loop {
            let Some((rel_end, sep_len)) = find_event_end(&buf[cursor..]) else {
                break;
            };
            let abs_end = cursor + rel_end;
            done = self.process_sse_event(&buf[cursor..abs_end], packet_ts_us);
            cursor = abs_end + sep_len;
            if done {
                break;
            }
        }

        // Put remaining (unprocessed) bytes back in one shot.
        buf.drain(..cursor);
        // Release excess capacity: if the buffer shrank to less than half its
        // allocated capacity, shrink to avoid holding onto a large allocation
        // for the rest of the stream after a burst of unprocessed data.
        if buf.capacity() > 4096 && buf.len() < buf.capacity() / 2 {
            buf.shrink_to_fit();
        }
        self.sse_buf = buf;
        done
    }

    /// Process one complete SSE event. Returns `true` if this is the terminal event.
    fn process_sse_event(&mut self, event_bytes: &[u8], packet_ts_us: u64) -> bool {
        // Skip events with invalid UTF-8 silently.
        let Ok(text) = std::str::from_utf8(event_bytes) else {
            return false;
        };

        let mut event_type = "";
        let mut data_line = "";

        for line in text.lines() {
            if let Some(v) = line.strip_prefix("event:") {
                event_type = v.trim();
            } else if let Some(v) = line.strip_prefix("data:") {
                data_line = v.trim();
            }
        }

        // Empty data line: SSE comment or keepalive (e.g. `: ping`). Nothing to parse.
        if data_line.is_empty() {
            return false;
        }

        // Check for Chat Completions stream terminator.
        if data_line == "[DONE]" {
            self.stream_completed = true;
            if self.usage.is_some() {
                self.usage_status = UsageStatus::Available;
            }
            return true;
        }

        // Parse JSON data payload.
        let json: Value = match serde_json::from_str(data_line) {
            Ok(v) => v,
            Err(_) => return false,
        };

        // Check for Responses API completion event.
        let is_responses_completed = event_type == "response.completed"
            || json.get("type").and_then(|t| t.as_str()) == Some("response.completed");

        if is_responses_completed {
            if let Some(usage) = parse_usage_from_json(&json, &self.usage_ptrs) {
                self.usage = Some(usage);
                self.usage_status = UsageStatus::Available;
            }
            self.stream_completed = true;
            return true;
        }

        // Extract usage whenever it is present. This covers both the dedicated
        // Chat Completions usage chunk (choices=[]) and providers that embed
        // usage in every content chunk.
        if let Some(usage) = parse_usage_from_json(&json, &self.usage_ptrs) {
            self.usage = Some(usage);
            self.usage_status = UsageStatus::Available;
        }

        // Usage-only chunk (choices=[]): not a terminal event; [DONE] follows.
        if json
            .get("choices")
            .and_then(|v| v.as_array())
            .map(|a| a.is_empty())
            .unwrap_or(false)
        {
            return false;
        }

        // Check if this is a valid output event.
        let is_output_event = match self.kind {
            OpenAIKind::ChatCompletions => {
                // choices[0].delta.content non-empty
                json.pointer("/choices/0/delta/content")
                    .and_then(|c| c.as_str())
                    .map(|s| !s.is_empty())
                    .unwrap_or(false)
            }
            OpenAIKind::Responses => {
                (event_type == "response.output_text.delta"
                    && json
                        .pointer("/delta")
                        .and_then(|d| d.as_str())
                        .map(|s| !s.is_empty())
                        .unwrap_or(false))
                    || event_type == "response.output_item.done"
            }
            OpenAIKind::Unknown => false,
        };

        if is_output_event {
            if self.first_output_ts_us.is_none() {
                self.first_output_ts_us = Some(packet_ts_us);
            }
            self.last_output_ts_us = Some(packet_ts_us);
            self.stream_event_count = self.stream_event_count.saturating_add(1);
        }

        false
    }

    /// Compute final TTFT and TPOT from the accumulated state.
    /// Returns `(ttft_us, tpot_us)` in microseconds.
    ///
    /// **Streaming**: TTFT = time to first SSE content event; TPOT = inter-event
    /// span divided by (output_tokens − 1).
    ///
    /// **Non-streaming**: TTFT = response latency (request → response received);
    /// TPOT = response latency / output_tokens.
    pub fn compute_timings(&self) -> (Option<f64>, Option<f64>) {
        if self.is_stream {
            let ttft_us = self
                .first_output_ts_us
                .map(|first| first.saturating_sub(self.request_ts_us) as f64);

            let tpot_us = match (
                self.first_output_ts_us,
                self.last_output_ts_us,
                self.usage.as_ref(),
            ) {
                (Some(first), Some(last), Some(usage)) if usage.output_tokens > 0 => {
                    let span_us = last.saturating_sub(first);
                    let divisor = usage.output_tokens.saturating_sub(1).max(1);
                    Some(span_us as f64 / divisor as f64)
                }
                _ => None,
            };

            (ttft_us, tpot_us)
        } else {
            // Non-streaming: all tokens arrive with the response body.
            // TTFT = response latency. TPOT = latency / output_tokens.
            let Some(end_ts) = self.stream_end_ts_us else {
                return (None, None);
            };
            let ttft_us = end_ts.saturating_sub(self.request_ts_us) as f64;
            let tpot_us = self.usage.as_ref().and_then(|u| {
                if u.output_tokens > 0 {
                    Some(ttft_us / u.output_tokens as f64)
                } else {
                    None
                }
            });
            (Some(ttft_us), tpot_us)
        }
    }

    /// Write computed attributes and metrics into the provided vectors.
    pub fn populate_log(&self, attrs: &mut Vec<KeyVal>, metrics: &mut Vec<MetricKeyVal>) {
        // Attributes.
        push_attr(attrs, ATTR_API_KIND, self.kind.as_str());
        push_attr(
            attrs,
            ATTR_STREAM,
            if self.is_stream { "true" } else { "false" },
        );
        push_attr(attrs, ATTR_USAGE_STATUS, self.usage_status.as_str());

        if self.is_stream {
            push_attr(
                attrs,
                ATTR_STREAM_COMPLETE,
                if self.stream_completed {
                    "true"
                } else {
                    "false"
                },
            );
            if let Some(reason) = &self.abort_reason {
                push_attr(attrs, ATTR_ABORT_REASON, reason);
            }
        }

        if let Some(v) = &self.biz_org_path {
            push_attr(attrs, ATTR_BIZ_ORG_PATH, v);
        }
        if let Some(v) = &self.biz_user_id {
            push_attr(attrs, ATTR_BIZ_USER_ID, v);
        }
        if let Some(v) = &self.biz_app_id {
            push_attr(attrs, ATTR_BIZ_APP_ID, v);
        }

        // Metrics.
        push_metric(metrics, METRIC_REQUEST, 1.0);
        push_metric(
            metrics,
            METRIC_STREAM_REQUEST,
            if self.is_stream { 1.0 } else { 0.0 },
        );

        if self.is_stream && self.stream_event_count > 0 {
            push_metric(
                metrics,
                METRIC_STREAM_EVENT_COUNT,
                self.stream_event_count as f64,
            );
        }

        let (ttft_us, tpot_us) = self.compute_timings();
        if let Some(v) = ttft_us {
            push_metric(metrics, METRIC_TTFT_US, v);
        }
        if let Some(v) = tpot_us {
            push_metric(metrics, METRIC_TPOT_US, v);
        }

        if let Some(usage) = &self.usage {
            push_metric(metrics, METRIC_INPUT_TOKENS, usage.input_tokens as f64);
            push_metric(metrics, METRIC_OUTPUT_TOKENS, usage.output_tokens as f64);
            push_metric(metrics, METRIC_TOTAL_TOKENS, usage.total_tokens as f64);
            if let Some(cached) = usage.cached_tokens {
                push_metric(metrics, METRIC_CACHED_TOKENS, cached as f64);
            }
        }

        // Total request-to-completion duration in microseconds.
        // For streaming: request → final [DONE] event (full stream wall-clock time).
        // For non-streaming: request → response body received (same as llm_ttft_us).
        if let Some(end_ts) = self.stream_end_ts_us {
            let total_us = end_ts.saturating_sub(self.request_ts_us) as f64;
            push_metric(metrics, METRIC_TOTAL_STREAM_US, total_us);
        }
    }
}

// ─── Request parsing helpers ──────────────────────────────────────────────

/// Check whether a request path matches the configured OpenAI API paths.
///
/// Matching rules (OR logic):
/// - The path matches if it starts with **any** entry in `path_prefixes`
///   **or** ends with **any** entry in `path_suffixes`.
/// - An empty list means that group contributes nothing to the match.
/// - If **both** lists are empty, no path matches (explicit configuration required).
pub fn is_openai_path(path: &str, config: &LogParserConfig) -> bool {
    if !config.openai_api.enabled {
        return false;
    }
    let cfg = &config.openai_api;
    // Both empty → no explicit paths configured, match nothing.
    if cfg.path_prefixes.is_empty() && cfg.path_suffixes.is_empty() {
        return false;
    }
    let matches_prefix = cfg
        .path_prefixes
        .iter()
        .any(|p| path.starts_with(p.as_str()));
    let matches_suffix = cfg.path_suffixes.iter().any(|s| path.ends_with(s.as_str()));
    matches_prefix || matches_suffix
}

/// Determine the API kind from the path.
pub fn kind_from_path(path: &str) -> OpenAIKind {
    if path.contains("/chat/completions") {
        OpenAIKind::ChatCompletions
    } else if path.contains("/responses") {
        OpenAIKind::Responses
    } else {
        OpenAIKind::Unknown
    }
}

/// Extract business dimensions from HTTP request headers.
/// `key` is the raw (mixed-case) header name; comparison is case-insensitive.
pub fn extract_biz_from_header(
    session: &mut OpenAISession,
    key: &str,
    val: &str,
    config: &LogParserConfig,
) {
    // Short-circuit once all dims are populated — avoids iterating extractor
    // lists for every remaining header in a request with many headers.
    if session.biz_org_path.is_some()
        && session.biz_user_id.is_some()
        && session.biz_app_id.is_some()
    {
        return;
    }

    let extractors = &config.openai_api.biz_dimension_extractors;

    if session.biz_org_path.is_none()
        && extractors
            .org_path
            .headers
            .iter()
            .any(|h| h.eq_ignore_ascii_case(key))
    {
        session.biz_org_path = Some(val.to_string());
    }
    if session.biz_user_id.is_none()
        && extractors
            .user_id
            .headers
            .iter()
            .any(|h| h.eq_ignore_ascii_case(key))
    {
        session.biz_user_id = Some(val.to_string());
    }
    if session.biz_app_id.is_none()
        && extractors
            .app_id
            .headers
            .iter()
            .any(|h| h.eq_ignore_ascii_case(key))
    {
        session.biz_app_id = Some(val.to_string());
    }
}

/// Parse an OpenAI request JSON body and update the session:
/// - Extract `stream` field
/// - Extract business dimensions via json_paths
///
/// When the body is a TCP continuation segment (partial JSON), full parsing
/// fails. In that case a raw byte search is used to detect `"stream": true`
/// so streaming is correctly identified even when the request spans multiple
/// TCP segments and the `stream` key is not in the first segment.
pub fn parse_request_body(session: &mut OpenAISession, body: &[u8], config: &LogParserConfig) {
    let limit = config.openai_api.request_body_max_bytes;
    let slice = if body.len() > limit {
        &body[..limit]
    } else {
        body
    };

    let Ok(json) = serde_json::from_slice::<Value>(slice) else {
        // Partial body segment: fall back to a byte search for the stream flag.
        // This handles cases where "stream": true lives in a later TCP segment
        // of a multi-segment POST body.
        if !session.is_stream {
            if contains_bytes(slice, b"\"stream\":true")
                || contains_bytes(slice, b"\"stream\": true")
            {
                session.is_stream = true;
                // Upgrade Unknown → Missing: we now know this is a streaming
                // request, so usage is expected but not yet seen.
                if session.usage_status == UsageStatus::Unknown {
                    session.usage_status = UsageStatus::Missing;
                }
            }
        }
        return;
    };

    // stream flag
    if let Some(stream) = json.get("stream").and_then(|v| v.as_bool()) {
        session.is_stream = stream;
        if stream && session.usage_status == UsageStatus::Unknown {
            session.usage_status = UsageStatus::Missing;
        }
    }

    let extractors = &config.openai_api.biz_dimension_extractors;

    if session.biz_org_path.is_none() {
        session.biz_org_path = extract_json_paths(&json, &extractors.org_path.json_paths);
    }
    if session.biz_user_id.is_none() {
        session.biz_user_id = extract_json_paths(&json, &extractors.user_id.json_paths);
    }
    if session.biz_app_id.is_none() {
        session.biz_app_id = extract_json_paths(&json, &extractors.app_id.json_paths);
    }
}

/// Extract the first matching non-empty string value from a list of dot-notation JSON paths.
/// Supports arbitrary depth: "a.b.c" → json pointer "/a/b/c".
fn extract_json_paths(json: &Value, paths: &[String]) -> Option<String> {
    for path in paths {
        let ptr = dot_path_to_pointer(path);
        if let Some(s) = json.pointer(&ptr).and_then(|v| v.as_str()) {
            if !s.is_empty() {
                return Some(s.to_string());
            }
        }
    }
    None
}

/// Parse a non-streaming (JSON) response body and extract token usage.
///
/// If JSON parsing fails (most commonly because the body is truncated by
/// `l7_log_packet_size`), the usage fields are searched for directly in the
/// raw bytes as a best-effort fallback. Usage may still be unavailable when
/// the fields are in the portion of the body beyond the capture limit.
pub fn parse_response_json(session: &mut OpenAISession, body: &[u8], config: &LogParserConfig) {
    let limit = config.openai_api.response_event_max_bytes;
    let slice = if body.len() > limit {
        &body[..limit]
    } else {
        body
    };

    let Ok(json) = serde_json::from_slice::<Value>(slice) else {
        // JSON parse failed — body is likely truncated by l7_log_packet_size.
        // Try a best-effort raw-byte extraction of the usage fields.  This
        // succeeds only when the fields happen to fall within the captured bytes.
        if let Some(usage) = extract_usage_raw(slice, &session.usage_ptrs) {
            session.usage = Some(usage);
            session.usage_status = UsageStatus::Available;
        } else {
            session.usage_status = UsageStatus::Missing;
        }
        return;
    };

    if let Some(usage) = parse_usage_from_json(&json, &session.usage_ptrs) {
        session.usage = Some(usage);
        session.usage_status = UsageStatus::Available;
    } else {
        session.usage_status = UsageStatus::Missing;
    }
}

// ─── Chunked transfer encoding decoder ───────────────────────────────────

/// Strip HTTP chunked-transfer-encoding framing from `payload`, writing the
/// decoded bytes into `out` (which is cleared first so the caller's buffer
/// capacity is reused across calls — zero extra allocation per invocation).
///
/// Returns `true` when the HTTP terminal chunk (`0\r\n\r\n`) is found,
/// signalling stream end. Returns `false` otherwise (normal chunk or partial
/// packet). `out` may contain decoded data even when `true` is returned —
/// callers must feed it before acting on the terminal signal.
///
/// If the payload does not look like valid chunk headers the remaining bytes
/// are appended to `out` unchanged so the SSE parser can still attempt to
/// process them.
pub fn decode_chunked_sse_into(payload: &[u8], out: &mut Vec<u8>) -> bool {
    out.clear();
    let mut pos = 0;

    while pos < payload.len() {
        // Find the end of the chunk-size line (terminated by \r\n).
        let Some(crlf) = payload[pos..].windows(2).position(|w| w == b"\r\n") else {
            // No \r\n — treat the rest as raw data (e.g., partial packet).
            out.extend_from_slice(&payload[pos..]);
            break;
        };

        let size_bytes = &payload[pos..pos + crlf];
        let Ok(size_str) = std::str::from_utf8(size_bytes) else {
            out.extend_from_slice(&payload[pos..]);
            break;
        };
        // Ignore chunk extensions (after ';').
        let size_str = size_str
            .find(';')
            .map(|i| &size_str[..i])
            .unwrap_or(size_str)
            .trim();

        let Ok(chunk_size) = usize::from_str_radix(size_str, 16) else {
            // Not a valid hex size — not chunked encoding; copy as-is.
            out.extend_from_slice(&payload[pos..]);
            break;
        };

        if chunk_size == 0 {
            return true; // Terminal chunk — HTTP stream has ended.
        }

        pos += crlf + 2; // Skip the chunk-size line including \r\n.

        // Append chunk data (handle partial last chunk).
        // saturating_add guards against crafted chunk sizes near usize::MAX.
        let data_end = pos.saturating_add(chunk_size).min(payload.len());
        out.extend_from_slice(&payload[pos..data_end]);
        pos = data_end;

        // Skip the chunk's trailing \r\n terminator (may be absent if partial).
        if pos + 2 <= payload.len() && payload[pos] == b'\r' && payload[pos + 1] == b'\n' {
            pos += 2;
        }
    }

    false
}

/// Allocating wrapper around `decode_chunked_sse_into` for call sites that
/// cannot pass a reusable buffer (e.g., tests). Returns `None` when the
/// terminal chunk is found, `Some(decoded)` otherwise.
pub fn decode_chunked_sse(payload: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(payload.len());
    if decode_chunked_sse_into(payload, &mut out) {
        None
    } else {
        Some(out)
    }
}

// ─── SSE helper ───────────────────────────────────────────────────────────

/// Find the end of the first complete SSE event in `buf`.
///
/// All four separator forms allowed by the SSE spec share the invariant that
/// a `\n` is immediately followed by either another `\n` (blank LF line) or
/// `\r\n` (blank CRLF line). Scanning for that covers `\n\n` (2 B),
/// `\n\r\n` / `\r\n\n` (3 B), and `\r\n\r\n` (4 B via the inner `\n`).
///
/// Returns `(end, sep_len)` where `buf[..end]` is the event content and
/// `buf[end..end+sep_len]` is the separator. Any trailing `\r` left in the
/// event content by a CRLF line ending is stripped by `.lines()` in
/// `process_sse_event`.
#[inline]
fn find_event_end(buf: &[u8]) -> Option<(usize, usize)> {
    let len = buf.len();
    if len < 2 {
        return None;
    }
    for i in 0..len - 1 {
        if buf[i] != b'\n' {
            continue;
        }
        if buf[i + 1] == b'\n' {
            return Some((i, 2));
        }
        if i + 2 < len && buf[i + 1] == b'\r' && buf[i + 2] == b'\n' {
            return Some((i, 3));
        }
    }
    None
}

/// Byte-level substring search. Zero allocation.
#[inline]
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

// ─── Attribute/metric push helpers ────────────────────────────────────────

fn push_attr(attrs: &mut Vec<KeyVal>, key: &str, val: &str) {
    attrs.push(KeyVal {
        key: key.to_string(),
        val: val.to_string(),
    });
}

fn push_metric(metrics: &mut Vec<MetricKeyVal>, key: &str, val: f64) {
    metrics.push(MetricKeyVal {
        key: key.to_string(),
        val: val as f32,
    });
}

// ─── Unit tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_session(kind: OpenAIKind, is_stream: bool) -> OpenAISession {
        OpenAISession::new(kind, is_stream, 1_000_000, 131072, &Default::default())
    }

    #[test]
    fn test_chat_completions_sse_ttft_tpot() {
        let mut s = make_session(OpenAIKind::ChatCompletions, true);
        s.request_ts_us = 0;

        // First output event at t=100ms (1 token).
        let chunk1 = b"data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\n";
        let done = s.feed_sse(chunk1, 100_000);
        assert!(!done);
        assert_eq!(s.stream_event_count, 1);
        assert_eq!(s.first_output_ts_us, Some(100_000));
        assert_eq!(s.last_output_ts_us, Some(100_000));

        // More content tokens at t=500ms (4 more tokens = 5 total output tokens),
        // then usage chunk and DONE – all in the same feed call.
        let chunk2 = concat!(
            "data: {\"choices\":[{\"delta\":{\"content\":\" w\"}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"or\"}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"ld\"}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"!\"}}]}\n\n",
            "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5,\"total_tokens\":15}}\n\n",
            "data: [DONE]\n\n",
        );
        let done = s.feed_sse(chunk2.as_bytes(), 500_000);
        assert!(done);
        assert!(s.stream_completed);
        assert_eq!(s.usage_status, UsageStatus::Available);
        let usage = s.usage.as_ref().unwrap();
        assert_eq!(usage.input_tokens, 10);
        assert_eq!(usage.output_tokens, 5);
        assert_eq!(s.stream_event_count, 5); // 1 + 4
        assert_eq!(s.last_output_ts_us, Some(500_000));

        let (ttft, tpot) = s.compute_timings();
        // ttft = (100_000 - 0) = 100_000 µs
        assert!((ttft.unwrap() - 100_000.0).abs() < 1.0);
        // tpot = (500_000 - 100_000) / max(5-1, 1) = 400_000 / 4 = 100_000 µs
        assert!((tpot.unwrap() - 100_000.0).abs() < 1.0);
    }

    #[test]
    fn test_responses_api_sse_completed() {
        // The Responses API `response.completed` event embeds usage under
        // `response.usage.*`, so we configure paths accordingly.
        use crate::config::config::OpenAIUsageFieldPaths;
        let paths = OpenAIUsageFieldPaths {
            input_tokens: vec!["response.usage.input_tokens".to_string()],
            output_tokens: vec!["response.usage.output_tokens".to_string()],
            total_tokens: vec!["response.usage.total_tokens".to_string()],
            ..Default::default()
        };
        let mut s = OpenAISession::new(OpenAIKind::Responses, true, 0, 131072, &paths);

        let chunk = b"event: response.output_text.delta\ndata: {\"delta\":\"Hi\"}\n\nevent: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":5,\"output_tokens\":3,\"total_tokens\":8}}}\n\n";
        let done = s.feed_sse(chunk, 200_000);
        assert!(done);
        assert!(s.stream_completed);
        assert_eq!(s.usage_status, UsageStatus::Available);
        let usage = s.usage.as_ref().unwrap();
        assert_eq!(usage.input_tokens, 5);
        assert_eq!(usage.output_tokens, 3);
        assert_eq!(s.stream_event_count, 1);
    }

    #[test]
    fn test_non_streaming_usage_extraction() {
        let mut s = make_session(OpenAIKind::ChatCompletions, false);
        let body = br#"{"usage":{"prompt_tokens":20,"completion_tokens":10,"total_tokens":30}}"#;
        let config = crate::config::handler::LogParserConfig::default();
        parse_response_json(&mut s, body, &config);
        assert_eq!(s.usage_status, UsageStatus::Available);
        let usage = s.usage.as_ref().unwrap();
        assert_eq!(usage.input_tokens, 20);
        assert_eq!(usage.output_tokens, 10);
        assert_eq!(usage.total_tokens, 30);
    }

    #[test]
    fn test_non_streaming_timings() {
        // Non-streaming: request at t=0, response at t=2_000_000 µs.
        // TTFT = TOTAL = 2_000_000 µs, TPOT = 2_000_000 / 10 output_tokens = 200_000 µs.
        let mut s = OpenAISession::new(
            OpenAIKind::ChatCompletions,
            false,
            0,
            131072,
            &Default::default(),
        );
        s.usage = Some(OpenAIUsage {
            input_tokens: 20,
            output_tokens: 10,
            total_tokens: 30,
            cached_tokens: None,
        });
        s.usage_status = UsageStatus::Available;
        s.stream_end_ts_us = Some(2_000_000); // 2 seconds in µs

        let (ttft, tpot) = s.compute_timings();
        assert!(
            (ttft.unwrap() - 2_000_000.0).abs() < 1.0,
            "ttft should be 2_000_000 µs, got {:?}",
            ttft
        );
        assert!(
            (tpot.unwrap() - 200_000.0).abs() < 1.0,
            "tpot should be 200_000 µs, got {:?}",
            tpot
        );

        // Verify populate_log emits the metrics.
        let mut attrs = Vec::new();
        let mut metrics = Vec::new();
        s.populate_log(&mut attrs, &mut metrics);

        let metric_map: std::collections::HashMap<_, _> =
            metrics.iter().map(|kv| (kv.key.as_str(), kv.val)).collect();
        assert!(metric_map.contains_key("llm_ttft_us"), "ttft missing");
        assert!(metric_map.contains_key("llm_tpot_us"), "tpot missing");
        assert!(
            metric_map.contains_key("llm_total_stream_us"),
            "total_stream_us missing"
        );
        assert!((metric_map["llm_ttft_us"] - 2_000_000.0).abs() < 1.0);
        assert!((metric_map["llm_tpot_us"] - 200_000.0).abs() < 1.0);
        assert!((metric_map["llm_total_stream_us"] - 2_000_000.0).abs() < 1.0);
    }

    fn make_config_with_json_paths() -> crate::config::handler::LogParserConfig {
        use crate::config::config::{
            OpenAIApiConfig, OpenAIBizDimExtractor, OpenAIBizDimExtractors, OpenAIUsageFieldPaths,
        };
        crate::config::handler::LogParserConfig {
            openai_api: OpenAIApiConfig {
                enabled: true,
                path_prefixes: vec!["/v1/chat/completions".to_string()],
                path_suffixes: vec![],
                request_body_max_bytes: 65536,
                response_event_max_bytes: 32768,
                sse_buffer_max_bytes: 131072,
                usage_field_paths: OpenAIUsageFieldPaths::default(),
                biz_dimension_extractors: OpenAIBizDimExtractors {
                    org_path: OpenAIBizDimExtractor {
                        headers: vec![],
                        json_paths: vec![
                            "metadata.org_path".to_string(),
                            "metadata.department_path".to_string(),
                        ],
                    },
                    user_id: OpenAIBizDimExtractor {
                        headers: vec![],
                        json_paths: vec![
                            "safety_identifier".to_string(),
                            "user".to_string(),
                            "metadata.user_id".to_string(),
                        ],
                    },
                    app_id: OpenAIBizDimExtractor {
                        headers: vec![],
                        json_paths: vec![
                            "metadata.app_id".to_string(),
                            "metadata.application_id".to_string(),
                        ],
                    },
                },
            },
            ..Default::default()
        }
    }

    #[test]
    fn test_biz_dims_from_json() {
        let mut s = make_session(OpenAIKind::ChatCompletions, false);
        let config = make_config_with_json_paths();
        let body =
            br#"{"user":"alice","safety_identifier":"si-001","metadata":{"org_path":"/root/eng","app_id":"app-42"}}"#;
        parse_request_body(&mut s, body, &config);
        // user_id: "safety_identifier" has priority over "user"
        assert_eq!(s.biz_user_id.as_deref(), Some("si-001"));
        assert_eq!(s.biz_org_path.as_deref(), Some("/root/eng"));
        assert_eq!(s.biz_app_id.as_deref(), Some("app-42"));
    }

    #[test]
    fn test_biz_dims_three_level_json_path() {
        // Regression test: paths deeper than 2 levels must work.
        use crate::config::config::{
            OpenAIApiConfig, OpenAIBizDimExtractor, OpenAIBizDimExtractors, OpenAIUsageFieldPaths,
        };
        let config = crate::config::handler::LogParserConfig {
            openai_api: OpenAIApiConfig {
                enabled: true,
                path_prefixes: vec!["/v1/chat/completions".to_string()],
                path_suffixes: vec![],
                request_body_max_bytes: 65536,
                response_event_max_bytes: 32768,
                sse_buffer_max_bytes: 131072,
                usage_field_paths: OpenAIUsageFieldPaths::default(),
                biz_dimension_extractors: OpenAIBizDimExtractors {
                    org_path: OpenAIBizDimExtractor {
                        headers: vec![],
                        json_paths: vec!["context.meta.org".to_string()],
                    },
                    user_id: OpenAIBizDimExtractor {
                        headers: vec![],
                        json_paths: vec![],
                    },
                    app_id: OpenAIBizDimExtractor {
                        headers: vec![],
                        json_paths: vec![],
                    },
                },
            },
            ..Default::default()
        };
        let mut s = make_session(OpenAIKind::ChatCompletions, false);
        let body = br#"{"context":{"meta":{"org":"/root/deep"}}}"#;
        parse_request_body(&mut s, body, &config);
        assert_eq!(s.biz_org_path.as_deref(), Some("/root/deep"));
    }

    #[test]
    fn test_biz_dims_user_fallback() {
        let mut s = make_session(OpenAIKind::ChatCompletions, false);
        let config = make_config_with_json_paths();
        let body = br#"{"user":"bob","metadata":{"org_path":"/root/sales"}}"#;
        parse_request_body(&mut s, body, &config);
        // No safety_identifier, fall back to "user"
        assert_eq!(s.biz_user_id.as_deref(), Some("bob"));
        assert_eq!(s.biz_org_path.as_deref(), Some("/root/sales"));
    }

    #[test]
    fn test_sse_across_chunks() {
        let mut s = make_session(OpenAIKind::ChatCompletions, true);
        s.request_ts_us = 0;

        // Event split across two feed calls.
        let part1 = b"data: {\"choices\":[{\"delta\":{\"content\":\"He";
        let done = s.feed_sse(part1, 50_000);
        assert!(!done);
        assert_eq!(s.stream_event_count, 0);

        let part2 = b"llo\"}}]}\n\ndata: [DONE]\n\n";
        let done = s.feed_sse(part2, 100_000);
        assert!(done);
        assert_eq!(s.stream_event_count, 1);
        assert_eq!(s.first_output_ts_us, Some(100_000));
    }

    /// Verify that `find_event_end` and `feed_sse` handle the `\n\r\n` SSE separator.
    ///
    /// Some servers (e.g., `openai_stream_v537.pcap`) deliver SSE over HTTP
    /// chunked transfer where each chunk only carries part of an SSE event:
    /// - Chunk 1: `data:`
    /// - Chunk 2: `{json}\n`     (single LF from SSE data line)
    /// - Chunk 3: `\r\n`         (CRLF blank line = event separator)
    ///
    /// After `decode_chunked_sse_into` concatenates the chunks, the buffer
    /// looks like `data:{json}\n\r\n`.  This test verifies the parser handles
    /// that `\n\r\n` separator correctly.
    #[test]
    fn test_sse_crlf_event_separator() {
        let mut s = make_session(OpenAIKind::ChatCompletions, true);
        s.request_ts_us = 0;

        // Simulate the decoded content from a chunked SSE packet in v537 format:
        // data:{json}\n  ← SSE data line (LF)
        // \r\n           ← CRLF blank line (event separator)
        let event = b"data:{\"choices\":[{\"delta\":{\"content\":\"Hi\"},\"finish_reason\":null}],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":1,\"total_tokens\":11}}\n\r\n";
        let done = s.feed_sse(event, 100_000);
        assert!(!done);
        assert_eq!(s.stream_event_count, 1, "should detect output event");
        assert_eq!(
            s.usage_status,
            UsageStatus::Available,
            "inline usage should be extracted"
        );
        let usage = s.usage.as_ref().unwrap();
        assert_eq!(usage.input_tokens, 10);
        assert_eq!(usage.output_tokens, 1);

        // Terminator: data:[DONE]\n\r\n (same separator style)
        let done_event = b"data:[DONE]\n\r\n";
        let done = s.feed_sse(done_event, 200_000);
        assert!(done);
        assert!(s.stream_completed);
    }

    #[test]
    fn test_tpot_missing_when_usage_absent() {
        let mut s = make_session(OpenAIKind::ChatCompletions, true);
        s.request_ts_us = 0;
        s.first_output_ts_us = Some(100_000);
        s.last_output_ts_us = Some(500_000);
        // No usage -> TPOT should be None
        let (_, tpot) = s.compute_timings();
        assert!(tpot.is_none());
    }
}
