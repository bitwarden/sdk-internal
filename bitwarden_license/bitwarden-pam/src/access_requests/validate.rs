use chrono::{DateTime, Duration, Utc};
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use super::models::AccessRequestCreateRequest;

/// Maximum span, in seconds, of an access request's activation window - mirrors the server's
/// cap. Applies to both the automatic path's
/// [`duration_seconds`](AccessRequestCreateRequest::duration_seconds) and the human path's
/// [`start`](AccessRequestCreateRequest::start)/[`end`](AccessRequestCreateRequest::end) span.
pub const MAX_REQUEST_ACCESS_WINDOW_SECONDS: u32 = 86_400;

/// [`MAX_REQUEST_ACCESS_WINDOW_SECONDS`], for callers that cannot read a Rust `const`.
///
/// wasm-bindgen exports functions, not constants, so this is a getter rather than a re-exported
/// value.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn max_request_access_window_seconds() -> u32 {
    MAX_REQUEST_ACCESS_WINDOW_SECONDS
}

/// Duration, in seconds, a request form pre-selects absent a rule- or server-named default;
/// mirrors the server's global default.
///
/// Only a fallback for a pre-check response that predates
/// [`default_duration_seconds`](super::AccessPreCheckView::default_duration_seconds).
pub const DEFAULT_REQUEST_ACCESS_DURATION_SECONDS: u32 = 3_600;

/// [`DEFAULT_REQUEST_ACCESS_DURATION_SECONDS`], for callers that cannot read a Rust `const`.
///
/// Same reason [`max_request_access_window_seconds`] exists: wasm-bindgen exports functions rather
/// than constants, and a client that hardcodes its own copy drifts the day the server's default
/// moves.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn default_request_access_duration_seconds() -> u32 {
    DEFAULT_REQUEST_ACCESS_DURATION_SECONDS
}

/// Errors from a locally-constructed [`AccessRequestCreateRequest`] failing validation before
/// being sent to the server.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AccessRequestWindowError {
    /// `end` was not strictly after `start`.
    #[error("end must be strictly after start")]
    EndBeforeStart,
    /// `end` had already passed, so the window could never be activated.
    ///
    /// Deliberately not the server's wording ("The end date must be in the future."): each has a
    /// separate catalog entry (`REQUEST_ACCESS_SDK_ERRORS` vs `REQUEST_ACCESS_SERVER_ERRORS`).
    #[error("The requested window has already ended.")]
    EndInPast,
    /// The requested window was longer than the server's 24h cap.
    #[error(
        "The requested window exceeds the maximum of {MAX_REQUEST_ACCESS_WINDOW_SECONDS} seconds"
    )]
    ExceedsMaxWindow,
}

impl AccessRequestCreateRequest {
    /// Validates the request's activation window before it is sent to the server.
    ///
    /// The human path requires `end` strictly after `start`, not already passed, and within
    /// `MAX_REQUEST_ACCESS_WINDOW_SECONDS`; the automatic path's `duration_seconds` faces the
    /// same cap.
    pub(crate) fn validate(&self) -> Result<(), AccessRequestWindowError> {
        self.validate_at(Utc::now())
    }

    /// [`validate`](Self::validate) against a caller-supplied instant, so the elapsed-window rule
    /// is testable without a fake clock.
    pub(crate) fn validate_at(&self, now: DateTime<Utc>) -> Result<(), AccessRequestWindowError> {
        if let (Some(start), Some(end)) = (self.start, self.end) {
            if end <= start {
                return Err(AccessRequestWindowError::EndBeforeStart);
            }
            // Measured on the end, not the start: a window already under way is still usable.
            // An ended window can never be activated.
            if end <= now {
                return Err(AccessRequestWindowError::EndInPast);
            }
            if end - start > Duration::seconds(MAX_REQUEST_ACCESS_WINDOW_SECONDS as i64) {
                return Err(AccessRequestWindowError::ExceedsMaxWindow);
            }
        }

        if let Some(duration_seconds) = self.duration_seconds
            && duration_seconds.get() > MAX_REQUEST_ACCESS_WINDOW_SECONDS
        {
            return Err(AccessRequestWindowError::ExceedsMaxWindow);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use super::*;

    /// The instant the fixed-window cases are judged against. Pinned rather than `Utc::now()` so
    /// the suite's verdicts do not change as the wall clock passes the dates written below.
    fn now() -> DateTime<Utc> {
        "2024-12-31T23:00:00Z".parse().unwrap()
    }

    fn base_request() -> AccessRequestCreateRequest {
        AccessRequestCreateRequest {
            duration_seconds: None,
            start: None,
            end: None,
            reason: None,
        }
    }

    #[test]
    fn neither_duration_nor_window_is_not_rejected_locally() {
        // The server decides which path applies to an incomplete request; an SDK-side rule here
        // would reject requests the server accepts.
        assert_eq!(base_request().validate_at(now()), Ok(()));
    }

    #[test]
    fn end_equal_to_start_is_invalid() {
        let start: DateTime<Utc> = "2025-01-01T00:00:00Z".parse().unwrap();
        let request = AccessRequestCreateRequest {
            start: Some(start),
            end: Some(start),
            ..base_request()
        };

        assert_eq!(
            request.validate_at(now()),
            Err(AccessRequestWindowError::EndBeforeStart)
        );
    }

    #[test]
    fn end_before_start_is_invalid() {
        let request = AccessRequestCreateRequest {
            start: Some("2025-01-01T01:00:00Z".parse().unwrap()),
            end: Some("2025-01-01T00:00:00Z".parse().unwrap()),
            ..base_request()
        };

        assert_eq!(
            request.validate_at(now()),
            Err(AccessRequestWindowError::EndBeforeStart)
        );
    }

    #[test]
    fn window_span_of_exactly_24_hours_is_valid() {
        let request = AccessRequestCreateRequest {
            start: Some("2025-01-01T00:00:00Z".parse().unwrap()),
            end: Some("2025-01-02T00:00:00Z".parse().unwrap()),
            ..base_request()
        };

        assert_eq!(request.validate_at(now()), Ok(()));
    }

    #[test]
    fn window_span_over_24_hours_is_invalid() {
        let request = AccessRequestCreateRequest {
            start: Some("2025-01-01T00:00:00Z".parse().unwrap()),
            end: Some("2025-01-02T00:00:01Z".parse().unwrap()),
            ..base_request()
        };

        assert_eq!(
            request.validate_at(now()),
            Err(AccessRequestWindowError::ExceedsMaxWindow)
        );
    }

    #[test]
    fn window_that_has_already_ended_is_invalid() {
        // A window dated days before submission. The server persisted this as a pending
        // request that activation could never start.
        let request = AccessRequestCreateRequest {
            start: Some("2024-12-23T07:00:00Z".parse().unwrap()),
            end: Some("2024-12-23T08:00:00Z".parse().unwrap()),
            ..base_request()
        };

        assert_eq!(
            request.validate_at(now()),
            Err(AccessRequestWindowError::EndInPast)
        );
    }

    #[test]
    fn window_ending_exactly_now_is_invalid() {
        // Matches activation's own already-expired refusal: a window with no time left isn't one.
        let request = AccessRequestCreateRequest {
            start: Some("2024-12-31T22:00:00Z".parse().unwrap()),
            end: Some(now()),
            ..base_request()
        };

        assert_eq!(
            request.validate_at(now()),
            Err(AccessRequestWindowError::EndInPast)
        );
    }

    #[test]
    fn window_already_under_way_is_valid() {
        // Deliberately not rejected: only the end is checked, so access starting immediately
        // must be requestable.
        let request = AccessRequestCreateRequest {
            start: Some("2024-12-31T22:00:00Z".parse().unwrap()),
            end: Some("2025-01-01T00:00:00Z".parse().unwrap()),
            ..base_request()
        };

        assert_eq!(request.validate_at(now()), Ok(()));
    }

    #[test]
    fn reversed_window_reports_end_before_start_rather_than_end_in_past() {
        // Both rules fire on a reversed window in the past; ordering puts the reversal first.
        let request = AccessRequestCreateRequest {
            start: Some("2024-12-23T08:00:00Z".parse().unwrap()),
            end: Some("2024-12-23T07:00:00Z".parse().unwrap()),
            ..base_request()
        };

        assert_eq!(
            request.validate_at(now()),
            Err(AccessRequestWindowError::EndBeforeStart)
        );
    }

    #[test]
    fn validate_measures_against_the_real_clock() {
        // `validate` is what `TryFrom` calls on the way to the wire; `validate_at` is only the
        // seam the tests use.
        let request = AccessRequestCreateRequest {
            start: Some("2020-01-01T00:00:00Z".parse().unwrap()),
            end: Some("2020-01-01T01:00:00Z".parse().unwrap()),
            ..base_request()
        };

        assert_eq!(request.validate(), Err(AccessRequestWindowError::EndInPast));
    }

    #[test]
    fn duration_seconds_of_exactly_24_hours_is_valid() {
        let request = AccessRequestCreateRequest {
            duration_seconds: NonZeroU32::new(86_400),
            ..base_request()
        };

        assert_eq!(request.validate_at(now()), Ok(()));
    }

    #[test]
    fn duration_seconds_over_24_hours_is_invalid() {
        let request = AccessRequestCreateRequest {
            duration_seconds: NonZeroU32::new(86_401),
            ..base_request()
        };

        assert_eq!(
            request.validate_at(now()),
            Err(AccessRequestWindowError::ExceedsMaxWindow)
        );
    }

    #[test]
    fn small_duration_seconds_is_valid() {
        let request = AccessRequestCreateRequest {
            duration_seconds: NonZeroU32::new(3600),
            ..base_request()
        };

        assert_eq!(request.validate_at(now()), Ok(()));
    }

    #[test]
    fn only_start_without_end_is_not_window_checked_locally() {
        // The human path isn't complete without both `start` and `end`; the server is the source
        // of truth for rejecting an incomplete pair.
        let request = AccessRequestCreateRequest {
            start: Some("2025-01-01T00:00:00Z".parse().unwrap()),
            ..base_request()
        };

        assert_eq!(request.validate_at(now()), Ok(()));
    }
}
