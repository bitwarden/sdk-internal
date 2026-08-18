use chrono::Duration;
use thiserror::Error;

use super::models::AccessRequestCreateRequest;

/// Maximum span, in seconds, of an access request's activation window - mirrors the server's
/// cap. Applies to both the automatic path's
/// [`duration_seconds`](AccessRequestCreateRequest::duration_seconds) and the human path's
/// [`start`](AccessRequestCreateRequest::start)/[`end`](AccessRequestCreateRequest::end) span.
const MAX_REQUEST_ACCESS_WINDOW_SECONDS: u32 = 86_400;

/// Errors returned when a locally-constructed [`AccessRequestCreateRequest`] fails validation
/// before being sent to the server.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AccessRequestWindowError {
    /// `end` was not strictly after `start`.
    #[error("end must be strictly after start")]
    EndBeforeStart,
    /// The requested window was longer than the server's 24h cap.
    #[error(
        "The requested window exceeds the maximum of {MAX_REQUEST_ACCESS_WINDOW_SECONDS} seconds"
    )]
    ExceedsMaxWindow,
}

impl AccessRequestCreateRequest {
    /// Validates the request's activation window before it is sent to the server.
    ///
    /// - When both [`start`](Self::start) and [`end`](Self::end) are supplied (the human path),
    ///   `end` must be strictly after `start` and the span between them must not exceed
    ///   `MAX_REQUEST_ACCESS_WINDOW_SECONDS`.
    /// - When [`duration_seconds`](Self::duration_seconds) is supplied (the automatic path), it
    ///   must not exceed `MAX_REQUEST_ACCESS_WINDOW_SECONDS`. It is a `NonZeroU32`, so positivity
    ///   is already guaranteed by the type and is not re-checked here.
    /// - A request with neither a duration nor a start/end pair is **not** rejected here: the
    ///   server decides which path applies to an incomplete request, and rejecting it locally would
    ///   reject requests the server is willing to accept.
    pub(crate) fn validate(&self) -> Result<(), AccessRequestWindowError> {
        if let (Some(start), Some(end)) = (self.start, self.end) {
            if end <= start {
                return Err(AccessRequestWindowError::EndBeforeStart);
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
        assert_eq!(base_request().validate(), Ok(()));
    }

    #[test]
    fn end_equal_to_start_is_invalid() {
        let start: chrono::DateTime<chrono::Utc> = "2025-01-01T00:00:00Z".parse().unwrap();
        let request = AccessRequestCreateRequest {
            start: Some(start),
            end: Some(start),
            ..base_request()
        };

        assert_eq!(
            request.validate(),
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
            request.validate(),
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

        assert_eq!(request.validate(), Ok(()));
    }

    #[test]
    fn window_span_over_24_hours_is_invalid() {
        let request = AccessRequestCreateRequest {
            start: Some("2025-01-01T00:00:00Z".parse().unwrap()),
            end: Some("2025-01-02T00:00:01Z".parse().unwrap()),
            ..base_request()
        };

        assert_eq!(
            request.validate(),
            Err(AccessRequestWindowError::ExceedsMaxWindow)
        );
    }

    #[test]
    fn duration_seconds_of_exactly_24_hours_is_valid() {
        let request = AccessRequestCreateRequest {
            duration_seconds: NonZeroU32::new(86_400),
            ..base_request()
        };

        assert_eq!(request.validate(), Ok(()));
    }

    #[test]
    fn duration_seconds_over_24_hours_is_invalid() {
        let request = AccessRequestCreateRequest {
            duration_seconds: NonZeroU32::new(86_401),
            ..base_request()
        };

        assert_eq!(
            request.validate(),
            Err(AccessRequestWindowError::ExceedsMaxWindow)
        );
    }

    #[test]
    fn small_duration_seconds_is_valid() {
        let request = AccessRequestCreateRequest {
            duration_seconds: NonZeroU32::new(3600),
            ..base_request()
        };

        assert_eq!(request.validate(), Ok(()));
    }

    #[test]
    fn only_start_without_end_is_not_window_checked_locally() {
        // The human path isn't complete without both `start` and `end`; the server is the source
        // of truth for rejecting an incomplete pair.
        let request = AccessRequestCreateRequest {
            start: Some("2025-01-01T00:00:00Z".parse().unwrap()),
            ..base_request()
        };

        assert_eq!(request.validate(), Ok(()));
    }
}
