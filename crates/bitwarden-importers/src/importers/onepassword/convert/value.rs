//! Renders a 1Password field value as the text of one Bitwarden custom field.

use chrono::{DateTime, TimeDelta};

/// Renders a field value as the text of one custom field. 1Password stores dates as unix seconds
/// and month/year as an integer such as `202112`; anything else it sends stays in its JSON form.
pub(super) fn render_value(kind: Option<&str>, value: &serde_json::Value) -> Option<String> {
    match (kind, value) {
        (_, serde_json::Value::Null) => None,
        (_, serde_json::Value::String(text)) => non_blank(text).map(str::to_string),
        (Some("date"), serde_json::Value::Number(seconds)) => seconds
            .as_i64()
            .map(render_date)
            .or(Some(value.to_string())),
        (Some("monthYear"), serde_json::Value::Number(number)) => Some(
            number
                .as_i64()
                .and_then(render_month_year)
                .unwrap_or_else(|| value.to_string()),
        ),
        (_, other) => Some(other.to_string()),
    }
}

/// 1Password writes a date as midnight in the writer's own time zone, which it does not record.
/// Adding 12 hours before formatting in UTC recovers the intended day for every zone from UTC-11
/// to UTC+12; further east it lands a day early. No single shift covers the full 26 hours of real
/// offsets.
fn render_date(seconds: i64) -> String {
    DateTime::from_timestamp(seconds, 0)
        .and_then(|date| date.checked_add_signed(TimeDelta::hours(12)))
        .map(|date| date.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| seconds.to_string())
}

/// `202112` is December 2021.
fn render_month_year(value: i64) -> Option<String> {
    let (year, month) = (value / 100, value % 100);
    (1..=12)
        .contains(&month)
        .then(|| format!("{year:04}-{month:02}"))
}

pub(super) fn non_blank(value: &str) -> Option<&str> {
    (!value.trim().is_empty()).then_some(value)
}
