//! Quartz cron schedule helpers shared by every rotation surface.

use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

/// The canonical Quartz cron expression for each named preset.
///
/// Quartz's format is `seconds minutes hours day-of-month month day-of-week [year]` - 6 or 7
/// fields, one more than the 5-field UNIX cron. Getting that wrong shifts every field by one
/// position, which is why these are constants rather than assembled per call site.
const HOURLY_CRON: &str = "0 0 * * * ?";
const EVERY_6_HOURS_CRON: &str = "0 0 */6 * * ?";
const DAILY_CRON: &str = "0 0 0 * * ?";
const WEEKLY_CRON: &str = "0 0 0 ? * SUN";
const MONTHLY_CRON: &str = "0 0 0 1 * ?";

/// A named rotation schedule, or the escape hatches either side of the presets.
///
/// This is a *presentation* concept, not a server one: the server stores only the cron string.
/// [`Custom`](QuartzSchedulePreset::Custom) therefore means "a valid cron that is not one of ours",
/// and round-trips unchanged.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "snake_case")]
pub enum QuartzSchedulePreset {
    /// No scheduled rotation. On-demand and access-end rotations still apply.
    None,
    /// Every hour, on the hour.
    Hourly,
    /// Every six hours, starting at midnight.
    Every6Hours,
    /// Every day at midnight.
    Daily,
    /// Every Sunday at midnight.
    Weekly,
    /// The first day of every month, at midnight.
    Monthly,
    /// An operator-authored expression that matches no preset.
    Custom,
}

impl QuartzSchedulePreset {
    /// The cron expression for this preset, or `None` for the two presets that have no fixed
    /// expression: [`None`](QuartzSchedulePreset::None) (no schedule at all) and
    /// [`Custom`](QuartzSchedulePreset::Custom) (whatever the operator wrote).
    pub fn cron(&self) -> Option<&'static str> {
        match self {
            Self::Hourly => Some(HOURLY_CRON),
            Self::Every6Hours => Some(EVERY_6_HOURS_CRON),
            Self::Daily => Some(DAILY_CRON),
            Self::Weekly => Some(WEEKLY_CRON),
            Self::Monthly => Some(MONTHLY_CRON),
            Self::None | Self::Custom => None,
        }
    }
}

/// Derives the preset that best describes a stored cron expression.
///
/// `None` maps to [`QuartzSchedulePreset::None`]; an exact match against a preset's expression
/// (ignoring surrounding whitespace) maps to that preset; anything else is
/// [`Custom`](QuartzSchedulePreset::Custom) - including a blank string, which the server should
/// have stored as `null` but which must not be reported as a real schedule if it wasn't.
pub fn preset_for_cron(cron: Option<&str>) -> QuartzSchedulePreset {
    let Some(cron) = cron else {
        return QuartzSchedulePreset::None;
    };

    let trimmed = cron.trim();
    if trimmed.is_empty() {
        return QuartzSchedulePreset::None;
    }

    [
        QuartzSchedulePreset::Hourly,
        QuartzSchedulePreset::Every6Hours,
        QuartzSchedulePreset::Daily,
        QuartzSchedulePreset::Weekly,
        QuartzSchedulePreset::Monthly,
    ]
    .into_iter()
    .find(|preset| preset.cron() == Some(trimmed))
    .unwrap_or(QuartzSchedulePreset::Custom)
}

/// Reports whether a string is shaped like a Quartz cron expression.
///
/// Advisory only - it checks field count and the character set, not that the expression describes a
/// reachable time. The server is authoritative, so this exists to fail an obviously-malformed entry
/// without a round trip, and deliberately errs towards accepting.
pub fn is_likely_quartz_cron(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return false;
    }

    let fields: Vec<&str> = trimmed.split_whitespace().collect();
    if fields.len() < 6 || fields.len() > 7 {
        return false;
    }

    fields.iter().all(|field| {
        !field.is_empty()
            && field.chars().all(|c| {
                c.is_ascii_alphanumeric()
                    || matches!(c, '*' | '/' | ',' | '-' | '?' | '#' | 'L' | 'W')
            })
    })
}

/// The WASM-facing surface for the schedule helpers.
///
/// The functions above are plain Rust so Rust callers - and the rest of this crate - can use them
/// without going through a client. This zero-sized client exists only because `wasm_bindgen` cannot
/// export free functions from a crate that is not itself the entry point.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct RotationScheduleClient;

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl RotationScheduleClient {
    /// See [`preset_for_cron`].
    pub fn preset_for_cron(&self, cron: Option<String>) -> QuartzSchedulePreset {
        preset_for_cron(cron.as_deref())
    }

    /// The cron expression for a preset, or `None` when the preset has no fixed expression.
    pub fn cron_for_preset(&self, preset: QuartzSchedulePreset) -> Option<String> {
        preset.cron().map(ToString::to_string)
    }

    /// See [`is_likely_quartz_cron`].
    pub fn is_likely_quartz_cron(&self, value: String) -> bool {
        is_likely_quartz_cron(&value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_cron_is_the_none_preset() {
        assert_eq!(preset_for_cron(None), QuartzSchedulePreset::None);
    }

    #[test]
    fn each_preset_round_trips_through_its_own_cron() {
        for preset in [
            QuartzSchedulePreset::Hourly,
            QuartzSchedulePreset::Every6Hours,
            QuartzSchedulePreset::Daily,
            QuartzSchedulePreset::Weekly,
            QuartzSchedulePreset::Monthly,
        ] {
            let cron = preset.cron().expect("a named preset has a cron");
            assert_eq!(preset_for_cron(Some(cron)), preset, "for {cron}");
        }
    }

    #[test]
    fn surrounding_whitespace_does_not_hide_a_preset() {
        assert_eq!(
            preset_for_cron(Some("  0 0 0 * * ?  ")),
            QuartzSchedulePreset::Daily
        );
    }

    #[test]
    fn an_unrecognized_expression_is_custom() {
        assert_eq!(
            preset_for_cron(Some("0 30 9 ? * MON-FRI")),
            QuartzSchedulePreset::Custom
        );
    }

    /// A blank string is not a schedule. The server should have stored `null`, but reporting
    /// `Custom` would render an empty cron as though the operator had authored one.
    #[test]
    fn a_blank_expression_is_not_a_custom_schedule() {
        assert_eq!(preset_for_cron(Some("   ")), QuartzSchedulePreset::None);
    }

    /// The presets differ only in a couple of fields, so an off-by-one in `cron()` would still look
    /// plausible. Pinning the strings catches that.
    #[test]
    fn preset_crons_are_six_field_quartz_expressions() {
        for preset in [
            QuartzSchedulePreset::Hourly,
            QuartzSchedulePreset::Every6Hours,
            QuartzSchedulePreset::Daily,
            QuartzSchedulePreset::Weekly,
            QuartzSchedulePreset::Monthly,
        ] {
            let cron = preset.cron().expect("a named preset has a cron");
            assert_eq!(cron.split_whitespace().count(), 6, "for {cron}");
            assert!(is_likely_quartz_cron(cron), "for {cron}");
        }
    }

    #[test]
    fn none_and_custom_have_no_fixed_cron() {
        assert_eq!(QuartzSchedulePreset::None.cron(), None);
        assert_eq!(QuartzSchedulePreset::Custom.cron(), None);
    }

    #[test]
    fn six_and_seven_field_expressions_are_accepted() {
        assert!(is_likely_quartz_cron("0 0 0 * * ?"));
        assert!(is_likely_quartz_cron("0 0 0 * * ? 2027"));
    }

    #[test]
    fn field_counts_outside_six_or_seven_are_rejected() {
        // A 5-field UNIX cron is the likeliest mistake, and Quartz would misread every field.
        assert!(!is_likely_quartz_cron("0 0 * * *"));
        assert!(!is_likely_quartz_cron("0 0 0 * * ? 2027 extra"));
    }

    #[test]
    fn blank_input_is_rejected() {
        assert!(!is_likely_quartz_cron(""));
        assert!(!is_likely_quartz_cron("      "));
    }

    #[test]
    fn quartz_special_characters_are_accepted() {
        assert!(is_likely_quartz_cron("0 0 0 L * ?"));
        assert!(is_likely_quartz_cron("0 0 0 ? * 6#3"));
        assert!(is_likely_quartz_cron("0 0 0 1W * ?"));
        assert!(is_likely_quartz_cron("0 0/15 * * * ?"));
    }

    #[test]
    fn characters_outside_the_quartz_set_are_rejected() {
        assert!(!is_likely_quartz_cron("0 0 0 * * ; rm -rf /"));
        assert!(!is_likely_quartz_cron("0 0 0 * * $(date)"));
    }

    /// Irregular internal spacing is an operator typo, not a different schedule -
    /// `split_whitespace` collapses runs, so this must not be read as an extra empty field.
    #[test]
    fn runs_of_internal_whitespace_collapse() {
        assert!(is_likely_quartz_cron("0  0   0 * * ?"));
        assert_eq!(
            preset_for_cron(Some("0 0 0 * * ?")),
            QuartzSchedulePreset::Daily
        );
    }
}
