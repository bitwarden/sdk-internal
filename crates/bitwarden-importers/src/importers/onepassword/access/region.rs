//! The standard 1Password sign-in regions.

/// One of the three regions 1Password operates. Each stores its accounts in a different
/// jurisdiction, and an account belongs to exactly one of them.
///
/// A convenience for callers offering a region to pick from: [`Region::domain`] gives the string
/// that goes into [`super::credentials::Credentials::domain`]. An Enterprise account on a custom
/// sign-in domain skips this and supplies that domain directly.
///
/// See <https://support.1password.com/regions/>.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Region {
    /// `my.1password.com`, the default. Data hosted in the United States.
    Global,
    /// `my.1password.eu`. Data hosted in the European Union.
    Europe,
    /// `my.1password.ca`. Data hosted in Canada.
    Canada,
}

impl Region {
    /// The API host for this region.
    pub fn domain(&self) -> &'static str {
        match self {
            Region::Global => "my.1password.com",
            Region::Europe => "my.1password.eu",
            Region::Canada => "my.1password.ca",
        }
    }
}
