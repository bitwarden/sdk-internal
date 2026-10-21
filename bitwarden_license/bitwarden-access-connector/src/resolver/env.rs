//! Environment variable naming for per-target credentials.

use bitwarden_pam_sealed::SealedTargetSystemKind;
use uuid::Uuid;

/// Environment variable suffixes required per target kind.
pub(crate) fn required_suffixes(kind: SealedTargetSystemKind) -> &'static [&'static str] {
    match kind {
        SealedTargetSystemKind::Entra => &["TENANT_ID", "CLIENT_ID", "CLIENT_SECRET"],
        SealedTargetSystemKind::CustomScript => &["SCRIPT"],
        SealedTargetSystemKind::Mssql => &["HOST", "USER", "SECRET"],
    }
}

/// Env var prefix for a target, e.g. `EC2C1D46_6A4B_4751_A310_AF9601317F2D_`.
pub(crate) fn prefix_for(id: Uuid) -> String {
    let mut s = id.to_string().to_uppercase();
    s = s.replace('-', "_");
    s.push('_');
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_plain_uuid() {
        let id: Uuid = "ec2c1d46-6a4b-4751-a310-af9601317f2d".parse().unwrap();
        assert_eq!(prefix_for(id), "EC2C1D46_6A4B_4751_A310_AF9601317F2D_");
    }

    #[test]
    fn prefix_hyphens_replaced_by_underscores() {
        let id: Uuid = "00000000-0000-0000-0000-000000000001".parse().unwrap();
        let p = prefix_for(id);
        assert!(!p.contains('-'), "hyphens must be replaced: {p}");
        assert!(p.ends_with('_'), "must have trailing underscore: {p}");
    }

    #[test]
    fn prefix_fully_uppercased() {
        let id: Uuid = "aabbccdd-eeff-1122-3344-556677889900".parse().unwrap();
        let p = prefix_for(id);
        assert_eq!(p, p.to_uppercase(), "prefix must be all-uppercase: {p}");
    }
}
