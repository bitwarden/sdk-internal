//! Scene template implementations

mod organization_login_cipher;
mod single_organization;
mod single_user;

pub use organization_login_cipher::{
    OrganizationLoginCipherArgs, OrganizationLoginCipherResult, OrganizationLoginCipherScene,
};
pub use single_organization::{
    OrganizationOverrides, PlanType, SingleOrganizationArgs, SingleOrganizationResult,
    SingleOrganizationScene,
};
pub use single_user::{SingleUserArgs, SingleUserResult, SingleUserScene};
