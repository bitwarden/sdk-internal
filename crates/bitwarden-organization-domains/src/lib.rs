#![doc = include_str!("../README.md")]

mod organization_domains_client;

pub use organization_domains_client::{
    OrganizationDomainsClient, OrganizationDomainsClientExt, OrganizationDomainsError,
};
