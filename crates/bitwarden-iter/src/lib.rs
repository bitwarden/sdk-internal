#![doc = include_str!("../README.md")]

mod iter;

pub mod wasm;

pub use iter::{BwIterator, BwStream};
