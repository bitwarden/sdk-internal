#![doc = include_str!("../README.md")]

mod config;
mod event;
mod visitor;

pub use config::FlightRecorderConfig;
pub use event::FlightRecorderEvent;
pub use visitor::MessageVisitor;
