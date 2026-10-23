#![doc = include_str!("../README.md")]

mod circular_buffer;
mod config;
mod event;
mod global;
#[cfg(feature = "ipc")]
pub mod ipc;
mod layer;
mod sink;
mod suppress;
mod visitor;

pub use bitwarden_logging_macro::instrument;
pub use circular_buffer::CircularBuffer;
pub use config::FlightRecorderConfig;
pub use event::FlightRecorderEvent;
pub use global::{
    flight_recorder_count, get_flight_recorder_buffer, init_flight_recorder, read_flight_recorder,
    set_flight_recorder_sink, write_flight_recorder,
};
pub use layer::FlightRecorderLayer;
pub use sink::{FlightRecorderSink, LocalBufferSink};
pub use suppress::without_flight_recorder;
pub use visitor::MessageVisitor;
