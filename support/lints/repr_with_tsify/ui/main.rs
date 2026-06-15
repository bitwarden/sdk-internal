use serde_repr::{Deserialize_repr, Serialize_repr};
use tsify::Tsify;

// ---- should warn ----

#[derive(Serialize_repr, Deserialize_repr, Tsify)]
#[repr(u8)]
pub enum BadEnum {
    A = 0,
    B = 1,
}

#[derive(Deserialize_repr, Tsify)]
#[repr(u8)]
pub enum BadEnumDeOnly {
    X = 0,
}

#[derive(Serialize_repr, Deserialize_repr, tsify::Tsify)]
#[repr(u8)]
pub enum BadEnumQualified {
    A = 0,
}

#[derive(Serialize_repr, Deserialize_repr)]
#[derive(Tsify)]
#[repr(u8)]
pub enum BadEnumSplit {
    A = 0,
}

// ---- should NOT warn ----

#[derive(Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum OkRepr {
    A = 0,
}

#[derive(Tsify)]
pub struct OkTsify {
    pub n: u32,
}

fn main() {}
