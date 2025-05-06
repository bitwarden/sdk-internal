use base64::{
    alphabet,
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
};

const INDIFFERENT: GeneralPurposeConfig =
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent);

/// A [GeneralPurpose] engine using the [alphabet::STANDARD] base64 alphabet with or without valid
/// padding.
pub const STANDARD_INDIFFERENT: GeneralPurpose =
    GeneralPurpose::new(&alphabet::STANDARD, INDIFFERENT);
