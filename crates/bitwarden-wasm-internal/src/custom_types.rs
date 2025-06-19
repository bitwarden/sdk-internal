/// This file contains custom TypeScript for types defined by external crates.
/// Everything in the string below is appended to the generated TypeScript definition file.
#[wasm_bindgen::prelude::wasm_bindgen(typescript_custom_section)]
const TS_CUSTOM_TYPES: &'static str = r#"

import { Tagged } from "type-fest";

/**
 * A string that **MUST** be a valid UUID.
 *
 * Never create or cast to this type directly, use the `uuid<T>()` function instead.
 */
export type Uuid = unknown;

/**
 * RFC3339 compliant date-time string.
 * @typeParam T - Not used in JavaScript.
 */
export type DateTime<T = unknown> = string;

/**
 * UTC date-time string. Not used in JavaScript.
 */
export type Utc = unknown;

/**
 * An integer that is known not to equal zero.
 */
export type NonZeroU32 = number;
"#;
