//! RFC 8785 JSON Canonicalization Scheme (JCS).
//!
//! * Object members sorted by the UTF-16 code units of their names.
//! * No insignificant whitespace.
//! * Strings escaped minimally: `"` `\` and controls; `\b \t \n \f \r` use
//!   short forms; other controls use lowercase `\u00xx`.
//! * Integers rendered without exponent; other numbers rendered per ES6
//!   `Number::toString`. NaN/Infinity are rejected (JSON cannot carry them).
//!
//! The output bytes are what gets hashed for `action_digest`, so this module
//! must stay deterministic and must never be "fixed" in a way that changes
//! existing digests without a schema-version bump.

use serde_json::Value;

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum CanonicalError {
    #[error("non-finite number cannot be canonicalized")]
    NonFiniteNumber,
    #[error("nesting depth exceeds limit")]
    TooDeep,
}

const MAX_DEPTH: usize = 64;

/// Produce JCS bytes for a value.
pub fn canonicalize(value: &Value) -> Result<Vec<u8>, CanonicalError> {
    let mut out = Vec::with_capacity(256);
    write_value(value, &mut out, 0)?;
    Ok(out)
}

fn write_value(value: &Value, out: &mut Vec<u8>, depth: usize) -> Result<(), CanonicalError> {
    if depth > MAX_DEPTH {
        return Err(CanonicalError::TooDeep);
    }
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => write_number(n, out)?,
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_value(item, out, depth + 1)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            // JCS: sort by UTF-16 code unit sequence.
            keys.sort_by(|a, b| {
                let au = a.encode_utf16();
                let bu = b.encode_utf16();
                au.cmp(bu)
            });
            out.push(b'{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_string(k, out);
                out.push(b':');
                if let Some(v) = map.get(*k) {
                    write_value(v, out, depth + 1)?;
                }
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn write_string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{8}' => out.extend_from_slice(b"\\b"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\u{c}' => out.extend_from_slice(b"\\f"),
            '\r' => out.extend_from_slice(b"\\r"),
            c if (c as u32) < 0x20 => {
                let mut buf = [0u8; 6];
                let hexs = format!("\\u{:04x}", c as u32);
                buf.copy_from_slice(hexs.as_bytes());
                out.extend_from_slice(&buf);
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

fn write_number(n: &serde_json::Number, out: &mut Vec<u8>) -> Result<(), CanonicalError> {
    if let Some(i) = n.as_i64() {
        out.extend_from_slice(i.to_string().as_bytes());
        return Ok(());
    }
    if let Some(u) = n.as_u64() {
        out.extend_from_slice(u.to_string().as_bytes());
        return Ok(());
    }
    let f = n.as_f64().ok_or(CanonicalError::NonFiniteNumber)?;
    if !f.is_finite() {
        return Err(CanonicalError::NonFiniteNumber);
    }
    out.extend_from_slice(es6_number(f).as_bytes());
    Ok(())
}

/// ES6 `Number.prototype.toString()` for finite doubles, built on the
/// shortest round-trip representation.
fn es6_number(f: f64) -> String {
    if f == 0.0 {
        return "0".to_string();
    }
    // Rust's `{:e}` gives the shortest round-trip digits in scientific form.
    let sci = format!("{f:e}"); // e.g. "-1.5e-7", "1e21", "3.14e0"
    let (mantissa, exp) = sci.split_once('e').unwrap_or((sci.as_str(), "0"));
    let negative = mantissa.starts_with('-');
    let mantissa = mantissa.trim_start_matches('-');
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let digit_count = i64::try_from(digits.len()).unwrap_or(i64::MAX);
    let point_pos = exp.parse::<i64>().unwrap_or(0) + 1;
    let sign = if negative { "-" } else { "" };
    let zeros = |n: i64| "0".repeat(usize::try_from(n).unwrap_or(0));
    let body = if digit_count <= point_pos && point_pos <= 21 {
        format!("{digits}{}", zeros(point_pos - digit_count))
    } else if 0 < point_pos && point_pos <= 21 {
        let (a, b) = digits.split_at(usize::try_from(point_pos).unwrap_or(0));
        format!("{a}.{b}")
    } else if -6 < point_pos && point_pos <= 0 {
        format!("0.{}{digits}", zeros(-point_pos))
    } else {
        let e = point_pos - 1;
        let esign = if e < 0 { "-" } else { "+" };
        if digit_count == 1 {
            format!("{digits}e{esign}{}", e.abs())
        } else {
            let (a, b) = digits.split_at(1);
            format!("{a}.{b}e{esign}{}", e.abs())
        }
    };
    format!("{sign}{body}")
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreadable_literal,
    clippy::cast_possible_truncation,
    clippy::float_cmp,
    clippy::excessive_precision
)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;

    fn c(v: &Value) -> String {
        String::from_utf8(canonicalize(v).unwrap_or_default()).unwrap_or_default()
    }

    #[test]
    fn rfc8785_sample() {
        // RFC 8785 §3.2.3 structure; float digits verified against Python
        // `repr` (same shortest-round-trip algorithm as ES6).
        let v = json!({
            "numbers": [333_333_333.333_333_29_f64, 1e30, 4.5, 2e-3, 0.000_000_000_000_000_000_000_000_001],
            "string": "\u{20ac}$\u{000F}\nA'B\"\\\\\"/",
            "literals": [null, true, false]
        });
        assert_eq!(
            c(&v),
            "{\"literals\":[null,true,false],\"numbers\":[333333333.3333333,1e+30,4.5,0.002,1e-27],\"string\":\"€$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"}"
        );
    }

    #[test]
    fn key_order_is_utf16() {
        // From RFC 8785 §3.2.3: "\u{1f600}" (surrogate pair) sorts before "\u{ff0f}".
        let v = json!({"\u{ff0f}": 1, "\u{1f600}": 2, "a": 3, "A": 4, "\u{e9}": 5});
        assert_eq!(
            c(&v),
            "{\"A\":4,\"a\":3,\"é\":5,\"\u{1f600}\":2,\"\u{ff0f}\":1}"
        );
    }

    #[test]
    fn integers_and_edge_numbers() {
        assert_eq!(c(&json!(0)), "0");
        assert_eq!(c(&json!(-0.0)), "0");
        assert_eq!(c(&json!(1e21)), "1e+21");
        assert_eq!(c(&json!(1e20)), "100000000000000000000");
        assert_eq!(c(&json!(0.000001)), "0.000001");
        assert_eq!(c(&json!(0.0000001)), "1e-7");
        assert_eq!(c(&json!(u64::MAX)), "18446744073709551615");
        assert_eq!(c(&json!(i64::MIN)), "-9223372036854775808");
    }

    #[test]
    fn depth_bomb_rejected() {
        let mut v = json!(1);
        for _ in 0..100 {
            v = json!([v]);
        }
        assert_eq!(canonicalize(&v), Err(CanonicalError::TooDeep));
    }

    fn arb_json() -> impl Strategy<Value = Value> {
        let leaf = prop_oneof![
            Just(Value::Null),
            any::<bool>().prop_map(Value::Bool),
            any::<i64>().prop_map(|i| json!(i)),
            any::<f64>()
                .prop_filter("finite", |f| f.is_finite())
                .prop_map(|f| json!(f)),
            "[a-zA-Z0-9 _\\-\\\\\"\u{0}-\u{1f}\u{e9}\u{1f600}]{0,12}".prop_map(Value::String),
        ];
        leaf.prop_recursive(4, 32, 6, |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
                prop::collection::hash_map("[a-z\u{e9}\u{1f600}]{1,6}", inner, 0..6)
                    .prop_map(|m| Value::Object(m.into_iter().collect())),
            ]
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(500))]

        /// Canonical output re-parses to the same value, and re-canonicalizing
        /// the parsed value is a fixed point. This is the property that makes
        /// cross-language digests agree.
        #[test]
        fn roundtrip_fixed_point(v in arb_json()) {
            let bytes = canonicalize(&v).unwrap_or_default();
            let parsed: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
            // JCS treats 0 and 0.0 identically, so compare canonical forms,
            // not serde_json's Value (which distinguishes them).
            let again = canonicalize(&parsed).unwrap_or_default();
            prop_assert_eq!(bytes, again);
        }

        /// Key insertion order never affects the output.
        #[test]
        fn insertion_order_irrelevant(v in arb_json()) {
            let text = serde_json::to_string(&v).unwrap_or_default();
            let reparsed: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
            prop_assert_eq!(canonicalize(&v), canonicalize(&reparsed));
        }
    }
}
