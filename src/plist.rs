//! A bounded plist (XML) reader/writer over `serde_json::Value`.
//!
//! The MDM protocol speaks Apple plist XML and nothing else, so
//! bosun needs exactly one plist codec. This one is deliberately
//! small and paranoid, in the estate's hand-rolled-parser style:
//!
//! - Input is bounded three ways before any structure is built:
//!   byte length, element depth, and total node count.
//! - `<!DOCTYPE` and every other `<!` construct are refused
//!   outright, so there is no DTD, no entity expansion, and no
//!   external entity to resolve. Only the five predefined XML
//!   entities and numeric character references are decoded.
//! - The value model is JSON: dict → object, array → array,
//!   string → string, integer → number (i64), real → number
//!   (finite f64 only), true/false → bool. Two plist types have
//!   no JSON twin and ride in a one-key wrapper object so the
//!   round trip is lossless: `<data>` as `{"$plist_data": "<b64>"}`
//!   and `<date>` as `{"$plist_date": "<iso8601>"}`. A genuine
//!   dict whose only key is one of those names would collide;
//!   MDM payloads do not use them, and the collision is recorded
//!   here rather than hidden.
//!
//! Serialization is deterministic: dict keys are sorted, so the
//! same value always renders the same bytes (the enrollment
//! profile is an artifact the Owner diffs and installs).

use serde_json::{Map, Value};

/// Hard bound on one plist document, in bytes.
pub const MAX_PLIST_BYTES: usize = 1024 * 1024;

/// Hard bound on element nesting depth.
pub const MAX_DEPTH: usize = 32;

/// Hard bound on total values in one document.
pub const MAX_NODES: usize = 10_000;

/// The wrapper key marking a `<data>` value in the JSON model.
pub const DATA_KEY: &str = "$plist_data";

/// The wrapper key marking a `<date>` value in the JSON model.
pub const DATE_KEY: &str = "$plist_date";

#[derive(Debug)]
pub struct PlistError {
    pub code: &'static str,
    pub message: String,
}

impl PlistError {
    fn new(code: &'static str, message: impl Into<String>) -> PlistError {
        PlistError {
            code,
            message: message.into(),
        }
    }
}

pub type PlistResult<T> = Result<T, PlistError>;

// ---------------------------------------------------------------------------
// Base64 (standard alphabet, padded). Plist `<data>` and the SCEP
// degenerate bundles both need it; a forty-line codec with test
// vectors beats a dependency for this one shape.
// ---------------------------------------------------------------------------

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(*chunk.get(1).unwrap_or(&0));
        let b2 = u32::from(*chunk.get(2).unwrap_or(&0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64_ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(B64_ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            B64_ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64_ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

pub fn base64_decode(text: &str) -> PlistResult<Vec<u8>> {
    fn value_of(byte: u8) -> Option<u32> {
        match byte {
            b'A'..=b'Z' => Some(u32::from(byte - b'A')),
            b'a'..=b'z' => Some(u32::from(byte - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(byte - b'0') + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let clean: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if !clean.len().is_multiple_of(4) {
        return Err(PlistError::new(
            "plist_data_invalid",
            "base64 length is not a multiple of 4",
        ));
    }
    let mut out = Vec::with_capacity(clean.len() / 4 * 3);
    for chunk in clean.chunks(4) {
        let pad = chunk.iter().filter(|&&b| b == b'=').count();
        if pad > 2 {
            return Err(PlistError::new("plist_data_invalid", "base64 over-padded"));
        }
        let mut n: u32 = 0;
        for (i, &b) in chunk.iter().enumerate() {
            let v = if b == b'=' {
                0
            } else {
                value_of(b).ok_or_else(|| {
                    PlistError::new("plist_data_invalid", format!("bad base64 byte {b:#x}"))
                })?
            };
            n |= v << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    Ok(out)
}

/// Lowercase hex, for APNs device tokens (which arrive as plist
/// `<data>` and are spoken to APNs as hex).
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit(u32::from(b >> 4), 16).expect("nibble"));
        out.push(char::from_digit(u32::from(b & 0xf), 16).expect("nibble"));
    }
    out
}

// ---------------------------------------------------------------------------
// Parsing. A small recursive-descent scanner over the XML text;
// recursion depth is capped by MAX_DEPTH before it can grow.
// ---------------------------------------------------------------------------

struct Scanner<'a> {
    bytes: &'a [u8],
    pos: usize,
    nodes: usize,
}

impl<'a> Scanner<'a> {
    fn error(&self, message: impl Into<String>) -> PlistError {
        PlistError::new(
            "plist_parse_failed",
            format!("at byte {}: {}", self.pos, message.into()),
        )
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn starts_with(&self, pat: &str) -> bool {
        self.bytes[self.pos..].starts_with(pat.as_bytes())
    }

    fn bump(&mut self) {
        self.pos += 1;
    }

    fn skip_misc(&mut self) -> PlistResult<()> {
        // Whitespace, the XML declaration, and comments may appear
        // between elements. DOCTYPE and friends may not, ever.
        loop {
            while self.peek().is_some_and(|b| b.is_ascii_whitespace()) {
                self.bump();
            }
            if self.starts_with("<?") {
                let end = find_subslice(&self.bytes[self.pos..], "?>")
                    .ok_or_else(|| self.error("unterminated processing instruction"))?;
                self.pos += end + 2;
                continue;
            }
            if self.starts_with("<!--") {
                let end = find_subslice(&self.bytes[self.pos..], "-->")
                    .ok_or_else(|| self.error("unterminated comment"))?;
                self.pos += end + 3;
                continue;
            }
            if self.starts_with("<!") {
                return Err(
                    self.error("markup declarations (DOCTYPE/DTD) are refused in plist input")
                );
            }
            return Ok(());
        }
    }

    /// Read `<name ...>` or `<name .../>`; returns (name, self_closing).
    fn read_open_tag(&mut self) -> PlistResult<(String, bool)> {
        if self.peek() != Some(b'<') {
            return Err(self.error("expected '<'"));
        }
        self.bump();
        let start = self.pos;
        while self
            .peek()
            .is_some_and(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            self.bump();
        }
        if self.pos == start {
            return Err(self.error("empty tag name"));
        }
        let name = String::from_utf8_lossy(&self.bytes[start..self.pos]).into_owned();
        // Skip attributes (version="1.0" on <plist>) up to > or />.
        loop {
            match self.peek() {
                None => return Err(self.error("unterminated tag")),
                Some(b'>') => {
                    self.bump();
                    return Ok((name, false));
                }
                Some(b'/') => {
                    self.bump();
                    if self.peek() == Some(b'>') {
                        self.bump();
                        return Ok((name, true));
                    }
                    return Err(self.error("stray '/' in tag"));
                }
                Some(_) => self.bump(),
            }
        }
    }

    fn read_close_tag(&mut self, want: &str) -> PlistResult<()> {
        if !self.starts_with("</") {
            return Err(self.error(format!("expected </{want}>")));
        }
        self.pos += 2;
        let start = self.pos;
        while self.peek().is_some_and(|b| b != b'>') {
            self.bump();
        }
        if self.peek().is_none() {
            return Err(self.error("unterminated close tag"));
        }
        let name = String::from_utf8_lossy(&self.bytes[start..self.pos])
            .trim()
            .to_string();
        self.bump();
        if name != want {
            return Err(self.error(format!("mismatched close tag </{name}> for <{want}>")));
        }
        Ok(())
    }

    /// Raw character data up to the next '<', entity-decoded.
    fn read_text(&mut self) -> PlistResult<String> {
        let start = self.pos;
        while self.peek().is_some_and(|b| b != b'<') {
            self.bump();
        }
        let raw = &self.bytes[start..self.pos];
        decode_entities(raw).map_err(|e| self.error(e))
    }

    fn count_node(&mut self) -> PlistResult<()> {
        self.nodes += 1;
        if self.nodes > MAX_NODES {
            return Err(PlistError::new(
                "plist_too_large",
                format!("document exceeds {MAX_NODES} values"),
            ));
        }
        Ok(())
    }

    fn parse_value(&mut self, depth: usize) -> PlistResult<Value> {
        if depth > MAX_DEPTH {
            return Err(PlistError::new(
                "plist_too_deep",
                format!("nesting exceeds {MAX_DEPTH} levels"),
            ));
        }
        self.count_node()?;
        self.skip_misc()?;
        let (name, self_closing) = self.read_open_tag()?;
        match name.as_str() {
            "dict" => {
                let mut map = Map::new();
                if !self_closing {
                    loop {
                        self.skip_misc()?;
                        if self.starts_with("</") {
                            break;
                        }
                        let (key_tag, key_empty) = self.read_open_tag()?;
                        if key_tag != "key" {
                            return Err(self.error(format!("dict child <{key_tag}> is not <key>")));
                        }
                        let key = if key_empty {
                            String::new()
                        } else {
                            let text = self.read_text()?;
                            self.read_close_tag("key")?;
                            text
                        };
                        let value = self.parse_value(depth + 1)?;
                        if map.insert(key.clone(), value).is_some() {
                            return Err(self.error(format!("duplicate dict key {key:?}")));
                        }
                    }
                    self.read_close_tag("dict")?;
                }
                Ok(Value::Object(map))
            }
            "array" => {
                let mut items = Vec::new();
                if !self_closing {
                    loop {
                        self.skip_misc()?;
                        if self.starts_with("</") {
                            break;
                        }
                        items.push(self.parse_value(depth + 1)?);
                    }
                    self.read_close_tag("array")?;
                }
                Ok(Value::Array(items))
            }
            "string" => Ok(Value::String(self.leaf_text("string", self_closing)?)),
            "integer" => {
                let text = self.leaf_text("integer", self_closing)?;
                let parsed: i64 = text
                    .trim()
                    .parse()
                    .map_err(|_| self.error(format!("bad integer {text:?}")))?;
                Ok(Value::Number(parsed.into()))
            }
            "real" => {
                let text = self.leaf_text("real", self_closing)?;
                let parsed: f64 = text
                    .trim()
                    .parse()
                    .map_err(|_| self.error(format!("bad real {text:?}")))?;
                if !parsed.is_finite() {
                    return Err(self.error("non-finite <real> is refused"));
                }
                serde_json::Number::from_f64(parsed)
                    .map(Value::Number)
                    .ok_or_else(|| self.error("real is not representable"))
            }
            "true" | "false" => {
                if !self_closing {
                    // Tolerate <true></true>; content must be empty.
                    let text = self.read_text()?;
                    if !text.trim().is_empty() {
                        return Err(self.error("boolean element carries text"));
                    }
                    self.read_close_tag(&name)?;
                }
                Ok(Value::Bool(name == "true"))
            }
            "data" => {
                let text = self.leaf_text("data", self_closing)?;
                // Validate eagerly; store the canonical encoding.
                let decoded = base64_decode(&text)?;
                let mut map = Map::new();
                map.insert(DATA_KEY.to_string(), Value::String(base64_encode(&decoded)));
                Ok(Value::Object(map))
            }
            "date" => {
                let text = self.leaf_text("date", self_closing)?;
                let mut map = Map::new();
                map.insert(DATE_KEY.to_string(), Value::String(text.trim().to_string()));
                Ok(Value::Object(map))
            }
            _ => Err(self.error(format!("unsupported plist element <{name}>"))),
        }
    }

    fn leaf_text(&mut self, tag: &str, self_closing: bool) -> PlistResult<String> {
        if self_closing {
            return Ok(String::new());
        }
        let text = self.read_text()?;
        self.read_close_tag(tag)?;
        Ok(text)
    }
}

fn find_subslice(haystack: &[u8], needle: &str) -> Option<usize> {
    let needle = needle.as_bytes();
    if needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn decode_entities(raw: &[u8]) -> Result<String, String> {
    let text = String::from_utf8_lossy(raw);
    if !text.contains('&') {
        return Ok(text.into_owned());
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text.as_ref();
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        let tail = &rest[at + 1..];
        let Some(end) = tail.find(';') else {
            return Err("unterminated entity reference".to_string());
        };
        let entity = &tail[..end];
        match entity {
            "amp" => out.push('&'),
            "lt" => out.push('<'),
            "gt" => out.push('>'),
            "quot" => out.push('"'),
            "apos" => out.push('\''),
            _ if entity.starts_with("#x") || entity.starts_with("#X") => {
                let code = u32::from_str_radix(&entity[2..], 16)
                    .map_err(|_| format!("bad character reference &{entity};"))?;
                out.push(char::from_u32(code).ok_or_else(|| "bad code point".to_string())?);
            }
            _ if entity.starts_with('#') => {
                let code = entity[1..]
                    .parse::<u32>()
                    .map_err(|_| format!("bad character reference &{entity};"))?;
                out.push(char::from_u32(code).ok_or_else(|| "bad code point".to_string())?);
            }
            _ => return Err(format!("unknown entity &{entity};")),
        }
        rest = &tail[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Parse one plist document. The root must be a single `<plist>`
/// element wrapping one value; trailing content is refused.
pub fn parse(bytes: &[u8]) -> PlistResult<Value> {
    if bytes.len() > MAX_PLIST_BYTES {
        return Err(PlistError::new(
            "plist_too_large",
            format!(
                "document is {} bytes; bound is {MAX_PLIST_BYTES}",
                bytes.len()
            ),
        ));
    }
    let mut scanner = Scanner {
        bytes,
        pos: 0,
        nodes: 0,
    };
    scanner.skip_misc()?;
    let (root, self_closing) = scanner.read_open_tag()?;
    if root != "plist" || self_closing {
        return Err(scanner.error("document root must be <plist>"));
    }
    let value = scanner.parse_value(0)?;
    scanner.skip_misc()?;
    scanner.read_close_tag("plist")?;
    scanner.skip_misc()?;
    if scanner.pos != scanner.bytes.len() {
        return Err(scanner.error("trailing content after </plist>"));
    }
    Ok(value)
}

/// The bytes of a `<data>` value in the JSON model, decoded.
pub fn data_bytes(value: &Value) -> Option<Vec<u8>> {
    let map = value.as_object()?;
    if map.len() != 1 {
        return None;
    }
    let encoded = map.get(DATA_KEY)?.as_str()?;
    base64_decode(encoded).ok()
}

/// Wrap raw bytes as a `<data>` value in the JSON model.
pub fn data_value(bytes: &[u8]) -> Value {
    let mut map = Map::new();
    map.insert(DATA_KEY.to_string(), Value::String(base64_encode(bytes)));
    Value::Object(map)
}

// ---------------------------------------------------------------------------
// Serialization. Deterministic: sorted dict keys, tab indent,
// the standard Apple header.
// ---------------------------------------------------------------------------

fn escape_text(text: &str, out: &mut String) {
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(ch),
        }
    }
}

fn write_value(value: &Value, depth: usize, out: &mut String) -> PlistResult<()> {
    if depth > MAX_DEPTH {
        return Err(PlistError::new("plist_too_deep", "value nesting too deep"));
    }
    let indent = "\t".repeat(depth);
    match value {
        Value::Object(map) => {
            if let Some(bytes) = data_bytes(value) {
                out.push_str(&indent);
                out.push_str("<data>");
                out.push_str(&base64_encode(&bytes));
                out.push_str("</data>\n");
                return Ok(());
            }
            if map.len() == 1
                && let Some(date) = map.get(DATE_KEY).and_then(Value::as_str)
            {
                out.push_str(&indent);
                out.push_str("<date>");
                escape_text(date, out);
                out.push_str("</date>\n");
                return Ok(());
            }
            if map.is_empty() {
                out.push_str(&indent);
                out.push_str("<dict/>\n");
                return Ok(());
            }
            out.push_str(&indent);
            out.push_str("<dict>\n");
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for key in keys {
                out.push_str(&indent);
                out.push_str("\t<key>");
                escape_text(key, out);
                out.push_str("</key>\n");
                write_value(&map[key], depth + 1, out)?;
            }
            out.push_str(&indent);
            out.push_str("</dict>\n");
            Ok(())
        }
        Value::Array(items) => {
            if items.is_empty() {
                out.push_str(&indent);
                out.push_str("<array/>\n");
                return Ok(());
            }
            out.push_str(&indent);
            out.push_str("<array>\n");
            for item in items {
                write_value(item, depth + 1, out)?;
            }
            out.push_str(&indent);
            out.push_str("</array>\n");
            Ok(())
        }
        Value::String(text) => {
            out.push_str(&indent);
            out.push_str("<string>");
            escape_text(text, out);
            out.push_str("</string>\n");
            Ok(())
        }
        Value::Bool(b) => {
            out.push_str(&indent);
            out.push_str(if *b { "<true/>\n" } else { "<false/>\n" });
            Ok(())
        }
        Value::Number(n) => {
            out.push_str(&indent);
            if let Some(i) = n.as_i64() {
                out.push_str(&format!("<integer>{i}</integer>\n"));
            } else if let Some(u) = n.as_u64() {
                out.push_str(&format!("<integer>{u}</integer>\n"));
            } else if let Some(f) = n.as_f64() {
                if !f.is_finite() {
                    return Err(PlistError::new("plist_unrepresentable", "non-finite real"));
                }
                let mut rendered = format!("{f}");
                if !rendered.contains(['.', 'e', 'E']) {
                    rendered.push_str(".0");
                }
                out.push_str(&format!("<real>{rendered}</real>\n"));
            } else {
                return Err(PlistError::new("plist_unrepresentable", "number shape"));
            }
            Ok(())
        }
        Value::Null => Err(PlistError::new(
            "plist_unrepresentable",
            "plist has no null value",
        )),
    }
}

/// Serialize a value as a complete plist document.
pub fn to_string(value: &Value) -> PlistResult<String> {
    let mut out = String::with_capacity(1024);
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str("<plist version=\"1.0\">\n");
    write_value(value, 0, &mut out)?;
    out.push_str("</plist>\n");
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SAMPLE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>MessageType</key>
	<string>TokenUpdate</string>
	<key>PushMagic</key>
	<string>magic&amp;&lt;1&gt;</string>
	<key>Token</key>
	<data>aGVsbG8=</data>
	<key>Queries</key>
	<array>
		<string>DeviceName</string>
		<integer>42</integer>
		<real>2.5</real>
		<true/>
	</array>
</dict>
</plist>
"#;

    #[test]
    fn parses_an_mdm_shaped_document() {
        let value = parse(SAMPLE.as_bytes()).expect("parse");
        assert_eq!(value["MessageType"], "TokenUpdate");
        assert_eq!(value["PushMagic"], "magic&<1>");
        assert_eq!(data_bytes(&value["Token"]), Some(b"hello".to_vec()));
        assert_eq!(value["Queries"][0], "DeviceName");
        assert_eq!(value["Queries"][1], 42);
        assert_eq!(value["Queries"][2], 2.5);
        assert_eq!(value["Queries"][3], true);
    }

    #[test]
    fn round_trips_through_the_serializer() {
        let value = json!({
            "UDID": "00008030-ABC",
            "Token": data_value(&[0xde, 0xad, 0xbe, 0xef]),
            "Nested": {"List": [1, 2.5, "x", false], "Empty": {}},
        });
        let text = to_string(&value).expect("serialize");
        let back = parse(text.as_bytes()).expect("reparse");
        assert_eq!(back, value);
        // Deterministic: serializing twice is byte-identical.
        assert_eq!(to_string(&back).expect("again"), text);
    }

    #[test]
    fn base64_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"hello"), "aGVsbG8=");
        assert_eq!(base64_decode("aGVs bG8=\n").expect("ws ok"), b"hello");
        assert!(base64_decode("aGVsbG8").is_err());
        assert!(base64_decode("aGV!").is_err());
        assert_eq!(hex_encode(&[0x00, 0xff, 0x1a]), "00ff1a");
    }

    #[test]
    fn doctype_and_entities_are_refused() {
        // Adversarial: a DTD must never be honoured, and an
        // unknown entity must not decode to anything.
        let dtd = "<?xml version=\"1.0\"?><!DOCTYPE plist [<!ENTITY x \"y\">]><plist version=\"1.0\"><string>&x;</string></plist>";
        assert_eq!(
            parse(dtd.as_bytes()).expect_err("dtd").code,
            "plist_parse_failed"
        );
        let entity = "<plist version=\"1.0\"><string>&xxe;</string></plist>";
        assert!(parse(entity.as_bytes()).is_err());
    }

    #[test]
    fn bounds_are_enforced() {
        // Adversarial: nesting bomb and oversized input refuse
        // before structure is built.
        let mut deep = String::from("<plist version=\"1.0\">");
        for _ in 0..(MAX_DEPTH + 4) {
            deep.push_str("<array>");
        }
        assert_eq!(
            parse(deep.as_bytes()).expect_err("deep").code,
            "plist_too_deep"
        );
        let big = vec![b' '; MAX_PLIST_BYTES + 1];
        assert_eq!(parse(&big).expect_err("big").code, "plist_too_large");
        let mismatched = "<plist version=\"1.0\"><dict><key>a</key><string>1</dict></plist>";
        assert!(parse(mismatched.as_bytes()).is_err());
        let trailing = "<plist version=\"1.0\"><string>x</string></plist><plist/>";
        assert!(parse(trailing.as_bytes()).is_err());
    }

    #[test]
    fn duplicate_keys_and_bad_numbers_refuse() {
        let dup = "<plist version=\"1.0\"><dict><key>a</key><integer>1</integer><key>a</key><integer>2</integer></dict></plist>";
        assert!(parse(dup.as_bytes()).is_err());
        let nan = "<plist version=\"1.0\"><real>nan</real></plist>";
        assert!(parse(nan.as_bytes()).is_err());
        let huge = "<plist version=\"1.0\"><integer>99999999999999999999</integer></plist>";
        assert!(parse(huge.as_bytes()).is_err());
    }
}
