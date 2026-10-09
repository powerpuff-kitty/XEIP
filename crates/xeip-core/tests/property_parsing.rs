//! Deterministic property/round-trip tests for the transport-neutral core.
//!
//! Everything is driven by a tiny inline xorshift PRNG with a fixed seed so
//! failures are reproducible and no external dependency is required. Inputs are
//! derived from the shared conformance fixtures, then checked through the crate's
//! existing public deserialization and `validate` entry points only.

use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value};
use xeip_core::{Capability, Entity, Envelope, Session};

const ENTITY_FIXTURE: &str = include_str!("../../../conformance/fixtures/entity.valid.json");
const MESSAGE_FIXTURE: &str = include_str!("../../../conformance/fixtures/message.valid.json");
const SESSION_FIXTURE: &str = include_str!("../../../conformance/fixtures/session.valid.json");
const CAPABILITY_FIXTURE: &str =
    include_str!("../../../conformance/fixtures/capability.valid.json");

// A deliberately tiny xorshift64* generator. Fixed seed makes every run identical.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        // xorshift must never start from zero.
        Self(seed | 1)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next_u64() % bound
    }

    fn index(&mut self, len: usize) -> usize {
        self.below(len as u64) as usize
    }

    fn bool(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }

    fn pick<'a>(&mut self, items: &'a [&'a str]) -> &'a str {
        items[self.index(items.len())]
    }
}

fn parse_fixture(source: &str) -> Value {
    serde_json::from_str(source).expect("compile-time fixture is valid JSON")
}

fn random_valid_uri(rng: &mut Rng) -> String {
    let n = rng.below(1000);
    match rng.below(5) {
        0 => format!("urn:xeip:entity:e{n}"),
        1 => format!("urn:xeip:session:s{n}"),
        2 => format!("urn:uuid:{n}"),
        3 => format!("https://example.org/path/{n}"),
        _ => format!("http://127.0.0.1:8787/events/{n}"),
    }
}

fn random_valid_capability_id(rng: &mut Rng) -> String {
    let n = rng.below(1000);
    match rng.below(5) {
        0 => format!("cap{n}"),
        1 => format!("svc.part{n}"),
        2 => format!("a-b.c{n}"),
        3 => format!("x{n}.y.z"),
        _ => format!("camera.snapshot{n}"),
    }
}

fn random_valid_transport(rng: &mut Rng) -> &'static str {
    const TRANSPORTS: &[&str] = &[
        "http-sse",
        "http",
        "websocket",
        "local",
        "webrtc",
        "a2a",
        "mcp",
    ];
    TRANSPORTS[rng.index(TRANSPORTS.len())]
}

fn random_valid_timestamp(rng: &mut Rng) -> String {
    let year = 2000 + rng.below(100);
    let month = 1 + rng.below(12);
    let day = 1 + rng.below(28);
    let hour = rng.below(24);
    let minute = rng.below(60);
    let second = rng.below(60);
    if rng.bool() {
        let millis = rng.below(1000);
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
    } else {
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
    }
}

fn random_data(rng: &mut Rng) -> Value {
    match rng.below(6) {
        0 => Value::Null,
        1 => Value::Bool(rng.bool()),
        2 => json!(rng.next_u64() as i64),
        3 => json!(random_text(rng)),
        4 => json!({"nested": [1, 2, 3]}),
        _ => json!({"ok": true}),
    }
}

fn random_text(rng: &mut Rng) -> String {
    const ALPHABET: &[char] = &[
        'a',
        'Z',
        '0',
        '-',
        '.',
        ':',
        '/',
        ' ',
        '\n',
        '%',
        '[',
        ']',
        '\u{1F600}',
    ];
    let len = rng.below(8) as usize;
    let mut text = String::new();
    for _ in 0..len {
        text.push(ALPHABET[rng.index(ALPHABET.len())]);
    }
    text
}

// ---------------------------------------------------------------------------
// Valid-value generators: start from the fixture shape and mutate fields.
// ---------------------------------------------------------------------------

fn random_valid_entity(rng: &mut Rng) -> Value {
    let mut value = parse_fixture(ENTITY_FIXTURE);
    let Some(obj) = value.as_object_mut() else {
        unreachable!("fixture is an object");
    };
    obj.insert("xeip".into(), json!("0.1"));
    obj.insert("id".into(), json!(random_valid_uri(rng)));
    if rng.bool() {
        obj.insert("name".into(), json!(format!("Entity {}", rng.below(1000))));
    } else {
        obj.remove("name");
    }

    let pool = ["human", "agent", "machine", "service"];
    let mut kinds: Vec<&str> = Vec::new();
    for kind in pool {
        if rng.bool() {
            kinds.push(kind);
        }
    }
    if kinds.is_empty() {
        kinds.push(pool[rng.index(pool.len())]);
    }
    obj.insert("kinds".into(), json!(kinds));

    let mut endpoints = Vec::new();
    for _ in 0..rng.below(3) {
        endpoints.push(json!({
            "transport": random_valid_transport(rng),
            "url": random_valid_uri(rng),
        }));
    }
    obj.insert("endpoints".into(), json!(endpoints));

    let mut capabilities = Vec::new();
    for i in 0..rng.below(3) {
        let mut capability = json!({ "id": random_valid_capability_id(rng) });
        if rng.bool() {
            capability["description"] = json!(format!("capability {i}"));
        }
        if rng.bool() {
            capability["spec"] = json!("https://example.org/spec");
        }
        capabilities.push(capability);
    }
    obj.insert("capabilities".into(), json!(capabilities));
    value
}

fn random_valid_envelope(rng: &mut Rng) -> Value {
    let mut value = parse_fixture(MESSAGE_FIXTURE);
    let Some(obj) = value.as_object_mut() else {
        unreachable!("fixture is an object");
    };
    const KINDS: &[&str] = &["message", "event", "command", "receipt"];
    const CONTENT_TYPES: &[&str] = &[
        "text/plain",
        "application/json",
        "application/x-xeip+json",
        " ",
    ];

    obj.insert("xeip".into(), json!("0.1"));
    obj.insert("id".into(), json!(random_valid_uri(rng)));
    obj.insert("kind".into(), json!(KINDS[rng.index(KINDS.len())]));
    obj.insert("sender".into(), json!(random_valid_uri(rng)));
    if rng.bool() {
        obj.insert("recipient".into(), json!(random_valid_uri(rng)));
    } else {
        obj.remove("recipient");
    }
    obj.insert("session".into(), json!(random_valid_uri(rng)));
    obj.insert("timestamp".into(), json!(random_valid_timestamp(rng)));
    obj.insert(
        "body".into(),
        json!({
            "contentType": CONTENT_TYPES[rng.index(CONTENT_TYPES.len())],
            "data": random_data(rng),
        }),
    );
    if rng.bool() {
        obj.insert("replyTo".into(), json!(random_valid_uri(rng)));
    } else {
        obj.remove("replyTo");
    }
    if rng.bool() {
        obj.insert("expiresAt".into(), json!(random_valid_timestamp(rng)));
    } else {
        obj.remove("expiresAt");
    }
    value
}

fn random_valid_session(rng: &mut Rng) -> Value {
    let mut value = parse_fixture(SESSION_FIXTURE);
    let Some(obj) = value.as_object_mut() else {
        unreachable!("fixture is an object");
    };
    obj.insert("xeip".into(), json!("0.1"));
    obj.insert("id".into(), json!(random_valid_uri(rng)));
    obj.insert(
        "mode".into(),
        json!(if rng.bool() { "direct" } else { "group" }),
    );
    obj.insert("createdAt".into(), json!(random_valid_timestamp(rng)));

    let mut members: Vec<String> = Vec::new();
    for _ in 0..rng.below(4) {
        let member = random_valid_uri(rng);
        if !members.contains(&member) {
            members.push(member);
        }
    }
    obj.insert("members".into(), json!(members));
    value
}

// ---------------------------------------------------------------------------
// Invalid-value generators: each mutation is guaranteed to be rejected.
// ---------------------------------------------------------------------------

const BAD_VERSIONS: &[&str] = &["0.2", "1.0", "", "0.1 ", "0.1.0", "v0.1"];
const BAD_URIS: &[&str] = &[
    "not-a-uri",
    " urn:xeip:x",
    "urn:xeip:bad id",
    "urn:xeip:bad%xy",
    "http://[bad]/",
    "urn:xeip:bad\\path",
    "",
    "://x",
    "urn:xeip:x\n",
];
const WHITESPACE: &[&str] = &[" ", "\t", "\n", "   "];
const BAD_TIMESTAMPS: &[&str] = &[
    "2026-02-30T12:00:00Z",
    "2100-02-29T12:00:00Z",
    "2026-13-01T12:00:00Z",
    "2026-01-01T24:00:00Z",
    "2026-01-01T12:00:60Z",
    "TZ",
    "2026-01-01T12:00:00+00:00",
    "2026-01-01 12:00:00Z",
    "2026-01-01T12:00:00z",
    "",
];
const BAD_CAPABILITY_IDS: &[&str] = &[
    "BAD ID",
    "Bad",
    "9start",
    "",
    "-lead",
    "trail.",
    "trail:",
    "double..dot",
    "sp ace",
    "xeip.message\n",
];

fn random_invalid_envelope(rng: &mut Rng) -> Value {
    let mut value = parse_fixture(MESSAGE_FIXTURE);
    match rng.below(9) {
        0 => value["xeip"] = json!(rng.pick(BAD_VERSIONS)),
        1 => {
            let field = rng.pick(&[
                "xeip",
                "id",
                "kind",
                "sender",
                "session",
                "timestamp",
                "body",
            ]);
            let _ = value.as_object_mut().map(|obj| obj.remove(field));
        }
        2 => {
            let key = format!("unknown{}", rng.below(1000));
            if let Some(obj) = value.as_object_mut() {
                obj.insert(key, Value::Bool(true));
            }
        }
        3 => {
            let field = rng.pick(&["id", "sender", "session"]);
            value[field] = json!(rng.pick(BAD_URIS));
        }
        4 => {
            let field = rng.pick(&["recipient", "replyTo", "expiresAt"]);
            value[field] = Value::Null;
        }
        5 => value["timestamp"] = json!(rng.pick(BAD_TIMESTAMPS)),
        6 => value["kind"] = json!([rng.pick(&["message", "event"])]),
        7 => value["body"] = json!("not-an-object"),
        _ => value["id"] = json!(rng.pick(WHITESPACE)),
    }
    value
}

fn random_invalid_entity(rng: &mut Rng) -> Value {
    let mut value = parse_fixture(ENTITY_FIXTURE);
    match rng.below(8) {
        0 => value["xeip"] = json!(rng.pick(BAD_VERSIONS)),
        1 => {
            let field = rng.pick(&["xeip", "id", "kinds"]);
            let _ = value.as_object_mut().map(|obj| obj.remove(field));
        }
        2 => {
            let key = format!("unknown{}", rng.below(1000));
            if let Some(obj) = value.as_object_mut() {
                obj.insert(key, Value::Bool(true));
            }
        }
        3 => value["id"] = json!(rng.pick(BAD_URIS)),
        4 => value["kinds"] = json!([]),
        5 => {
            let kind = rng.pick(&["human", "agent", "machine", "service"]);
            value["kinds"] = json!([kind, kind]);
        }
        6 => value["kinds"] = json!(["alien"]),
        _ => value["id"] = json!(rng.pick(WHITESPACE)),
    }
    value
}

fn random_invalid_session(rng: &mut Rng) -> Value {
    let mut value = parse_fixture(SESSION_FIXTURE);
    match rng.below(8) {
        0 => value["xeip"] = json!(rng.pick(BAD_VERSIONS)),
        1 => {
            let field = rng.pick(&["xeip", "id", "mode", "members", "createdAt"]);
            let _ = value.as_object_mut().map(|obj| obj.remove(field));
        }
        2 => {
            let key = format!("unknown{}", rng.below(1000));
            if let Some(obj) = value.as_object_mut() {
                obj.insert(key, Value::Bool(true));
            }
        }
        3 => value["id"] = json!(rng.pick(BAD_URIS)),
        4 => value["createdAt"] = json!(rng.pick(BAD_TIMESTAMPS)),
        5 => value["members"] = json!([rng.pick(BAD_URIS)]),
        6 => {
            let member = random_valid_uri(rng);
            value["members"] = json!([member, member]);
        }
        _ => value["id"] = json!(rng.pick(WHITESPACE)),
    }
    value
}

fn random_invalid_capability(rng: &mut Rng) -> Value {
    let mut value = parse_fixture(CAPABILITY_FIXTURE);
    match rng.below(5) {
        0 => {
            let _ = value.as_object_mut().map(|obj| obj.remove("id"));
        }
        1 => {
            let key = format!("unknown{}", rng.below(1000));
            if let Some(obj) = value.as_object_mut() {
                obj.insert(key, Value::Bool(true));
            }
        }
        2 => value["id"] = json!(rng.pick(BAD_CAPABILITY_IDS)),
        3 => value["spec"] = json!(rng.pick(BAD_URIS)),
        _ => value["description"] = json!("x".repeat(1025)),
    }
    value
}

// ---------------------------------------------------------------------------
// Public-API acceptance/rejection helpers.
// ---------------------------------------------------------------------------

fn reparse<T>(value: &Value) -> Result<(T, T), serde_json::Error>
where
    T: Serialize + DeserializeOwned,
{
    let first: T = serde_json::from_value(value.clone())?;
    let encoded = serde_json::to_string(&first)?;
    let second: T = serde_json::from_str(&encoded)?;
    Ok((first, second))
}

fn envelope_accepted(value: &Value) -> bool {
    serde_json::from_value::<Envelope>(value.clone()).is_ok_and(|v| v.validate().is_ok())
}

fn entity_accepted(value: &Value) -> bool {
    serde_json::from_value::<Entity>(value.clone()).is_ok_and(|v| v.validate().is_ok())
}

fn session_accepted(value: &Value) -> bool {
    serde_json::from_value::<Session>(value.clone()).is_ok_and(|v| v.validate().is_ok())
}

fn capability_accepted(value: &Value) -> bool {
    serde_json::from_value::<Capability>(value.clone()).is_ok_and(|v| v.validate().is_ok())
}

fn envelope_error_field(value: &Value) -> Option<&'static str> {
    match serde_json::from_value::<Envelope>(value.clone()) {
        Ok(v) => v.validate().err().map(|error| error.field),
        Err(_) => None,
    }
}

fn entity_error_field(value: &Value) -> Option<&'static str> {
    match serde_json::from_value::<Entity>(value.clone()) {
        Ok(v) => v.validate().err().map(|error| error.field),
        Err(_) => None,
    }
}

fn session_error_field(value: &Value) -> Option<&'static str> {
    match serde_json::from_value::<Session>(value.clone()) {
        Ok(v) => v.validate().err().map(|error| error.field),
        Err(_) => None,
    }
}

fn capability_error_field(value: &Value) -> Option<&'static str> {
    match serde_json::from_value::<Capability>(value.clone()) {
        Ok(v) => v.validate().err().map(|error| error.field),
        Err(_) => None,
    }
}

// ---------------------------------------------------------------------------
// Property tests.
// ---------------------------------------------------------------------------

#[test]
fn valid_envelopes_round_trip_and_preserve_fields() {
    let mut rng = Rng::new(0x1234_5678_9abc_def0);
    for i in 0..1000 {
        let raw = random_valid_envelope(&mut rng);
        assert!(
            envelope_accepted(&raw),
            "generated valid envelope {i} was rejected: {raw}"
        );
        match reparse::<Envelope>(&raw) {
            Ok((first, second)) => {
                assert_eq!(first, second, "envelope {i} did not round-trip");
                assert_eq!(first.xeip, raw["xeip"].as_str().expect("xeip is a string"));
                assert_eq!(
                    first.timestamp,
                    raw["timestamp"].as_str().expect("timestamp is a string")
                );
            }
            Err(error) => panic!("generated valid envelope {i} failed to parse: {error}"),
        }
    }
}

#[test]
fn valid_entities_round_trip_and_preserve_fields() {
    let mut rng = Rng::new(0x0fed_cba9_8765_4321);
    for i in 0..1000 {
        let raw = random_valid_entity(&mut rng);
        assert!(
            entity_accepted(&raw),
            "generated valid entity {i} was rejected: {raw}"
        );
        match reparse::<Entity>(&raw) {
            Ok((first, second)) => {
                assert_eq!(first, second, "entity {i} did not round-trip");
                assert_eq!(first.id, raw["id"].as_str().expect("id is a string"));
                assert!(!first.kinds.is_empty());
            }
            Err(error) => panic!("generated valid entity {i} failed to parse: {error}"),
        }
    }
}

#[test]
fn valid_sessions_round_trip_and_preserve_fields() {
    let mut rng = Rng::new(0xdead_beef_cafe_0001);
    for i in 0..1000 {
        let raw = random_valid_session(&mut rng);
        assert!(
            session_accepted(&raw),
            "generated valid session {i} was rejected: {raw}"
        );
        match reparse::<Session>(&raw) {
            Ok((first, second)) => {
                assert_eq!(first, second, "session {i} did not round-trip");
                assert_eq!(first.id, raw["id"].as_str().expect("id is a string"));
                assert_eq!(
                    first.created_at,
                    raw["createdAt"].as_str().expect("createdAt is a string")
                );
            }
            Err(error) => panic!("generated valid session {i} failed to parse: {error}"),
        }
    }
}

#[test]
fn invalid_envelopes_are_rejected() {
    let mut rng = Rng::new(0x0000_1111_2222_3333);
    for i in 0..600 {
        let raw = random_invalid_envelope(&mut rng);
        assert!(
            !envelope_accepted(&raw),
            "invalid envelope {i} was accepted: {raw}"
        );
    }
}

#[test]
fn invalid_entities_are_rejected() {
    let mut rng = Rng::new(0x0000_4444_5555_6666);
    for i in 0..600 {
        let raw = random_invalid_entity(&mut rng);
        assert!(
            !entity_accepted(&raw),
            "invalid entity {i} was accepted: {raw}"
        );
    }
}

#[test]
fn invalid_sessions_are_rejected() {
    let mut rng = Rng::new(0x0000_7777_8888_9999);
    for i in 0..600 {
        let raw = random_invalid_session(&mut rng);
        assert!(
            !session_accepted(&raw),
            "invalid session {i} was accepted: {raw}"
        );
    }
}

#[test]
fn invalid_capabilities_are_rejected() {
    let mut rng = Rng::new(0x0000_aaaa_bbbb_cccc);
    for i in 0..600 {
        let raw = random_invalid_capability(&mut rng);
        assert!(
            !capability_accepted(&raw),
            "invalid capability {i} was accepted: {raw}"
        );
    }
}

#[test]
fn deterministic_validation_reports_expected_field() {
    let mut envelope = parse_fixture(MESSAGE_FIXTURE);
    envelope["xeip"] = json!("9.9");
    assert_eq!(envelope_error_field(&envelope), Some("xeip"));

    envelope = parse_fixture(MESSAGE_FIXTURE);
    envelope["sender"] = json!("not-a-uri");
    assert_eq!(envelope_error_field(&envelope), Some("sender"));

    envelope = parse_fixture(MESSAGE_FIXTURE);
    envelope["timestamp"] = json!("2026-02-30T12:00:00Z");
    assert_eq!(envelope_error_field(&envelope), Some("timestamp"));

    let mut entity = parse_fixture(ENTITY_FIXTURE);
    entity["kinds"] = json!([]);
    assert_eq!(entity_error_field(&entity), Some("kinds"));

    entity = parse_fixture(ENTITY_FIXTURE);
    entity["kinds"] = json!(["human", "human"]);
    assert_eq!(entity_error_field(&entity), Some("kinds"));

    entity = parse_fixture(ENTITY_FIXTURE);
    entity["id"] = json!(" ");
    assert_eq!(entity_error_field(&entity), Some("id"));

    entity = parse_fixture(ENTITY_FIXTURE);
    entity["endpoints"] = json!([{ "transport": "unknown", "url": "urn:xeip:test" }]);
    assert_eq!(entity_error_field(&entity), Some("endpoints.transport"));

    let mut session = parse_fixture(SESSION_FIXTURE);
    session["members"] = json!(["urn:xeip:entity:test", "urn:xeip:entity:test"]);
    assert_eq!(session_error_field(&session), Some("members"));

    session = parse_fixture(SESSION_FIXTURE);
    session["createdAt"] = json!("2026-01-01T12:00:00z");
    assert_eq!(session_error_field(&session), Some("createdAt"));

    let mut capability = parse_fixture(CAPABILITY_FIXTURE);
    capability["id"] = json!("BAD ID");
    assert_eq!(capability_error_field(&capability), Some("capabilities.id"));

    capability = parse_fixture(CAPABILITY_FIXTURE);
    capability["spec"] = json!("not-uri");
    assert_eq!(
        capability_error_field(&capability),
        Some("capabilities.spec")
    );
}

fn random_json(rng: &mut Rng, depth: u32) -> Value {
    let choices = if depth < 2 { 7 } else { 4 };
    match rng.below(choices) {
        0 => Value::Null,
        1 => Value::Bool(rng.bool()),
        2 => json!(rng.next_u64() as i64),
        3 => json!(random_text(rng)),
        4 => {
            let count = rng.below(4);
            let mut items = Vec::new();
            for _ in 0..count {
                items.push(random_json(rng, depth + 1));
            }
            Value::Array(items)
        }
        _ => {
            let count = rng.below(4);
            let mut map = serde_json::Map::new();
            for _ in 0..count {
                map.insert(random_text(rng), random_json(rng, depth + 1));
            }
            Value::Object(map)
        }
    }
}

#[test]
fn arbitrary_json_never_panics() {
    let mut rng = Rng::new(0x5eed_5eed_5eed_5eed);
    for i in 0..2000 {
        let value = random_json(&mut rng, 0);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = serde_json::from_value::<Envelope>(value.clone());
            let _ = serde_json::from_value::<Entity>(value.clone());
            let _ = serde_json::from_value::<Session>(value.clone());
            let _ = serde_json::from_value::<Capability>(value.clone());
            if let Ok(envelope) = serde_json::from_value::<Envelope>(value.clone()) {
                let _ = envelope.validate();
            }
            if let Ok(entity) = serde_json::from_value::<Entity>(value.clone()) {
                let _ = entity.validate();
            }
            if let Ok(session) = serde_json::from_value::<Session>(value.clone()) {
                let _ = session.validate();
            }
            if let Ok(capability) = serde_json::from_value::<Capability>(value.clone()) {
                let _ = capability.validate();
            }
        }));
        assert!(
            outcome.is_ok(),
            "core panicked on arbitrary input {i}: {value}"
        );
    }

    for _ in 0..1000 {
        let text = random_text(&mut rng);
        let _ = serde_json::from_str::<Envelope>(&text);
        let _ = serde_json::from_str::<Entity>(&text);
        let _ = serde_json::from_str::<Session>(&text);
        let _ = serde_json::from_str::<Capability>(&text);
    }
}
