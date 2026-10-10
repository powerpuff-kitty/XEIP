//! Experimental transport-neutral XEIP 0.1 models.
//! Data received from a peer is untrusted until independently authenticated and authorized.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt;

pub const PROTOCOL_VERSION: &str = "0.1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    pub field: &'static str,
    pub reason: &'static str,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.field, self.reason)
    }
}

impl std::error::Error for ValidationError {}

mod validation;
use validation::{ensure_string, ensure_uri, ensure_utc, ensure_version, optional_string};

// Deserializing through String excludes Serde's externally tagged object enum form.
macro_rules! string_enum {
    ($name:ident { $($variant:ident => $wire:literal),+ $(,)? }) => {
        #[derive(Debug, Clone, Serialize, PartialEq, Eq)]
        #[serde(rename_all = "lowercase")]
        pub enum $name { $($variant),+ }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let value = String::deserialize(deserializer)?;
                match value.as_str() {
                    $($wire => Ok(Self::$variant),)+
                    _ => Err(serde::de::Error::unknown_variant(&value, &[$($wire),+])),
                }
            }
        }
    };
}

string_enum! { EntityKind { Human => "human", Agent => "agent", Machine => "machine", Service => "service" } }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Capability {
    pub id: String,
    #[serde(
        default,
        deserialize_with = "optional_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub description: Option<String>,
    #[serde(
        default,
        deserialize_with = "optional_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub spec: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub transport: String,
    pub url: String,
}

impl Capability {
    pub fn validate(&self) -> Result<(), ValidationError> {
        ensure_string("capabilities.id", &self.id, 1, 128)?;
        let bytes = self.id.as_bytes();
        let mut component_start = false;
        if !bytes[0].is_ascii_lowercase() {
            return Err(ValidationError {
                field: "capabilities.id",
                reason: "invalid capability ID",
            });
        }
        // The first component is alphanumeric; later components may contain hyphens.
        let mut first_component = true;
        for &byte in bytes {
            if matches!(byte, b'.' | b':') || (first_component && byte == b'-') {
                if component_start {
                    return Err(ValidationError {
                        field: "capabilities.id",
                        reason: "empty ID component",
                    });
                }
                first_component = false;
                component_start = true;
            } else if byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (!first_component && byte == b'-')
            {
                component_start = false;
            } else {
                return Err(ValidationError {
                    field: "capabilities.id",
                    reason: "invalid capability ID",
                });
            }
        }
        if component_start {
            return Err(ValidationError {
                field: "capabilities.id",
                reason: "empty ID component",
            });
        }
        if let Some(description) = &self.description {
            ensure_string("capabilities.description", description, 0, 1024)?;
        }
        if let Some(spec) = &self.spec {
            ensure_uri("capabilities.spec", spec)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Entity {
    pub xeip: String,
    pub id: String,
    #[serde(
        default,
        deserialize_with = "optional_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub name: Option<String>,
    pub kinds: Vec<EntityKind>,
    #[serde(default)]
    pub endpoints: Vec<Endpoint>,
    #[serde(default)]
    pub capabilities: Vec<Capability>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extensions: BTreeMap<String, Value>,
}

impl Entity {
    pub fn validate(&self) -> Result<(), ValidationError> {
        ensure_version(&self.xeip)?;
        ensure_uri("id", &self.id)?;
        if let Some(name) = &self.name {
            ensure_string("name", name, 1, 256)?;
        }
        if self.kinds.is_empty() {
            return Err(ValidationError {
                field: "kinds",
                reason: "at least one kind required",
            });
        }
        for (i, kind) in self.kinds.iter().enumerate() {
            if self.kinds[..i].contains(kind) {
                return Err(ValidationError {
                    field: "kinds",
                    reason: "duplicate kind",
                });
            }
        }
        for e in &self.endpoints {
            if ![
                "http-sse",
                "http",
                "websocket",
                "local",
                "webrtc",
                "a2a",
                "mcp",
            ]
            .contains(&e.transport.as_str())
            {
                return Err(ValidationError {
                    field: "endpoints.transport",
                    reason: "unsupported transport",
                });
            }
            ensure_uri("endpoints.url", &e.url)?;
        }
        for c in &self.capabilities {
            c.validate()?;
        }
        Ok(())
    }
}

string_enum! { SessionMode { Direct => "direct", Group => "group" } }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Session {
    pub xeip: String,
    pub id: String,
    pub mode: SessionMode,
    pub members: Vec<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extensions: BTreeMap<String, Value>,
}

impl Session {
    pub fn validate(&self) -> Result<(), ValidationError> {
        ensure_version(&self.xeip)?;
        ensure_uri("id", &self.id)?;
        ensure_utc("createdAt", &self.created_at)?;
        for member in &self.members {
            ensure_uri("members", member)?;
        }
        let mut members = std::collections::HashSet::new();
        if self.members.iter().any(|member| !members.insert(member)) {
            return Err(ValidationError {
                field: "members",
                reason: "duplicate member",
            });
        }
        Ok(())
    }
}

string_enum! { MessageKind { Message => "message", Event => "event", Command => "command", Receipt => "receipt" } }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Body {
    #[serde(rename = "contentType")]
    pub content_type: String,
    pub data: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub xeip: String,
    pub id: String,
    pub kind: MessageKind,
    pub sender: String,
    #[serde(
        default,
        deserialize_with = "optional_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub recipient: Option<String>,
    pub session: String,
    pub timestamp: String,
    pub body: Body,
    #[serde(
        rename = "replyTo",
        default,
        deserialize_with = "optional_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub reply_to: Option<String>,
    #[serde(
        rename = "expiresAt",
        default,
        deserialize_with = "optional_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub expires_at: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extensions: BTreeMap<String, Value>,
}

impl Envelope {
    /// Structural checks only. NOT an authentication/authorization check.
    pub fn validate(&self) -> Result<(), ValidationError> {
        ensure_version(&self.xeip)?;
        ensure_uri("id", &self.id)?;
        ensure_uri("sender", &self.sender)?;
        ensure_uri("session", &self.session)?;
        if let Some(recipient) = &self.recipient {
            ensure_uri("recipient", recipient)?;
        }
        if let Some(reply_to) = &self.reply_to {
            ensure_uri("replyTo", reply_to)?;
        }
        ensure_utc("timestamp", &self.timestamp)?;
        if let Some(expires_at) = &self.expires_at {
            ensure_utc("expiresAt", expires_at)?;
        }
        ensure_string("body.contentType", &self.body.content_type, 1, 255)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_valid_entity_fixture() {
        let entity: Entity = serde_json::from_str(include_str!(
            "../../../conformance/fixtures/entity.valid.json"
        ))
        .unwrap();
        assert_eq!(entity.kinds, vec![EntityKind::Machine, EntityKind::Agent]);
        entity.validate().unwrap();
        let roundtrip: Entity =
            serde_json::from_str(&serde_json::to_string(&entity).unwrap()).unwrap();
        assert_eq!(roundtrip, entity);
    }

    #[test]
    fn deserialize_valid_message_fixture() {
        let msg: Envelope = serde_json::from_str(include_str!(
            "../../../conformance/fixtures/message.valid.json"
        ))
        .unwrap();
        assert_eq!(msg.kind, MessageKind::Message);
        assert_eq!(msg.body.content_type, "text/plain");
        msg.validate().unwrap();
        let roundtrip: Envelope =
            serde_json::from_str(&serde_json::to_string(&msg).unwrap()).unwrap();
        assert_eq!(roundtrip, msg);
    }

    #[test]
    fn deserialize_valid_session_fixture() {
        let session: Session = serde_json::from_str(include_str!(
            "../../../conformance/fixtures/session.valid.json"
        ))
        .unwrap();
        assert_eq!(session.mode, SessionMode::Group);
        session.validate().unwrap();
    }

    #[test]
    fn rejects_unknown_version() {
        let msg: Envelope = serde_json::from_str(include_str!(
            "../../../conformance/fixtures/message.invalid-version.json"
        ))
        .unwrap();
        let error = msg.validate().unwrap_err();
        assert_eq!(error.field, "xeip");
        assert_eq!(error.reason, "unsupported version");
    }

    #[test]
    fn rejects_malformed_version_distinctly() {
        let malformed: Envelope = serde_json::from_str(include_str!(
            "../../../conformance/fixtures/message.invalid-malformed-version.json"
        ))
        .unwrap();
        let error = malformed.validate().unwrap_err();
        assert_eq!(error.field, "xeip");
        assert_eq!(error.reason, "malformed xeip version");

        let mut raw: Value = serde_json::from_str(include_str!(
            "../../../conformance/fixtures/message.valid.json"
        ))
        .unwrap();
        raw["xeip"] = Value::String(String::new());
        let empty: Envelope = serde_json::from_value(raw).unwrap();
        assert_eq!(
            empty.validate().unwrap_err().reason,
            "malformed xeip version"
        );
    }

    #[test]
    fn accepts_inert_extensions_fixture() {
        let msg: Envelope = serde_json::from_str(include_str!(
            "../../../conformance/fixtures/extensions/message.valid.json"
        ))
        .unwrap();
        assert_eq!(msg.extensions.len(), 2);
        msg.validate().unwrap();
    }

    #[test]
    fn rejects_unknown_top_level_field_fixture() {
        let raw: Value = serde_json::from_str(include_str!(
            "../../../conformance/fixtures/message.invalid-unknown-field.json"
        ))
        .unwrap();
        assert!(serde_json::from_value::<Envelope>(raw).is_err());
    }

    #[test]
    fn rejects_missing_uri_scheme() {
        let mut msg: Envelope = serde_json::from_str(include_str!(
            "../../../conformance/fixtures/message.valid.json"
        ))
        .unwrap();
        msg.sender = "not-an-absolute-uri".into();
        assert_eq!(msg.validate().unwrap_err().field, "sender");
    }

    #[test]
    fn rejects_unknown_fields() {
        let mut raw: Value = serde_json::from_str(include_str!(
            "../../../conformance/fixtures/message.valid.json"
        ))
        .unwrap();
        raw["unrecognized"] = Value::Bool(true);
        assert!(serde_json::from_value::<Envelope>(raw).is_err());
    }

    #[test]
    fn shared_conformance_vectors() {
        let vectors: Vec<Value> =
            serde_json::from_str(include_str!("../../../conformance/vectors.json")).unwrap();
        for vector in vectors {
            let schema = vector["schema"].as_str().unwrap();
            let fixture = match schema {
                "message" => include_str!("../../../conformance/fixtures/message.valid.json"),
                "entity" => include_str!("../../../conformance/fixtures/entity.valid.json"),
                "session" => include_str!("../../../conformance/fixtures/session.valid.json"),
                "capability" => include_str!("../../../conformance/fixtures/capability.valid.json"),
                _ => panic!("unknown schema"),
            };
            let mut raw: Value = serde_json::from_str(fixture).unwrap();
            if let Some(patch) = vector["patch"].as_object() {
                raw.as_object_mut().unwrap().extend(patch.clone());
            }
            if let Some(fields) = vector["remove"].as_array() {
                for field in fields {
                    raw.as_object_mut().unwrap().remove(field.as_str().unwrap());
                }
            }
            let accepted = match schema {
                "message" => {
                    serde_json::from_value::<Envelope>(raw).is_ok_and(|v| v.validate().is_ok())
                }
                "entity" => {
                    serde_json::from_value::<Entity>(raw).is_ok_and(|v| v.validate().is_ok())
                }
                "session" => {
                    serde_json::from_value::<Session>(raw).is_ok_and(|v| v.validate().is_ok())
                }
                // Capability fixtures also exercise validation within an entity.
                "capability" => {
                    let mut entity: Entity = serde_json::from_str(include_str!(
                        "../../../conformance/fixtures/entity.valid.json"
                    ))
                    .unwrap();
                    serde_json::from_value::<Capability>(raw).is_ok_and(|v| {
                        entity.capabilities = vec![v];
                        entity.validate().is_ok()
                    })
                }
                _ => unreachable!(),
            };
            assert_eq!(
                accepted,
                vector["valid"].as_bool().unwrap(),
                "{}",
                vector["name"]
            );
        }
    }
}
