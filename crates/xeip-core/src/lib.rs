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

fn valid_uri(value: &str) -> bool {
    let Some((scheme, rest)) = value.split_once(':') else { return false };
    !rest.is_empty()
        && scheme.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        && scheme.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

fn ensure_uri(field: &'static str, value: &str) -> Result<(), ValidationError> {
    if valid_uri(value) { Ok(()) } else { Err(ValidationError { field, reason: "expected absolute URI" }) }
}

fn ensure_version(value: &str) -> Result<(), ValidationError> {
    if value == PROTOCOL_VERSION { Ok(()) } else {
        Err(ValidationError { field: "xeip", reason: "unsupported XEIP version" })
    }
}

fn ensure_utc(field: &'static str, value: &str) -> Result<(), ValidationError> {
    // Full RFC 3339 parsing is intentionally deferred to the conformance validator.
    if value.contains('T') && value.ends_with('Z') {
        Ok(())
    } else {
        Err(ValidationError { field, reason: "expected UTC date-time string" })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum EntityKind { Human, Agent, Machine, Service }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Capability {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub transport: String,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Entity {
    pub xeip: String,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
        if self.kinds.is_empty() { return Err(ValidationError { field: "kinds", reason: "at least one kind required" }); }
        for e in &self.endpoints { ensure_uri("endpoints.url", &e.url)?; }
        for c in &self.capabilities {
            if c.id.trim().is_empty() { return Err(ValidationError { field: "capabilities.id", reason: "required" }); }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SessionMode { Direct, Group }

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
        for member in &self.members { ensure_uri("members", member)?; }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MessageKind { Message, Event, Command, Receipt }

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient: Option<String>,
    pub session: String,
    pub timestamp: String,
    pub body: Body,
    #[serde(rename = "replyTo", default, skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<String>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
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
        if let Some(recipient) = &self.recipient { ensure_uri("recipient", recipient)?; }
        if let Some(reply_to) = &self.reply_to { ensure_uri("replyTo", reply_to)?; }
        ensure_utc("timestamp", &self.timestamp)?;
        if let Some(expires_at) = &self.expires_at { ensure_utc("expiresAt", expires_at)?; }
        if self.body.content_type.trim().is_empty() {
            return Err(ValidationError { field: "body.contentType", reason: "required" });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_valid_entity_fixture() {
        let entity: Entity = serde_json::from_str(include_str!("../../../conformance/fixtures/entity.valid.json")).unwrap();
        assert_eq!(entity.kinds, vec![EntityKind::Machine, EntityKind::Agent]);
        entity.validate().unwrap();
        let roundtrip: Entity = serde_json::from_str(&serde_json::to_string(&entity).unwrap()).unwrap();
        assert_eq!(roundtrip, entity);
    }

    #[test]
    fn deserialize_valid_message_fixture() {
        let msg: Envelope = serde_json::from_str(include_str!("../../../conformance/fixtures/message.valid.json")).unwrap();
        assert_eq!(msg.kind, MessageKind::Message);
        assert_eq!(msg.body.content_type, "text/plain");
        msg.validate().unwrap();
        let roundtrip: Envelope = serde_json::from_str(&serde_json::to_string(&msg).unwrap()).unwrap();
        assert_eq!(roundtrip, msg);
    }

    #[test]
    fn deserialize_valid_session_fixture() {
        let session: Session = serde_json::from_str(include_str!("../../../conformance/fixtures/session.valid.json")).unwrap();
        assert_eq!(session.mode, SessionMode::Group);
        session.validate().unwrap();
    }

    #[test]
    fn rejects_unknown_version() {
        let msg: Envelope = serde_json::from_str(include_str!("../../../conformance/fixtures/message.invalid-version.json")).unwrap();
        assert_eq!(msg.validate().unwrap_err().field, "xeip");
    }

    #[test]
    fn rejects_missing_uri_scheme() {
        let mut msg: Envelope = serde_json::from_str(include_str!("../../../conformance/fixtures/message.valid.json")).unwrap();
        msg.sender = "not-an-absolute-uri".into();
        assert_eq!(msg.validate().unwrap_err().field, "sender");
    }

    #[test]
    fn rejects_unknown_fields() {
        let mut raw: Value = serde_json::from_str(include_str!("../../../conformance/fixtures/message.valid.json")).unwrap();
        raw["unrecognized"] = Value::Bool(true);
        assert!(serde_json::from_value::<Envelope>(raw).is_err());
    }
}
