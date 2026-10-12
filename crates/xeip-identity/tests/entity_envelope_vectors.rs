use serde_json::Value;
use xeip_identity::{
    entity_envelope_signing_input, sign_entity_envelope, verify_entity_envelope,
    EntityTrustOptions, TrustAnchor,
};
fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../conformance/fixtures/entity-envelope/vectors.json"
    ))
    .unwrap()
}
fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|a| a.iter().map(|v| v.as_str().unwrap().to_owned()).collect())
        .unwrap_or_default()
}
#[test]
fn every_entity_envelope_vector_matches() {
    let f = fixture();
    for v in f["vectors"].as_array().unwrap() {
        let o = &v["options"];
        let known = strings(&o["knownExtensions"]);
        let docs = o["keyDocuments"].as_array().unwrap();
        let anchor = TrustAnchor {
            genesis_kid: o["anchor"]["genesisKid"].as_str().map(str::to_owned),
            genesis_digest: o["anchor"]["genesisDigest"].as_str().map(str::to_owned),
        };
        let options = EntityTrustOptions {
            key_documents: docs,
            anchor: Some(anchor),
            status_document: &o["statusDocument"],
            now_seconds: o["nowSeconds"].as_i64().unwrap_or(-1),
            max_age_seconds: o["maxAgeSeconds"].as_i64().unwrap_or(0),
            known_extensions: &known,
        };
        let result = verify_entity_envelope(&v["envelope"], &options);
        assert_eq!(
            result.is_ok(),
            v["valid"].as_bool().unwrap(),
            "{}: {:?}",
            v["name"],
            result
        );
        if let Err(error) = result {
            assert_eq!(
                error.to_string(),
                v["reason"].as_str().unwrap(),
                "{}",
                v["name"]
            );
        }
    }
}
#[test]
fn reproduces_committed_entity_signature_and_bytes() {
    let f = fixture();
    let hex = f["seed"].as_str().unwrap();
    let mut seed = [0u8; 32];
    for (i, byte) in seed.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
    }
    let signed = sign_entity_envelope(
        &f["envelope"],
        &seed,
        f["kid"].as_str().unwrap(),
        &strings(&f["criticalExtensions"]),
    )
    .unwrap();
    assert_eq!(signed, f["signed"]);
    assert_eq!(
        entity_envelope_signing_input(&signed).unwrap(),
        f["signingInput"].as_str().unwrap()
    );
}
