//! The card <-> server.json join invariant (agent-cards skill,
//! D-1605/D-1607): the two provisioning manifests must agree
//! exactly, held by test rather than by care.

use serde_json::Value;

fn read_manifest(rel: &str) -> (String, Value) {
    let path = format!("{}/{rel}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let value: Value = serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {path}: {e}"));
    (text, value)
}

#[test]
fn card_and_server_json_agree() {
    let (card_text, card) = read_manifest(".well-known/agent-card.json");
    let (_server_text, server) = read_manifest("server.json");

    // card name == server.json title; card version == server.json version.
    assert_eq!(card["name"], server["title"]);
    assert_eq!(card["version"], server["version"]);

    // Exactly one interface, the fleet MCP binding, whose url is
    // the extension's invocation command.
    let interfaces = card["supportedInterfaces"]
        .as_array()
        .expect("interfaces array");
    assert_eq!(interfaces.len(), 1);
    assert_eq!(
        interfaces[0]["protocolBinding"],
        "https://qompass.ai/extensions/mcp-interface/v1"
    );
    assert_eq!(interfaces[0]["protocolVersion"], "1.0");

    let extensions = card["capabilities"]["extensions"]
        .as_array()
        .expect("extensions array");
    assert_eq!(extensions.len(), 1);
    assert_eq!(
        extensions[0]["uri"],
        "https://qompass.ai/extensions/mcp-interface/v1"
    );
    let params = &extensions[0]["params"];
    assert_eq!(params["registryName"], server["name"]);
    assert_eq!(params["interface"], "mcp");
    assert_eq!(params["invocation"]["transport"], "stdio");
    assert_eq!(params["invocation"]["protocolEra"], "2026-07-28");
    assert_eq!(interfaces[0]["url"], params["invocation"]["command"]);

    // The v1.0-nonexistent field must be absent (it fails
    // validation and was a born defect elsewhere in the fleet).
    assert!(!card_text.contains("stateTransitionHistory"));

    // Provider is the studio, never a person (D-489).
    assert_eq!(card["provider"]["organization"], "Qompass AI");

    // Every skill carries the four required fields.
    let skills = card["skills"].as_array().expect("skills array");
    assert!(!skills.is_empty());
    for skill in skills {
        for field in ["id", "name", "description", "tags"] {
            assert!(skill.get(field).is_some(), "skill missing {field}: {skill}");
        }
    }
}
