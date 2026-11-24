//! The declared tool surface. Schemas and annotations are born
//! with the tools (Tiger Style MCP Rules 3 and 5): every input
//! schema is an object with an explicit `properties` key, and
//! every tool declares its access hints. The surface is 9 tools
//! in 5 role-shaped groups — well inside the 25-tool budget.
//!
//! No `outputSchema` is published at Stage 0: backend results
//! carry platform output whose shape is not yet stable, and a
//! schema that is not enforced is decoration (Rule 3). The
//! departure and its reason are recorded in the README.

use rmcp::model::{Tool, ToolAnnotations};
use serde_json::{Value, json};

use crate::gate::Action;

/// What a tool does to the world, for dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// Read-only and ungated.
    Read,
    /// The gate itself, exposed so a caller can see a verdict
    /// without attempting a mutation (the meister_lane_check
    /// pattern).
    GateCheck,
    /// A mutation: dispatched only through `gate::decide`.
    Mutation(Action),
}

pub struct ToolSpec {
    pub name: &'static str,
    // The role-shaped group (Rule 8): consumed by trigger-scoped
    // loading and client-config generators, and asserted by the
    // catalog tests — dispatch itself keys on `kind`.
    #[allow(dead_code)]
    pub group: &'static str,
    pub description: &'static str,
    pub input: Value,
    pub annotations: ToolAnnotations,
    pub kind: Kind,
}

fn obj_schema(props: &[(&str, Value)], required: &[&str]) -> Value {
    let mut map = serde_json::Map::new();
    for (name, schema) in props {
        map.insert((*name).to_string(), schema.clone());
    }
    json!({
        "type": "object",
        "properties": map,
        "required": required,
        "additionalProperties": false,
    })
}

fn string_prop() -> Value {
    json!({"type": "string"})
}

fn approval_prop() -> Value {
    json!({
        "type": "object",
        "properties": {
            "approved_by": {"type": "string"},
            "note": {"type": "string"},
        },
        "required": ["approved_by"],
        "additionalProperties": false,
    })
}

fn read_ann() -> ToolAnnotations {
    ToolAnnotations::new()
        .read_only(true)
        .destructive(false)
        .idempotent(true)
        .open_world(false)
}

fn write_ann(idempotent: bool, destructive: bool) -> ToolAnnotations {
    ToolAnnotations::new()
        .read_only(false)
        .destructive(destructive)
        .idempotent(idempotent)
        .open_world(false)
}

fn device_id() -> (&'static str, Value) {
    ("device_id", json!({"type": "string"}))
}
const APPROVAL: &str = "operator_approval";

pub fn specs() -> Vec<ToolSpec> {
    vec![
        ToolSpec {
            name: "bosun_device_list",
            group: "inventory",
            description: "List inventoried devices with platform, enrollment, and declared capabilities. Bounded by `limit` (default 50, max 256); the total count is computed by the server.",
            input: obj_schema(
                &[(
                    "limit",
                    json!({"type": "integer", "minimum": 1, "maximum": 256}),
                )],
                &[],
            ),
            annotations: read_ann(),
            kind: Kind::Read,
        },
        ToolSpec {
            name: "bosun_device_get",
            group: "inventory",
            description: "Fetch one device's record, including the capabilities the gate will enforce for it.",
            input: obj_schema(&[device_id()], &["device_id"]),
            annotations: read_ann(),
            kind: Kind::Read,
        },
        ToolSpec {
            name: "bosun_device_register",
            group: "inventory",
            description: "Register a device in the inventory. A mutation: requires operator approval. iOS devices register with an enrollment state; supervision is what later unlocks application management.",
            input: obj_schema(
                &[
                    ("id", string_prop()),
                    ("label", string_prop()),
                    (
                        "platform",
                        json!({"type": "string", "enum": ["android", "windows", "ios"]}),
                    ),
                    ("transport", string_prop()),
                    (
                        "enrollment",
                        json!({"type": "string", "enum": ["not_applicable", "unenrolled", "enrolled_unsupervised", "enrolled_supervised"]}),
                    ),
                    (APPROVAL, approval_prop()),
                ],
                &["id", "label", "platform", "transport", APPROVAL],
            ),
            annotations: write_ann(false, false),
            kind: Kind::Mutation(Action::RegisterDevice),
        },
        ToolSpec {
            name: "bosun_device_diagnostics",
            group: "diagnostics",
            description: "Collect a device's diagnostics bundle (platform facts the provisioning flow asks first: battery, storage, build/OS). Read-only and ungated; refused for devices that do not declare the diagnostics capability.",
            input: obj_schema(&[device_id()], &["device_id"]),
            annotations: read_ann(),
            kind: Kind::Read,
        },
        ToolSpec {
            name: "bosun_package_list",
            group: "diagnostics",
            description: "List packages/applications on a device (Android: pm list; Windows: winget list; iOS: the MDM installed-application query). Read-only and ungated.",
            input: obj_schema(&[device_id()], &["device_id"]),
            annotations: read_ann(),
            kind: Kind::Read,
        },
        ToolSpec {
            name: "bosun_package_install",
            group: "packages",
            description: "Install a package on a device. A mutation: requires operator approval and the device's package_install capability. Android takes an APK path on the server host; Windows a winget id; iOS a managed-app identifier (queued via MDM).",
            input: obj_schema(
                &[
                    device_id(),
                    ("package", string_prop()),
                    (APPROVAL, approval_prop()),
                ],
                &["device_id", "package", APPROVAL],
            ),
            annotations: write_ann(true, false),
            kind: Kind::Mutation(Action::PackageInstall),
        },
        ToolSpec {
            name: "bosun_package_update",
            group: "packages",
            description: "Update packages on a device. A mutation: requires operator approval and the package_update capability. Omit `package` on Windows to upgrade all (winget upgrade --all); Android and iOS name one package.",
            input: obj_schema(
                &[
                    device_id(),
                    ("package", string_prop()),
                    (APPROVAL, approval_prop()),
                ],
                &["device_id", APPROVAL],
            ),
            annotations: write_ann(true, false),
            kind: Kind::Mutation(Action::PackageUpdate),
        },
        ToolSpec {
            name: "bosun_device_reboot",
            group: "power",
            description: "Reboot a device. A mutation: requires operator approval and the reboot capability (Android and Windows; iOS does not declare it at Stage 0).",
            input: obj_schema(
                &[device_id(), (APPROVAL, approval_prop())],
                &["device_id", APPROVAL],
            ),
            annotations: write_ann(true, true),
            kind: Kind::Mutation(Action::Reboot),
        },
        ToolSpec {
            name: "bosun_gate_check",
            group: "gate",
            description: "Ask the mutation gate for its verdict on an action (and optionally a device and approval) without performing it. Read-only; the answer is the same decision a real call would meet.",
            input: obj_schema(
                &[
                    (
                        "action",
                        json!({"type": "string", "enum": ["register_device", "package_install", "package_update", "reboot"]}),
                    ),
                    device_id(),
                    (APPROVAL, approval_prop()),
                ],
                &["action"],
            ),
            annotations: read_ann(),
            kind: Kind::GateCheck,
        },
    ]
}

pub fn spec_named(name: &str) -> Option<ToolSpec> {
    specs().into_iter().find(|s| s.name == name)
}

pub fn tool_definitions() -> Vec<Tool> {
    specs()
        .into_iter()
        .map(|spec| {
            let Value::Object(input_map) = spec.input else {
                unreachable!("catalog input schemas are objects");
            };
            Tool::new(spec.name, spec.description, input_map).with_annotations(spec.annotations)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn surface_is_nine_tools_uniquely_named_and_prefixed() {
        let all = specs();
        assert_eq!(all.len(), 9);
        let mut names: Vec<&str> = all.iter().map(|s| s.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), 9);
        assert!(names.iter().all(|n| n.starts_with("bosun_")));
    }

    #[test]
    fn every_input_schema_is_an_object_with_properties() {
        for spec in specs() {
            assert_eq!(spec.input["type"], "object", "{}", spec.name);
            assert!(spec.input.get("properties").is_some(), "{}", spec.name);
        }
    }

    #[test]
    fn every_tool_is_annotated_from_birth() {
        for spec in specs() {
            let a = &spec.annotations;
            assert!(a.read_only_hint.is_some(), "{}", spec.name);
            assert!(a.destructive_hint.is_some(), "{}", spec.name);
            assert!(a.idempotent_hint.is_some(), "{}", spec.name);
            // Declared access matches kind: reads declare read-only,
            // mutations declare writing. Both directions (Rule 5).
            match spec.kind {
                Kind::Read | Kind::GateCheck => {
                    assert_eq!(a.read_only_hint, Some(true), "{}", spec.name)
                }
                Kind::Mutation(_) => assert_eq!(a.read_only_hint, Some(false), "{}", spec.name),
            }
        }
    }

    #[test]
    fn every_mutation_schema_requires_the_approval() {
        for spec in specs() {
            if matches!(spec.kind, Kind::Mutation(_)) {
                let required = spec.input["required"].as_array().expect("required list");
                assert!(
                    required.iter().any(|r| r == "operator_approval"),
                    "{} must require operator_approval in its schema",
                    spec.name
                );
            }
        }
    }

    #[test]
    fn groups_are_the_five_declared() {
        let mut groups: Vec<&str> = specs().iter().map(|s| s.group).collect();
        groups.sort_unstable();
        groups.dedup();
        assert_eq!(
            groups,
            ["diagnostics", "gate", "inventory", "packages", "power"]
        );
    }

    #[test]
    fn tools_list_payload_is_inside_the_token_budget() {
        // Rule 1 metadata budget: the full served tools/list
        // payload stays at or under ~2,500 tokens (~4 chars/token
        // is the conservative estimator the fleet uses).
        let payload = serde_json::to_string(&tool_definitions()).expect("serialize tools");
        let estimated_tokens = payload.len() / 4;
        assert!(
            estimated_tokens <= 2500,
            "tools/list payload ~{estimated_tokens} tokens exceeds the 2,500 budget ({} bytes)",
            payload.len()
        );
    }
}
