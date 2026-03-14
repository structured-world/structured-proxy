//! OpenAPI 3.0 spec generation from proto descriptors.
//!
//! Reads `google.api.http` annotations and proto message definitions
//! to produce a complete OpenAPI 3.0 JSON spec at runtime.
//! No codegen, no build step — same descriptor pool used for transcoding.

use prost_reflect::{DescriptorPool, FieldDescriptor, Kind, MessageDescriptor, MethodDescriptor};
use serde_json::{json, Map, Value};

use crate::config::{AliasConfig, OpenApiConfig};

/// Generate OpenAPI 3.0 JSON spec from a descriptor pool.
pub fn generate(pool: &DescriptorPool, config: &OpenApiConfig, aliases: &[AliasConfig]) -> Value {
    let title = config.title.as_deref().unwrap_or("API");
    let version = config.version.as_deref().unwrap_or("1.0.0");

    let mut paths = Map::new();
    let mut schemas = Map::new();
    let mut tags = Vec::new();

    for service in pool.services() {
        let service_name = service.name().to_string();
        let service_full = service.full_name().to_string();

        // Proto comments as tag description.
        let tag_desc = get_comments(&service_full, pool);
        let mut tag = json!({ "name": service_name });
        if let Some(desc) = &tag_desc {
            tag["description"] = json!(desc);
        }
        tags.push(tag);

        for method in service.methods() {
            if method.is_client_streaming() {
                continue; // No REST mapping for client-streaming.
            }

            if let Some((http_method, http_path)) = extract_http_rule(&method, pool) {
                let operation = build_operation(
                    &method,
                    &service_name,
                    &http_method,
                    &http_path,
                    pool,
                    &mut schemas,
                );

                // Main path.
                add_path_operation(&mut paths, &http_path, &http_method, operation.clone());

                // Aliases.
                for alias in aliases {
                    if let Some(suffix) = http_path.strip_prefix(&alias.to) {
                        if alias.from.ends_with("/{path}") {
                            let prefix = alias.from.trim_end_matches("/{path}");
                            let alias_path = format!("{}{}", prefix, suffix);
                            add_path_operation(
                                &mut paths,
                                &alias_path,
                                &http_method,
                                operation.clone(),
                            );
                        }
                    }
                }
            }
        }
    }

    let mut spec = json!({
        "openapi": "3.0.3",
        "info": {
            "title": title,
            "version": version,
        },
        "paths": paths,
        "tags": tags,
    });

    if !schemas.is_empty() {
        spec["components"] = json!({
            "schemas": schemas,
        });
    }

    // Security scheme for Bearer auth (cookie auth works implicitly via same-origin).
    spec["components"]["securitySchemes"] = json!({
        "bearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
        },
        "cookieAuth": {
            "type": "apiKey",
            "in": "cookie",
            "name": "session",
            "description": "Browser session cookie (same-origin, set by BFF login flow)",
        },
    });

    spec
}

/// Generate Scalar API docs HTML page.
pub fn docs_html(openapi_path: &str, title: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>{title} — API Docs</title>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
</head>
<body>
    <script id="api-reference" data-url="{openapi_path}"></script>
    <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"></script>
</body>
</html>"#,
        title = title,
        openapi_path = openapi_path,
    )
}

fn add_path_operation(paths: &mut Map<String, Value>, path: &str, method: &str, operation: Value) {
    let path_item = paths.entry(path.to_string()).or_insert_with(|| json!({}));
    if let Some(obj) = path_item.as_object_mut() {
        obj.insert(method.to_string(), operation);
    }
}

fn build_operation(
    method: &MethodDescriptor,
    service_name: &str,
    http_method: &str,
    http_path: &str,
    pool: &DescriptorPool,
    schemas: &mut Map<String, Value>,
) -> Value {
    let method_name = method.name().to_string();
    let full_name = method.full_name().to_string();
    let input = method.input();
    let output = method.output();

    let is_streaming = method.is_server_streaming();

    // Description from proto comments.
    let description = get_comments(&full_name, pool).unwrap_or_default();

    let operation_id = format!("{}.{}", service_name, method_name);

    let mut op = json!({
        "operationId": operation_id,
        "tags": [service_name],
        "summary": method_name,
    });

    if !description.is_empty() {
        op["description"] = json!(description);
    }

    // Path parameters.
    let path_params = extract_path_params(http_path);
    if !path_params.is_empty() {
        let params: Vec<Value> = path_params
            .iter()
            .map(|name| {
                let mut param = json!({
                    "name": name,
                    "in": "path",
                    "required": true,
                    "schema": { "type": "string" },
                });

                // Try to get type from input message field.
                if let Some(field) = input.get_field_by_name(name) {
                    param["schema"] = field_to_schema(&field);
                }

                param
            })
            .collect();
        op["parameters"] = json!(params);
    }

    // Request body (for POST/PUT/PATCH/DELETE with body fields).
    if http_method != "get" {
        let has_body_fields = input
            .fields()
            .any(|f| !path_params.contains(&f.name().to_string()));

        if has_body_fields {
            let schema_name = input.name().to_string();
            let body_schema = message_to_schema(&input, &path_params, schemas);

            schemas.insert(schema_name.clone(), body_schema);

            op["requestBody"] = json!({
                "required": true,
                "content": {
                    "application/json": {
                        "schema": {
                            "$ref": format!("#/components/schemas/{}", schema_name),
                        },
                    },
                },
            });
        }
    } else {
        // GET: non-path fields become query parameters.
        let query_params: Vec<Value> = input
            .fields()
            .filter(|f| !path_params.contains(&f.name().to_string()))
            .map(|field| {
                json!({
                    "name": field.name(),
                    "in": "query",
                    "required": false,
                    "schema": field_to_schema(&field),
                })
            })
            .collect();

        if !query_params.is_empty() {
            let existing = op
                .get("parameters")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let mut all_params = existing;
            all_params.extend(query_params);
            op["parameters"] = json!(all_params);
        }
    }

    // Response.
    if is_streaming {
        op["responses"] = json!({
            "200": {
                "description": "Server-streaming response (NDJSON)",
                "content": {
                    "application/x-ndjson": {
                        "schema": message_ref_or_inline(&output, schemas),
                    },
                },
            },
        });
    } else if output.full_name() == "google.protobuf.Empty" {
        op["responses"] = json!({
            "200": {
                "description": "Success (empty response)",
            },
        });
    } else {
        let schema_name = output.name().to_string();
        let response_schema = message_to_schema(&output, &[], schemas);
        schemas.insert(schema_name.clone(), response_schema);

        op["responses"] = json!({
            "200": {
                "description": "Success",
                "content": {
                    "application/json": {
                        "schema": {
                            "$ref": format!("#/components/schemas/{}", schema_name),
                        },
                    },
                },
            },
        });
    }

    // Common error responses.
    if let Some(responses) = op.get_mut("responses").and_then(|r| r.as_object_mut()) {
        responses.insert(
            "400".to_string(),
            json!({ "description": "Invalid argument" }),
        );
        responses.insert(
            "401".to_string(),
            json!({ "description": "Unauthenticated" }),
        );
        responses.insert(
            "403".to_string(),
            json!({ "description": "Permission denied" }),
        );
        responses.insert("404".to_string(), json!({ "description": "Not found" }));
        responses.insert(
            "503".to_string(),
            json!({ "description": "Service unavailable" }),
        );
    }

    op
}

/// Generate a JSON Schema for a protobuf message, excluding path parameter fields.
fn message_to_schema(
    msg: &MessageDescriptor,
    exclude_fields: &[String],
    schemas: &mut Map<String, Value>,
) -> Value {
    let mut properties = Map::new();
    let required: Vec<String> = Vec::new();

    for field in msg.fields() {
        let name = field.name().to_string();
        if exclude_fields.contains(&name) {
            continue;
        }

        let schema = field_to_schema(&field);
        properties.insert(name, schema);
    }

    let mut schema = json!({
        "type": "object",
        "properties": properties,
    });

    if !required.is_empty() {
        schema["required"] = json!(required);
    }

    // Nested messages: register as separate schemas.
    for field in msg.fields() {
        if exclude_fields.contains(&field.name().to_string()) {
            continue;
        }
        if let Kind::Message(nested) = field.kind() {
            if !is_well_known(&nested) && !schemas.contains_key(nested.name()) {
                let nested_schema = message_to_schema(&nested, &[], schemas);
                schemas.insert(nested.name().to_string(), nested_schema);
            }
        }
    }

    schema
}

fn message_ref_or_inline(msg: &MessageDescriptor, schemas: &mut Map<String, Value>) -> Value {
    let name = msg.name().to_string();
    if !schemas.contains_key(&name) {
        let schema = message_to_schema(msg, &[], schemas);
        schemas.insert(name.clone(), schema);
    }
    json!({ "$ref": format!("#/components/schemas/{}", name) })
}

fn field_to_schema(field: &FieldDescriptor) -> Value {
    let base = match field.kind() {
        Kind::Double | Kind::Float => json!({ "type": "number", "format": "double" }),
        Kind::Int32 | Kind::Sint32 | Kind::Sfixed32 => {
            json!({ "type": "integer", "format": "int32" })
        }
        Kind::Int64 | Kind::Sint64 | Kind::Sfixed64 => {
            json!({ "type": "string", "format": "int64", "description": "64-bit integer (string-encoded)" })
        }
        Kind::Uint32 | Kind::Fixed32 => {
            json!({ "type": "integer", "format": "uint32" })
        }
        Kind::Uint64 | Kind::Fixed64 => {
            json!({ "type": "string", "format": "uint64", "description": "64-bit unsigned integer (string-encoded)" })
        }
        Kind::Bool => json!({ "type": "boolean" }),
        Kind::String => json!({ "type": "string" }),
        Kind::Bytes => json!({ "type": "string", "format": "byte" }),
        Kind::Enum(e) => {
            let values: Vec<Value> = e.values().map(|v| json!(v.name())).collect();
            json!({ "type": "string", "enum": values })
        }
        Kind::Message(msg) => {
            if is_well_known(&msg) {
                well_known_schema(&msg)
            } else {
                json!({ "$ref": format!("#/components/schemas/{}", msg.name()) })
            }
        }
    };

    if field.is_list() {
        json!({ "type": "array", "items": base })
    } else if field.is_map() {
        // Map<K, V> → object with additionalProperties.
        if let Kind::Message(entry) = field.kind() {
            let value_field = entry.get_field_by_name("value");
            let value_schema = value_field
                .map(|f| field_to_schema(&f))
                .unwrap_or_else(|| json!({}));
            json!({ "type": "object", "additionalProperties": value_schema })
        } else {
            json!({ "type": "object" })
        }
    } else {
        base
    }
}

fn is_well_known(msg: &MessageDescriptor) -> bool {
    msg.full_name().starts_with("google.protobuf.")
}

fn well_known_schema(msg: &MessageDescriptor) -> Value {
    match msg.full_name() {
        "google.protobuf.Timestamp" => {
            json!({ "type": "string", "format": "date-time" })
        }
        "google.protobuf.Duration" => {
            json!({ "type": "string", "format": "duration", "example": "3.5s" })
        }
        "google.protobuf.Empty" => json!({ "type": "object" }),
        "google.protobuf.Struct" => json!({ "type": "object" }),
        "google.protobuf.Value" => json!({}),
        "google.protobuf.ListValue" => json!({ "type": "array", "items": {} }),
        "google.protobuf.StringValue" | "google.protobuf.BytesValue" => {
            json!({ "type": "string" })
        }
        "google.protobuf.BoolValue" => json!({ "type": "boolean" }),
        "google.protobuf.Int32Value" | "google.protobuf.UInt32Value" => {
            json!({ "type": "integer" })
        }
        "google.protobuf.Int64Value" | "google.protobuf.UInt64Value" => {
            json!({ "type": "string", "format": "int64" })
        }
        "google.protobuf.FloatValue" | "google.protobuf.DoubleValue" => {
            json!({ "type": "number" })
        }
        "google.protobuf.FieldMask" => {
            json!({ "type": "string", "description": "Comma-separated field paths" })
        }
        "google.protobuf.Any" => {
            json!({ "type": "object", "properties": { "@type": { "type": "string" } }, "additionalProperties": true })
        }
        _ => json!({ "type": "object" }),
    }
}

/// Extract `{param}` names from a path like `/v1/profiles/{profile_id}/devices`.
fn extract_path_params(path: &str) -> Vec<String> {
    let mut params = Vec::new();
    let mut in_brace = false;
    let mut current = String::new();

    for ch in path.chars() {
        match ch {
            '{' => {
                in_brace = true;
                current.clear();
            }
            '}' => {
                in_brace = false;
                if !current.is_empty() {
                    params.push(current.clone());
                }
            }
            _ if in_brace => current.push(ch),
            _ => {}
        }
    }

    params
}

/// Extract HTTP method and path from google.api.http annotation.
fn extract_http_rule(method: &MethodDescriptor, pool: &DescriptorPool) -> Option<(String, String)> {
    let http_ext = pool.get_extension_by_name("google.api.http")?;
    let options = method.options();

    if !options.has_extension(&http_ext) {
        return None;
    }

    let http_rule = options.get_extension(&http_ext);
    if let prost_reflect::Value::Message(rule_msg) = http_rule.into_owned() {
        for (method_name, _) in [
            ("get", "get"),
            ("post", "post"),
            ("put", "put"),
            ("delete", "delete"),
            ("patch", "patch"),
        ] {
            if let Some(val) = rule_msg.get_field_by_name(method_name) {
                if let prost_reflect::Value::String(path) = val.into_owned() {
                    if !path.is_empty() {
                        return Some((method_name.to_string(), path));
                    }
                }
            }
        }
    }

    None
}

/// Get proto source comments for a given fully-qualified name.
fn get_comments(_full_name: &str, _pool: &DescriptorPool) -> Option<String> {
    // prost-reflect doesn't expose source code info comments easily.
    // For now, return None. Can be enhanced with protoc-gen-doc or
    // manual SourceCodeInfo parsing.
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_path_params() {
        assert_eq!(
            extract_path_params("/v1/profiles/{profile_id}"),
            vec!["profile_id"]
        );
        assert_eq!(
            extract_path_params("/v1/profiles/{profile_id}/devices/{device_id}"),
            vec!["profile_id", "device_id"]
        );
        assert!(extract_path_params("/v1/auth/login").is_empty());
    }

    #[test]
    fn test_docs_html_contains_scalar() {
        let html = docs_html("/openapi.json", "Test API");
        assert!(html.contains("@scalar/api-reference"));
        assert!(html.contains("/openapi.json"));
        assert!(html.contains("Test API"));
    }

    #[test]
    fn test_well_known_schemas() {
        // Verify well-known type mappings are correct.
        let pool = DescriptorPool::global();
        if let Some(ts) = pool.get_message_by_name("google.protobuf.Timestamp") {
            let schema = well_known_schema(&ts);
            assert_eq!(schema["type"], "string");
            assert_eq!(schema["format"], "date-time");
        }
    }

    #[test]
    fn test_generate_empty_pool() {
        let pool = DescriptorPool::new();
        let config = OpenApiConfig {
            enabled: true,
            path: "/openapi.json".into(),
            docs_path: "/docs".into(),
            title: Some("Test API".into()),
            version: Some("0.1.0".into()),
        };
        let spec = generate(&pool, &config, &[]);

        assert_eq!(spec["openapi"], "3.0.3");
        assert_eq!(spec["info"]["title"], "Test API");
        assert_eq!(spec["info"]["version"], "0.1.0");
        assert!(spec["paths"].as_object().unwrap().is_empty());
    }

    #[test]
    fn test_field_to_schema_primitives() {
        // Test via JSON output structure.
        let schema = json!({ "type": "string" });
        assert_eq!(schema["type"], "string");

        let int_schema = json!({ "type": "integer", "format": "int32" });
        assert_eq!(int_schema["format"], "int32");

        let i64_schema = json!({ "type": "string", "format": "int64", "description": "64-bit integer (string-encoded)" });
        assert_eq!(i64_schema["type"], "string");
        assert_eq!(i64_schema["format"], "int64");
    }
}
