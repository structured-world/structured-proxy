//! OpenAPI 3.0 spec generation from proto descriptors.
//!
//! Reads `google.api.http` annotations and proto message definitions
//! to produce a complete OpenAPI 3.0 JSON spec at runtime.
//! No codegen, no build step — same descriptor pool used for transcoding.

use std::collections::HashSet;

use axum::http::Method;
use prost_reflect::{DescriptorPool, FieldDescriptor, Kind, MessageDescriptor, MethodDescriptor};
use serde_json::{json, Map, Value};

use crate::config::{AliasConfig, OpenApiConfig};
use crate::transcode::request::BodyMapping;
use crate::transcode::rule::{self, HttpBinding, RouteMethod};
use crate::transcode::RpcSelection;
use crate::transcode::{self, httpbody, path};

/// The operations an OpenAPI 3.0 path item can hold, in the order a `*` rule
/// lists them.
const OPERATIONS: [&str; 8] = [
    "get", "put", "post", "delete", "options", "head", "patch", "trace",
];

/// Generate OpenAPI 3.0 JSON spec from a descriptor pool: the RPCs
/// `selection` transcodes, and their services as tags.
pub fn generate(
    pool: &DescriptorPool,
    config: &OpenApiConfig,
    aliases: &[AliasConfig],
    selection: &RpcSelection,
) -> Value {
    let title = config.title.as_deref().unwrap_or("API");
    let version = config.version.as_deref().unwrap_or("1.0.0");

    let mut paths = Map::new();
    let mut schemas = Map::new();
    let mut tags = Vec::new();
    let mut operation_ids = HashSet::new();
    let http_ext = pool.get_extension_by_name("google.api.http");
    // The router paths the routes mount: a template the router cannot match,
    // or one it refuses beside another, would promise a URL that is 404.
    let mounted = transcode::mounted_shapes(pool, aliases, selection);

    for service in pool.services() {
        if !selection.is_all() && !service.methods().any(|m| selection.selects(&m)) {
            continue;
        }
        let service_name = service.name().to_string();
        let service_full = service.full_name().to_string();

        // Proto comments as tag description.
        let tag_desc = get_comments(&service_full, pool);
        let mut tag = json!({ "name": service_name });
        if let Some(desc) = &tag_desc {
            tag["description"] = json!(desc);
        }
        tags.push(tag);

        let Some(http_ext) = &http_ext else {
            continue;
        };
        for method in service.methods() {
            // No REST mapping for client-streaming.
            if method.is_client_streaming() || !selection.selects(&method) {
                continue;
            }

            for binding in rule::http_bindings(&method, http_ext) {
                let operations = operation_methods(&binding.method);
                let expanded = operations.len() > 1;
                if operations.is_empty() {
                    continue;
                }
                let operation = build_operation(&method, &service_name, &binding, &mut schemas);
                for http_method in operations {
                    let mut id = format!("{service_name}.{}", method.name());
                    if expanded {
                        id = format!("{id}_{http_method}");
                    }

                    let mut targets = vec![binding.path.clone()];
                    for alias in aliases {
                        if let Some(suffix) = binding.path.strip_prefix(&alias.to) {
                            if alias.from.ends_with("/{path}") {
                                let prefix = alias.from.trim_end_matches("/{path}");
                                targets.push(format!("{prefix}{suffix}"));
                            }
                        }
                    }
                    for path in targets {
                        let mount = path::MountedPath::new(&path);
                        if mount.routable().is_err() || !mounted.contains(&mount.shape) {
                            continue;
                        }
                        let mut operation = operation.clone();
                        if http_method == "head" {
                            strip_response_content(&mut operation);
                        }
                        operation["operationId"] = json!(unique_id(&mut operation_ids, &id));
                        add_path_operation(&mut paths, &path, http_method, operation);
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

/// The OpenAPI operations a binding appears under: every one for a `*` rule,
/// the method's own for a method OpenAPI 3.0 has an operation for, and none for
/// any other method token (OpenAPI 3.0 cannot describe it).
fn operation_methods(method: &RouteMethod) -> Vec<&'static str> {
    let RouteMethod::One(method) = method else {
        return OPERATIONS.to_vec();
    };
    let operation = match *method {
        Method::GET => "get",
        Method::PUT => "put",
        Method::POST => "post",
        Method::DELETE => "delete",
        Method::OPTIONS => "options",
        Method::HEAD => "head",
        Method::PATCH => "patch",
        Method::TRACE => "trace",
        _ => return Vec::new(),
    };
    vec![operation]
}

/// Drop the content of every response: a HEAD response carries none
/// (RFC 9110 §9.3.2).
fn strip_response_content(operation: &mut Value) {
    if let Some(responses) = operation["responses"].as_object_mut() {
        for response in responses.values_mut() {
            if let Some(response) = response.as_object_mut() {
                response.remove("content");
            }
        }
    }
}

/// `base`, or `base_2`, `base_3`, ... when taken: OpenAPI requires every
/// `operationId` to be unique, and one RPC can be mounted several times
/// (additional bindings, aliases, a `*` rule).
fn unique_id(ids: &mut HashSet<String>, base: &str) -> String {
    let mut id = base.to_owned();
    let mut n = 1;
    while !ids.insert(id.clone()) {
        n += 1;
        id = format!("{base}_{n}");
    }
    id
}

fn add_path_operation(paths: &mut Map<String, Value>, path: &str, method: &str, operation: Value) {
    let path_item = paths.entry(path.to_string()).or_insert_with(|| json!({}));
    if let Some(obj) = path_item.as_object_mut() {
        obj.insert(method.to_string(), operation);
    }
}

/// Content of a raw `google.api.HttpBody`: any media type, as bytes.
fn raw_content() -> Value {
    json!({ "*/*": { "schema": { "type": "string", "format": "binary" } } })
}

/// The operation for one binding of `method`, without its `operationId`.
fn build_operation(
    method: &MethodDescriptor,
    service_name: &str,
    binding: &HttpBinding,
    schemas: &mut Map<String, Value>,
) -> Value {
    let method_name = method.name().to_string();
    let full_name = method.full_name().to_string();
    let input = method.input();
    let output = method.output();

    // Description from proto comments.
    let description = get_comments(&full_name, method.parent_pool()).unwrap_or_default();

    let mut op = json!({
        "tags": [service_name],
        "summary": method_name,
    });

    if !description.is_empty() {
        op["description"] = json!(description);
    }

    // Path parameters.
    let path_params = extract_path_params(&binding.path);
    let mut params: Vec<Value> = path_params
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

    // The body rule decides which fields travel in the body; every field
    // bound by neither the path nor the body is a query parameter.
    match &binding.body {
        BodyMapping::None => {}
        BodyMapping::Root => {
            let has_body_fields = input
                .fields()
                .any(|f| !path_params.contains(&f.name().to_string()));
            if httpbody::is_http_body(&input) {
                op["requestBody"] = json!({ "required": true, "content": raw_content() });
            } else if has_body_fields {
                let schema_name = input.name().to_string();
                let body_schema = message_to_schema(&input, &path_params, schemas);
                schemas.insert(schema_name.clone(), body_schema);
                op["requestBody"] = json!({
                    "required": true,
                    "content": {
                        "application/json": {
                            "schema": { "$ref": format!("#/components/schemas/{}", schema_name) },
                        },
                    },
                });
            }
        }
        BodyMapping::Field(name) => {
            if let Some(field) = input.get_field_by_name(name) {
                let content = if httpbody::http_body_field(&input, name).is_some() {
                    raw_content()
                } else {
                    register_nested(&field, schemas);
                    json!({ "application/json": { "schema": field_to_schema(&field) } })
                };
                op["requestBody"] = json!({ "required": true, "content": content });
            }
        }
    }
    let body_field = match &binding.body {
        BodyMapping::Field(name) => Some(name.as_str()),
        BodyMapping::None | BodyMapping::Root => None,
    };
    // With `body: "*"` the whole message is the body: no query parameters.
    if binding.body != BodyMapping::Root {
        params.extend(
            input
                .fields()
                .filter(|f| {
                    !path_params.contains(&f.name().to_string()) && body_field != Some(f.name())
                })
                .map(|field| {
                    // A message-typed parameter refers to its schema by `$ref`.
                    register_nested(&field, schemas);
                    json!({
                        "name": field.name(),
                        "in": "query",
                        "required": false,
                        "schema": field_to_schema(&field),
                    })
                }),
        );
    }
    if !params.is_empty() {
        op["parameters"] = json!(params);
    }

    // Response.
    let raw_response = match &binding.response_body {
        None => httpbody::is_http_body(&output),
        Some(path) => httpbody::http_body_path(&output, path).is_some(),
    };
    op["responses"] = if raw_response {
        let description = if method.is_server_streaming() {
            "Server-streaming raw body (the data of every message, concatenated)"
        } else {
            "Success"
        };
        json!({ "200": { "description": description, "content": raw_content() } })
    } else if method.is_server_streaming() {
        json!({
            "200": {
                "description": "Server-streaming response (NDJSON)",
                "content": {
                    "application/x-ndjson": {
                        "schema": message_ref_or_inline(&output, schemas),
                    },
                },
            },
        })
    } else if let Some(path) = &binding.response_body {
        // The answer is only the field `response_body` names.
        let schema = match response_field(&output, path) {
            Some(field) => {
                register_nested(&field, schemas);
                field_to_schema(&field)
            }
            // The runtime answers JSON `null` for a path that names no field.
            None => json!({ "nullable": true }),
        };
        json!({
            "200": {
                "description": "Success",
                "content": { "application/json": { "schema": schema } },
            },
        })
    } else if output.full_name() == "google.protobuf.Empty" {
        json!({ "200": { "description": "Success (empty response)" } })
    } else {
        let schema_name = output.name().to_string();
        let response_schema = message_to_schema(&output, &[], schemas);
        schemas.insert(schema_name.clone(), response_schema);
        json!({
            "200": {
                "description": "Success",
                "content": {
                    "application/json": {
                        "schema": { "$ref": format!("#/components/schemas/{}", schema_name) },
                    },
                },
            },
        })
    };

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

/// The field a (possibly dotted) `response_body` path names in `output`,
/// walking singular message fields.
fn response_field(output: &MessageDescriptor, path: &str) -> Option<FieldDescriptor> {
    let mut desc = output.clone();
    let mut segments = path.split('.').peekable();
    while let Some(segment) = segments.next() {
        let field = desc.get_field_by_name(segment)?;
        if segments.peek().is_none() {
            return Some(field);
        }
        match field.kind() {
            Kind::Message(inner) if !field.is_list() && !field.is_map() => desc = inner,
            _ => return None,
        }
    }
    None
}

/// Register the schema of a message-typed field so its `$ref` resolves. A
/// placeholder goes in before the fields are walked, so a message that
/// contains itself (directly or through others) is referenced rather than
/// expanded without end.
fn register_nested(field: &FieldDescriptor, schemas: &mut Map<String, Value>) {
    if let Kind::Message(nested) = field.kind() {
        if !is_well_known(&nested) && !schemas.contains_key(nested.name()) {
            schemas.insert(nested.name().to_string(), json!({ "type": "object" }));
            let nested_schema = message_to_schema(&nested, &[], schemas);
            schemas.insert(nested.name().to_string(), nested_schema);
        }
    }
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
        register_nested(&field, schemas);
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

/// Extract the field names of the `{param}` / `{param=template}` captures of a
/// path like `/v1/profiles/{profile_id}/devices`.
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
                // `{name=shelves/*}` binds the field `name`.
                let name = current.split('=').next().unwrap_or_default();
                if !name.is_empty() {
                    params.push(name.to_string());
                }
            }
            _ if in_brace => current.push(ch),
            _ => {}
        }
    }

    params
}

/// Get proto source comments for a given fully-qualified name.
fn get_comments(_full_name: &str, _pool: &DescriptorPool) -> Option<String> {
    // prost-reflect doesn't expose source code info comments easily.
    // For now, return None. Can be enhanced with protoc-gen-doc or
    // manual SourceCodeInfo parsing.
    None
}

#[cfg(test)]
mod tests;
