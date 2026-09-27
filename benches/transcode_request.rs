//! Building the gRPC request message of one transcoded HTTP request: a GET
//! bound from path and query parameters, and a POST with a nested JSON body
//! plus a query string.

use std::collections::HashMap;
use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use prost_reflect::{DynamicMessage, MessageDescriptor};
use structured_proxy::transcode::request;

const PROTO: &str = r#"
syntax = "proto3";
package bench.v1;
import "google/protobuf/timestamp.proto";

enum Size {
  SIZE_UNSPECIFIED = 0;
  SMALL = 1;
  LARGE = 2;
}

message Address {
  string city = 1;
  string zip = 2;
  repeated string lines = 3;
}

message Req {
  string name = 1;
  int64 count = 2;
  repeated string tags = 3;
  Address address = 4;
  bool active = 5;
  google.protobuf.Timestamp at = 6;
  Size size = 7;
  double score = 8;
}
"#;

/// Serves the bench proto from memory and `google/protobuf` from protox.
struct Protos;

impl protox::file::FileResolver for Protos {
    fn open_file(&self, name: &str) -> Result<protox::file::File, protox::Error> {
        match name {
            "bench.proto" => protox::file::File::from_source(name, PROTO),
            _ => protox::file::GoogleFileResolver::new().open_file(name),
        }
    }
}

fn request_type() -> MessageDescriptor {
    protox::Compiler::with_file_resolver(Protos)
        .open_file("bench.proto")
        .expect("bench proto compiles")
        .descriptor_pool()
        .get_message_by_name("bench.v1.Req")
        .expect("bench.v1.Req")
}

const GET_QUERY: &str = "count=7&tags=a&tags=b&address.city=berlin&active=true&size=LARGE";

const POST_BODY: &str = r#"{"name":"beta","count":"3","tags":["x","y","z"],"address":{"city":"paris","zip":"75001","lines":["1 rue de la Paix","2e etage"]},"active":true,"at":"2026-01-01T00:00:00Z","size":"SMALL","score":1.5}"#;

const POST_QUERY: &str = "active=false&address.zip=00000&count=9";

/// The message a request maps onto, built the way the transcoder builds it.
fn build(
    input: &MessageDescriptor,
    mapping: &request::BodyMapping,
    body_bytes: &[u8],
    path: &HashMap<String, String>,
    raw_query: &str,
) -> DynamicMessage {
    let body = match mapping {
        request::BodyMapping::None => request::Body::Absent,
        _ => request::Body::new(Some("application/json"), body_bytes),
    };
    let query = (!raw_query.is_empty()).then_some(raw_query);
    request::build_request_message(input, mapping, body, path, query).unwrap()
}

fn bench(c: &mut Criterion) {
    let input = request_type();
    let mut group = c.benchmark_group("transcode_request");

    let path: HashMap<String, String> = [("name".to_owned(), "alpha".to_owned())].into();
    let none = request::BodyMapping::None;
    group.bench_function("get_path_and_query", |b| {
        b.iter(|| black_box(build(&input, &none, b"", &path, GET_QUERY)))
    });

    let no_path = HashMap::new();
    let root = request::BodyMapping::Root;
    // Without a query nothing has to track which fields the body set.
    group.bench_function("post_nested_body", |b| {
        b.iter(|| black_box(build(&input, &root, POST_BODY.as_bytes(), &no_path, "")))
    });
    // A query that binds nothing: the cost of tracking the body's fields.
    group.bench_function("post_nested_body_unbound_query", |b| {
        b.iter(|| {
            black_box(build(
                &input,
                &root,
                POST_BODY.as_bytes(),
                &no_path,
                "unbound=1",
            ))
        })
    });
    group.bench_function("post_nested_body_and_query", |b| {
        b.iter(|| {
            black_box(build(
                &input,
                &root,
                POST_BODY.as_bytes(),
                &no_path,
                POST_QUERY,
            ))
        })
    });
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
