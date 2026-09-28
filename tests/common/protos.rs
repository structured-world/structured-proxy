//! Compiles a test `.proto` with `google.api.http` routes in memory, with no
//! protoc binary.

use prost_reflect::DescriptorPool;

/// Minimal `google/api/http.proto`: the fields the transcoder reads.
const HTTP_PROTO: &str = r#"
syntax = "proto3";
package google.api;
message HttpRule {
  string selector = 1;
  oneof pattern {
    string get = 2;
    string put = 3;
    string post = 4;
    string delete = 5;
    string patch = 6;
    CustomHttpPattern custom = 8;
  }
  string body = 7;
  string response_body = 12;
  repeated HttpRule additional_bindings = 11;
}
message CustomHttpPattern {
  string kind = 1;
  string path = 2;
}
"#;

/// `google/api/httpbody.proto`.
const HTTPBODY_PROTO: &str = r#"
syntax = "proto3";
package google.api;
import "google/protobuf/any.proto";
message HttpBody {
  string content_type = 1;
  bytes data = 2;
  repeated google.protobuf.Any extensions = 3;
}
"#;

const ANNOTATIONS_PROTO: &str = r#"
syntax = "proto3";
package google.api;
import "google/api/http.proto";
import "google/protobuf/descriptor.proto";
extend google.protobuf.MethodOptions {
  HttpRule http = 72295728;
}
"#;

/// Serves the google.api sources and one test file from memory, and the
/// `google/protobuf` files from protox's bundled Google files.
struct TestProtos {
    name: &'static str,
    source: &'static str,
}

impl protox::file::FileResolver for TestProtos {
    fn open_file(&self, name: &str) -> Result<protox::file::File, protox::Error> {
        let source = match name {
            "google/api/http.proto" => HTTP_PROTO,
            "google/api/annotations.proto" => ANNOTATIONS_PROTO,
            "google/api/httpbody.proto" => HTTPBODY_PROTO,
            _ if name == self.name => self.source,
            _ => return protox::file::GoogleFileResolver::new().open_file(name),
        };
        protox::file::File::from_source(name, source)
    }
}

/// Compile the test file `name` (which may import
/// `google/api/annotations.proto`) into a descriptor pool.
pub fn compile(name: &'static str, source: &'static str) -> DescriptorPool {
    protox::Compiler::with_file_resolver(TestProtos { name, source })
        .open_file(name)
        .expect("test protos compile")
        .descriptor_pool()
}
