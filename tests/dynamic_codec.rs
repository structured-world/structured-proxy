//! `DynamicCodec` over a real tonic client and server.
//!
//! A message whose fields all hold their default values encodes to zero bytes
//! (`google.protobuf.Empty` always does). Those frames must decode to the
//! default message on both ends, like tonic's own prost codec does; a decoder
//! that reads an empty frame as "no message" makes the server answer
//! `Missing request message` and leaves the client without its response.

use std::convert::Infallible;
use std::future::{ready, Ready};
use std::pin::Pin;
use std::task::{Context, Poll};

use prost::Message as _;
use prost_reflect::prost_types::{
    field_descriptor_proto::{Label, Type},
    DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
};
use prost_reflect::{DescriptorPool, DynamicMessage, MessageDescriptor, ReflectMessage};
use structured_proxy::transcode::codec::DynamicCodec;

/// `test.v1.Item { string name = 1; }`.
fn item_desc() -> MessageDescriptor {
    let item = DescriptorProto {
        name: Some("Item".to_string()),
        field: vec![FieldDescriptorProto {
            name: Some("name".to_string()),
            number: Some(1),
            label: Some(Label::Optional as i32),
            r#type: Some(Type::String as i32),
            ..Default::default()
        }],
        ..Default::default()
    };
    let file = FileDescriptorProto {
        name: Some("item.proto".to_string()),
        package: Some("test.v1".to_string()),
        message_type: vec![item],
        syntax: Some("proto3".to_string()),
        ..Default::default()
    };
    let fds = FileDescriptorSet { file: vec![file] };
    DescriptorPool::decode(fds.encode_to_vec().as_slice())
        .unwrap()
        .get_message_by_name("test.v1.Item")
        .unwrap()
}

fn item(desc: &MessageDescriptor, name: &str) -> DynamicMessage {
    let mut msg = DynamicMessage::new(desc.clone());
    msg.set_field_by_name("name", prost_reflect::Value::String(name.to_string()));
    msg
}

/// Answers `Item { name: "echo:" + request.name }`, or the default (empty)
/// Item when the request name is `"reply-empty"`.
#[derive(Clone)]
struct Echo {
    desc: MessageDescriptor,
}

impl tonic::server::UnaryService<DynamicMessage> for Echo {
    type Response = DynamicMessage;
    type Future = Ready<Result<tonic::Response<DynamicMessage>, tonic::Status>>;

    fn call(&mut self, request: tonic::Request<DynamicMessage>) -> Self::Future {
        let name = match request.get_ref().get_field_by_name("name").as_deref() {
            Some(prost_reflect::Value::String(name)) => name.clone(),
            _ => String::new(),
        };
        let reply = if name == "reply-empty" {
            DynamicMessage::new(self.desc.clone())
        } else {
            item(&self.desc, &format!("echo:{name}"))
        };
        ready(Ok(tonic::Response::new(reply)))
    }
}

#[derive(Clone)]
struct EchoService {
    desc: MessageDescriptor,
}

impl tonic::server::NamedService for EchoService {
    const NAME: &'static str = "test.v1.Echo";
}

impl tower::Service<http::Request<tonic::body::Body>> for EchoService {
    type Response = http::Response<tonic::body::Body>;
    type Error = Infallible;
    type Future =
        Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: http::Request<tonic::body::Body>) -> Self::Future {
        let desc = self.desc.clone();
        Box::pin(async move {
            let mut grpc = tonic::server::Grpc::new(DynamicCodec::new(desc.clone()));
            Ok(grpc.unary(Echo { desc }, req).await)
        })
    }
}

/// Call `test.v1.Echo/Call` with `request` on a fresh server.
async fn call(request: DynamicMessage) -> Result<DynamicMessage, tonic::Status> {
    let desc = request.descriptor();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = futures::stream::unfold(listener, |listener| async move {
        let conn = listener.accept().await.map(|(stream, _)| stream);
        Some((conn, listener))
    });
    tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(EchoService { desc: desc.clone() })
            .serve_with_incoming(incoming),
    );

    let channel = tonic::transport::Channel::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client = tonic::client::Grpc::new(channel);
    client.ready().await.unwrap();
    client
        .unary(
            tonic::Request::new(request),
            "/test.v1.Echo/Call".parse().unwrap(),
            DynamicCodec::new(desc),
        )
        .await
        .map(tonic::Response::into_inner)
}

#[tokio::test]
async fn server_decodes_an_all_default_request() {
    // The request encodes to zero bytes; the server must still see a request
    // (with the default, empty name) rather than fail with `INTERNAL`.
    let desc = item_desc();
    let reply = call(DynamicMessage::new(desc.clone())).await.unwrap();
    assert_eq!(reply, item(&desc, "echo:"));
}

#[tokio::test]
async fn client_decodes_an_all_default_response() {
    // The upstream answers with the default message (zero bytes on the wire);
    // the client must receive it instead of an error about a missing message.
    let desc = item_desc();
    let reply = call(item(&desc, "reply-empty")).await.unwrap();
    assert_eq!(reply, DynamicMessage::new(desc));
}

#[tokio::test]
async fn non_empty_messages_round_trip() {
    let desc = item_desc();
    let reply = call(item(&desc, "alice")).await.unwrap();
    assert_eq!(reply, item(&desc, "echo:alice"));
}
