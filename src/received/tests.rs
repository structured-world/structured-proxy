use super::*;

/// The accessors give back what was recorded: a custom method, the path with
/// its percent-encoding untouched, the query, and the RPC path.
#[test]
fn a_received_request_keeps_what_was_received() {
    let received = ReceivedRequest::new(
        Method::from_bytes(b"PROPFIND").unwrap(),
        PathAndQuery::from_static("/v1/files/a%2Fb?depth=1"),
        PathAndQuery::from_static("/acme.v1.Files/Find"),
    );
    assert_eq!(received.method().as_str(), "PROPFIND");
    assert_eq!(received.path_and_query().path(), "/v1/files/a%2Fb");
    assert_eq!(received.path_and_query().query(), Some("depth=1"));
    assert_eq!(received.rpc(), "/acme.v1.Files/Find");
}
