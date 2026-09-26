use super::*;

/// A pool compiled from one in-memory `.proto` source.
fn pool(source: &str) -> prost_reflect::DescriptorPool {
    struct OneFile(String);
    impl protox::file::FileResolver for OneFile {
        fn open_file(&self, name: &str) -> Result<protox::file::File, protox::Error> {
            if name == "test.proto" {
                protox::file::File::from_source(name, &self.0)
            } else {
                protox::file::GoogleFileResolver::new().open_file(name)
            }
        }
    }
    protox::Compiler::with_file_resolver(OneFile(source.to_owned()))
        .open_file("test.proto")
        .expect("test proto compiles")
        .descriptor_pool()
}

const REQUIRED: &str = "syntax = \"proto2\"; package t; \
    message Leaf { required string id = 1; } \
    message Holder { optional Leaf one = 1; repeated Leaf many = 2; map<string, Leaf> by_key = 3; } \
    message Tree { optional string name = 1; repeated Tree children = 2; } \
    message Loose { optional string note = 1; }";

fn leaf(pool: &prost_reflect::DescriptorPool, id: Option<&str>) -> Value {
    let mut leaf = DynamicMessage::new(pool.get_message_by_name("t.Leaf").unwrap());
    if let Some(id) = id {
        leaf.set_field_by_name("id", Value::String(id.into()));
    }
    Value::Message(leaf)
}

#[test]
fn required_fields_are_found_at_any_depth_and_recursion_ends() {
    // Holder has no required field itself but contains Leaf; Tree refers to
    // itself and has none, so the walk must stop rather than loop.
    let pool = pool(REQUIRED);
    let desc = |name: &str| pool.get_message_by_name(name).unwrap();
    assert!(has_required_fields(&desc("t.Leaf")));
    assert!(has_required_fields(&desc("t.Holder")));
    assert!(!has_required_fields(&desc("t.Tree")));
    assert!(!has_required_fields(&desc("t.Loose")));
}

#[test]
fn missing_required_field_is_reported_wherever_it_sits() {
    // An unset required field is reported through a singular field, a
    // repeated element or a map value; a fully set message reports nothing.
    let pool = pool(REQUIRED);
    let holder = || DynamicMessage::new(pool.get_message_by_name("t.Holder").unwrap());

    let mut one = holder();
    one.set_field_by_name("one", leaf(&pool, None));
    let mut many = holder();
    many.set_field_by_name(
        "many",
        Value::List(vec![leaf(&pool, Some("a")), leaf(&pool, None)]),
    );
    let mut by_key = holder();
    let mut entries = std::collections::HashMap::new();
    entries.insert(prost_reflect::MapKey::String("k".into()), leaf(&pool, None));
    by_key.set_field_by_name("by_key", Value::Map(entries));
    for msg in [one, many, by_key] {
        assert_eq!(
            missing_required(&msg).as_deref(),
            Some("t.Leaf.id"),
            "{msg:?}"
        );
    }

    let mut complete = holder();
    complete.set_field_by_name("one", leaf(&pool, Some("a")));
    complete.set_field_by_name("many", Value::List(vec![leaf(&pool, Some("b"))]));
    assert_eq!(missing_required(&complete), None);
    assert_eq!(missing_required(&holder()), None);
}
