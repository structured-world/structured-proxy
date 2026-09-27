//! The fields a request body sets, recorded while prost-reflect deserializes
//! it, so query parameters can fill only what the body left out.
//!
//! A proto3 field without explicit presence reads the same whether the body
//! set it to its default or omitted it, so presence cannot be read off the
//! built message: `{"count": 0}` must still beat `?count=5`. The body's keys
//! are recorded instead, by field number (a body may use the JSON or the proto
//! name), during the one pass that builds the message.

use prost_reflect::{Kind, MessageDescriptor};
use serde::de::value::StringDeserializer;
use serde::de::{self, DeserializeSeed, Deserializer, IntoDeserializer, MapAccess, Visitor};
use std::fmt;

/// Field paths set by the body or a path parameter, each a run of field
/// numbers from the input message down.
#[derive(Debug, Default)]
pub(super) struct Presence {
    /// Every recorded path, back to back.
    numbers: Vec<u32>,
    entries: Vec<Entry>,
    /// The path of the key being read, one number per nesting level.
    stack: Vec<u32>,
}

#[derive(Debug)]
struct Entry {
    start: usize,
    len: usize,
    /// The value was a JSON object, whose own keys are recorded below it; any
    /// other value (null, a string for a well-known type) sets the field as a
    /// whole.
    object: bool,
}

impl Presence {
    fn record(&mut self, depth: usize, number: u32) {
        self.stack.truncate(depth);
        self.stack.push(number);
        self.push(false);
    }

    /// Record `path` as set by something other than the body.
    pub(super) fn record_path(&mut self, path: &[u32], object: bool) {
        self.stack.clear();
        self.stack.extend_from_slice(path);
        self.push(object);
    }

    fn push(&mut self, object: bool) {
        let start = self.numbers.len();
        self.numbers.extend_from_slice(&self.stack);
        self.entries.push(Entry {
            start,
            len: self.stack.len(),
            object,
        });
    }

    /// The field whose key was recorded last holds an object.
    fn mark_object(&mut self) {
        if let Some(entry) = self.entries.last_mut() {
            entry.object = true;
        }
    }

    /// Whether a query parameter for `path` must leave it alone: the path was
    /// set, or a field above it was set to something other than an object.
    pub(super) fn blocks(&self, path: &[u32]) -> bool {
        self.entries.iter().any(|entry| {
            let set = &self.numbers[entry.start..entry.start + entry.len];
            set == path || (!entry.object && path.starts_with(set))
        })
    }
}

/// Whether prost-reflect reads `message` through its own JSON form rather than
/// as a map of fields (its list of well-known types).
fn has_special_json(message: &MessageDescriptor) -> bool {
    matches!(
        message.full_name(),
        "google.protobuf.Any"
            | "google.protobuf.Timestamp"
            | "google.protobuf.Duration"
            | "google.protobuf.Struct"
            | "google.protobuf.FloatValue"
            | "google.protobuf.DoubleValue"
            | "google.protobuf.Int32Value"
            | "google.protobuf.Int64Value"
            | "google.protobuf.UInt32Value"
            | "google.protobuf.UInt64Value"
            | "google.protobuf.BoolValue"
            | "google.protobuf.StringValue"
            | "google.protobuf.BytesValue"
            | "google.protobuf.FieldMask"
            | "google.protobuf.ListValue"
            | "google.protobuf.Value"
            | "google.protobuf.Empty"
    )
}

/// The message type below a field whose keys are recorded too: a singular
/// field of a message read as a map of fields.
fn nested(kind: Kind, list_or_map: bool) -> Option<MessageDescriptor> {
    match kind {
        Kind::Message(message) if !list_or_map && !has_special_json(&message) => Some(message),
        _ => None,
    }
}

/// `inner`, recording into `presence` the keys of the `desc` message it holds.
pub(super) struct Recording<'p, D> {
    inner: D,
    presence: &'p mut Presence,
    desc: MessageDescriptor,
    depth: usize,
}

impl<'p, D> Recording<'p, D> {
    /// Record the keys of the `input` message `inner` holds, or `None` when
    /// `input` is not read as a map of fields.
    pub(super) fn root(
        inner: D,
        presence: &'p mut Presence,
        input: &MessageDescriptor,
    ) -> Result<Self, D> {
        if has_special_json(input) {
            return Err(inner);
        }
        Ok(Self {
            inner,
            presence,
            desc: input.clone(),
            depth: 0,
        })
    }
}

/// Forward each listed `deserialize_*` call to the wrapped deserializer.
macro_rules! forward {
    ($($method:ident($($arg:ident: $ty:ty),*);)*) => {$(
        fn $method<V: Visitor<'de>>(self, $($arg: $ty,)* visitor: V) -> Result<V::Value, D::Error> {
            self.inner.$method($($arg,)* visitor)
        }
    )*};
}

impl<'de, D: Deserializer<'de>> Deserializer<'de> for Recording<'_, D> {
    type Error = D::Error;

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, D::Error> {
        let Self {
            inner,
            presence,
            desc,
            depth,
        } = self;
        inner.deserialize_option(OptionVisitor {
            visitor,
            presence,
            desc,
            depth,
        })
    }

    fn deserialize_map<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, D::Error> {
        let Self {
            inner,
            presence,
            desc,
            depth,
        } = self;
        inner.deserialize_map(MapVisitor {
            visitor,
            presence,
            desc,
            depth,
        })
    }

    forward! {
        deserialize_any();
        deserialize_bool();
        deserialize_i8();
        deserialize_i16();
        deserialize_i32();
        deserialize_i64();
        deserialize_i128();
        deserialize_u8();
        deserialize_u16();
        deserialize_u32();
        deserialize_u64();
        deserialize_u128();
        deserialize_f32();
        deserialize_f64();
        deserialize_char();
        deserialize_str();
        deserialize_string();
        deserialize_bytes();
        deserialize_byte_buf();
        deserialize_unit();
        deserialize_unit_struct(name: &'static str);
        deserialize_newtype_struct(name: &'static str);
        deserialize_seq();
        deserialize_tuple(len: usize);
        deserialize_tuple_struct(name: &'static str, len: usize);
        deserialize_struct(name: &'static str, fields: &'static [&'static str]);
        deserialize_enum(name: &'static str, variants: &'static [&'static str]);
        deserialize_identifier();
        deserialize_ignored_any();
    }

    fn is_human_readable(&self) -> bool {
        self.inner.is_human_readable()
    }
}

/// A field value that may be `null`: records below it only when present.
struct OptionVisitor<'p, V> {
    visitor: V,
    presence: &'p mut Presence,
    desc: MessageDescriptor,
    depth: usize,
}

impl<'de, V: Visitor<'de>> Visitor<'de> for OptionVisitor<'_, V> {
    type Value = V::Value;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.visitor.expecting(f)
    }

    fn visit_none<E: de::Error>(self) -> Result<V::Value, E> {
        self.visitor.visit_none()
    }

    fn visit_unit<E: de::Error>(self) -> Result<V::Value, E> {
        self.visitor.visit_unit()
    }

    fn visit_some<D: Deserializer<'de>>(self, inner: D) -> Result<V::Value, D::Error> {
        self.visitor.visit_some(Recording {
            inner,
            presence: self.presence,
            desc: self.desc,
            depth: self.depth,
        })
    }
}

/// A message's JSON object, whose keys are recorded as they are read.
struct MapVisitor<'p, V> {
    visitor: V,
    presence: &'p mut Presence,
    desc: MessageDescriptor,
    depth: usize,
}

impl<'de, V: Visitor<'de>> Visitor<'de> for MapVisitor<'_, V> {
    type Value = V::Value;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.visitor.expecting(f)
    }

    fn visit_map<A: MapAccess<'de>>(self, inner: A) -> Result<V::Value, A::Error> {
        if self.depth > 0 {
            self.presence.mark_object();
        }
        self.visitor.visit_map(RecordingMap {
            inner,
            presence: self.presence,
            desc: self.desc,
            depth: self.depth,
            below: None,
        })
    }
}

struct RecordingMap<'p, A> {
    inner: A,
    presence: &'p mut Presence,
    desc: MessageDescriptor,
    depth: usize,
    /// The message type of the value about to be read, when its keys are
    /// recorded too.
    below: Option<MessageDescriptor>,
}

impl<'de, A: MapAccess<'de>> MapAccess<'de> for RecordingMap<'_, A> {
    type Error = A::Error;

    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, A::Error> {
        // prost-reflect reads each key into an owned string anyway, so reading
        // it here first and handing it over costs no extra copy.
        let Some(key) = self.inner.next_key::<String>()? else {
            return Ok(None);
        };
        // The lookup prost-reflect makes: the JSON name, then the proto name.
        let field = self
            .desc
            .get_field_by_json_name(&key)
            .or_else(|| self.desc.get_field_by_name(&key));
        self.below = match field {
            Some(field) => {
                self.presence.record(self.depth, field.number());
                nested(field.kind(), field.is_list() || field.is_map())
            }
            None => None,
        };
        let key: StringDeserializer<A::Error> = key.into_deserializer();
        seed.deserialize(key).map(Some)
    }

    fn next_value_seed<S: DeserializeSeed<'de>>(&mut self, seed: S) -> Result<S::Value, A::Error> {
        match self.below.take() {
            Some(desc) => self.inner.next_value_seed(RecordingSeed {
                seed,
                presence: self.presence,
                desc,
                depth: self.depth + 1,
            }),
            None => self.inner.next_value_seed(seed),
        }
    }

    fn size_hint(&self) -> Option<usize> {
        self.inner.size_hint()
    }
}

struct RecordingSeed<'p, S> {
    seed: S,
    presence: &'p mut Presence,
    desc: MessageDescriptor,
    depth: usize,
}

impl<'de, S: DeserializeSeed<'de>> DeserializeSeed<'de> for RecordingSeed<'_, S> {
    type Value = S::Value;

    fn deserialize<D: Deserializer<'de>>(self, inner: D) -> Result<S::Value, D::Error> {
        self.seed.deserialize(Recording {
            inner,
            presence: self.presence,
            desc: self.desc,
            depth: self.depth,
        })
    }
}

/// A one-entry JSON object `{key: value}`, where `value` is another
/// deserializer: how a body bound to one field (`body: "field"`) reaches the
/// input message in the same pass as any other body.
pub(super) struct OneEntry<'k, D> {
    pub(super) key: &'k str,
    pub(super) value: D,
}

impl<'de, D: Deserializer<'de>> Deserializer<'de> for OneEntry<'_, D> {
    type Error = D::Error;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, D::Error> {
        visitor.visit_map(OneEntryAccess {
            key: Some(self.key),
            value: Some(self.value),
        })
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct seq tuple
        tuple_struct map struct enum identifier ignored_any
    }
}

struct OneEntryAccess<'k, D> {
    key: Option<&'k str>,
    value: Option<D>,
}

impl<'de, D: Deserializer<'de>> MapAccess<'de> for OneEntryAccess<'_, D> {
    type Error = D::Error;

    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, D::Error> {
        match self.key.take() {
            Some(key) => seed
                .deserialize(de::value::StrDeserializer::<D::Error>::new(key))
                .map(Some),
            None => Ok(None),
        }
    }

    fn next_value_seed<S: DeserializeSeed<'de>>(&mut self, seed: S) -> Result<S::Value, D::Error> {
        let value = self
            .value
            .take()
            .expect("serde reads a value only after its key");
        seed.deserialize(value)
    }

    fn size_hint(&self) -> Option<usize> {
        Some(usize::from(self.key.is_some()))
    }
}
