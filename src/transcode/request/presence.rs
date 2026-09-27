//! The fields a request body sets, recorded while prost-reflect deserializes
//! it, so query parameters can fill only what the body left out.
//!
//! A proto3 field without explicit presence reads the same whether the body
//! set it to its default or omitted it, so presence cannot be read off the
//! built message: `{"count": 0}` must still beat `?count=5`. The body's keys
//! are recorded instead, during the one pass that builds the message, as the
//! body spelled them; they are matched against fields (by JSON or proto name)
//! only for the few keys a query names.

use prost_reflect::{FieldDescriptor, MessageDescriptor};
use serde::de::value::StringDeserializer;
use serde::de::{self, DeserializeSeed, Deserializer, IntoDeserializer, MapAccess, Visitor};
use std::fmt;

/// The keys set by the body, a path parameter or a form field, as a tree in
/// the order they were read (a parent before its children).
#[derive(Debug, Default)]
pub(super) struct Presence {
    /// Every key, back to back.
    names: String,
    entries: Vec<Entry>,
    /// Whether each nesting level matched the path being checked.
    matched: Vec<bool>,
    /// The body set the whole message at once (a well-known type read from
    /// its JSON form), so no query parameter can fill any of it.
    whole: bool,
}

#[derive(Debug)]
struct Entry {
    depth: u32,
    /// The key's bytes in `names`.
    start: u32,
    end: u32,
    /// The value was a JSON object, whose own keys are recorded below it; any
    /// other value (null, a string for a well-known type) sets the field as a
    /// whole.
    object: bool,
}

impl Presence {
    /// Room for the keys of a body of `len` bytes, up to a bound, so a
    /// typical body records without regrowing and a large one does not
    /// reserve memory in proportion to its size.
    pub(super) fn for_body(len: usize) -> Self {
        Self {
            names: String::with_capacity(len.min(512)),
            // A key and its value take at least 6 bytes: `"k":0,`.
            entries: Vec::with_capacity((len / 6).min(64)),
            matched: Vec::new(),
            whole: false,
        }
    }

    /// Forget what a body pass recorded, keeping the buffers.
    pub(super) fn clear(&mut self) {
        self.names.clear();
        self.entries.clear();
        self.whole = false;
    }

    /// The body set the whole message.
    pub(super) fn record_whole(&mut self) {
        self.whole = true;
    }

    /// Record `key` read at nesting level `depth`.
    fn record(&mut self, depth: usize, key: &str, object: bool) {
        let start = self.names.len();
        self.names.push_str(key);
        self.entries.push(Entry {
            depth: u32::try_from(depth).expect("fewer than 2^32 nesting levels"),
            start: u32::try_from(start).expect("keys shorter than 4 GiB"),
            end: u32::try_from(self.names.len()).expect("keys shorter than 4 GiB"),
            object,
        });
    }

    /// Record `path` as set by something other than the body: every field on
    /// the way as an object, the last one as an object when `object`.
    pub(super) fn record_path(&mut self, path: &[FieldDescriptor], object: bool) {
        for (depth, field) in path.iter().enumerate() {
            self.record(depth, field.name(), object || depth + 1 < path.len());
        }
    }

    /// The object the key recorded last holds.
    fn mark_object(&mut self) {
        if let Some(entry) = self.entries.last_mut() {
            entry.object = true;
        }
    }

    /// Whether a query parameter for `path` must leave it alone: the path was
    /// set, or a field above it was set to something other than an object.
    pub(super) fn blocks(&mut self, path: &[FieldDescriptor]) -> bool {
        if self.whole {
            return true;
        }
        // Entries come parent first, so each one matches when its parent did
        // and its own key names the field at its depth.
        self.matched.clear();
        for entry in &self.entries {
            let depth = entry.depth as usize;
            self.matched.truncate(depth);
            let parent = depth == 0 || self.matched.get(depth - 1) == Some(&true);
            let key = &self.names[entry.start as usize..entry.end as usize];
            let hit = parent
                && path
                    .get(depth)
                    .is_some_and(|field| key == field.name() || key == field.json_name());
            if hit && (depth + 1 == path.len() || !entry.object) {
                return true;
            }
            // Pad to this depth when a level was skipped under a non-match.
            self.matched.resize(depth, false);
            self.matched.push(hit);
        }
        false
    }
}

/// Whether prost-reflect reads `message` through its own JSON form rather than
/// as a map of fields (its list of well-known types).
pub(super) fn has_special_json(message: &MessageDescriptor) -> bool {
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

/// `inner`, recording into `presence` the keys of every JSON object
/// prost-reflect reads from it as a message. The values of a
/// `google.protobuf.Struct` are recorded too; no query parameter can reach
/// below one, so those entries never match.
pub(super) struct Recording<'p, D> {
    inner: D,
    presence: &'p mut Presence,
    depth: usize,
}

impl<'p, D> Recording<'p, D> {
    /// Record the keys of the input message `inner` holds, which prost-reflect
    /// reads as a map of fields (see [`has_special_json`]).
    pub(super) fn root(inner: D, presence: &'p mut Presence) -> Self {
        Self {
            inner,
            presence,
            depth: 0,
        }
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
            depth,
        } = self;
        inner.deserialize_option(OptionVisitor {
            visitor,
            presence,
            depth,
        })
    }

    fn deserialize_map<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, D::Error> {
        let Self {
            inner,
            presence,
            depth,
        } = self;
        inner.deserialize_map(MapVisitor {
            visitor,
            presence,
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
            depth: self.depth,
        })
    }
}

/// A message's JSON object, whose keys are recorded as they are read.
struct MapVisitor<'p, V> {
    visitor: V,
    presence: &'p mut Presence,
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
            depth: self.depth,
        })
    }
}

struct RecordingMap<'p, A> {
    inner: A,
    presence: &'p mut Presence,
    depth: usize,
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
        self.presence.record(self.depth, &key, false);
        let key: StringDeserializer<A::Error> = key.into_deserializer();
        seed.deserialize(key).map(Some)
    }

    fn next_value_seed<S: DeserializeSeed<'de>>(&mut self, seed: S) -> Result<S::Value, A::Error> {
        self.inner.next_value_seed(RecordingSeed {
            seed,
            presence: self.presence,
            depth: self.depth + 1,
        })
    }

    fn size_hint(&self) -> Option<usize> {
        self.inner.size_hint()
    }
}

struct RecordingSeed<'p, S> {
    seed: S,
    presence: &'p mut Presence,
    depth: usize,
}

impl<'de, S: DeserializeSeed<'de>> DeserializeSeed<'de> for RecordingSeed<'_, S> {
    type Value = S::Value;

    fn deserialize<D: Deserializer<'de>>(self, inner: D) -> Result<S::Value, D::Error> {
        self.seed.deserialize(Recording {
            inner,
            presence: self.presence,
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
