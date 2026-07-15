pub mod arbitrary;
pub mod range;
pub mod tuple_of;
pub mod utility;

use anyhow;
use anyhow::Context;

/// Type alias for a type-erased corpus value.
pub type GenericCorpusValue = Box<dyn std::any::Any>;

/// Type alias for a type-erased user value.
pub type GenericUserValue = Box<dyn std::any::Any>;

/// A trait for types that represent a set of values that an input can take.
///
/// Domain types are used to represent the domain of values that a fuzz test input can take
/// throughout the fuzzing process.
/// Domain types are used by the fuzzing engine through the APIs defined in this trait.
///
/// ## Serialization/Deserialization of CorpusValue and UserValue relationship.
///
/// The values drawn from a domain are always of type `CorpusValue`. These values are the
/// internal representation of the value and they are not directly usable by the fuzz property
/// function.
///
/// The `get_user_value` method is used to retrieve the user value from the corpus value. For
/// example, if the domain outputs an `&str` then the CorpusValue could be a `String` and the
/// `get_user_value` method would be used to retrieve the `&str` from the `String`.
///
/// The `parse_corpus` (resp. `serialize_corpus`) method is used deserialize (resp. serialize)
/// the corpus value from (to) a slice of bytes (resp. a vector of bytes).
///
/// ### Relationship diagram
///
/// The methods below are responsible for transforming between `UserValue`, `CorpusValue`, and the
/// serialized representation of `CorpusValue`. Here's a quick overview:
///
/// ```text
///        +-- get_user_value() <---+     +-- parse_corpus() <---+
///        |                        |     |                      |
///        v                        |     v                      |
///   UserValue<'a>               CorpusValue                  &[u8]
///                                       |                      ^
///                                       |                      |
///                                       +-> serialize_corpus() +
/// ```
pub trait Domain {
    /// The type of the values that the domain outputs. This should of the same type as the
    /// parameter of the fuzz property function.
    type UserValue<'user>;
    /// The type of the corpus from which the values of type UserValue are drawn.
    /// For example, if the domain should output an `&str` then the UserValue should be `&str` and
    /// the CorpusValue could the owned data structured that the `&str` points to (eg: String).
    /// The CorpusValue type should implement `serde::Serialize` and `serde::de::DeserializeOwned`.
    type CorpusValue: ::serde::Serialize + ::serde::de::DeserializeOwned;

    /// Initializes a new value drawn from the domain.
    fn init(&self, rng: &mut dyn rand::Rng) -> anyhow::Result<Self::CorpusValue>;

    /// Mutates the value in `val` to a new value drawn from the domain.
    ///
    /// If `only_shrink` is `true`, then the mutation must not increase the size of the corpus
    /// value. Otherwise, the mutation can both shrink and grow the corpus value.
    fn mutate(
        &self,
        val: &mut Self::CorpusValue,
        rng: &mut dyn rand::Rng,
        only_shrink: bool,
    ) -> anyhow::Result<()>;

    /// Retrieves a UserValue from a given CorpusValue.
    ///
    /// This is used to convert the corpus value into the user value that can then be passed to the
    /// fuzz property function.
    fn get_user_value<'a>(
        &self,
        corpus_value: &'a Self::CorpusValue,
    ) -> anyhow::Result<Self::UserValue<'a>>;

    /// Turns a slice of bytes into `CorpusValue`.
    ///
    /// By default, it uses Postcard to deserialize the data.
    fn parse_corpus(&self, data: &[u8]) -> anyhow::Result<Self::CorpusValue> {
        postcard::from_bytes(data).context("Failed to deserialize corpus value from bytes")
    }

    /// Serializes `corpus_value` to a Vec of bytes (ie, Vec<u8>).
    ///
    /// By default, it uses Postcard to serialize the data.
    fn serialize_corpus(&self, corpus_value: &Self::CorpusValue) -> anyhow::Result<Vec<u8>> {
        postcard::to_stdvec(corpus_value).context("Failed to serialize corpus value to bytes")
    }
}

/// A type-erased interface for Domain types.
///
/// This trait is used to expose a common interface for Domain types to the fuzzing engine through
/// the `FuzzTest` trait.
/// The methods of this trait are similar to that of the `Domain` trait, but they operate on
/// a type-erased `GenericCorpusValue` instead of an explicit type.
pub trait GenericDomain {
    /// Initializes a new value drawn from the domain.
    ///
    /// See `Domain::init` for more details.
    fn init(&self, rng: &mut dyn rand::Rng) -> anyhow::Result<GenericCorpusValue>;

    /// Mutates the value in `val` to a new value drawn from the domain.
    ///
    /// See `Domain::mutate` for more details.
    fn mutate(
        &self,
        val: &mut GenericCorpusValue,
        rng: &mut dyn rand::Rng,
        only_shrink: bool,
    ) -> anyhow::Result<()>;

    /// Parses a slice of bytes into a `GenericCorpusValue`.
    ///
    /// See `Domain::parse_corpus` for more details.
    fn parse_corpus(&self, data: &[u8]) -> anyhow::Result<GenericCorpusValue>;

    /// Serializes a `GenericCorpusValue` to a Vec of bytes (ie, Vec<u8>).
    ///
    /// See `Domain::serialize_corpus` for more details.
    fn serialize_corpus(&self, val: &GenericCorpusValue) -> anyhow::Result<Vec<u8>>;
}

/// Blanket implementation of the `GenericDomain` trait for types implementing the `Domain` trait.
///
/// This implementation is a simple pass-through implementation that uses the methods of the
/// `Domain` trait to implement the `GenericDomain` trait.
impl<D> GenericDomain for D
where
    D: Domain,
    D::CorpusValue: 'static,
{
    fn init(&self, rng: &mut dyn rand::Rng) -> anyhow::Result<GenericCorpusValue> {
        Ok(Box::new(self.init(rng)?))
    }

    /// Retrieves the underlying `Domain`'s `CorpusValue` from the `GenericCorpusValue` and calls
    /// the underlying `Domain::mutate` method.
    ///
    /// If the `GenericCorpusValue` cannot be downcasted to the underlying `Domain`'s `CorpusValue`
    /// then an Error is returned.
    ///
    /// See `GenericDomain::mutate` for more details.
    fn mutate(
        &self,
        val: &mut GenericCorpusValue,
        rng: &mut dyn rand::Rng,
        only_shrink: bool,
    ) -> anyhow::Result<()> {
        self.mutate(
            val.downcast_mut().context("Failed to retrieve the Corpus Value")?,
            rng,
            only_shrink,
        )
    }

    /// Calls the underlying `Domain::parse_corpus` method with the `data` and wraps the resulting
    /// `CorpusValue` in a `GenericCorpusValue`.
    ///
    /// See `GenericDomain::parse_corpus` for more details.
    fn parse_corpus(&self, data: &[u8]) -> anyhow::Result<GenericCorpusValue> {
        Ok(Box::new(self.parse_corpus(data)?))
    }

    /// Retrieves the underlying `Domain`'s `CorpusValue` from the `GenericCorpusValue` and calls
    /// the underlying `Domain::serialize_corpus` method.
    ///
    /// If the `GenericCorpusValue` cannot be downcasted to the underlying `Domain`'s `CorpusValue`
    /// then an Error is returned.
    ///
    /// See `GenericDomain::serialize_corpus` for more details.
    fn serialize_corpus(&self, val: &GenericCorpusValue) -> anyhow::Result<Vec<u8>> {
        self.serialize_corpus(val.downcast_ref().context("Failed to retrieve the Corpus Value")?)
    }
}
