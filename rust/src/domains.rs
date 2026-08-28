// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

pub mod arbitrary;
pub mod containers;
pub mod range;
pub mod tuple_of;
pub mod utility;
use ::serde::de::DeserializeOwned;
use ::serde::Serialize;

use anyhow;
use anyhow::Context;

use std::any::Any;

pub trait CloneAny: Any {
    fn clone_box(&self) -> Box<dyn CloneAny>;
    fn as_any(&self) -> &dyn Any;
    fn as_mut_any(&mut self) -> &mut dyn Any;
}

impl dyn CloneAny {
    pub fn downcast_ref<T: Any>(&self) -> Option<&T> {
        self.as_any().downcast_ref::<T>()
    }

    pub fn downcast_mut<T: Any>(&mut self) -> Option<&mut T> {
        self.as_mut_any().downcast_mut::<T>()
    }
}

impl<T: Any + Clone> CloneAny for T {
    fn clone_box(&self) -> Box<dyn CloneAny> {
        if let Some(boxed) = self.as_any().downcast_ref::<Box<dyn CloneAny>>() {
            return (**boxed).clone_box();
        }
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_mut_any(&mut self) -> &mut dyn Any {
        self
    }
}

impl Clone for Box<dyn CloneAny> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

/// Type alias for a type-erased corpus value.
pub type GenericCorpusValue = Box<dyn CloneAny>;

/// Type alias for a type-erased user value.
pub type GenericUserValue = Box<dyn CloneAny>;

pub trait Domain: 'static {
    /// The user-facing type representing values in this domain.
    type UserValue<'user>;

    /// The type representing the value stored in the corpus for this domain.
    type CorpusValue: Serialize + DeserializeOwned + Clone;

    /// Produces a new initial `CorpusValue` for this domain.
    fn init(&mut self, rng: &mut dyn rand::Rng) -> anyhow::Result<Self::CorpusValue>;

    /// Mutates the given `corpus_value` in place.
    fn mutate(
        &mut self,
        corpus_value: &mut Self::CorpusValue,
        rng: &mut dyn rand::Rng,
        only_shrink: bool,
    ) -> anyhow::Result<()>;

    /// Obtains a `UserValue` from a `corpus_value`.
    fn get_user_value<'a>(
        &self,
        corpus_value: &'a Self::CorpusValue,
    ) -> anyhow::Result<Self::UserValue<'a>>;

    /// Deserializes a `CorpusValue` from a byte slice.
    fn parse_corpus(&self, data: &[u8]) -> anyhow::Result<Self::CorpusValue> {
        postcard::from_bytes(data).context("Failed to deserialize corpus value from bytes")
    }

    /// Serializes `corpus_value` to a Vec of bytes (ie, Vec<u8>).
    fn serialize_corpus(&self, corpus_value: &Self::CorpusValue) -> anyhow::Result<Vec<u8>> {
        postcard::to_stdvec(corpus_value).context("Failed to serialize corpus value to bytes")
    }

    /// Converts a user value to a corpus value.
    #[allow(clippy::wrong_self_convention)]
    fn from_value(&self, value: Self::UserValue<'_>) -> anyhow::Result<Self::CorpusValue>;

    /// Validates that a corpus value satisfies the domain's constraints.
    fn validate_corpus_value(&self, _corpus_value: &Self::CorpusValue) -> anyhow::Result<()> {
        Ok(())
    }
}

pub trait GenericDomain {
    fn init(&mut self, rng: &mut dyn rand::Rng) -> anyhow::Result<GenericCorpusValue>;
    fn mutate(
        &mut self,
        val: &mut GenericCorpusValue,
        rng: &mut dyn rand::Rng,
        only_shrink: bool,
    ) -> anyhow::Result<()>;
    fn parse_corpus(&self, data: &[u8]) -> anyhow::Result<GenericCorpusValue>;
    fn serialize_corpus(&self, val: &GenericCorpusValue) -> anyhow::Result<Vec<u8>>;
}

impl<D> GenericDomain for D
where
    D: Domain,
    D::CorpusValue: 'static,
{
    fn init(&mut self, rng: &mut dyn rand::Rng) -> anyhow::Result<GenericCorpusValue> {
        Ok(Box::new(self.init(rng)?))
    }

    fn mutate(
        &mut self,
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

    fn parse_corpus(&self, data: &[u8]) -> anyhow::Result<GenericCorpusValue> {
        Ok(Box::new(self.parse_corpus(data)?))
    }

    fn serialize_corpus(&self, val: &GenericCorpusValue) -> anyhow::Result<Vec<u8>> {
        self.serialize_corpus(val.downcast_ref().context("Failed to retrieve the Corpus Value")?)
    }
}
