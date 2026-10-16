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

//! Domain seeding support for FuzzTest.
//!
//! Seeding lets a domain occasionally return user-chosen values from
//! [`Domain::init`](crate::domains::Domain::init). This mirrors the C++ FuzzTest
//! `.WithSeeds(...)` functionality.
//!
//! When seeds are present, [`Domain::init`](crate::domains::Domain::init) returns a uniformly
//! chosen seed with probability 1/2; otherwise, it delegates to the inner domain. Other domain
//! operations—such as [`Domain::mutate`](crate::domains::Domain::mutate), serialization,
//! parsing, and validation—always delegate directly to the inner domain.
//!
//! # Eager Seeds vs. Lazy Providers
//!
//! - **Eager seeds** ([`SeedableDomainExt::with_seeds`]) are converted and validated immediately
//!   when added, panicking if any seed is invalid for the domain.
//! - **Lazy seed providers** ([`SeedableDomainExt::with_seed_provider`]) run once, on the first
//!   call to [`Domain::init`](crate::domains::Domain::init), and panic if any produced seed is
//!   invalid.
//!
//! # Compile-time Opt-in via [`UserValueConstructible`]
//!
//! Seeding is opt-in per domain via the [`UserValueConstructible`] trait. Domains whose corpus
//! value cannot be reconstructed from a user value (such as one-way maps or irreversible
//! transformations) cannot be seeded. This provides a compile-time guarantee against seeding
//! incompatible domains, in contrast to the runtime failure in C++ FuzzTest `WithSeeds`.
//!
//! # Order of Configuration
//!
//! Configure inner-domain constraints (such as `VecOf::with_max_len`) *before* seeding. Seeds
//! are validated against the domain at the time they are added (or upon first initialization for
//! providers), and [`Seeded`] does not forward domain-specific constraint setters.
//!
//! # Examples
//!
//! ```rust
//! use fuzztest::domains::{Domain, SeedableDomainExt, UserValueConstructible};
//! use fuzztest::reexports::anyhow;
//! use fuzztest::reexports::rand::rngs::SmallRng;
//! use fuzztest::reexports::rand::RngExt;
//! use fuzztest::reexports::rand::SeedableRng;
//!
//! #[derive(Clone, Debug)]
//! struct Percent;
//!
//! impl Domain for Percent {
//!     type UserValue<'user> = u8;
//!     type CorpusValue = u8;
//!
//!     fn init(
//!         &mut self,
//!         rng: &mut dyn fuzztest::reexports::rand::Rng,
//!     ) -> anyhow::Result<Self::CorpusValue> {
//!         Ok(rng.random_range(0..=100))
//!     }
//!
//!     fn mutate(
//!         &mut self,
//!         corpus_value: &mut Self::CorpusValue,
//!         rng: &mut dyn fuzztest::reexports::rand::Rng,
//!         _only_shrink: bool,
//!     ) -> anyhow::Result<()> {
//!         *corpus_value = self.init(rng)?;
//!         Ok(())
//!     }
//!
//!     fn corpus_to_user_value<'a>(
//!         &self,
//!         corpus_value: &'a Self::CorpusValue,
//!     ) -> anyhow::Result<Self::UserValue<'a>> {
//!         Ok(*corpus_value)
//!     }
//!
//!     fn validate_corpus_value(&self, corpus_value: &Self::CorpusValue) -> anyhow::Result<()> {
//!         anyhow::ensure!(*corpus_value <= 100, "percent {corpus_value} exceeds 100");
//!         Ok(())
//!     }
//! }
//!
//! impl UserValueConstructible for Percent {
//!     fn user_to_corpus_value<'a>(
//!         &self,
//!         value: Self::UserValue<'a>,
//!     ) -> anyhow::Result<Self::CorpusValue> {
//!         Ok(value)
//!     }
//! }
//!
//! let mut domain = Percent
//!     .with_seeds([0, 100])
//!     .with_seed_provider(|| vec![50]);
//! let mut rng = SmallRng::seed_from_u64(73);
//! let value = domain.init(&mut rng).unwrap();
//! assert!(value <= 100);
//! ```

use super::Domain;

use anyhow::Context;
use rand::RngExt;

use std::fmt;
use std::mem;

/// Allows constructing domain corpus values from user values.
///
/// Implementing this trait is what makes a domain seedable via the blanket
/// [`SeedableDomainExt`] implementation. It represents the inverse of
/// [`Domain::corpus_to_user_value`](super::Domain::corpus_to_user_value).
///
/// Implementations must only convert the value and must **not** perform validation;
/// callers validate the converted corpus value via
/// [`Domain::validate_corpus_value`](super::Domain::validate_corpus_value).
///
/// # Errors
///
/// Returns an error if the user value cannot be represented as a corpus value for
/// this domain.
pub trait UserValueConstructible: Domain {
    /// Converts a user value into an internal corpus value.
    ///
    /// Implementations must only convert the value without validating domain constraints.
    ///
    /// # Errors
    ///
    /// Returns an error if `value` cannot be converted into a valid corpus representation.
    fn user_to_corpus_value<'a>(
        &self,
        value: Self::UserValue<'a>,
    ) -> anyhow::Result<Self::CorpusValue>;
}

/// Extension trait providing seeding methods for domains implementing [`UserValueConstructible`].
///
/// Blanket-implemented for all types that implement [`UserValueConstructible`]. Each method
/// wraps the domain in a [`Seeded<Self>`].
pub trait SeedableDomainExt: UserValueConstructible + Sized {
    /// Adds pre-defined seeds to the domain.
    ///
    /// Seeds are converted and validated immediately against the domain.
    ///
    /// # Panics
    ///
    /// Panics if any seed fails conversion or validation for this domain. The panic message
    /// includes the index of the failing seed.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use fuzztest::domains::{Domain, SeedableDomainExt, UserValueConstructible};
    /// # use fuzztest::reexports::anyhow;
    /// # use fuzztest::reexports::rand::RngExt;
    /// #
    /// # #[derive(Clone, Debug)]
    /// # struct Percent;
    /// # impl Domain for Percent {
    /// #     type UserValue<'user> = u8;
    /// #     type CorpusValue = u8;
    /// #     fn init(&mut self, rng: &mut dyn fuzztest::reexports::rand::Rng) -> anyhow::Result<Self::CorpusValue> {
    /// #         Ok(rng.random_range(0..=100))
    /// #     }
    /// #     fn mutate(&mut self, corpus_value: &mut Self::CorpusValue, rng: &mut dyn fuzztest::reexports::rand::Rng, _only_shrink: bool) -> anyhow::Result<()> {
    /// #         *corpus_value = self.init(rng)?;
    /// #         Ok(())
    /// #     }
    /// #     fn corpus_to_user_value<'a>(&self, corpus_value: &'a Self::CorpusValue) -> anyhow::Result<Self::UserValue<'a>> {
    /// #         Ok(*corpus_value)
    /// #     }
    /// #     fn validate_corpus_value(&self, corpus_value: &Self::CorpusValue) -> anyhow::Result<()> {
    /// #         anyhow::ensure!(*corpus_value <= 100);
    /// #         Ok(())
    /// #     }
    /// # }
    /// # impl UserValueConstructible for Percent {
    /// #     fn user_to_corpus_value<'a>(&self, value: Self::UserValue<'a>) -> anyhow::Result<Self::CorpusValue> {
    /// #         Ok(value)
    /// #     }
    /// # }
    /// #
    /// let domain = Percent.with_seeds([0, 50, 100]);
    /// ```
    fn with_seeds<'a>(self, seeds: impl IntoIterator<Item = Self::UserValue<'a>>) -> Seeded<Self> {
        Seeded::new(self).with_seeds(seeds)
    }

    /// Adds a lazy seed provider evaluated on first sampling.
    ///
    /// The provider is invoked at most once per [`Seeded`] instance on the first call to
    /// [`Domain::init`](super::Domain::init). Multiple providers can be added, and all will
    /// contribute their seeds.
    ///
    /// The provider closure requires `F: FnOnce() -> I + Clone + Send + 'static`. The `FnOnce`
    /// bound allows moving captured data out of the closure. The `Clone` bound ensures that if a
    /// [`Seeded`] instance is cloned before its first [`Domain::init`](super::Domain::init), the
    /// clone receives its own independent copy of the provider.
    ///
    /// # Panics
    ///
    /// Panics on the first call to [`Domain::init`](super::Domain::init) if the provider yields
    /// a seed that fails conversion or validation.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use fuzztest::domains::{Domain, SeedableDomainExt, UserValueConstructible};
    /// # use fuzztest::reexports::anyhow;
    /// # use fuzztest::reexports::rand::RngExt;
    /// #
    /// # #[derive(Clone, Debug)]
    /// # struct Percent;
    /// # impl Domain for Percent {
    /// #     type UserValue<'user> = u8;
    /// #     type CorpusValue = u8;
    /// #     fn init(&mut self, rng: &mut dyn fuzztest::reexports::rand::Rng) -> anyhow::Result<Self::CorpusValue> {
    /// #         Ok(rng.random_range(0..=100))
    /// #     }
    /// #     fn mutate(&mut self, corpus_value: &mut Self::CorpusValue, rng: &mut dyn fuzztest::reexports::rand::Rng, _only_shrink: bool) -> anyhow::Result<()> {
    /// #         *corpus_value = self.init(rng)?;
    /// #         Ok(())
    /// #     }
    /// #     fn corpus_to_user_value<'a>(&self, corpus_value: &'a Self::CorpusValue) -> anyhow::Result<Self::UserValue<'a>> {
    /// #         Ok(*corpus_value)
    /// #     }
    /// #     fn validate_corpus_value(&self, corpus_value: &Self::CorpusValue) -> anyhow::Result<()> {
    /// #         anyhow::ensure!(*corpus_value <= 100);
    /// #         Ok(())
    /// #     }
    /// # }
    /// # impl UserValueConstructible for Percent {
    /// #     fn user_to_corpus_value<'a>(&self, value: Self::UserValue<'a>) -> anyhow::Result<Self::CorpusValue> {
    /// #         Ok(value)
    /// #     }
    /// # }
    /// #
    /// let domain = Percent.with_seed_provider(move || vec![0, 50, 100]);
    /// ```
    fn with_seed_provider<'a, F, I>(self, seed_provider: F) -> Seeded<Self>
    where
        F: FnOnce() -> I + Clone + Send + 'static,
        I: IntoIterator<Item = Self::UserValue<'a>>,
    {
        Seeded::new(self).with_seed_provider(seed_provider)
    }
}

impl<D: UserValueConstructible> SeedableDomainExt for D {}

/// A type-erased, cloneable `FnOnce` provider for seeds.
///
/// Standard `FnOnce` closures cannot be called through a trait object (`dyn FnOnce`) by value
/// in stable Rust without unsized rvalues. By using `call_once(self: Box<Self>, domain: &D)`,
/// this trait is dyn-compatible and allows calling the provider by value out of a `Box`.
///
/// The `clone_box` method enables cloning trait objects (`Box<dyn CloneableSeedProvider<D>>`),
/// which allows `Seeded<D>` to implement `Clone` even when seed providers are pending.
trait CloneableSeedProvider<D: Domain>: Send {
    fn call_once(self: Box<Self>, domain: &D) -> anyhow::Result<Vec<D::CorpusValue>>;
    fn clone_box(&self) -> Box<dyn CloneableSeedProvider<D>>;
}

impl<D: Domain> Clone for Box<dyn CloneableSeedProvider<D>> {
    fn clone(&self) -> Self {
        self.as_ref().clone_box()
    }
}

impl<D, F> CloneableSeedProvider<D> for F
where
    D: Domain,
    F: FnOnce(&D) -> anyhow::Result<Vec<D::CorpusValue>> + Send + Clone + 'static,
{
    fn call_once(self: Box<Self>, domain: &D) -> anyhow::Result<Vec<D::CorpusValue>> {
        (*self)(domain)
    }

    fn clone_box(&self) -> Box<dyn CloneableSeedProvider<D>> {
        Box::new(self.clone())
    }
}

/// A domain wrapper that occasionally samples from user-provided seeds during initialization.
///
/// Produced by [`SeedableDomainExt::with_seeds`] or [`SeedableDomainExt::with_seed_provider`].
/// All domain operations delegate to the inner domain `D`, except for
/// [`Domain::init`](super::Domain::init), which returns a seed with probability 1/2 when seeds
/// are present.
///
/// Implements [`Clone`] when `D: Clone`, and [`fmt::Debug`] to display existing seeds and whether
/// seed providers are currently pending.
#[derive(Clone)]
pub struct Seeded<D: Domain> {
    domain: D,
    seeds: Vec<D::CorpusValue>,
    seed_providers: Vec<Box<dyn CloneableSeedProvider<D>>>,
}

impl<D: Domain> Seeded<D> {
    fn new(domain: D) -> Self {
        Seeded { domain, seeds: Vec::new(), seed_providers: Vec::new() }
    }
}

/// Converts and validates each user seed against the domain.
///
/// Each seed is first converted via [`UserValueConstructible::user_to_corpus_value`] and then
/// validated using [`Domain::validate_corpus_value`]. If either step fails, the returned error
/// context includes the index of the offending seed.
fn validate_and_convert_seeds<'a, D: UserValueConstructible>(
    domain: &D,
    seeds: impl IntoIterator<Item = D::UserValue<'a>>,
) -> anyhow::Result<Vec<D::CorpusValue>> {
    seeds
        .into_iter()
        .enumerate()
        .map(|(idx, s)| {
            let corpus_val = domain
                .user_to_corpus_value(s)
                .context(format!("Failed to convert to corpus value seed at index {idx}."))?;
            domain
                .validate_corpus_value(&corpus_val)
                .context(format!("Failed to validate seed at index {idx}."))?;
            Ok(corpus_val)
        })
        .collect()
}

impl<D: UserValueConstructible> Seeded<D> {
    /// Adds pre-defined seeds, appending them to existing seeds.
    ///
    /// Calling this method on an already seeded domain appends seeds directly without
    /// nesting [`Seeded`] wrappers. Seeds are converted and validated immediately.
    ///
    /// # Panics
    ///
    /// Panics if any seed fails conversion or validation for this domain. The panic message
    /// includes the index of the failing seed.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use fuzztest::domains::{Domain, SeedableDomainExt, UserValueConstructible};
    /// # use fuzztest::reexports::anyhow;
    /// # use fuzztest::reexports::rand::RngExt;
    /// #
    /// # #[derive(Clone, Debug)]
    /// # struct Percent;
    /// # impl Domain for Percent {
    /// #     type UserValue<'user> = u8;
    /// #     type CorpusValue = u8;
    /// #     fn init(&mut self, rng: &mut dyn fuzztest::reexports::rand::Rng) -> anyhow::Result<Self::CorpusValue> {
    /// #         Ok(rng.random_range(0..=100))
    /// #     }
    /// #     fn mutate(&mut self, corpus_value: &mut Self::CorpusValue, rng: &mut dyn fuzztest::reexports::rand::Rng, _only_shrink: bool) -> anyhow::Result<()> {
    /// #         *corpus_value = self.init(rng)?;
    /// #         Ok(())
    /// #     }
    /// #     fn corpus_to_user_value<'a>(&self, corpus_value: &'a Self::CorpusValue) -> anyhow::Result<Self::UserValue<'a>> {
    /// #         Ok(*corpus_value)
    /// #     }
    /// #     fn validate_corpus_value(&self, corpus_value: &Self::CorpusValue) -> anyhow::Result<()> {
    /// #         anyhow::ensure!(*corpus_value <= 100);
    /// #         Ok(())
    /// #     }
    /// # }
    /// # impl UserValueConstructible for Percent {
    /// #     fn user_to_corpus_value<'a>(&self, value: Self::UserValue<'a>) -> anyhow::Result<Self::CorpusValue> {
    /// #         Ok(value)
    /// #     }
    /// # }
    /// #
    /// let domain = Percent.with_seeds([0]).with_seeds([50, 100]);
    /// ```
    pub fn with_seeds<'a>(mut self, seeds: impl IntoIterator<Item = D::UserValue<'a>>) -> Self {
        let validated_seeds =
            validate_and_convert_seeds(&self.domain, seeds).expect("Failed to add seeds");
        self.seeds.extend(validated_seeds);
        self
    }
}

impl<D: UserValueConstructible> Seeded<D> {
    /// Adds a lazy seed provider evaluated on first sampling.
    ///
    /// Calling this method on an already seeded domain appends the provider without
    /// nesting [`Seeded`] wrappers. The provider is evaluated at most once on the first
    /// call to [`Domain::init`](super::Domain::init). Multiple providers can be added, and all will
    /// contribute their seeds.
    ///
    /// The provider closure requires `F: FnOnce() -> I + Send + Clone + 'static`. The `FnOnce`
    /// bound allows moving captured data out of the closure. The `Clone` bound ensures that
    /// cloning `self` before the first [`Domain::init`](super::Domain::init) duplicates the
    /// provider.
    ///
    /// # Panics
    ///
    /// Panics on the first call to [`Domain::init`](super::Domain::init) if the provider yields
    /// a seed that fails conversion or validation.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use fuzztest::domains::{Domain, SeedableDomainExt, UserValueConstructible};
    /// # use fuzztest::reexports::anyhow;
    /// # use fuzztest::reexports::rand::RngExt;
    /// #
    /// # #[derive(Clone, Debug)]
    /// # struct Percent;
    /// # impl Domain for Percent {
    /// #     type UserValue<'user> = u8;
    /// #     type CorpusValue = u8;
    /// #     fn init(&mut self, rng: &mut dyn fuzztest::reexports::rand::Rng) -> anyhow::Result<Self::CorpusValue> {
    /// #         Ok(rng.random_range(0..=100))
    /// #     }
    /// #     fn mutate(&mut self, corpus_value: &mut Self::CorpusValue, rng: &mut dyn fuzztest::reexports::rand::Rng, _only_shrink: bool) -> anyhow::Result<()> {
    /// #         *corpus_value = self.init(rng)?;
    /// #         Ok(())
    /// #     }
    /// #     fn corpus_to_user_value<'a>(&self, corpus_value: &'a Self::CorpusValue) -> anyhow::Result<Self::UserValue<'a>> {
    /// #         Ok(*corpus_value)
    /// #     }
    /// #     fn validate_corpus_value(&self, corpus_value: &Self::CorpusValue) -> anyhow::Result<()> {
    /// #         anyhow::ensure!(*corpus_value <= 100);
    /// #         Ok(())
    /// #     }
    /// # }
    /// # impl UserValueConstructible for Percent {
    /// #     fn user_to_corpus_value<'a>(&self, value: Self::UserValue<'a>) -> anyhow::Result<Self::CorpusValue> {
    /// #         Ok(value)
    /// #     }
    /// # }
    /// #
    /// let domain = Percent.with_seeds([0]).with_seed_provider(move || vec![50, 100]);
    /// ```
    pub fn with_seed_provider<'a, F, I>(mut self, seed_provider: F) -> Seeded<D>
    where
        F: FnOnce() -> I + Send + Clone + 'static,
        I: IntoIterator<Item = D::UserValue<'a>>,
    {
        self.seed_providers
            .push(Box::new(move |d: &D| validate_and_convert_seeds(d, seed_provider())));
        self
    }
}

impl<D> fmt::Debug for Seeded<D>
where
    D: Domain + fmt::Debug,
    D::CorpusValue: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Seeded")
            .field("domain", &self.domain)
            .field("seeds", &self.seeds)
            .field("has_seed_providers", &!self.seed_providers.is_empty())
            .finish()
    }
}

impl<D: Domain> Domain for Seeded<D> {
    type UserValue<'user> = D::UserValue<'user>;
    type CorpusValue = D::CorpusValue;

    /// Initializes a value from the domain, evaluating pending seed providers on first call.
    ///
    /// On the first call to `init`, all pending seed providers are evaluated, converted, and
    /// validated; their seeds are appended to the domain's seed pool.
    ///
    /// If seeds are present, returns a uniformly chosen seed with probability 1/2.
    /// Otherwise (or if no seeds were provided), delegates to the inner domain's `init`.
    ///
    /// # Panics
    ///
    /// Panics if any seed provider yields a seed that fails conversion or validation.
    fn init(&mut self, rng: &mut dyn rand::Rng) -> anyhow::Result<Self::CorpusValue> {
        for provider in mem::take(&mut self.seed_providers) {
            let seeds = provider
                .call_once(&self.domain)
                .expect("Failed to retrieve seeds from seed provider");
            self.seeds.extend(seeds);
        }

        if self.seeds.is_empty() || !rng.random_bool(0.5) {
            self.domain.init(rng)
        } else {
            let idx = rng.random_range(0..self.seeds.len());
            Ok(self.seeds[idx].clone())
        }
    }

    /// Delegates to the inner domain.
    fn mutate(
        &mut self,
        corpus_value: &mut Self::CorpusValue,
        rng: &mut dyn rand::Rng,
        only_shrink: bool,
    ) -> anyhow::Result<()> {
        self.domain.mutate(corpus_value, rng, only_shrink)
    }

    /// Delegates to the inner domain.
    fn parse_corpus(&self, data: &[u8]) -> anyhow::Result<Self::CorpusValue> {
        self.domain.parse_corpus(data)
    }

    /// Delegates to the inner domain.
    fn serialize_corpus(&self, corpus_value: &Self::CorpusValue) -> anyhow::Result<Vec<u8>> {
        self.domain.serialize_corpus(corpus_value)
    }

    /// Delegates to the inner domain.
    fn validate_corpus_value(&self, corpus_value: &Self::CorpusValue) -> anyhow::Result<()> {
        self.domain.validate_corpus_value(corpus_value)
    }

    /// Delegates to the inner domain.
    fn corpus_to_user_value<'a>(
        &self,
        corpus_value: &'a Self::CorpusValue,
    ) -> anyhow::Result<Self::UserValue<'a>> {
        self.domain.corpus_to_user_value(corpus_value)
    }
}

/// Delegates to the inner domain, enabling seeding a seeded domain inside a seedable combinator.
impl<D: UserValueConstructible> UserValueConstructible for Seeded<D> {
    fn user_to_corpus_value<'a>(
        &self,
        value: Self::UserValue<'a>,
    ) -> anyhow::Result<D::CorpusValue> {
        self.domain.user_to_corpus_value(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use googletest::prelude::*;
    use rand::RngExt;
    use rand::SeedableRng;
    use rand::rngs::{SmallRng, SysRng};
    use std::collections::HashSet;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn get_rng() -> SmallRng {
        SmallRng::try_from_rng(&mut SysRng).expect("Failed to create RNG")
    }

    #[derive(Clone, Debug)]
    struct BoundedI32 {
        max: i32,
    }

    impl Domain for BoundedI32 {
        type UserValue<'user> = i32;
        type CorpusValue = i32;

        fn init(&mut self, _rng: &mut dyn rand::Rng) -> anyhow::Result<Self::CorpusValue> {
            Ok(0)
        }

        fn mutate(
            &mut self,
            corpus_value: &mut Self::CorpusValue,
            _rng: &mut dyn rand::Rng,
            _only_shrink: bool,
        ) -> anyhow::Result<()> {
            *corpus_value = (*corpus_value + 1).min(self.max);
            Ok(())
        }

        fn corpus_to_user_value<'a>(
            &self,
            corpus_value: &'a Self::CorpusValue,
        ) -> anyhow::Result<Self::UserValue<'a>> {
            Ok(*corpus_value)
        }

        fn validate_corpus_value(&self, corpus_value: &Self::CorpusValue) -> anyhow::Result<()> {
            anyhow::ensure!(
                *corpus_value <= self.max,
                "value {} exceeds max {}",
                corpus_value,
                self.max
            );
            Ok(())
        }
    }

    impl UserValueConstructible for BoundedI32 {
        fn user_to_corpus_value<'a>(
            &self,
            value: Self::UserValue<'a>,
        ) -> anyhow::Result<Self::CorpusValue> {
            Ok(value)
        }
    }

    #[derive(Clone, Debug)]
    struct NonNegativeOnly;

    impl Domain for NonNegativeOnly {
        type UserValue<'user> = i32;
        type CorpusValue = i32;

        fn init(&mut self, _rng: &mut dyn rand::Rng) -> anyhow::Result<Self::CorpusValue> {
            Ok(0)
        }

        fn mutate(
            &mut self,
            _corpus_value: &mut Self::CorpusValue,
            _rng: &mut dyn rand::Rng,
            _only_shrink: bool,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        fn corpus_to_user_value<'a>(
            &self,
            corpus_value: &'a Self::CorpusValue,
        ) -> anyhow::Result<Self::UserValue<'a>> {
            Ok(*corpus_value)
        }
    }

    impl UserValueConstructible for NonNegativeOnly {
        fn user_to_corpus_value<'a>(
            &self,
            value: Self::UserValue<'a>,
        ) -> anyhow::Result<Self::CorpusValue> {
            if value < 0 {
                anyhow::bail!("negative value {value}");
            }
            Ok(value)
        }
    }

    #[derive(Clone, Debug)]
    struct Percent;

    impl Domain for Percent {
        type UserValue<'user> = u8;
        type CorpusValue = u8;

        fn init(&mut self, rng: &mut dyn rand::Rng) -> anyhow::Result<Self::CorpusValue> {
            Ok(rng.random_range(0..=100))
        }

        fn mutate(
            &mut self,
            corpus_value: &mut Self::CorpusValue,
            rng: &mut dyn rand::Rng,
            _only_shrink: bool,
        ) -> anyhow::Result<()> {
            *corpus_value = self.init(rng)?;
            Ok(())
        }

        fn corpus_to_user_value<'a>(
            &self,
            corpus_value: &'a Self::CorpusValue,
        ) -> anyhow::Result<Self::UserValue<'a>> {
            Ok(*corpus_value)
        }

        fn validate_corpus_value(&self, corpus_value: &Self::CorpusValue) -> anyhow::Result<()> {
            anyhow::ensure!(*corpus_value <= 100, "percent {corpus_value} exceeds 100");
            Ok(())
        }
    }

    impl UserValueConstructible for Percent {
        fn user_to_corpus_value<'a>(
            &self,
            value: Self::UserValue<'a>,
        ) -> anyhow::Result<Self::CorpusValue> {
            Ok(value)
        }
    }

    #[gtest]
    fn test_with_seeds_samples_all_seeds() {
        let mut domain = BoundedI32 { max: i32::MAX }.with_seeds([10, 20, 30]);
        let mut rng = get_rng();
        let mut observed = HashSet::new();
        for _ in 0..200 {
            observed.insert(domain.init(&mut rng).unwrap());
        }
        expect_that!(observed.contains(&10), eq(true));
        expect_that!(observed.contains(&20), eq(true));
        expect_that!(observed.contains(&30), eq(true));
    }

    #[gtest]
    fn test_with_seeds_falls_back_to_inner_domain() {
        let mut domain = BoundedI32 { max: 100 }.with_seeds([42]);
        let mut rng = get_rng();
        let mut observed = HashSet::new();
        for _ in 0..200 {
            observed.insert(domain.init(&mut rng).unwrap());
        }
        expect_that!(observed.contains(&42), eq(true));
        expect_that!(observed.contains(&0), eq(true));
    }

    #[gtest]
    #[should_panic(expected = "Failed to add seeds")]
    fn test_with_seeds_panics_on_validation_failure() {
        let _ = BoundedI32 { max: 10 }.with_seeds([1, 20]);
    }

    #[gtest]
    #[should_panic(expected = "Failed to add seeds")]
    fn test_with_seeds_panics_on_conversion_failure() {
        let _ = NonNegativeOnly.with_seeds([-1]);
    }

    #[gtest]
    fn test_chained_with_seeds_appends_without_nesting() {
        let mut domain: Seeded<BoundedI32> =
            BoundedI32 { max: i32::MAX }.with_seeds([1]).with_seeds([2]);
        let mut rng = get_rng();
        let mut observed = HashSet::new();
        for _ in 0..200 {
            observed.insert(domain.init(&mut rng).unwrap());
        }
        expect_that!(observed.contains(&1), eq(true));
        expect_that!(observed.contains(&2), eq(true));
    }

    #[gtest]
    fn test_seed_provider_lazy_and_called_exactly_once() {
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = Arc::clone(&counter);
        let mut domain = BoundedI32 { max: 100 }.with_seed_provider(move || {
            counter_clone.fetch_add(1, Ordering::SeqCst);
            vec![7]
        });
        expect_that!(counter.load(Ordering::SeqCst), eq(0));

        let mut rng = get_rng();
        let first = domain.init(&mut rng).unwrap();
        expect_that!(counter.load(Ordering::SeqCst), eq(1));

        let mut observed = HashSet::new();
        observed.insert(first);
        for _ in 0..100 {
            observed.insert(domain.init(&mut rng).unwrap());
        }
        expect_that!(counter.load(Ordering::SeqCst), eq(1));
        expect_that!(observed.contains(&7), eq(true));
    }

    #[gtest]
    fn test_multiple_providers_and_seeds_all_contribute() {
        let mut domain = BoundedI32 { max: 100 }
            .with_seed_provider(|| vec![1])
            .with_seed_provider(|| vec![2])
            .with_seeds([3]);
        let mut rng = get_rng();
        let mut observed = HashSet::new();
        for _ in 0..200 {
            observed.insert(domain.init(&mut rng).unwrap());
        }
        expect_that!(observed.contains(&1), eq(true));
        expect_that!(observed.contains(&2), eq(true));
        expect_that!(observed.contains(&3), eq(true));
    }

    #[gtest]
    #[should_panic(expected = "Failed to retrieve seeds from seed provider")]
    fn test_provider_yielding_invalid_seed_panics_on_first_init() {
        let mut domain = BoundedI32 { max: 10 }.with_seed_provider(|| vec![99]);
        let mut rng = get_rng();
        let _ = domain.init(&mut rng);
    }

    #[gtest]
    fn test_fnonce_move_out_provider() {
        let owned = vec![5];
        let mut domain = BoundedI32 { max: 100 }.with_seed_provider(move || owned);
        let mut rng = get_rng();
        let mut observed = HashSet::new();
        for _ in 0..200 {
            observed.insert(domain.init(&mut rng).unwrap());
        }
        expect_that!(observed.contains(&5), eq(true));
    }

    #[gtest]
    fn test_clone_before_init_evaluates_provider_for_both_copies() {
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = Arc::clone(&counter);
        let a = BoundedI32 { max: 100 }.with_seed_provider(move || {
            counter_clone.fetch_add(1, Ordering::SeqCst);
            vec![7]
        });
        let mut a = a;
        let mut b = a.clone();
        expect_that!(counter.load(Ordering::SeqCst), eq(0));

        let mut rng = get_rng();
        let _ = a.init(&mut rng).unwrap();
        expect_that!(counter.load(Ordering::SeqCst), eq(1));

        let _ = b.init(&mut rng).unwrap();
        expect_that!(counter.load(Ordering::SeqCst), eq(2));
    }

    #[gtest]
    fn test_clone_after_init_shares_already_evaluated_seeds() {
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = Arc::clone(&counter);
        let mut a = BoundedI32 { max: 100 }.with_seed_provider(move || {
            counter_clone.fetch_add(1, Ordering::SeqCst);
            vec![7]
        });
        let mut rng = get_rng();
        let _ = a.init(&mut rng).unwrap();
        expect_that!(counter.load(Ordering::SeqCst), eq(1));

        let mut b = a.clone();
        let mut observed = HashSet::new();
        for _ in 0..200 {
            observed.insert(b.init(&mut rng).unwrap());
        }
        expect_that!(counter.load(Ordering::SeqCst), eq(1));
        expect_that!(observed.contains(&7), eq(true));
    }

    #[gtest]
    fn test_seeded_delegates_to_inner_domain() {
        let mut domain = BoundedI32 { max: 10 }.with_seeds([3]);
        let mut inner = BoundedI32 { max: 10 };

        // validate_corpus_value
        expect_that!(domain.validate_corpus_value(&11).is_err(), eq(true));
        expect_that!(domain.validate_corpus_value(&5).is_ok(), eq(true));

        // serialize_corpus and parse_corpus round-trip
        let serialized = domain.serialize_corpus(&5).unwrap();
        let deserialized = domain.parse_corpus(&serialized).unwrap();
        expect_that!(deserialized, eq(5));

        // corpus_to_user_value
        let user_val = domain.corpus_to_user_value(&5).unwrap();
        expect_that!(user_val, eq(5));

        // user_to_corpus_value
        let corpus_val = domain.user_to_corpus_value(5).unwrap();
        expect_that!(corpus_val, eq(5));

        // mutate
        let mut rng = get_rng();
        let mut val1 = 5;
        let mut val2 = 5;
        domain.mutate(&mut val1, &mut rng, false).unwrap();
        inner.mutate(&mut val2, &mut rng, false).unwrap();
        expect_that!(val1, eq(val2));
    }

    #[gtest]
    fn test_seeded_debug_formatting() {
        let domain = BoundedI32 { max: 1 }.with_seeds([1]).with_seed_provider(|| vec![0]);
        let debug_str = format!("{:?}", domain);
        expect_that!(debug_str, contains_substring("seeds: [1]"));
        expect_that!(debug_str, contains_substring("has_seed_providers: true"));
    }

    #[gtest]
    fn test_doc_example_percent_domain() {
        let mut domain = Percent.with_seeds([0, 100]).with_seed_provider(|| vec![50]);
        let mut rng = SmallRng::seed_from_u64(73);
        let value = domain.init(&mut rng).unwrap();
        expect_that!(value, le(100));

        let mut observed = HashSet::new();
        for _ in 0..200 {
            observed.insert(domain.init(&mut rng).unwrap());
        }
        expect_that!(observed.contains(&0), eq(true));
        expect_that!(observed.contains(&50), eq(true));
        expect_that!(observed.contains(&100), eq(true));
    }
}
