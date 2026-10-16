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
//! # Compile-time Opt-in via [`ReversibleDomain`]
//!
//! Seeding is opt-in per domain via the [`ReversibleDomain`] trait. Domains whose corpus
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
//! use fuzztest::domains::{Domain, ReversibleDomain, SeedableDomainExt};
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
//! impl ReversibleDomain<u8> for Percent {
//!     fn to_unvalidated_corpus_value(&self, value: u8) -> anyhow::Result<Self::CorpusValue> {
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
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;

/// Allows constructing domain corpus values from values of type `T`.
///
/// Implementing this trait for a seed type `T` (typically the domain's `UserValue`, or an owned
/// counterpart for domains whose `UserValue` borrows from the corpus) makes the domain seedable
/// with values of type `T` via the blanket [`SeedableDomainExt`] implementation. It represents
/// the inverse of [`Domain::corpus_to_user_value`](super::Domain::corpus_to_user_value).
///
/// Implementations must only convert the value and must **not** perform validation;
/// callers validate the converted corpus value via
/// [`Domain::validate_corpus_value`](super::Domain::validate_corpus_value).
///
/// # Errors
///
/// Returns an error if the value cannot be represented as a corpus value for
/// this domain.
pub trait ReversibleDomain<T>: Domain {
    /// Converts `value` into an unvalidated [`Domain::CorpusValue`].
    ///
    /// Do not validate domain constraints here; implement them in
    /// [`Domain::validate_corpus_value`] so they apply to both seeds and
    /// deserialized corpus entries.
    fn to_unvalidated_corpus_value(&self, value: T) -> anyhow::Result<Self::CorpusValue>;
}

mod sealed {
    pub trait Sealed {}
    impl<D: super::Domain> Sealed for D {}
}

/// Extension trait providing seeding methods for domains.
///
/// Blanket-implemented for all types that implement [`Domain`]. The seeding methods
/// require `Self: ReversibleDomain<T>` for the chosen seed type `T` and wrap the domain
/// in a [`Seeded<Self>`].
pub trait SeedableDomainExt: Domain + Sized + sealed::Sealed {
    /// Converts a seed `value` into a [`Domain::CorpusValue`] and validates it
    /// against [`Domain::validate_corpus_value`].
    ///
    /// Because `SeedableDomainExt` is blanket-implemented, this pipeline cannot
    /// be overridden to skip validation.
    fn into_corpus_value<T>(&self, value: T) -> anyhow::Result<Self::CorpusValue>
    where
        Self: ReversibleDomain<T>,
    {
        let corpus_val = self
            .to_unvalidated_corpus_value(value)
            .context("Failed to convert seed to corpus value")?;
        self.validate_corpus_value(&corpus_val)
            .context("Failed to validate seed against domain constraints")?;
        Ok(corpus_val)
    }

    /// Adds pre-defined seeds to the domain.
    ///
    /// Seeds are converted and validated immediately against the domain.
    ///
    /// # Panics
    ///
    /// Panics if any seed fails conversion or validation for this domain. The panic message
    /// includes the index of the failing seed.
    fn with_seeds<T>(self, seeds: impl IntoIterator<Item = T>) -> Seeded<Self>
    where
        Self: ReversibleDomain<T>,
    {
        Seeded::new(self).with_seeds(seeds)
    }

    /// Adds a lazy seed provider evaluated on first sampling.
    ///
    /// The provider is evaluated at most once on the first call to
    /// [`Domain::init`](super::Domain::init). Multiple providers can be added, and all will
    /// contribute their seeds.
    ///
    /// The provider closure requires `F: FnOnce() -> I + Send + 'static`. The `FnOnce` bound
    /// allows moving non-`Clone` captured data out of the closure. If a [`Seeded`] instance is
    /// cloned before its first [`Domain::init`](super::Domain::init), the lazy provider is shared
    /// via `Arc` and evaluated at most once across all clones.
    ///
    /// # Panics
    ///
    /// Panics on the first call to [`Domain::init`](super::Domain::init) if the provider yields
    /// a seed that fails conversion or validation.
    fn with_seed_provider<T, F, I>(self, seed_provider: F) -> Seeded<Self>
    where
        Self: ReversibleDomain<T>,
        F: FnOnce() -> I + Send + 'static,
        I: IntoIterator<Item = T>,
    {
        Seeded::new(self).with_seed_provider(seed_provider)
    }
}

impl<D: Domain> SeedableDomainExt for D {}

type BoxedSeedProvider<D> =
    Box<dyn FnOnce(&D) -> anyhow::Result<Vec<<D as Domain>::CorpusValue>> + Send>;

/// A shared, lazily-evaluated `FnOnce` seed provider.
///
/// Wrapping the provider in an `Arc` allows `Seeded<D>` to implement `Clone` without requiring
/// the user's `FnOnce` closure (or its captured variables) to implement `Clone`.
struct OnceSeedProvider<D: Domain> {
    provider: Mutex<Option<BoxedSeedProvider<D>>>,
    resolved: OnceLock<Result<Vec<D::CorpusValue>, Arc<anyhow::Error>>>,
}

impl<D: Domain> OnceSeedProvider<D> {
    fn new<T, F, I>(seed_provider: F) -> Arc<Self>
    where
        D: ReversibleDomain<T>,
        F: FnOnce() -> I + Send + 'static,
        I: IntoIterator<Item = T>,
    {
        Arc::new(Self {
            provider: Mutex::new(Some(Box::new(move |domain: &D| {
                validate_and_convert_seeds(domain, seed_provider())
            }))),
            resolved: OnceLock::new(),
        })
    }

    fn resolve(&self, domain: &D) -> Result<&[D::CorpusValue], &Arc<anyhow::Error>> {
        self.resolved
            .get_or_init(|| {
                let provider = self
                    .provider
                    .lock()
                    .expect("Seed provider mutex should not be poisoned")
                    .take()
                    .expect("OnceLock initializes at most once");
                provider(domain).map_err(Arc::new)
            })
            .as_deref()
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
#[must_use]
pub struct Seeded<D: Domain> {
    domain: D,
    seeds: Vec<D::CorpusValue>,
    seed_providers: Vec<Arc<OnceSeedProvider<D>>>,
}

impl<D: Domain> Seeded<D> {
    fn new(domain: D) -> Self {
        Seeded { domain, seeds: Vec::new(), seed_providers: Vec::new() }
    }

    /// Returns a reference to the inner domain.
    pub fn inner(&self) -> &D {
        &self.domain
    }

    /// Consumes the seeded wrapper and returns the inner domain.
    pub fn into_inner(self) -> D {
        self.domain
    }

    /// Adds pre-defined seeds, appending them to existing seeds.
    ///
    /// Calling this method on an already seeded domain appends seeds directly without
    /// nesting [`Seeded`] wrappers. Seeds are converted and validated immediately.
    ///
    /// # Panics
    ///
    /// Panics if any seed fails conversion or validation for this domain. The panic message
    /// includes the index of the failing seed.
    pub fn with_seeds<T>(mut self, seeds: impl IntoIterator<Item = T>) -> Self
    where
        D: ReversibleDomain<T>,
    {
        let validated_seeds = validate_and_convert_seeds(&self.domain, seeds)
            .unwrap_or_else(|e| panic!("Failed to add seeds: {e:#}"));
        self.seeds.extend(validated_seeds);
        self
    }

    /// Adds a lazy seed provider evaluated on first sampling.
    ///
    /// Calling this method on an already seeded domain appends the provider without
    /// nesting [`Seeded`] wrappers. The provider is evaluated at most once on the first
    /// call to [`Domain::init`](super::Domain::init). Multiple providers can be added, and all will
    /// contribute their seeds.
    ///
    /// The provider closure requires `F: FnOnce() -> I + Send + 'static`. The `FnOnce` bound
    /// allows moving non-`Clone` captured data out of the closure. If a [`Seeded`] instance is
    /// cloned before its first [`Domain::init`](super::Domain::init), the lazy provider is shared
    /// via `Arc` and evaluated at most once across all clones.
    ///
    /// # Panics
    ///
    /// Panics on the first call to [`Domain::init`](super::Domain::init) if the provider yields
    /// a seed that fails conversion or validation.
    pub fn with_seed_provider<T, F, I>(mut self, seed_provider: F) -> Self
    where
        D: ReversibleDomain<T>,
        F: FnOnce() -> I + Send + 'static,
        I: IntoIterator<Item = T>,
    {
        self.seed_providers.push(OnceSeedProvider::new(seed_provider));
        self
    }
}

/// Converts and validates each user seed against the domain.
///
/// Each seed is converted and validated via [`SeedableDomainExt::into_corpus_value`] (which calls
/// [`ReversibleDomain::to_unvalidated_corpus_value`] and [`Domain::validate_corpus_value`]). If
/// either step fails, the returned error context includes the index of the offending seed.
fn validate_and_convert_seeds<D, T>(
    domain: &D,
    seeds: impl IntoIterator<Item = T>,
) -> anyhow::Result<Vec<D::CorpusValue>>
where
    D: ReversibleDomain<T>,
{
    seeds
        .into_iter()
        .enumerate()
        .map(|(idx, s)| {
            domain
                .into_corpus_value(s)
                .with_context(|| format!("Failed to convert seed at index {idx} to corpus value."))
        })
        .collect()
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
                .resolve(&self.domain)
                .unwrap_or_else(|e| panic!("Failed to retrieve seeds from seed provider: {e:#}"));
            self.seeds.extend_from_slice(seeds);
        }

        if !self.seeds.is_empty() && rng.random_bool(0.5) {
            let idx = rng.random_range(0..self.seeds.len());
            Ok(self.seeds[idx].clone())
        } else {
            self.domain.init(rng)
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

/// Delegates seed conversion to the inner domain.
///
/// This implementation enables outer container or combinator domains (such as
/// `VectorOf<Seeded<D>>`) to construct corpus values when seeding the composite domain.
///
/// When adding more seeds directly to an existing `Seeded<D>`, callers should call the inherent
/// [`Seeded::with_seeds`] or [`Seeded::with_seed_provider`] methods instead of trait-based
/// wrapping, ensuring seeds are appended into a single pool without introducing nested
/// `Seeded<Seeded<D>>` wrappers.
impl<D, T> ReversibleDomain<T> for Seeded<D>
where
    D: ReversibleDomain<T>,
{
    fn to_unvalidated_corpus_value(&self, value: T) -> anyhow::Result<D::CorpusValue> {
        self.domain.to_unvalidated_corpus_value(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use googletest::prelude::*;
    use rand::rngs::{SmallRng, SysRng};
    use rand::RngExt;
    use rand::SeedableRng;
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

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

    impl ReversibleDomain<i32> for BoundedI32 {
        fn to_unvalidated_corpus_value(&self, value: i32) -> anyhow::Result<Self::CorpusValue> {
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

        fn validate_corpus_value(&self, corpus_value: &Self::CorpusValue) -> anyhow::Result<()> {
            anyhow::ensure!(*corpus_value >= 0, "negative value {}", corpus_value);
            Ok(())
        }
    }

    impl ReversibleDomain<i32> for NonNegativeOnly {
        fn to_unvalidated_corpus_value(&self, value: i32) -> anyhow::Result<Self::CorpusValue> {
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

    impl ReversibleDomain<u8> for Percent {
        fn to_unvalidated_corpus_value(&self, value: u8) -> anyhow::Result<Self::CorpusValue> {
            Ok(value)
        }
    }

    #[derive(Clone, Debug)]
    struct StrDomain;

    impl Domain for StrDomain {
        type UserValue<'user> = &'user str;
        type CorpusValue = String;

        fn init(&mut self, _rng: &mut dyn rand::Rng) -> anyhow::Result<Self::CorpusValue> {
            Ok(String::new())
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
            Ok(corpus_value.as_str())
        }

        fn validate_corpus_value(&self, _corpus_value: &Self::CorpusValue) -> anyhow::Result<()> {
            Ok(())
        }
    }

    impl<'a> ReversibleDomain<&'a str> for StrDomain {
        fn to_unvalidated_corpus_value(&self, value: &'a str) -> anyhow::Result<Self::CorpusValue> {
            Ok(value.to_owned())
        }
    }

    impl ReversibleDomain<String> for StrDomain {
        fn to_unvalidated_corpus_value(&self, value: String) -> anyhow::Result<Self::CorpusValue> {
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
        expect_that!(observed, contains(eq(&10)));
        expect_that!(observed, contains(eq(&20)));
        expect_that!(observed, contains(eq(&30)));
    }

    #[gtest]
    fn test_with_seeds_falls_back_to_inner_domain() {
        let mut domain = BoundedI32 { max: 100 }.with_seeds([42]);
        let mut rng = get_rng();
        let mut observed = HashSet::new();
        for _ in 0..200 {
            observed.insert(domain.init(&mut rng).unwrap());
        }
        expect_that!(observed, contains(eq(&42)));
        expect_that!(observed, contains(eq(&0)));
    }

    #[gtest]
    fn test_empty_seeds_and_empty_provider_fall_back_to_inner_domain() {
        let mut domain = BoundedI32 { max: 100 }.with_seeds([]).with_seed_provider(Vec::<i32>::new);
        let mut rng = get_rng();
        let mut observed = HashSet::new();
        for _ in 0..200 {
            observed.insert(domain.init(&mut rng).unwrap());
        }
        expect_that!(observed, contains(eq(&0)));
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
        expect_that!(observed, contains(eq(&1)));
        expect_that!(observed, contains(eq(&2)));
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
        expect_that!(observed, contains(eq(&7)));
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
        expect_that!(observed, contains(eq(&1)));
        expect_that!(observed, contains(eq(&2)));
        expect_that!(observed, contains(eq(&3)));
    }

    #[gtest]
    #[should_panic(expected = "Failed to retrieve seeds from seed provider")]
    fn test_provider_yielding_invalid_seed_panics_on_first_init() {
        let mut domain = BoundedI32 { max: 10 }.with_seed_provider(|| vec![99]);
        let mut rng = get_rng();
        let _ = domain.init(&mut rng);
    }

    #[gtest]
    fn test_clone_before_init_with_failing_provider_does_not_poison_mutex() {
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = Arc::clone(&counter);
        let a = BoundedI32 { max: 10 }.with_seed_provider(move || {
            counter_clone.fetch_add(1, Ordering::SeqCst);
            vec![99]
        });
        let mut a = a;
        let mut b = a.clone();
        let res_a = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut rng = get_rng();
            let _ = a.init(&mut rng);
        }));
        expect_true!(res_a.is_err());
        expect_that!(counter.load(Ordering::SeqCst), eq(1));
        let res_b = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut rng = get_rng();
            let _ = b.init(&mut rng);
        }));
        expect_true!(res_b.is_err());
        expect_that!(counter.load(Ordering::SeqCst), eq(1));
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
        expect_that!(observed, contains(eq(&5)));
    }

    #[gtest]
    fn test_clone_before_init_evaluates_provider_once_and_shares_seeds() {
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
        expect_that!(counter.load(Ordering::SeqCst), eq(1));

        let mut observed_a = HashSet::new();
        let mut observed_b = HashSet::new();
        for _ in 0..200 {
            observed_a.insert(a.init(&mut rng).unwrap());
            observed_b.insert(b.init(&mut rng).unwrap());
        }
        expect_that!(observed_a, contains(eq(&7)));
        expect_that!(observed_b, contains(eq(&7)));
    }

    #[gtest]
    fn test_non_clone_capture_in_seed_provider() {
        struct NonClone(i32);
        let non_clone = NonClone(5);
        let a = BoundedI32 { max: 100 }.with_seed_provider(move || vec![non_clone.0]);
        let mut a = a;
        let mut b = a.clone();

        let mut rng = get_rng();
        let mut observed_a = HashSet::new();
        let mut observed_b = HashSet::new();
        for _ in 0..200 {
            observed_a.insert(a.init(&mut rng).unwrap());
            observed_b.insert(b.init(&mut rng).unwrap());
        }
        expect_that!(observed_a, contains(eq(&5)));
        expect_that!(observed_b, contains(eq(&5)));
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
        expect_that!(observed, contains(eq(&7)));
    }

    #[gtest]
    fn test_seeded_delegates_to_inner_domain() {
        let mut domain = BoundedI32 { max: 10 }.with_seeds([3]);
        let mut inner = BoundedI32 { max: 10 };

        // validate_corpus_value
        expect_that!(domain.validate_corpus_value(&11), err(anything()));
        expect_that!(domain.validate_corpus_value(&5), ok(anything()));

        // serialize_corpus and parse_corpus round-trip
        let serialized = domain.serialize_corpus(&5).unwrap();
        let deserialized = domain.parse_corpus(&serialized).unwrap();
        expect_that!(deserialized, eq(5));

        // parse_corpus validates deserialized value against domain constraints
        let invalid_bytes = domain.serialize_corpus(&11).unwrap();
        expect_that!(domain.parse_corpus(&invalid_bytes), err(anything()));

        // corpus_to_user_value
        let user_val = domain.corpus_to_user_value(&5).unwrap();
        expect_that!(user_val, eq(5));

        // into_corpus_value
        let corpus_val = domain.into_corpus_value(5).unwrap();
        expect_that!(corpus_val, eq(5));

        // mutate
        let mut rng = get_rng();
        let mut val1 = 5;
        let mut val2 = 5;
        domain.mutate(&mut val1, &mut rng, false).unwrap();
        inner.mutate(&mut val2, &mut rng, false).unwrap();
        expect_that!(val1, eq(val2));

        // inner and into_inner
        expect_that!(domain.inner().max, eq(10));
        let inner_domain = domain.into_inner();
        expect_that!(inner_domain.max, eq(10));
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
        expect_that!(observed, contains(eq(&0u8)));
        expect_that!(observed, contains(eq(&50u8)));
        expect_that!(observed, contains(eq(&100u8)));
    }

    #[gtest]
    fn test_borrowed_user_value_domain_seeding_with_owned_and_borrowed_seeds() {
        let local_seed = String::from("borrowed_local");
        let mut domain: Seeded<StrDomain> = StrDomain
            .with_seeds([local_seed.as_str()])
            .with_seed_provider(|| vec![String::from("owned_from_provider")]);
        drop(local_seed);

        let mut rng = get_rng();
        let mut observed = HashSet::new();
        for _ in 0..200 {
            observed.insert(domain.init(&mut rng).unwrap());
        }
        expect_that!(observed, contains(eq("borrowed_local")));
        expect_that!(observed, contains(eq("owned_from_provider")));
    }
}
