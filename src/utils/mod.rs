//! Features expected to land into Arkworks at some point in the future

/// Common utilities
pub(crate) mod common;
/// Twisted Edwards to Short Weierstrass mapping.
pub(crate) mod te_sw_map;

pub(crate) use common::*;

pub use te_sw_map::{sw_to_te, te_to_sw, SWMapping, TEMapping};

// Prevents downstream warnings when `ring` feature is not enabled.
#[doc(hidden)]
#[cfg(feature = "ring")]
pub type RingProof<S> = crate::ring::Proof<S>;
#[doc(hidden)]
#[cfg(not(feature = "ring"))]
pub type RingProof<S> = core::marker::PhantomData<S>;

#[macro_export]
macro_rules! suite_types {
    ($suite:ident) => {
        #[allow(dead_code)]
        pub type Secret = $crate::Secret<$suite>;
        #[allow(dead_code)]
        pub type Public = $crate::Public<$suite>;
        #[allow(dead_code)]
        pub type Input = $crate::Input<$suite>;
        #[allow(dead_code)]
        pub type Output = $crate::Output<$suite>;
        #[allow(dead_code)]
        pub type AffinePoint = $crate::AffinePoint<$suite>;
        #[allow(dead_code)]
        pub type ScalarField = $crate::ScalarField<$suite>;
        #[allow(dead_code)]
        pub type BaseField = $crate::BaseField<$suite>;
        #[allow(dead_code)]
        pub type IetfProof = $crate::ietf::Proof<$suite>;
        #[allow(dead_code)]
        pub type PedersenProof = $crate::pedersen::Proof<$suite>;
        #[allow(dead_code)]
        pub type RingProof = $crate::utils::RingProof<$suite>;
    };
}
