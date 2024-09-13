//! Features expected to land into Arkworks at some point in the future

/// Elligator 2 hash-to-curve.
pub(crate) mod elligator2;
/// Twisted Edwards to Short Weierstrass mapping.
pub(crate) mod te_sw_map;
// Common utilities
pub(crate) mod common;

pub(crate) use common::*;

pub use te_sw_map::{sw_to_te, te_to_sw, SWMapping};

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
        #[cfg(feature = "ring")]
        #[allow(dead_code)]
        pub type RingProof = $crate::ring::Proof<$suite>;
    };
}
