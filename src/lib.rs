//! # Elliptic Curve VRF (DEPRECATED)
//!
//! **This library has been deprecated and superseeded by [ark-vrf](https://github.com/davxy/ark-vrf)**
//!
//! Please use [ark-vrf](https://crates.io/crates/ark-vrf) for all future development.

#![deprecated = "The `ark-ec-vrfs` crate has been deprecated. Please use the `ark-vrf` crate instead."]

compile_error!(
    "The `ark-ec-vrfs` crate has been deprecated. Please use the `ark-vrf` crate instead"
);

pub use ark_vrf::{
    codec, ietf, pedersen, reexports, ring, ring_suite_types, suite_types, suites, utils,
    AffinePoint, BaseField, CurveConfig, Error, HashOutput, Input, Output, Public, ScalarField,
    Secret, Suite,
};
