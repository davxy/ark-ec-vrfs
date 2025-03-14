//! Common utilities

pub mod common;
pub mod te_sw_map;

/// Standard procedures.
pub use common::*;
/// Twisted Edwards to Short Weierstrass mapping.
pub use te_sw_map::*;

/// Point scalar multiplication with optional secret splitting.
///
/// Secret scalar split into the sum of two scalars, which randomly mutate but
/// retain the same sum. Incurs 2x penalty in scalar multiplications, but provides
/// side channel defenses.
///
/// Note: actual secret splitting is enabled via the `secret-split` feature.
mod secret_split {
    #[cfg(feature = "secret-split")]
    #[doc(hidden)]
    #[macro_export]
    macro_rules! smul {
        ($p:expr, $s:expr) => {{
            #[inline(always)]
            fn get_rand<T: ark_std::UniformRand>(_: &T) -> T {
                T::rand(&mut ark_std::rand::rngs::OsRng)
            }
            let x1 = get_rand(&$s);
            let x2 = $s - x1;
            $p * x1 + $p * x2
        }};
    }

    #[cfg(not(feature = "secret-split"))]
    #[doc(hidden)]
    #[macro_export]
    macro_rules! smul {
        ($p:expr, $s:expr) => {
            $p * $s
        };
    }
}
