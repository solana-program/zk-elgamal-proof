#![allow(unused_imports, unused_macros, dead_code)]
#![cfg(target_arch = "wasm32")]

pub mod encryption;
pub mod proof_data;

// Conditional Test Configuration
// This block is only active when running tests (cfg(test)) on Wasm architecture.
#[cfg(all(test, target_arch = "wasm32"))]
mod wasm_test_config {
    use wasm_bindgen_test::*;

    #[cfg(feature = "test-browser")]
    wasm_bindgen_test_configure!(run_in_browser);
}

/// Simple macro for implementing conversion functions between wrapper types and
/// wrapped types.
mod conversion {
    macro_rules! impl_inner_conversion {
        ($Wrapper:ty, $Inner:ty) => {
            impl From<$Inner> for $Wrapper {
                fn from(inner: $Inner) -> Self {
                    Self { inner }
                }
            }
            impl std::ops::Deref for $Wrapper {
                type Target = $Inner;
                fn deref(&self) -> &Self::Target {
                    &self.inner
                }
            }
        };
    }
    pub(crate) use impl_inner_conversion;
}
