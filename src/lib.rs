//! Focused developer tooling over the reusable Coppice Names wallet adapter.

pub mod names_v1_config;

/// Compatibility namespace for existing qualification binaries. The
/// implementation lives in `coppice-names-wallet` so production wallets and
/// developer tooling cannot drift onto different constructors.
pub mod names_v1_builder {
    pub use coppice_names_wallet::builder::*;
}

/// Compatibility namespace for existing qualification binaries.
pub mod names_v1_operation {
    pub use coppice_names_wallet::operation::*;
}
