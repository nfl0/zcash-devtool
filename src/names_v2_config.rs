//! Host configuration used by the disposable Names v2 live harness.
//!
//! The receiver is an incoming-only Orchard capability. It is testnet/
//! regtest tooling configuration, not Names semantic state or consensus.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NamesV2Rendezvous {
    pub orchard_ivk: [u8; 64],
    pub orchard_receiver: [u8; 43],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NamesV2NetworkConfig {
    pub rendezvous: NamesV2Rendezvous,
}

/// Disposable local-regtest receiver used by the v2 live qualification
/// harness. These bytes are intentionally unchanged from the established
/// qualification fixture.
pub const REGTEST: NamesV2NetworkConfig = NamesV2NetworkConfig {
    rendezvous: NamesV2Rendezvous {
        orchard_ivk: [
            101, 222, 178, 179, 238, 122, 198, 144, 32, 84, 63, 64, 242, 17, 34, 203, 109, 193,
            244, 32, 26, 50, 159, 205, 249, 213, 227, 187, 45, 251, 186, 190, 41, 213, 66, 53, 47,
            227, 108, 60, 123, 36, 194, 152, 157, 201, 208, 0, 11, 158, 4, 244, 68, 224, 93, 196,
            83, 139, 222, 57, 92, 14, 96, 8,
        ],
        orchard_receiver: [
            158, 197, 158, 77, 68, 123, 162, 133, 8, 108, 195, 69, 108, 173, 246, 32, 4, 161, 155,
            106, 121, 137, 199, 38, 218, 170, 153, 68, 166, 205, 191, 37, 247, 191, 165, 26, 250,
            21, 182, 109, 165, 56, 129,
        ],
    },
};

/// Decodes the configured incoming-only Orchard receiver.
pub fn bulletin_address(
    rendezvous: NamesV2Rendezvous,
) -> Result<orchard::Address, NamesV2ConfigError> {
    Option::from(orchard::Address::from_raw_address_bytes(
        &rendezvous.orchard_receiver,
    ))
    .ok_or(NamesV2ConfigError::InvalidReceiver)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NamesV2ConfigError {
    InvalidReceiver,
}
