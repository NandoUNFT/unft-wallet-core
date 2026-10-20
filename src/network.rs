use serde::{Deserialize, Serialize};

use crate::{ChainFamily, NetworkIdentity};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnftNetwork {
    Mainnet,
    Testnet,
}

impl UnftNetwork {
    pub const fn p2pkh_prefix(self) -> u8 {
        match self {
            Self::Mainnet => 50,
            Self::Testnet => 111,
        }
    }

    pub const fn ext_public_key_prefix(self) -> [u8; 4] {
        match self {
            Self::Mainnet => [0x04, 0x4e, 0x46, 0x54],
            Self::Testnet => [0x04, 0x54, 0x46, 0x54],
        }
    }

    pub const fn ext_private_key_prefix(self) -> [u8; 4] {
        match self {
            Self::Mainnet => [0x04, 0x4e, 0x46, 0x58],
            Self::Testnet => [0x04, 0x54, 0x46, 0x58],
        }
    }

    pub const fn bech32_hrp(self) -> &'static str {
        match self {
            Self::Mainnet => "uc",
            Self::Testnet => "ut",
        }
    }

    pub const fn identity(self) -> NetworkIdentity {
        match self {
            Self::Mainnet => NetworkIdentity {
                family: ChainFamily::BitcoinCompatibleUtxo,
                chain_id: "unft-main",
                network: "mainnet",
                genesis_hash: "7b2ad83470d152867b388cb4224ee88f2e2655400b18b4b8b64b6d649dcd6d7f",
            },
            Self::Testnet => NetworkIdentity {
                family: ChainFamily::BitcoinCompatibleUtxo,
                chain_id: "unft-testnet4-porepool-V2",
                network: "testnet4",
                genesis_hash: "1feb289ac03939a34ef549a10cf1f870b579592169f9e6a43f2f87c3d0cefaee",
            },
        }
    }
}
