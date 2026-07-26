//! Token-2022 mint extension parsing and safety checks.
//!
//! Token-2022 mints can have extensions that modify transfer behavior. Some
//! extensions are unsafe for automated agent payments (e.g., transfer fees,
//! transfer hooks, non-transferable tokens). This module parses the TLV-encoded
//! extension data and blocks transfers involving unsafe extensions.

#[derive(Debug)]
pub struct MintExtensions {
    pub types: Vec<u16>,
}

#[derive(Debug)]
pub enum ExtError {
    Truncated,
    BadTlv,
}

impl std::fmt::Display for ExtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExtError::Truncated => write!(f, "extension data truncated"),
            ExtError::BadTlv => write!(f, "invalid TLV encoding"),
        }
    }
}

/// Classic mint layout is 82 bytes. Token-2022 mints may add:
/// byte 165 = account_type marker, then repeating TLV: [u16 LE type][u16 LE len][data...]
pub fn parse_mint_extensions(data: &[u8]) -> Result<MintExtensions, ExtError> {
    const BASE_MINT_LEN: usize = 82;
    const ACCOUNT_TYPE_OFFSET: usize = 165;

    if data.len() <= BASE_MINT_LEN {
        return Ok(MintExtensions { types: vec![] }); // classic mint, no TLV region
    }
    if data.len() <= ACCOUNT_TYPE_OFFSET {
        return Err(ExtError::Truncated);
    }

    let mut offset = ACCOUNT_TYPE_OFFSET + 1;
    let mut types = Vec::new();

    while offset + 4 <= data.len() {
        let ext_type = u16::from_le_bytes([data[offset], data[offset + 1]]);
        let ext_len = u16::from_le_bytes([data[offset + 2], data[offset + 3]]) as usize;
        offset += 4;
        if offset + ext_len > data.len() {
            return Err(ExtError::BadTlv);
        }
        types.push(ext_type);
        offset += ext_len;
    }
    Ok(MintExtensions { types })
}

/// Extension type IDs that are unsafe for automated agent payments.
/// Verify these numeric values against the actual spl-token-2022 ExtensionType enum
/// before shipping.
const BLOCKED_EXTENSIONS: &[(u16, &str)] = &[
    (1, "TransferFeeConfig"),
    (7, "TransferHook"),
    (12, "PermanentDelegate"),
    (9, "NonTransferable"),
    (2, "ConfidentialTransferMint"),
    (16, "Pausable"),
    (17, "DefaultAccountStateFrozen"),
];

pub fn check_extensions_safe(ext: &MintExtensions) -> Result<(), String> {
    for &t in &ext.types {
        if let Some((_, name)) = BLOCKED_EXTENSIONS.iter().find(|(id, _)| *id == t) {
            return Err(name.to_string());
        }
    }
    // fail closed: any tag not in a known-safe allowlist also blocks.
    // Since we have no "known safe" list here at all, presence of ANY
    // unrecognized type also blocks — adjust if you later add a safe set.
    if !ext.types.is_empty() {
        return Err("unknown extension".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classic_mint_no_extensions() {
        let classic_mint = vec![0u8; 82];
        let ext = parse_mint_extensions(&classic_mint).unwrap();
        assert!(ext.types.is_empty());
        assert!(check_extensions_safe(&ext).is_ok());
    }

    #[test]
    fn token2022_empty_tlv() {
        let mut mint = vec![0u8; 166];
        mint[165] = 1; // account type marker
        let ext = parse_mint_extensions(&mint).unwrap();
        assert!(ext.types.is_empty());
        assert!(check_extensions_safe(&ext).is_ok());
    }

    #[test]
    fn transfer_fee_extension_blocked() {
        let mut mint = vec![0u8; 166];
        mint[165] = 1;
        // Add TLV for TransferFeeConfig (type 1, length 0 for test)
        mint.extend_from_slice(&1u16.to_le_bytes());
        mint.extend_from_slice(&0u16.to_le_bytes());
        let ext = parse_mint_extensions(&mint).unwrap();
        assert_eq!(ext.types, vec![1]);
        assert_eq!(check_extensions_safe(&ext).unwrap_err(), "TransferFeeConfig");
    }

    #[test]
    fn transfer_hook_extension_blocked() {
        let mut mint = vec![0u8; 166];
        mint[165] = 1;
        // Add TLV for TransferHook (type 7, length 0 for test)
        mint.extend_from_slice(&7u16.to_le_bytes());
        mint.extend_from_slice(&0u16.to_le_bytes());
        let ext = parse_mint_extensions(&mint).unwrap();
        assert_eq!(ext.types, vec![7]);
        assert_eq!(check_extensions_safe(&ext).unwrap_err(), "TransferHook");
    }

    #[test]
    fn unrecognized_extension_blocked() {
        let mut mint = vec![0u8; 166];
        mint[165] = 1;
        // Add TLV for unknown extension (type 99, length 0 for test)
        mint.extend_from_slice(&99u16.to_le_bytes());
        mint.extend_from_slice(&0u16.to_le_bytes());
        let ext = parse_mint_extensions(&mint).unwrap();
        assert_eq!(ext.types, vec![99]);
        assert_eq!(check_extensions_safe(&ext).unwrap_err(), "unknown extension");
    }

    #[test]
    fn truncated_data_fails() {
        let mint = vec![0u8; 100]; // between 82 and 165
        assert!(matches!(parse_mint_extensions(&mint), Err(ExtError::Truncated)));
    }

    #[test]
    fn bad_tlv_fails() {
        let mut mint = vec![0u8; 166];
        mint[165] = 1;
        // Add TLV with length that exceeds data
        mint.extend_from_slice(&1u16.to_le_bytes());
        mint.extend_from_slice(&1000u16.to_le_bytes());
        assert!(matches!(parse_mint_extensions(&mint), Err(ExtError::BadTlv)));
    }
}
