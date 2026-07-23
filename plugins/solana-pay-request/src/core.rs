//! Pure, host-testable Solana Pay URL construction.
//!
//! This T1 component never holds a key, signs, submits, or broadcasts a
//! transaction. A `solana:` URL is a request for a separate wallet to build
//! and approve the transfer.

use serde::{Deserialize, Serialize};
use solana_core_wasi::{
    pay::TransferRequest,
    pubkey::Pubkey,
};

pub const PARAMETERS_SCHEMA: &str = r#"{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "recipient": { "type": "string", "description": "Base58 public key of the payment recipient" },
    "amount": { "type": "string", "pattern": "^[0-9]+(\\.[0-9]+)?$", "description": "Exact positive decimal amount, for example \"25.0\"" },
    "mint": { "type": "string", "description": "Base58 SPL token mint, for example the USDC mint" },
    "memo": { "type": "string", "maxLength": 500, "description": "Invoice or reconciliation memo" },
    "reference": { "type": "string", "description": "Base58 public key used by the merchant to locate this payment" }
  },
  "required": ["recipient", "amount", "mint", "reference"]
}"#;

const MAX_MEMO_BYTES: usize = 500;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum PayError {
    #[error("{field} must be a base58 public key")]
    InvalidPubkey { field: &'static str },
    #[error("amount must be a positive decimal string")]
    InvalidAmount,
    #[error("memo exceeds {MAX_MEMO_BYTES} bytes")]
    MemoTooLong,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayRequestArgs {
    pub recipient: String,
    /// Kept as a string so a request never crosses binary floating point.
    pub amount: String,
    pub mint: String,
    pub memo: Option<String>,
    pub reference: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct PayRequestResult {
    pub solana_pay_url: String,
    /// Chat clients can pass this exact value to a QR renderer.
    pub qr_payload: String,
    pub summary: String,
}

pub fn build_solana_pay_request(args: &PayRequestArgs) -> Result<PayRequestResult, PayError> {
    validate_pubkey(&args.recipient, "recipient")?;
    validate_pubkey(&args.mint, "mint")?;
    validate_pubkey(&args.reference, "reference")?;
    validate_amount(&args.amount)?;
    if let Some(memo) = &args.memo {
        if memo.len() > MAX_MEMO_BYTES {
            return Err(PayError::MemoTooLong);
        }
    }

    let solana_pay_url = TransferRequest {
        recipient: args.recipient.clone(),
        amount: Some(args.amount.clone()),
        spl_token: Some(args.mint.clone()),
        references: vec![args.reference.clone()],
        memo: args.memo.clone(),
        ..Default::default()
    }
    .to_url();
    let summary = format!(
        "Request {} tokens to {}\nMint: {}\nReference: {}\nMemo: {}\nRequires wallet approval; this plugin cannot sign or submit.",
        args.amount,
        args.recipient,
        args.mint,
        args.reference,
        args.memo.as_deref().unwrap_or("(none)"),
    );

    Ok(PayRequestResult {
        qr_payload: solana_pay_url.clone(),
        solana_pay_url,
        summary,
    })
}

fn validate_pubkey(value: &str, field: &'static str) -> Result<(), PayError> {
    Pubkey::parse(value).map(|_| ()).map_err(|_| PayError::InvalidPubkey { field })
}

fn validate_amount(value: &str) -> Result<(), PayError> {
    if value.is_empty() || value.trim() != value {
        return Err(PayError::InvalidAmount);
    }
    let mut parts = value.split('.');
    let whole = parts.next().expect("split returns one element");
    let fractional = parts.next();
    if parts.next().is_some()
        || whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || fractional
            .is_some_and(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
        || fractional.is_some_and(|part| part.len() > 255)
        || !value
            .bytes()
            .any(|byte| byte.is_ascii_digit() && byte != b'0')
    {
        return Err(PayError::InvalidAmount);
    }
    Ok(())
}

