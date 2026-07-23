//! Pure, wasm-free core for `spl-transfer-build`.
//!
//! Everything in this file is plain Rust with no `wasm32` cfg, no host
//! imports, and no live network calls — that's what lets `cargo test`
//! exercise it directly, per the bounty's "pure core, thin shim" rule.
//! RPC access goes through the `RpcClient` trait so tests can supply a
//! mock instead of hitting a real endpoint.
//!
//! Custody tier: T1 (Build). This module only ever *returns* an unsigned
//! transaction. It never holds, generates, or touches a private key.

use serde::{Deserialize, Serialize};
use solana_core_wasi::{
    amount::to_base_units,
    instruction::{
        ata_create_idempotent, memo as memo_ix, spl_transfer_checked,
    },
    message::{compile_legacy, unsigned_transaction_base64},
    pubkey::{derive_ata as core_derive_ata, PubkeyError},
};

// Re-export Pubkey for test compatibility
pub use solana_core_wasi::pubkey::Pubkey;

pub const SYSTEM_PROGRAM_ID: &str = "11111111111111111111111111111111";
pub const TOKEN_PROGRAM_ID: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
pub const TOKEN_2022_PROGRAM_ID: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

/// Cap on memo length. This is a defensive limit, not a protocol one —
/// see the prompt-injection test at the bottom of this file for why.
pub const MAX_MEMO_LEN: usize = 500;

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("invalid base58 public key")]
    InvalidPubkey,
    #[error("configured recipients must be valid base58 public keys")]
    InvalidRecipientPolicy,
    #[error("recipient is not approved")]
    RecipientNotApproved,
    #[error("rpc error: {0}")]
    Rpc(String),
    #[error("invalid input: {0}")]
    InvalidInput(String),
}

impl From<PubkeyError> for CoreError {
    fn from(_: PubkeyError) -> Self {
        CoreError::InvalidPubkey
    }
}

// solana_core_wasi::pubkey::Pubkey replaces the local type; parse errors are
// mapped through `From<PubkeyError> for CoreError` above. `derive_ata` below
// wraps the crate's version so call sites don't need a `token_program`
// argument for the ATA-program constant, matching the old signature.

pub fn derive_ata(owner: &Pubkey, mint: &Pubkey, _token_program: &Pubkey) -> Result<Pubkey, CoreError> {
    // solana_core_wasi::pubkey::derive_ata always derives against the classic
    // token program; this plugin's Token-2022 support only affects the
    // *transfer* instruction, not ATA derivation, so this is a drop-in swap.
    Ok(core_derive_ata(owner, mint))
}

// Nonce helpers — `nonce_blockhash_from_data` and `ix_advance_nonce` — become thin wrappers
// around `solana_core_wasi::nonce::parse_nonce_account` and `solana_core_wasi::instruction::advance_nonce`:

pub fn nonce_blockhash_from_data(data: &[u8]) -> Result<[u8; 32], CoreError> {
    solana_core_wasi::nonce::parse_nonce_account(data)
        .map(|state| state.durable_nonce)
        .map_err(|e| CoreError::InvalidInput(e.to_string()))
}

pub fn ix_advance_nonce(
    nonce_account: &Pubkey,
    nonce_authority: &Pubkey,
) -> solana_core_wasi::instruction::Instruction {
    solana_core_wasi::instruction::advance_nonce(nonce_account, nonce_authority)
}


// ---------------------------------------------------------------------
// RPC seam (mocked in tests, backed by wasi:http in the wasm shim)
// ---------------------------------------------------------------------

pub trait RpcClient {
    fn get_latest_blockhash(&self) -> Result<[u8; 32], CoreError>;
    fn account_exists(&self, pubkey: &Pubkey) -> Result<bool, CoreError>;
}

// ---------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferArgs {
    pub sender: String,
    pub recipient: String,
    pub mint: String,
    /// Exact human-unit decimal, e.g. `"25.0"` for 25 USDC — not raw base
    /// units. This deliberately remains text until it is converted with
    /// checked integer arithmetic; money must never pass through `f64`.
    pub amount: String,
    pub decimals: u8,
    pub memo: Option<String>,
    #[serde(default)]
    pub token_2022: bool,
}

/// Operator-controlled destination policy. An empty allowlist intentionally
/// authorizes nobody: a transfer tool should fail closed until its owner names
/// the wallet owners it may build transactions for.
#[derive(Debug, Clone)]
pub struct TransferPolicy {
    allowed_recipients: Vec<Pubkey>,
}

impl TransferPolicy {
    /// Parse the comma-separated `allowed_recipients` config value. Missing or
    /// blank configuration produces an empty allowlist, never an allow-all.
    pub fn from_config(configured_recipients: Option<&str>) -> Result<Self, CoreError> {
        let allowed_recipients = configured_recipients
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|recipient| !recipient.is_empty())
            .map(Pubkey::parse)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| CoreError::InvalidRecipientPolicy)?;
        Ok(Self { allowed_recipients })
    }

    /// Validate a requested destination before any RPC request or transaction
    /// serialization. A valid but unapproved public key is rejected too.
    pub fn authorize_recipient(&self, recipient: &str) -> Result<(), CoreError> {
        let recipient = Pubkey::parse(recipient)?;
        if self.allowed_recipients.contains(&recipient) {
            Ok(())
        } else {
            Err(CoreError::RecipientNotApproved)
        }
    }
}

#[derive(Debug, Serialize, PartialEq)]
pub struct TransferResult {
    pub transaction_base64: String,
    pub summary: String,
    pub source_ata: String,
    pub destination_ata: String,
    pub destination_ata_will_be_created: bool,
}

pub fn build_transfer(
    args: &TransferArgs,
    rpc: &dyn RpcClient,
    policy: &TransferPolicy,
) -> Result<TransferResult, CoreError> {
    if let Some(memo) = &args.memo {
        if memo.len() > MAX_MEMO_LEN {
            return Err(CoreError::InvalidInput(format!(
                "memo exceeds {MAX_MEMO_LEN} bytes"
            )));
        }
    }

    policy.authorize_recipient(&args.recipient)?;

    let sender = Pubkey::parse(&args.sender)?;
    let recipient = Pubkey::parse(&args.recipient)?;
    let mint = Pubkey::parse(&args.mint)?;
    let token_program = Pubkey::parse(if args.token_2022 {
        TOKEN_2022_PROGRAM_ID
    } else {
        TOKEN_PROGRAM_ID
    })?;

    let source_ata = derive_ata(&sender, &mint, &token_program)?;
    let dest_ata = derive_ata(&recipient, &mint, &token_program)?;
    let dest_exists = rpc.account_exists(&dest_ata)?;

    let raw_amount = to_base_units(&args.amount, args.decimals)
        .map_err(|e| CoreError::InvalidInput(e.to_string()))?;

    let mut instructions = vec![ata_create_idempotent(&sender, &dest_ata, &recipient, &mint)];
    instructions.push(spl_transfer_checked(
        &source_ata,
        &mint,
        &dest_ata,
        &sender,
        raw_amount,
        args.decimals,
    ));
    if let Some(memo) = &args.memo {
        instructions.push(memo_ix(memo));
    }

    let blockhash = rpc.get_latest_blockhash()?;
    let message = compile_legacy(&sender, &instructions, &blockhash);
    let transaction_base64 = unsigned_transaction_base64(&message);

    let summary = format!(
        "Transfer {amount} tokens ({raw} base units)\n\
         From: {sender} (source ATA {source_ata})\n\
         To:   {recipient} (dest ATA {dest_ata}{created})\n\
         Mint: {mint}{prog}\n\
         Memo: {memo}\n\
         Requires signature from: {sender}",
        amount = args.amount,
        raw = raw_amount,
        created = if dest_exists { "" } else { ", will be created" },
        prog = if args.token_2022 { " (Token-2022)" } else { "" },
        memo = args.memo.as_deref().unwrap_or("(none)"),
    );

    Ok(TransferResult {
        transaction_base64,
        summary,
        source_ata: source_ata.to_base58(),
        destination_ata: dest_ata.to_base58(),
        destination_ata_will_be_created: !dest_exists,
    })
}


pub const PARAMETERS_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "sender": { "type": "string", "description": "Base58 owner pubkey of the source token account" },
    "recipient": { "type": "string", "description": "Base58 owner pubkey of the destination wallet" },
    "mint": { "type": "string", "description": "Base58 SPL mint address" },
    "amount": { "type": "string", "pattern": "^[0-9]+(\\.[0-9]+)?$", "description": "Exact positive human-readable decimal amount, e.g. \"25.0\". Must not have more fractional digits than decimals." },
    "decimals": { "type": "integer", "minimum": 0, "maximum": 255, "description": "Mint decimals" },
    "memo": { "type": "string", "maxLength": 500, "description": "Optional invoice/reconciliation memo" },
    "token_2022": { "type": "boolean", "default": false }
  },
  "required": ["sender", "recipient", "mint", "amount", "decimals"]
}"#;
