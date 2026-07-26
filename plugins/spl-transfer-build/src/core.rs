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
    #[error("unsafe mint extension: {0}")]
    UnsafeMintExtension(String),
    #[error("max_auto_approve_base_units must be a non-negative integer")]
    InvalidAutoApproveCap,
    #[error(
        "amount exceeds the auto-approve cap and requires a durable nonce_account so the \
         built transaction can wait for out-of-band approval instead of expiring"
    )]
    ApprovalRequiresNonce,
}

impl From<PubkeyError> for CoreError {
    fn from(_: PubkeyError) -> Self {
        CoreError::InvalidPubkey
    }
}

// solana_core_wasi::pubkey::Pubkey replaces the local type; parse errors are
// mapped through `From<PubkeyError> for CoreError` above.

pub fn derive_ata(owner: &Pubkey, mint: &Pubkey, token_program: &Pubkey) -> Result<Pubkey, CoreError> {
    // The ATA address depends on which program owns the mint: a Token-2022
    // mint's associated token account is a different PDA than the classic
    // Token derivation. token_program must reflect the caller's token_2022
    // choice, not the classic program unconditionally.
    Ok(core_derive_ata(owner, mint, token_program))
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
    fn get_account_data(&self, pubkey: &Pubkey) -> Result<(Vec<u8>, Pubkey), CoreError>;
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
    pub nonce_account: Option<String>,
}

/// Result of policy evaluation, surfaced to the caller and to structured
/// logs so an operator can audit *why* a transfer was or wasn't built
/// straight to a ready-to-sign transaction — not just that it was.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum PolicyVerdict {
    /// Recipient is allowlisted and the amount is at or under the
    /// configured auto-approve cap (or no cap is configured).
    AutoApproved,
    /// Recipient is allowlisted but the amount exceeds the configured
    /// auto-approve cap. The transaction is still built (so it's ready the
    /// moment it's approved) but against a durable nonce rather than a
    /// recent blockhash, and callers must treat it as unsigned-and-pending
    /// rather than ready.
    RequiresApproval { cap_base_units: u64 },
    /// Recipient is not on the allowlist. No transaction is built.
    Denied { reason: String },
}

/// Operator-controlled destination policy. An empty allowlist intentionally
/// authorizes nobody: a transfer tool should fail closed until its owner names
/// the wallet owners it may build transactions for.
#[derive(Debug, Clone)]
pub struct TransferPolicy {
    allowed_recipients: Vec<Pubkey>,
    /// Above this many base units, a transfer is still built (as a durable-
    /// nonce transaction) but comes back `requires_approval` instead of
    /// ready-to-sign. `None` means no cap: any allowlisted recipient is
    /// auto-approved regardless of amount, matching the tool's original
    /// (pre-approval-rail) behavior.
    max_auto_approve_base_units: Option<u64>,
}

impl TransferPolicy {
    /// Parse the comma-separated `allowed_recipients` config value plus the
    /// optional `max_auto_approve_base_units` cap. Missing or blank
    /// configuration produces an empty allowlist, never an allow-all.
    pub fn from_config(
        configured_recipients: Option<&str>,
        max_auto_approve_base_units: Option<&str>,
    ) -> Result<Self, CoreError> {
        let allowed_recipients = configured_recipients
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|recipient| !recipient.is_empty())
            .map(Pubkey::parse)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| CoreError::InvalidRecipientPolicy)?;

        let max_auto_approve_base_units = match max_auto_approve_base_units.map(str::trim) {
            None | Some("") => None,
            Some(raw) => Some(
                raw.parse::<u64>()
                    .map_err(|_| CoreError::InvalidAutoApproveCap)?,
            ),
        };

        Ok(Self {
            allowed_recipients,
            max_auto_approve_base_units,
        })
    }

    /// Validate a requested destination before any RPC request or transaction
    /// serialization. A valid but unapproved public key is rejected too.
    /// Kept alongside `evaluate` because a bad recipient should fail before
    /// any amount is even parsed.
    pub fn authorize_recipient(&self, recipient: &str) -> Result<(), CoreError> {
        let recipient = Pubkey::parse(recipient)?;
        if self.allowed_recipients.contains(&recipient) {
            Ok(())
        } else {
            Err(CoreError::RecipientNotApproved)
        }
    }

    /// Full policy verdict for an already-approved recipient and a known
    /// amount in base units. Call `authorize_recipient` (or check the
    /// `Denied` arm here) first — this only decides auto-approve vs.
    /// requires-approval once the recipient itself is known to be allowed.
    pub fn evaluate(&self, recipient: &str, amount_base_units: u64) -> PolicyVerdict {
        let Ok(recipient) = Pubkey::parse(recipient) else {
            return PolicyVerdict::Denied {
                reason: "invalid recipient public key".to_string(),
            };
        };
        if !self.allowed_recipients.contains(&recipient) {
            return PolicyVerdict::Denied {
                reason: "recipient is not approved".to_string(),
            };
        }
        match self.max_auto_approve_base_units {
            Some(cap) if amount_base_units > cap => {
                PolicyVerdict::RequiresApproval { cap_base_units: cap }
            }
            _ => PolicyVerdict::AutoApproved,
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
    /// `"auto_approved"` or `"requires_approval"` — mirrors `policy_verdict` 
    /// as a plain string so callers that only look at `status` (e.g. a log
    /// filter) don't need to parse the nested verdict shape.
    pub status: String,
    pub policy_verdict: PolicyVerdict,
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

    if sender == recipient {
        return Err(CoreError::InvalidInput("sender and recipient must differ".into()));
    }

    if args.token_2022 {
        let (mint_data, owner) = rpc.get_account_data(&mint)?;
        let token_2022_program = Pubkey::parse(TOKEN_2022_PROGRAM_ID)?;
        if owner != token_2022_program {
            return Err(CoreError::InvalidInput(
                "token_2022=true but mint is not owned by Token-2022 program".into(),
            ));
        }
        let extensions = solana_core_wasi::token2022::parse_mint_extensions(&mint_data)
            .map_err(|e| CoreError::InvalidInput(format!("{e:?}")))?;
        if let Err(name) = solana_core_wasi::token2022::check_extensions_safe(&extensions) {
            return Err(CoreError::UnsafeMintExtension(name));
        }
    }

    let source_ata = derive_ata(&sender, &mint, &token_program)?;
    let dest_ata = derive_ata(&recipient, &mint, &token_program)?;
    let dest_exists = rpc.account_exists(&dest_ata)?;

    let raw_amount = to_base_units(&args.amount, args.decimals)
        .map_err(|e| CoreError::InvalidInput(e.to_string()))?;

    // The recipient was already fail-closed-checked above; this second look
    // decides auto-approve vs. requires-approval now that we know the
    // amount. A transfer over the cap is still built — as a durable-nonce
    // transaction so it can sit unsigned until someone approves it — rather
    // than rejected outright.
    let policy_verdict = policy.evaluate(&args.recipient, raw_amount);
    if matches!(policy_verdict, PolicyVerdict::RequiresApproval { .. }) && args.nonce_account.is_none()
    {
        return Err(CoreError::ApprovalRequiresNonce);
    }

    let mut instructions = vec![ata_create_idempotent(
        &sender,
        &dest_ata,
        &recipient,
        &mint,
        &token_program,
    )];
    instructions.push(spl_transfer_checked(
        &source_ata,
        &mint,
        &dest_ata,
        &sender,
        raw_amount,
        args.decimals,
        &token_program,
    ));
    if let Some(memo) = &args.memo {
        instructions.push(memo_ix(memo));
    }

    let recent_blockhash = if let Some(nonce_acct) = &args.nonce_account {
        let nonce_pubkey = Pubkey::parse(nonce_acct)
            .map_err(|e| CoreError::InvalidInput(e.to_string()))?;
        let (data, _owner) = rpc.get_account_data(&nonce_pubkey)?;
        let state = solana_core_wasi::nonce::parse_nonce_account(&data)
            .map_err(|e| CoreError::InvalidInput(e.to_string()))?;
        instructions.insert(0, solana_core_wasi::instruction::advance_nonce(&nonce_pubkey, &sender));
        state.durable_nonce
    } else {
        rpc.get_latest_blockhash()?
    };
    let message = compile_legacy(&sender, &instructions, &recent_blockhash);
    let transaction_base64 = unsigned_transaction_base64(&message);

    let status = match policy_verdict {
        PolicyVerdict::RequiresApproval { .. } => "requires_approval",
        _ => "auto_approved",
    };
    let approval_note = match &policy_verdict {
        PolicyVerdict::RequiresApproval { cap_base_units } => format!(
            "\nStatus: requires_approval — {raw_amount} base units exceeds the \
             {cap_base_units} auto-approve cap; built against a durable nonce so it \
             can wait to be approved without expiring."
        ),
        _ => String::new(),
    };

    let summary = format!(
        "Transfer {amount} tokens ({raw} base units)\n\
         From: {sender} (source ATA {source_ata})\n\
         To:   {recipient} (dest ATA {dest_ata}{created})\n\
         Mint: {mint}{prog}\n\
         Memo: {memo}\n\
         Requires signature from: {sender}{approval_note}",
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
        status: status.to_string(),
        policy_verdict,
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
    "token_2022": { "type": "boolean", "default": false },
    "nonce_account": { "type": "string", "description": "Optional durable-nonce account; when set, the transaction stays valid until this nonce advances instead of expiring with a recent blockhash." }
  },
  "required": ["sender", "recipient", "mint", "amount", "decimals"]
}"#;
