//! Native CLI wrapper around spl-transfer-build's pure core, for local
//! testing via a ZeroClaw SKILL.md + built-in shell tool, before the real
//! WASM plugin host is available on this ZeroClaw version.
//!
//! Usage:
//!   SOLANA_RPC_URL=https://api.devnet.solana.com \
//!   ALLOWED_RECIPIENTS=<comma-separated base58 pubkeys> \
//!   spl-transfer-cli '<json TransferArgs>'
//!
//! Prints TransferResult JSON on success, or {"error": "..."} + exit(1).

use spl_transfer_build::core::{
    build_transfer, CoreError, Pubkey, RpcClient, TransferArgs, TransferPolicy,
};

struct NativeRpc {
    rpc_url: String,
}

impl NativeRpc {
    fn call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value, CoreError> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let value: serde_json::Value = ureq::post(&self.rpc_url)
            .set("Content-Type", "application/json")
            .send_json(body)
            .map_err(|e| CoreError::Rpc(format!("HTTP request failed: {e}")))?
            .into_json()
            .map_err(|e| CoreError::Rpc(format!("invalid JSON-RPC response: {e}")))?;
        if let Some(error) = value.get("error") {
            return Err(CoreError::Rpc(format!("RPC returned an error: {error}")));
        }
        Ok(value)
    }
}

impl RpcClient for NativeRpc {
    fn get_latest_blockhash(&self) -> Result<[u8; 32], CoreError> {
        let value = self.call(
            "getLatestBlockhash",
            serde_json::json!([{"commitment": "finalized"}]),
        )?;
        let blockhash = value
            .pointer("/result/value/blockhash")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| CoreError::Rpc("missing blockhash in RPC response".to_string()))?;
        let bytes = bs58::decode(blockhash)
            .into_vec()
            .map_err(|_| CoreError::Rpc("blockhash is not valid base58".to_string()))?;
        bytes
            .try_into()
            .map_err(|_| CoreError::Rpc("blockhash is not 32 bytes".to_string()))
    }

    fn account_exists(&self, pubkey: &Pubkey) -> Result<bool, CoreError> {
        let value = self.call(
            "getAccountInfo",
            serde_json::json!([pubkey.to_base58(), {"encoding": "base64"}]),
        )?;
        value
            .pointer("/result/value")
            .map(|account| !account.is_null())
            .ok_or_else(|| CoreError::Rpc("missing account value in RPC response".to_string()))
    }

    fn get_account_data(&self, pubkey: &Pubkey) -> Result<(Vec<u8>, Pubkey), CoreError> {
        let raw = self.call(
            "getAccountInfo",
            serde_json::json!([pubkey.to_base58(), {"encoding": "base64"}]),
        )?;
        solana_core_wasi::rpc::parse_account_info(&raw.to_string())
            .map_err(|e| CoreError::Rpc(e.to_string()))
    }
}

fn main() {
    let args_json = std::env::args()
        .nth(1)
        .unwrap_or_else(|| { eprintln!("usage: spl-transfer-cli '<json TransferArgs>'"); std::process::exit(2); });

    let args: TransferArgs = match serde_json::from_str(&args_json) {
        Ok(a) => a,
        Err(e) => { eprintln!("{{\"error\":\"invalid TransferArgs JSON: {e}\"}}"); std::process::exit(1); }
    };

    let rpc_url = std::env::var("SOLANA_RPC_URL")
        .unwrap_or_else(|_| { eprintln!("{{\"error\":\"SOLANA_RPC_URL not set\"}}"); std::process::exit(1); });
    let allowed = std::env::var("ALLOWED_RECIPIENTS").unwrap_or_default();
    let max_auto_approve = std::env::var("MAX_AUTO_APPROVE_BASE_UNITS").ok();

    let policy = match TransferPolicy::from_config(Some(&allowed), max_auto_approve.as_deref()) {
        Ok(p) => p,
        Err(e) => { eprintln!("{{\"error\":\"invalid policy: {e}\"}}"); std::process::exit(1); }
    };

    let rpc = NativeRpc { rpc_url };

    match build_transfer(&args, &rpc, &policy) {
        Ok(result) => println!("{}", serde_json::to_string(&result).unwrap()),
        Err(e) => { eprintln!("{{\"error\":\"{e}\"}}"); std::process::exit(1); }
    }
}
