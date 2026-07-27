# SPL Transfer CLI Skill

This skill enables the agent to build unsigned Solana SPL token transfers using the `spl-transfer-cli` binary.

## What it does

- Constructs unsigned SPL token transfer transactions
- Enforces recipient allowlist policy
- Returns base64-encoded transaction + approval summary
- Does NOT sign or broadcast transactions (no private key access)

## When to use

Use this when the user asks to:
- Transfer SPL tokens between Solana addresses
- Build a token transfer transaction
- Create a transfer for approval

## How to call

Use the shell tool to execute `spl-transfer-cli` with a JSON argument:

```bash
spl-transfer-cli '{
  "sender": "<sender_wallet_pubkey>",
  "recipient": "<recipient_wallet_pubkey>",
  "mint": "<token_mint_address>",
  "amount": "<amount_as_string>",
  "decimals": <token_decimals>,
  "memo": null,
  "token_2022": false,
  "nonce_account": null
}'
```

## Required environment variables

The binary requires these env vars (inherited from daemon):
- `SOLANA_RPC_URL`: Solana RPC endpoint (default: https://api.devnet.solana.com)
- `ALLOWED_RECIPIENTS`: Comma-separated list of approved recipient addresses

## Example request

User: "Send 1.0 USDC from pt6Ws1... to EYSHit..."

Agent should run:
```bash
spl-transfer-cli '{"sender":"pt6Ws1FMbdrLbUZqKooediS8mu6SNvDJodzXUx6ypak","recipient":"EYSHit3n1e6qQWKG6L4g34SNoG6P7R9U7y6MGREBLebB","mint":"4zMMC9srt5LbHEgmQ875n83us92Wr284r2ekHDQ2B9uw","amount":"1.0","decimals":6,"memo":null,"token_2022":false,"nonce_account":null}'
```

## Output format

Returns JSON with:
- `transaction_base64`: Unsigned transaction (base64)
- `summary`: Human-readable transfer description
- `source_ata`: Source token account address
- `destination_ata`: Destination token account address
- `destination_ata_will_be_created`: Boolean
- `status`: "auto_approved" or "requires_approval"
- `policy_verdict`: Policy decision details

## Security notes

- Recipient must be in ALLOWED_RECIPIENTS or transfer is rejected
- No private key access - only builds unsigned transactions
- User must independently sign and submit the transaction
