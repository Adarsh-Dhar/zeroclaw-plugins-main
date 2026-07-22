# Running `spl-transfer-build` with ZeroClaw

This guide shows how to build, install, configure, and test the local
`spl-transfer-build` plugin in ZeroClaw.

`spl-transfer-build` is a **build-only** Solana tool. It creates an unsigned
versioned SPL token transfer and an approval summary. It does **not** hold a
private key, sign a transaction, or broadcast a transfer.

## 1. Prerequisites

You need:

- macOS with Rust and Cargo installed.
- At least 5 GB of free disk space. Building ZeroClaw with the Wasm host uses
  substantially more space than compiling the plugin alone.
- A configured model provider for ZeroClaw. The agent uses it to decide when
  to call the plugin.
- A Solana wallet-owner public key you intend to allow as a recipient.

Check available disk space before building:

```bash
df -h
```

## 2. Build and test the plugin

From this plugin directory:

```bash
cd ~/Documents/zeroclaw-plugins-main/plugins/spl-transfer-build

# Run the deterministic host-side tests.
cargo test --locked

# Install the WebAssembly target once, if it is not already installed.
rustup target add wasm32-wasip2

# Build the WebAssembly component ZeroClaw loads.
cargo build --locked --target wasm32-wasip2 --release

# Place the component at the package-root-relative path declared in manifest.toml.
cp target/wasm32-wasip2/release/spl_transfer_build.wasm spl_transfer_build.wasm
```

The component is produced at:

```text
target/wasm32-wasip2/release/spl_transfer_build.wasm
```

This is a WebAssembly plugin artifact, **not** a command to run directly. Do
not execute the `.wasm` path in your shell; install the package-root
`spl_transfer_build.wasm` through the plugin-enabled ZeroClaw binary in step 5.

Useful focused tests:

```bash
# Valid unsigned transaction construction.
cargo test --locked builds_valid_looking_versioned_tx_new_ata

# Ensures a non-allowlisted recipient fails before RPC access.
cargo test --locked prompt_injected_attacker_recipient_fails_closed
```

## 3. Build a plugin-enabled ZeroClaw host

The ordinary Homebrew ZeroClaw binary may not include the `plugin` command.
Build ZeroClaw from source with the Wasm host enabled instead:

```bash
cd ~/Documents
git clone https://github.com/zeroclaw-labs/zeroclaw.git
cd zeroclaw

cargo build --release --features plugins-wasm,plugins-wasm-cranelift
```

Always use this source-built binary for the commands below:

```bash
./target/release/zeroclaw --version
./target/release/zeroclaw plugin --help
```

If `plugin` is reported as an unrecognized subcommand, you are using a binary
without the required Wasm features. Rebuild using the command above.

## 4. Set up an agent

Run Quickstart once to create a model-provider profile and an agent:

```bash
cd ~/Documents/zeroclaw
./target/release/zeroclaw quickstart
```

Choose a model provider, a risk profile, memory backend, and an agent alias.
The CLI channel is enough for local testing; external messaging channels are
optional.

If Quickstart reports that an agent alias already exists, the agent is already
configured. Confirm it with:

```bash
./target/release/zeroclaw agents list
./target/release/zeroclaw status
```

## Update a Gemini API key or resolve a rate limit

The example ZeroClaw profile in this guide is named `openai.gemini_tools` and
uses Gemini through Google's OpenAI-compatible endpoint. Create or select a
Gemini API key in [Google AI Studio](https://aistudio.google.com/), then update
the secret without putting it into terminal history:

```bash
cd ~/Documents/zeroclaw
./target/release/zeroclaw config set \
  providers.models.openai.gemini_tools.api_key
```

Paste the new key only at the masked prompt. Do not add it to this repository,
the plugin configuration, or a shell command line.

Confirm that ZeroClaw stores a key without revealing it:

```bash
./target/release/zeroclaw config list \
  --filter providers.models.openai.gemini_tools
```

The API key line should display as `****`.

A replacement key from the same Google AI Studio project does not necessarily
remove a `429` rate limit; quota is normally tied to the project and usage
tier. Wait for the retry duration returned by Gemini, or use a key from a
project with available quota and billing configured. Check quota in
[Google AI Studio](https://aistudio.google.com/) before retrying.

## 5. Install the local plugin

Install the local directory containing `manifest.toml` and the built Wasm file:

```bash
cd ~/Documents/zeroclaw
./target/release/zeroclaw plugin install \
  ~/Documents/zeroclaw-plugins-main/plugins/spl-transfer-build
```

Verify the installation:

```bash
./target/release/zeroclaw plugin list
./target/release/zeroclaw plugin info spl-transfer-build
```

Expected capabilities and permissions:

```text
Capabilities: [Tool]
Permissions: [HttpClient, ConfigRead]
```

If ZeroClaw says `plugin 'spl-transfer-build' is already loaded`, the plugin
is already installed. This is not a build failure; use `plugin list` and
`plugin info` to verify it instead.

## 6. Configure the recipient allowlist

The plugin denies every recipient until you explicitly allow one. Open the
ZeroClaw configuration field through the CLI:

```bash
cd ~/Documents/zeroclaw
./target/release/zeroclaw config set \
  plugins.entries.spl-transfer-build.config.allowed_recipients
```

Paste the **wallet-owner** public key you want to allow at the masked prompt.
Do not use a private key or seed phrase. This is the supported configuration
path for a plugin named `spl-transfer-build` and ensures the resolved value is
injected into the Wasm component.

For multiple recipients, use a comma-separated list:

```text
FIRST_WALLET_OWNER,SECOND_WALLET_OWNER
```

Keep this list narrowly scoped. An empty or missing `allowed_recipients`
value deliberately allows nobody.

`rpc_url` is optional; the plugin uses `https://api.devnet.solana.com/` by
default. To override it, use the matching configuration field:

```bash
./target/release/zeroclaw config set \
  plugins.entries.spl-transfer-build.config.rpc_url
```

## 7. Run an end-to-end safe test

Use the agent alias you created (the example below uses `adarsh`). The prompt
asks the agent to call only this plugin, and uses Devnet RPC. It builds an
unsigned transaction; it cannot move tokens.

```bash
cd ~/Documents/zeroclaw
./target/release/zeroclaw agent -a adarsh -m 'Use the spl_transfer_build tool exactly once with these arguments and return its output: {"sender":"7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU","recipient":"YOUR_DESTINATION_WALLET_OWNER_ADDRESS","mint":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v","amount":"25.0","decimals":6,"memo":"Plugin smoke test","token_2022":false}. Do not use any other tool.'
```

Because the `adarsh` agent uses supervised mode, ZeroClaw will show a prompt
similar to:

```text
Agent wants to execute: spl_transfer_build
[Y]es / [N]o / [A]lways for spl_transfer_build:
```

Inspect the sender, recipient, mint, amount, decimals, and memo. Enter `Y`
only when those values are correct.

On success, the output contains:

```json
{
  "transaction_base64": "...",
  "summary": "Transfer 25 tokens (25000000 base units) ...",
  "source_ata": "...",
  "destination_ata": "...",
  "destination_ata_will_be_created": true
}
```

The returned transaction still needs an independent wallet approval, signature,
and submission workflow. This plugin never performs those steps.

## 8. Troubleshooting

### `recipient is not approved`

The plugin loaded and its policy worked correctly. Add the exact recipient
wallet-owner public key to `allowed_recipients`, then retry.

### `rpc error: HTTP request failed: ErrorCode::HttpProtocolError`

This commonly occurs with an older build of this plugin whose Devnet RPC URL
lacks an explicit `/` request path. Rebuild and reinstall the plugin so it uses
the corrected default `https://api.devnet.solana.com/`. Alternatively, set the
plugin's `rpc_url` through ZeroClaw to that exact trailing-slash URL:

```bash
./target/release/zeroclaw config set \
  plugins.entries.spl-transfer-build.config.rpc_url
```

Confirm that the endpoint itself is healthy with:

```bash
curl --fail --silent --show-error --max-time 10 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getLatestBlockhash","params":[{"commitment":"finalized"}]}' \
  https://api.devnet.solana.com
```

If this request succeeds and a rebuilt plugin with the trailing-slash URL still
returns `HttpProtocolError`, inspect the ZeroClaw runtime's Wasm HTTP support.

### `unrecognized subcommand 'plugin'`

You are running a ZeroClaw binary built without Wasm plugin features. Use the
source-built binary from step 3.

### `plugin 'spl-transfer-build' is already loaded`

The local plugin is already installed. Run:

```bash
./target/release/zeroclaw plugin info spl-transfer-build
```

### `agent <name> already exists`

Quickstart does not overwrite existing agents. List existing aliases and run
the desired one directly:

```bash
./target/release/zeroclaw agents list
./target/release/zeroclaw agent -a YOUR_AGENT_ALIAS
```

### `No space left on device`

Free disk space and retry the build. A source build of ZeroClaw with the Wasm
host enabled needs several gigabytes of working space.

### `unable to open database file`

Run the command from your normal macOS terminal, where ZeroClaw can access
`~/.zeroclaw/`. If you intentionally use a separate profile, run every command
with the same `--config-dir /path/to/profile` option.

## 9. Normal development loop

After changing plugin code:

```bash
cd ~/Documents/zeroclaw-plugins-main/plugins/spl-transfer-build
cargo test --locked
cargo build --locked --target wasm32-wasip2 --release
cp target/wasm32-wasip2/release/spl_transfer_build.wasm spl_transfer_build.wasm

cd ~/Documents/zeroclaw
./target/release/zeroclaw plugin remove spl-transfer-build
./target/release/zeroclaw plugin install \
  ~/Documents/zeroclaw-plugins-main/plugins/spl-transfer-build
./target/release/zeroclaw plugin info spl-transfer-build
```

Then repeat the safe test in step 7.
