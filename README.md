# OctoMCP

OctoMCP is a Solana Programs Model Context Protocol (MCP) tool that allows anyone to build, test, and deploy Solana programs within minutes, directly from your AI assistant.

## Features

- Build and deploy Solana programs from your AI assistant
- Validate Solana code before building
- Full support for Rust and Anchor frameworks
- Seamless wallet integration
- Support for both devnet and mainnet deployments
- User-friendly error messages and guidance
- Pre-configured UI generation for deployed programs
- Fetch program files (lib.rs, program.so, idl.json)

# Installing OctoMCP

## Prerequisites
* Node.js (v16 or higher)
* npm or yarn
* A Solana wallet with some SOL for transaction fees

## Build from source

```bash
# Clone the repository
git clone https://github.com/octonetai/octomcp.git
cd octomcp

# Install dependencies
npm install

# Build the project
npm run build
```

## Setup

1. Build the project to generate the `build` folder:

```bash
npm run build
```

2. Configure your AI assistant's MCP host to use OctoMCP by creating a configuration file (e.g., `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "OctoMCP": {
      "command": "node",
      "args": [
        "/path/to/your/octomcp/build/index.js"
      ],
      "env": {
        "SOLANA_WALLET_PUBLIC_KEY": "YOUR_WALLET_PUBLIC_KEY",
        "SOLANA_WALLET_PRIVATE_KEY_BS58": "YOUR_BS58_PRIVATE_KEY",
        "SOLANA_DEFAULT_CLUSTER": "devnet"
      }
    }
  }
}
```

Replace the placeholders:
* `/path/to/your/octomcp/build/index.js` - The full path to the built index.js file
* `YOUR_WALLET_PUBLIC_KEY` - Your Solana wallet public key (e.g., `GsAqi6PLSjfDX271Rf3u8wtecidWEpYoYFswmG9wF4QW`)
* `YOUR_BS58_PRIVATE_KEY` - Your Solana wallet private key in BS58 format (see instructions below)
* `devnet` - The default Solana cluster (can be `devnet` or `mainnet`)

## Wallet Configuration Options

OctoMCP supports multiple ways to provide wallet information:

1. **Environment variables** (as shown in the config above)
2. **Command line arguments**: `--wallet-public-key` and `--wallet-private-key-bs58`
3. **Config file**: Create a `solana-config.json` file with wallet information
4. **Auto-generated**: If no wallet is provided, one will be generated automatically on deployment

## Getting Your BS58 Private Key

### 🔑 How to Get Your Private Key from Phantom for OctoMCP

1. Open **Phantom** wallet.
2. Click the **gear icon** (⚙️) in the bottom right corner.
3. Select **Manage Accounts**.
4. Choose your **wallet**.
5. Click **Show Private Key**.
6. Enter your **wallet password**.
7. Copy the **Private Key** and paste it into your **OctoMCP config**.


### From Solflare Wallet

1. Open Solflare wallet
2. Click on your wallet name at the top
3. Click "Export Private Key"
4. Enter your password
5. Copy the private key (this is in BS58 format)

### From Solana CLI Keypair

If you have a Solana CLI keypair file, you can convert it to BS58 format:

```bash
# First, get the byte array from your keypair
solana-keygen dump-keypair --keypair /path/to/your/keypair.json

# Then use this Node.js script to convert to BS58:
node -e "
const bs58 = require('bs58');
const secretKey = [YOUR_SECRET_KEY_ARRAY_HERE]; // Replace with actual array
console.log(bs58.encode(Buffer.from(secretKey)));
"
```

### From Secret Key Array (Legacy Support)

If you have your secret key as an array of numbers, you can convert it to BS58:

```javascript
const bs58 = require('bs58');
const secretKeyArray = [/* your 64-number array */];
const bs58PrivateKey = bs58.encode(Buffer.from(secretKeyArray));
console.log(bs58PrivateKey);
```

## Legacy Configuration (Deprecated)

For backward compatibility, you can still use the array format:

```json
{
  "mcpServers": {
    "OctoMCP": {
      "command": "node",
      "args": [
        "/path/to/your/octomcp/build/index.js"
      ],
      "env": {
        "SOLANA_WALLET_PUBLIC_KEY": "YOUR_WALLET_PUBLIC_KEY",
        "SOLANA_WALLET_SECRET_KEY": "[SECRET_KEY_ARRAY_NUMBERS]",
        "SOLANA_DEFAULT_CLUSTER": "devnet"
      }
    }
  }
}
```

However, using BS58 format is recommended as it's more convenient and matches the format used by popular wallets.

## Security Best Practices

⚠️ **IMPORTANT SECURITY WARNING** ⚠️ 

* Never share your private key with anyone
* Keep your MCP configuration file secure and never commit it to public repositories
* Consider using environment variables instead of hardcoding keys in config files
* Use devnet for testing before deploying to mainnet
* Regularly rotate your keys if they may have been compromised

## Environment Variables Setup

For enhanced security, you can set environment variables instead of putting keys in config files:

```bash
export SOLANA_WALLET_PUBLIC_KEY="your_public_key_here"
export SOLANA_WALLET_PRIVATE_KEY_BS58="your_bs58_private_key_here"
export SOLANA_DEFAULT_CLUSTER="devnet"
```

Then use a simpler config file:

```json
{
  "mcpServers": {
    "OctoMCP": {
      "command": "node",
      "args": [
        "/path/to/your/octomcp/build/index.js"
      ]
    }
  }
}
```

## Working with your AI Assistant

Once configured, you can ask your AI assistant to:

1. Validate a Solana program:
   ```
   "Check if this Solana counter program code is valid"
   ```

2. Build a Solana program:
   ```
   "Build this Solana counter program"
   ```

3. Deploy a program:
   ```
   "Deploy my counter program to devnet with build ID 12345"
   ```

4. Fetch program files:
   ```
   "Fetch the source code, binary, and IDL for build ID 12345"
   ```

5. Generate a UI for your deployed program:
   ```
   "Generate a UI for my deployed program with address Gsa..."
   ```

## Available MCP Tools

OctoMCP provides several tools that your AI assistant can use:

- `validate-solana-program`: Validates Solana code before building
- `build-solana-program`: Compiles Solana programs written in Rust/Anchor
- `deploy-solana-program`: Deploys a program to Solana devnet or mainnet
- `fetch-program-files`: Fetches program files (lib.rs, program.so, idl.json)
- `build-ui`: Generates a frontend UI for an already deployed program

## Tool Parameters

### validate-solana-program
```javascript
{
  code: "Solana program code to validate"
}
```

### build-solana-program
```javascript
{
  code: "Solana program code to build",
  forceBuild: false  // Optional: force build even if validation fails
}
```

### deploy-solana-program
```javascript
{
  buildId: "12345",  // Build ID from build-solana-program
  cluster: "devnet", // "devnet" or "mainnet"
  wallet: {          // Optional: uses default wallet if not specified
    publicKey: "optional-public-key",
    secretKey: [array-of-numbers] // or "base58-encoded-string"
  }
}
```

### fetch-program-files
```javascript
{
  buildId: "12345",      // Build ID to fetch files for
  downloadOnly: false    // Optional: only show download links
}
```





## API Endpoints

OctoMCP communicates with the following API endpoints:

- Build endpoint: `https://octomcp.xyz/build`
- Deploy endpoint: `https://octomcp.xyz/deploy`
- Program files: `https://octomcp.xyz:3003/program/{buildId}/files`
- UI generation: `https://octo.up.railway.app/`

## Troubleshooting

If you encounter issues:

1. Ensure your wallet has sufficient SOL for deployments
2. Check that the path to the index.js file is correct
3. Verify that your wallet keys are properly formatted
4. Look for error messages in the console output

Common issues:
- "Failed to build Solana program" - Check your code for syntax errors
- "Failed to deploy" - Ensure your wallet has enough SOL and the build ID exists
- "Could not fetch IDL" - The build may have succeeded but the IDL couldn't be generated

## Recovering SOL from Failed Deployments

Sometimes Solana program deployments can fail after rent has been paid, leaving your SOL locked in a buffer account. This is particularly common with larger programs or during network congestion. Here's how to recover your SOL:

### Prerequisites
- Install the Solana CLI: `sh -c "$(curl -sSfL https://release.solana.com/v1.16.15/install)"`
- Have your wallet keypair file ready (the same one used for deployment)

### Steps to Recover SOL

1. First, list all your program buffers to identify the ones taking up rent:

```bash
solana program show --buffers --keypair ~/path/to/keypair.json
```

2. Close all buffer accounts to recover the SOL:

```bash
solana program close --buffers --keypair ~/path/to/keypair.json
```

3. For a specific buffer, you can specify the buffer address:

```bash
solana program close <BUFFER_ADDRESS> --keypair ~/path/to/keypair.json
```

This will return the SOL from the buffer accounts back to your wallet. Note that once you close these buffers, any failed deployment will need to be rebuilt completely.


## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.


## Support

For questions and support, please join telegram https://t.me/OctonetAiChat

