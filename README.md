# @yamo/core

Core blockchain and IPFS library for the YAMO Protocol.

## Overview

`@yamo/core` provides TypeScript client libraries for interacting with YAMO smart contracts on EVM-compatible blockchains and managing IPFS storage for YAMO blocks.

## Features

- **YamoChainClient**: Ethereum/EVM blockchain interaction via ethers.js
  - Submit YAMO blocks to the YAMORegistry smart contract
  - Verify block integrity
  - Query block metadata
  - Support for UUPS upgradeable contracts

- **IpfsManager**: IPFS storage management via Pinata
  - Upload YAMO content and artifacts
  - Deep bundling support (bundle YAMO files with output artifacts)
  - Mock mode for local development (no Pinata credentials required)
  - Returns IPFS CIDs for content verification

## Installation

```bash
npm install @yamo/core
```

## Usage

### YamoChainClient

```typescript
import { YamoChainClient } from '@yamo/core';

const client = new YamoChainClient(
  'http://127.0.0.1:8545',           // RPC URL
  'YOUR_PRIVATE_KEY',                 // Wallet private key
  '0x...'                             // Contract address
);

// Submit a block
await client.submitBlock(
  'block_001',                        // Block ID
  'genesis',                          // Previous block ID
  '0xabc123...',                      // Content hash (SHA256)
  'single_agent',                     // Consensus type
  'main',                             // Ledger name
  'QmXyz...'                           // IPFS CID (optional)
);

// Verify a block
const isValid = await client.verifyBlock('block_001', '0xabc123...');

// Query block metadata
const block = await client.getBlock('block_001');
console.log(block);
```

### IpfsManager

```typescript
import { IpfsManager } from '@yamo/core';

const ipfs = new IpfsManager('YOUR_PINATA_JWT'); // or omit for mock mode

// Upload single file
const cid = await ipfs.upload('agent: MyAgent;\nintent: test;');

// Upload with deep bundling
const cid = await ipfs.uploadBundle(
  'block_001.yamo',
  'agent: MyAgent;\nintent: test;',
  [
    { name: 'output.json', content: '{"result": "success"}' },
    { name: 'analysis.txt', content: 'Analysis results...' }
  ]
);

console.log(`Uploaded to IPFS: ${cid}`);
```

## Environment Variables

- `RPC_URL`: Blockchain RPC endpoint (default: `http://127.0.0.1:8545`)
- `PRIVATE_KEY`: Wallet private key for signing transactions
- `CONTRACT_ADDRESS`: Deployed YAMORegistry contract address
- `PINATA_JWT` or `PINATA_API_KEY`: Pinata credentials (optional, uses mock if not set)

## Development

```bash
# Install dependencies
npm install

# Build
npm run build

# Test
npm test
```

## License

MIT
