# @yamo/core

[![npm version](https://img.shields.io/npm/v/@yamo/core)](https://www.npmjs.com/package/@yamo/core)

The core logic library for the YAMO Protocol. It handles:
- Blockchain interactions (reading/writing to the Registry).
- IPFS Storage (Mock and Pinata).
- **Secure Bundling**: Creating and managing encrypted/unencrypted file bundles.

## Features

### 📦 IPFS Bundling
Automatically bundles a main YAMO file with its referenced artifacts (outputs) into a single IPFS directory structure.

### 🔒 Encryption (AES-256-GCM)
Provides robust, optional encryption for IPFS content.
- **Zero-Knowledge**: Keys are never sent to the network, only used locally to encrypt/decrypt.
- **Authenticated**: GCM mode ensures data integrity; any tampering with the ciphertext is detected.
- **Key Derivation**: Uses `scrypt` for secure password hashing.

## Usage

```typescript
import { IpfsManager } from "@yamo/core";

const ipfs = new IpfsManager({ useRealIpfs: true });

// Upload with Encryption
const cid = await ipfs.upload({
  content: "agent: secret_bot; ...",
  files: [{ name: "data.json", content: "{...}" }],
  encryptionKey: "my-super-secret-password"
});

// Download and Decrypt
const content = await ipfs.download(cid, "my-super-secret-password");
```
