import fs from "fs";
import path from "path";
import crypto from "crypto";
import axios from "axios";
import FormData from "form-data";
import chalk from "chalk";

export interface IpfsUploadOptions {
  content: string;
  files?: { name: string, content: string }[];
  encryptionKey?: string;
}

interface EncryptionMetadata {
  version: string;
  algorithm: string;
  salt: string;
  files: {
    [filename: string]: {
      iv: string;
      authTag: string;
    };
  };
}

// Encryption Helpers
function deriveKey(password: string, salt: Buffer): Buffer {
  return crypto.scryptSync(password, salt, 32);
}

function encryptBuffer(buffer: Buffer, key: Buffer): { encrypted: Buffer, iv: string, authTag: string } {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return { encrypted, iv: iv.toString('hex'), authTag: authTag.toString('hex') };
}

function decryptBuffer(encrypted: Buffer, key: Buffer, iv: string, authTag: string): Buffer {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'hex'));
  decipher.setAuthTag(Buffer.from(authTag, 'hex'));
  return Buffer.concat([decipher.update(encrypted), decipher.final()]);
}

/**
 * Unified IPFS Manager
 * Handles Mock vs Real (Pinata) logic internally.
 */
export class IpfsManager {
  private useRealIpfs: boolean;
  private apiKey: string;
  private apiSecret: string;
  private jwt: string;
  private mockStorageDir: string;

  constructor(options?: { useRealIpfs?: boolean, apiKey?: string, apiSecret?: string, jwt?: string }) {
    this.useRealIpfs = options?.useRealIpfs ?? (process.env.USE_REAL_IPFS === "true");
    this.apiKey = options?.apiKey ?? process.env.PINATA_API_KEY ?? "";
    this.apiSecret = options?.apiSecret ?? process.env.PINATA_SECRET_KEY ?? "";
    this.jwt = options?.jwt ?? process.env.PINATA_JWT ?? "";
    
    // Ensure mock directory exists
    this.mockStorageDir = path.join(process.cwd(), "ipfs_storage");
    if (!this.useRealIpfs && !fs.existsSync(this.mockStorageDir)) {
      fs.mkdirSync(this.mockStorageDir, { recursive: true });
    }
  }

  async upload(options: IpfsUploadOptions): Promise<string> {
    if (this.useRealIpfs) {
      return this.uploadReal(options);
    }
    return this.uploadMock(options);
  }

  private async uploadMock(options: IpfsUploadOptions): Promise<string> {
    console.log(chalk.yellow("Using Mock IPFS..."));
    
    // Deterministic hash based on main content (original content for stability)
    const hash = crypto.createHash("sha256").update(options.content).digest("hex");
    const cid = `QmFake${hash.substring(0, 40)}`;
    
    const bundleDir = path.join(this.mockStorageDir, `${cid}_bundle`);
    if (!fs.existsSync(bundleDir)) fs.mkdirSync(bundleDir);

    let encryptionMetadata: EncryptionMetadata | null = null;
    let key: Buffer | null = null;

    if (options.encryptionKey) {
      const salt = crypto.randomBytes(16);
      key = deriveKey(options.encryptionKey, salt);
      encryptionMetadata = {
        version: "1.0",
        algorithm: "aes-256-gcm",
        salt: salt.toString('hex'),
        files: {}
      };
    }

    // Process main file (block.yamo)
    let mainContentBuffer = Buffer.from(options.content);
    if (encryptionMetadata && key) {
      const { encrypted, iv, authTag } = encryptBuffer(mainContentBuffer, key);
      mainContentBuffer = encrypted as any;
      encryptionMetadata.files["block.yamo"] = { iv, authTag };
    }
    fs.writeFileSync(path.join(bundleDir, "block.yamo"), mainContentBuffer);
    
    // Also save legacy single file for non-bundle lookups (only if not encrypted, or maybe just skip?)
    // If encrypted, single file lookup of just content is confusing. We will rely on bundle structure.
    // However, to keep mock consistent, we might write it. But if it's encrypted, it's garbage.
    // We'll write the main content to the CID file (encrypted if enabled).
    fs.writeFileSync(path.join(this.mockStorageDir, cid), mainContentBuffer);

    // Process artifacts
    if (options.files) {
      for (const file of options.files) {
        let fileBuffer = Buffer.from(file.content);
        if (encryptionMetadata && key) {
          const { encrypted, iv, authTag } = encryptBuffer(fileBuffer, key);
           fileBuffer = encrypted as any;
          encryptionMetadata.files[file.name] = { iv, authTag };
        }
        fs.writeFileSync(path.join(bundleDir, file.name), fileBuffer);
      }
    }

    // Save metadata if encrypted
    if (encryptionMetadata) {
      fs.writeFileSync(
        path.join(bundleDir, "encryption_metadata.json"),
        JSON.stringify(encryptionMetadata, null, 2)
      );
    }

    return cid;
  }

  private async uploadReal(options: IpfsUploadOptions): Promise<string> {
    console.log(chalk.yellow("Using Real IPFS (Pinata)..."));
    const endpoint = "https://api.pinata.cloud/pinning/pinFileToIPFS";
    const data = new FormData();
    const bundleDirName = `yamo_bundle_${Date.now()}`;

    let encryptionMetadata: EncryptionMetadata | null = null;
    let key: Buffer | null = null;

    if (options.encryptionKey) {
      const salt = crypto.randomBytes(16);
      key = deriveKey(options.encryptionKey, salt);
      encryptionMetadata = {
        version: "1.0",
        algorithm: "aes-256-gcm",
        salt: salt.toString('hex'),
        files: {}
      };
    }

    // Helper to add file to FormData
    const addFile = (name: string, content: Buffer) => {
       data.append("file", content, {
        filepath: `${bundleDirName}/${name}`,
        contentType: "application/octet-stream", // Binary if encrypted, but safe generic
      });
    };

    // Process main block
    let mainContentBuffer = Buffer.from(options.content);
    if (encryptionMetadata && key) {
      const { encrypted, iv, authTag } = encryptBuffer(mainContentBuffer, key);
      mainContentBuffer = encrypted as any;
      encryptionMetadata.files["block.yamo"] = { iv, authTag };
    }
    
    // Check if block.yamo is explicitly in files (rare but possible)
    const hasBlockYamo = options.files?.some(f => f.name === "block.yamo");
    if (!hasBlockYamo) {
      addFile("block.yamo", mainContentBuffer);
    }

    // Process artifacts
    if (options.files) {
      for (const file of options.files) {
        if (file.name === "block.yamo" && !hasBlockYamo) continue; // Already handled
        
        let fileBuffer = Buffer.from(file.content);
        if (encryptionMetadata && key) {
           const { encrypted, iv, authTag } = encryptBuffer(fileBuffer, key);
            fileBuffer = encrypted as any;
           encryptionMetadata.files[file.name] = { iv, authTag };
        }
        addFile(file.name, fileBuffer);
      }
    }

    // Add metadata file
    if (encryptionMetadata) {
      const metadataBuffer = Buffer.from(JSON.stringify(encryptionMetadata, null, 2));
      addFile("encryption_metadata.json", metadataBuffer);
    }

    const headers: any = { ...data.getHeaders() };
    if (this.jwt) {
      headers["Authorization"] = `Bearer ${this.jwt}`;
    } else {
      headers["pinata_api_key"] = this.apiKey;
      headers["pinata_secret_api_key"] = this.apiSecret;
    }

    try {
      const res = await axios.post(endpoint, data, {
        maxBodyLength: Infinity,
        headers: headers,
      });
      return res.data.IpfsHash;
    } catch (error: any) {
      console.error(chalk.red("IPFS Upload Error:"), error.response?.data || error.message);
      throw new Error("Failed to upload to IPFS");
    }
  }

  async download(cid: string, encryptionKey?: string): Promise<string> {
    const gateway = process.env.IPFS_GATEWAY || "https://gateway.pinata.cloud/ipfs/";
    
    // Helper to fetch/read file
    const getFile = async (filename: string): Promise<Buffer | null> => {
      if (!this.useRealIpfs) {
         // Try bundle path first
         const bundleP = path.join(this.mockStorageDir, `${cid}_bundle`, filename);
         if (fs.existsSync(bundleP)) return fs.readFileSync(bundleP);
         // Try direct path (only for main file/cid)
         if (filename === "block.yamo" || filename === cid) {
             const directP = path.join(this.mockStorageDir, cid);
             if (fs.existsSync(directP)) return fs.readFileSync(directP);
         }
         return null;
      } else {
        try {
          const url = `${gateway}${cid}/${filename}`;
          const res = await axios.get(url, { responseType: 'arraybuffer' });
          return Buffer.from(res.data);
        } catch (e) {
          // If trying to get block.yamo fails, maybe it's a single file CID?
          if (filename === "block.yamo") {
             try {
               const url = `${gateway}${cid}`;
               const res = await axios.get(url, { responseType: 'arraybuffer' });
               return Buffer.from(res.data);
             } catch (e2) { return null; }
          }
          return null;
        }
      }
    };

    // Check for encryption metadata
    const metadataBuf = await getFile("encryption_metadata.json");
    
    if (metadataBuf) {
      if (!encryptionKey) {
        throw new Error(`CID ${cid} is encrypted. Please provide an encryption key.`);
      }
      
      const metadata: EncryptionMetadata = JSON.parse(metadataBuf.toString());
      if (metadata.algorithm !== "aes-256-gcm") {
        throw new Error(`Unsupported encryption algorithm: ${metadata.algorithm}`);
      }
      
      const key = deriveKey(encryptionKey, Buffer.from(metadata.salt, 'hex'));
      const fileMeta = metadata.files["block.yamo"];
      
      if (!fileMeta) {
        throw new Error("Encrypted bundle missing block.yamo metadata");
      }

      const encryptedContent = await getFile("block.yamo");
      if (!encryptedContent) throw new Error("Could not find block.yamo in encrypted bundle");

      const decrypted = decryptBuffer(encryptedContent, key, fileMeta.iv, fileMeta.authTag);
      return decrypted.toString('utf8');
    }

    // Not encrypted
    const content = await getFile("block.yamo");
    if (content) return content.toString('utf8');
    
    // Fallback for single file CIDs (legacy or non-bundle)
    const direct = await getFile(cid); // This effectively retries the gateway root
    if (direct) return direct.toString('utf8');

    throw new Error(`Failed to download CID ${cid}`);
  }
}
