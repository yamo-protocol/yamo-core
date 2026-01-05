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

export interface BundleDownloadResult {
  block: string;
  files: { [filename: string]: string };
  metadata?: {
    version: string;
    algorithm: string;
    hasEncryption: boolean;
  };
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

export interface PasswordPolicy {
  minLength: number;
  requireUppercase: boolean;
  requireLowercase: boolean;
  requireNumbers: boolean;
  requireSymbols: boolean;
  minStrengthScore: number;
}

export const DEFAULT_PASSWORD_POLICY: PasswordPolicy = {
  minLength: 12,
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
  requireSymbols: true,
  minStrengthScore: 4  // Require ALL character types for strong passwords
};

/**
 * Validates password strength against security policy.
 * Throws Error if password doesn't meet requirements.
 */
export function validatePasswordStrength(
  password: string,
  policy: PasswordPolicy = DEFAULT_PASSWORD_POLICY
): void {
  // Check for common patterns FIRST (fail fast)
  const commonPatterns = [
    /^password/i,
    /^123456/,
    /^qwerty/i,
    /^abc123/i,
    /^(.)\1{4,}/  // Repeated characters like "aaaaa"
  ];

  for (const pattern of commonPatterns) {
    if (pattern.test(password)) {
      throw new Error(
        "Encryption key contains common or insecure pattern. " +
        "Use a more secure passphrase."
      );
    }
  }

  const errors: string[] = [];

  // Check length
  if (password.length < policy.minLength) {
    errors.push(`at least ${policy.minLength} characters`);
  }

  // Check character types
  let strengthScore = 0;

  if (policy.requireUppercase && /[A-Z]/.test(password)) {
    strengthScore++;
  } else if (policy.requireUppercase) {
    errors.push("uppercase letter");
  }

  if (policy.requireLowercase && /[a-z]/.test(password)) {
    strengthScore++;
  } else if (policy.requireLowercase) {
    errors.push("lowercase letter");
  }

  if (policy.requireNumbers && /[0-9]/.test(password)) {
    strengthScore++;
  } else if (policy.requireNumbers) {
    errors.push("number");
  }

  if (policy.requireSymbols && /[^A-Za-z0-9]/.test(password)) {
    strengthScore++;
  } else if (policy.requireSymbols) {
    errors.push("special character (!@#$%^&*)");
  }

  // Check overall strength (character types)
  if (strengthScore < policy.minStrengthScore) {
    throw new Error(
      `Encryption key too weak. Must include ${errors.join(", ")}. ` +
      `Current strength: ${strengthScore}/${policy.minStrengthScore} criteria met.`
    );
  }

  // Check length separately to ensure both requirements are met
  if (password.length < policy.minLength) {
    throw new Error(
      `Encryption key too weak. Must be at least ${policy.minLength} characters. ` +
      `Current length: ${password.length}.`
    );
  }
}

// Security Helper: Prevent path traversal attacks
function sanitizeFilename(filename: string): string {
  // Get just the basename (removes any directory components)
  const basename = path.basename(filename);

  // Reject if the basename doesn't match the original (indicates path traversal attempt)
  // or if it starts with a dot (hidden files could be security risk)
  if (basename !== filename) {
    throw new Error(
      `Invalid filename: "${filename}". Filenames cannot contain directory separators.`
    );
  }

  if (basename.startsWith('.')) {
    throw new Error(
      `Invalid filename: "${filename}". Filenames cannot start with a dot.`
    );
  }

  // Reject empty or whitespace-only names
  if (!basename.trim()) {
    throw new Error(`Invalid filename: Filename cannot be empty or whitespace.`);
  }

  return basename;
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
 * Prepares encryption key and metadata from password.
 * Returns null if no encryption key provided.
 */
function prepareEncryption(encryptionKey?: string): {
  key: Buffer;
  metadata: EncryptionMetadata;
} | null {
  if (!encryptionKey) return null;

  // Validate password strength before encryption
  validatePasswordStrength(encryptionKey);

  const salt = crypto.randomBytes(16);
  const key = deriveKey(encryptionKey, salt);
  const metadata: EncryptionMetadata = {
    version: "1.0",
    algorithm: "aes-256-gcm",
    salt: salt.toString('hex'),
    files: {}
  };

  return { key, metadata };
}

/**
 * Encrypts content and updates metadata. Returns encrypted buffer.
 * If encryption context not provided, returns original buffer.
 */
function encryptContent(
  content: string,
  filename: string,
  encryptionContext: { key: Buffer; metadata: EncryptionMetadata } | null
): Buffer {
  const buffer = Buffer.from(content);

  if (encryptionContext) {
    const { encrypted, iv, authTag } = encryptBuffer(buffer, encryptionContext.key);
    encryptionContext.metadata.files[filename] = { iv, authTag };
    return encrypted;
  }

  return buffer;
}

/**
 * Wrapper for decryptBuffer with enhanced error messages.
 * Provides context-specific error information for debugging.
 */
function decryptBufferSafe(
  encrypted: Buffer,
  key: Buffer,
  iv: string,
  authTag: string,
  context?: string
): Buffer {
  try {
    return decryptBuffer(encrypted, key, iv, authTag);
  } catch (e: unknown) {
    const errorMessage = e instanceof Error ? e.message : String(e);
    throw new Error(
      `Decryption failed${context ? ` for ${context}` : ""}. ` +
      `Possible causes:\n` +
      `  • Incorrect encryption key\n` +
      `  • Data corrupted during transmission\n` +
      `  • Encryption metadata tampered with\n` +
      `  • Unsupported algorithm version\n` +
      `Original error: ${errorMessage}`
    );
  }
}

/**
 * Unified IPFS Manager for uploading and downloading YAMO blocks.
 * Supports both mock (local filesystem) and real IPFS (Pinata) storage.
 * Provides optional AES-256-GCM encryption for secure off-chain storage.
 *
 * @example
 * ```typescript
 * // Mock IPFS (local storage)
 * const ipfs = new IpfsManager({ useRealIpfs: false });
 *
 * // Real IPFS with Pinata
 * const ipfs = new IpfsManager({
 *   useRealIpfs: true,
 *   jwt: "your-pinata-jwt"
 * });
 *
 * // Upload with encryption
 * const cid = await ipfs.upload({
 *   content: "yamo block content",
 *   files: [{ name: "output.json", content: "{}" }],
 *   encryptionKey: "MyStr0ng!Password123"
 * });
 *
 * // Download with decryption
 * const content = await ipfs.download(cid, "MyStr0ng!Password123");
 * ```
 */
export class IpfsManager {
  private useRealIpfs: boolean;
  private apiKey: string;
  private apiSecret: string;
  private jwt: string;
  private mockStorageDir: string;

  /**
   * Creates a new IpfsManager instance.
   * @param options - Configuration options
   * @param options.useRealIpfs - If true, uses Pinata for real IPFS. If false, uses local mock storage. Defaults to USE_REAL_IPFS environment variable
   * @param options.apiKey - Pinata API key (alternative to JWT). Defaults to PINATA_API_KEY environment variable
   * @param options.apiSecret - Pinata API secret (alternative to JWT). Defaults to PINATA_SECRET_KEY environment variable
   * @param options.jwt - Pinata JWT token (recommended over API key). Defaults to PINATA_JWT environment variable
   */
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

  /**
   * Uploads a YAMO block bundle to IPFS (or mock storage).
   * Optionally encrypts all files with AES-256-GCM encryption.
   * @param options - Upload options
   * @param options.content - Main YAMO block content (stored as block.yamo)
   * @param options.files - Optional array of additional files to include in the bundle
   * @param options.encryptionKey - Optional password for encrypting the bundle. Must meet strength requirements.
   * @returns The IPFS CID (Content Identifier) for the uploaded bundle
   * @throws {Error} If encryption key doesn't meet strength requirements
   * @throws {Error} If file names contain invalid characters or path traversal attempts
   * @throws {Error} If upload to IPFS fails
   * @example
   * ```typescript
   * // Upload unencrypted
   * const cid = await ipfs.upload({
   *   content: "yamo block data",
   *   files: [
   *     { name: "output.json", content: "{}" },
   *     { name: "metrics.csv", content: "..." }
   *   ]
   * });
   *
   * // Upload with encryption
   * const cid = await ipfs.upload({
   *   content: "sensitive data",
   *   encryptionKey: "MySecure!Pass123"
   * });
   * ```
   */
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

    // Prepare encryption if needed
    const encryptionContext = prepareEncryption(options.encryptionKey);

    // Process main file (block.yamo)
    const mainContentBuffer = encryptContent(options.content, "block.yamo", encryptionContext);
    fs.writeFileSync(path.join(bundleDir, "block.yamo"), mainContentBuffer);

    // Process artifacts
    if (options.files) {
      for (const file of options.files) {
        const safeName = sanitizeFilename(file.name);
        const fileBuffer = encryptContent(file.content, safeName, encryptionContext);
        fs.writeFileSync(path.join(bundleDir, safeName), fileBuffer);
      }
    }

    // Save metadata if encrypted
    if (encryptionContext) {
      fs.writeFileSync(
        path.join(bundleDir, "encryption_metadata.json"),
        JSON.stringify(encryptionContext.metadata, null, 2)
      );
    }

    return cid;
  }

  private async uploadReal(options: IpfsUploadOptions): Promise<string> {
    console.log(chalk.yellow("Using Real IPFS (Pinata)..."));
    const endpoint = "https://api.pinata.cloud/pinning/pinFileToIPFS";
    const data = new FormData();
    const bundleDirName = `yamo_bundle_${Date.now()}`;

    // Prepare encryption if needed
    const encryptionContext = prepareEncryption(options.encryptionKey);

    // Helper to add file to FormData
    const addFile = (name: string, content: Buffer) => {
       data.append("file", content, {
        filepath: `${bundleDirName}/${name}`,
        contentType: "application/octet-stream", // Binary if encrypted, but safe generic
      });
    };

    // Process main block
    const mainContentBuffer = encryptContent(options.content, "block.yamo", encryptionContext);

    // Check if block.yamo is explicitly in files (rare but possible)
    const hasBlockYamo = options.files?.some(f => f.name === "block.yamo");
    if (!hasBlockYamo) {
      addFile("block.yamo", mainContentBuffer);
    }

    // Process artifacts
    if (options.files) {
      for (const file of options.files) {
        const safeName = sanitizeFilename(file.name);
        if (safeName === "block.yamo" && !hasBlockYamo) continue; // Already handled

        const fileBuffer = encryptContent(file.content, safeName, encryptionContext);
        addFile(safeName, fileBuffer);
      }
    }

    // Add metadata file
    if (encryptionContext) {
      const metadataBuffer = Buffer.from(JSON.stringify(encryptionContext.metadata, null, 2));
      addFile("encryption_metadata.json", metadataBuffer);
    }

    const headers: Record<string, string> = { ...data.getHeaders() };
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
    } catch (error: unknown) {
      const errorData = error instanceof Error && 'response' in error
        ? (error as { response?: { data?: unknown } }).response?.data
        : undefined;
      const errorMessage = error instanceof Error ? error.message : String(error);
      console.error(chalk.red("IPFS Upload Error:"), errorData || errorMessage);
      throw new Error("Failed to upload to IPFS");
    }
  }

  /**
   * Downloads and decrypts a YAMO block from IPFS (or mock storage).
   * Returns only the main block content (block.yamo).
   * @param cid - The IPFS CID to download
   * @param encryptionKey - Optional decryption password (required if bundle is encrypted)
   * @returns The main block content as a string
   * @throws {Error} If CID is encrypted but no decryption key provided
   * @throws {Error} If decryption fails (wrong key or corrupted data)
   * @throws {Error} If CID not found
   * @example
   * ```typescript
   * // Download unencrypted block
   * const content = await ipfs.download("QmTest123...");
   *
   * // Download encrypted block
   * const content = await ipfs.download("QmTest123...", "MySecure!Pass123");
   * ```
   */
  async download(cid: string, encryptionKey?: string): Promise<string> {
    const gateway = process.env.IPFS_GATEWAY || "https://gateway.pinata.cloud/ipfs/";
    
    // Helper to fetch/read file
    const getFile = async (filename: string): Promise<Buffer | null> => {
      if (!this.useRealIpfs) {
         // Try bundle path first (correct path)
         const bundleP = path.join(this.mockStorageDir, `${cid}_bundle`, filename);
         if (fs.existsSync(bundleP)) return fs.readFileSync(bundleP);
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

  /**
   * Downloads a complete YAMO bundle including all files.
   * Returns the main block content plus all additional artifact files.
   * @param cid - The IPFS CID to download
   * @param encryptionKey - Optional decryption password (required if bundle is encrypted)
   * @returns Bundle data containing block content, all files, and encryption metadata
   * @throws {Error} If CID is encrypted but no decryption key provided
   * @throws {Error} If decryption fails for any file
   * @example
   * ```typescript
   * // Download unencrypted bundle
   * const bundle = await ipfs.downloadBundle("QmTest123...");
   * console.log("Block:", bundle.block);
   * console.log("Files:", Object.keys(bundle.files));
   *
   * // Download encrypted bundle
   * const bundle = await ipfs.downloadBundle("QmTest123...", "MySecure!Pass123");
   * console.log("Output:", bundle.files["output.json"]);
   * console.log("Encrypted:", bundle.metadata?.hasEncryption);
   * ```
   */
  async downloadBundle(
    cid: string,
    encryptionKey?: string
  ): Promise<BundleDownloadResult> {
    const result: BundleDownloadResult = {
      block: "",
      files: {},
      metadata: undefined
    };

    const gateway = process.env.IPFS_GATEWAY || "https://gateway.pinata.cloud/ipfs/";

    // Helper to fetch/read file
    const getFile = async (filename: string): Promise<Buffer | null> => {
      if (!this.useRealIpfs) {
        const bundleP = path.join(this.mockStorageDir, `${cid}_bundle`, filename);
        if (fs.existsSync(bundleP)) return fs.readFileSync(bundleP);
        return null;
      } else {
        try {
          const url = `${gateway}${cid}/${filename}`;
          const res = await axios.get(url, { responseType: 'arraybuffer' });
          return Buffer.from(res.data);
        } catch (e) {
          return null;
        }
      }
    };

    // Check for encryption metadata
    const metadataBuf = await getFile("encryption_metadata.json");

    if (metadataBuf) {
      // Encrypted bundle
      if (!encryptionKey) {
        throw new Error(
          `CID ${cid} is encrypted. Please provide an encryption key to download the bundle.`
        );
      }

      const metadata: EncryptionMetadata = JSON.parse(metadataBuf.toString());
      result.metadata = {
        version: metadata.version,
        algorithm: metadata.algorithm,
        hasEncryption: true
      };

      if (metadata.algorithm !== "aes-256-gcm") {
        throw new Error(`Unsupported encryption algorithm: ${metadata.algorithm}`);
      }

      const key = deriveKey(encryptionKey, Buffer.from(metadata.salt, 'hex'));

      // Decrypt block.yamo
      const blockMeta = metadata.files["block.yamo"];
      if (!blockMeta) {
        throw new Error("Encrypted bundle missing block.yamo metadata");
      }

      const encryptedBlock = await getFile("block.yamo");
      if (!encryptedBlock) {
        throw new Error("Could not find block.yamo in encrypted bundle");
      }

      try {
        const decryptedBlock = decryptBuffer(
          encryptedBlock,
          key,
          blockMeta.iv,
          blockMeta.authTag
        );
        result.block = decryptedBlock.toString('utf8');
      } catch (e: unknown) {
        throw new Error(
          "Failed to decrypt block.yamo. " +
          "This usually means the encryption key is incorrect."
        );
      }

      // Decrypt all artifact files
      for (const [filename, fileMeta] of Object.entries(metadata.files)) {
        if (filename === "block.yamo") continue; // Already handled

        const encryptedFile = await getFile(filename);
        if (!encryptedFile) {
          console.warn(chalk.yellow(`Warning: Could not find ${filename} in bundle`));
          continue;
        }

        try {
          const decryptedFile = decryptBuffer(
            encryptedFile,
            key,
            fileMeta.iv,
            fileMeta.authTag
          );
          result.files[filename] = decryptedFile.toString('utf8');
        } catch (e) {
          console.warn(chalk.yellow(`Warning: Failed to decrypt ${filename}`));
          result.files[filename] = `[ENCRYPTED - decryption failed]`;
        }
      }

    } else {
      // Not encrypted - plain download
      result.metadata = {
        version: "1.0",
        algorithm: "none",
        hasEncryption: false
      };

      // Get block.yamo
      const blockBuf = await getFile("block.yamo");
      if (blockBuf) {
        result.block = blockBuf.toString('utf8');
      }

      // Get all files in bundle
      if (!this.useRealIpfs) {
        const bundleDir = path.join(this.mockStorageDir, `${cid}_bundle`);
        if (fs.existsSync(bundleDir)) {
          const files = fs.readdirSync(bundleDir);
          for (const file of files) {
            if (file === "block.yamo" || file === "encryption_metadata.json") continue;

            const filePath = path.join(bundleDir, file);
            if (fs.statSync(filePath).isFile()) {
              result.files[file] = fs.readFileSync(filePath, 'utf8');
            }
          }
        }
      }
    }

    return result;
  }
}
