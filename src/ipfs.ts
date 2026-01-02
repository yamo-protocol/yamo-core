import fs from "fs";
import path from "path";
import crypto from "crypto";
import axios from "axios";
import FormData from "form-data";
import chalk from "chalk";

export interface IpfsUploadOptions {
  content: string;
  files?: { name: string, content: string }[];
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
    
    // Deterministic hash based on main content
    const hash = crypto.createHash("sha256").update(options.content).digest("hex");
    const cid = `QmFake${hash.substring(0, 40)}`;
    
    // Save main file
    fs.writeFileSync(path.join(this.mockStorageDir, cid), options.content);
    
    // Save bundle if present
    if (options.files) {
      const bundleDir = path.join(this.mockStorageDir, `${cid}_bundle`);
      if (!fs.existsSync(bundleDir)) fs.mkdirSync(bundleDir);
      
      for (const file of options.files) {
        fs.writeFileSync(path.join(bundleDir, file.name), file.content);
      }
    }

    return cid;
  }

  private async uploadReal(options: IpfsUploadOptions): Promise<string> {
    console.log(chalk.yellow("Using Real IPFS (Pinata)..."));
    const endpoint = "https://api.pinata.cloud/pinning/pinFileToIPFS";
    const data = new FormData();

    if (options.files && options.files.length > 0) {
      // Deep Bundle Mode
      const bundleDir = `yamo_bundle_${Date.now()}`;

      // Add main block if not already in files
      const hasBlockYamo = options.files.some(f => f.name === "block.yamo");
      if (!hasBlockYamo) {
        data.append("file", Buffer.from(options.content), {
          filepath: `${bundleDir}/block.yamo`,
          contentType: "text/plain",
        });
      }

      // Add artifacts
      for (const file of options.files) {
        data.append("file", Buffer.from(file.content), {
          filepath: `${bundleDir}/${file.name}`,
          contentType: "text/plain",
        });
      }
    } else {
      // Single File Mode
      data.append("file", Buffer.from(options.content), {
        filename: `yamo_block_${Date.now()}.txt`,
        contentType: "text/plain",
      });
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

  async download(cid: string): Promise<string> {
    const gateway = process.env.IPFS_GATEWAY || "https://gateway.pinata.cloud/ipfs/";
    try {
      if (!this.useRealIpfs) {
        // Mock download
        const p = path.join(this.mockStorageDir, cid);
        if (fs.existsSync(p)) return fs.readFileSync(p, "utf8");
        // Check for bundle
        const bundleP = path.join(this.mockStorageDir, `${cid}_bundle`, "block.yamo");
        if (fs.existsSync(bundleP)) return fs.readFileSync(bundleP, "utf8");
        throw new Error("Mock file not found");
      }

      // Real download
      const res = await axios.get(`${gateway}${cid}/block.yamo`); // Try bundle path first
      return typeof res.data === 'string' ? res.data : JSON.stringify(res.data);
    } catch (error) {
      // Fallback to direct file (not bundle)
      try {
        if (this.useRealIpfs) {
            const res = await axios.get(`${gateway}${cid}`);
            return typeof res.data === 'string' ? res.data : JSON.stringify(res.data);
        }
        throw error;
      } catch (e) {
        throw new Error(`Failed to download CID ${cid}`);
      }
    }
  }
}
