import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { IpfsManager, validatePasswordStrength, DEFAULT_PASSWORD_POLICY } from "../src/ipfs.js";
import axios from "axios";
import fs from "fs";
import path from "path";

// Mock axios
vi.mock("axios");

describe("IpfsManager", () => {
  const mockStorageDir = path.join(process.cwd(), "ipfs_storage");

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe("Password Validation", () => {
    it("should accept strong passwords", () => {
      expect(() => validatePasswordStrength("MyStr0ng!Pass")).not.toThrow();
      expect(() => validatePasswordStrength("C0mpl3x!ty#2025")).not.toThrow();
    });

    it("should reject short passwords", () => {
      expect(() => validatePasswordStrength("Short1!"))
        .toThrow("at least 12 characters");
    });

    it("should reject missing character types", () => {
      // Missing uppercase
      expect(() => validatePasswordStrength("noupper12345!"))
        .toThrow("uppercase letter");

      // Missing lowercase
      expect(() => validatePasswordStrength("NOLOWER12345!"))
        .toThrow("lowercase letter");

      // Missing numbers
      expect(() => validatePasswordStrength("NoNumbersHere!"))
        .toThrow("number");

      // Missing symbols
      expect(() => validatePasswordStrength("NoSymbolsHere123"))
        .toThrow("special character");
    });

    it("should reject common patterns", () => {
      expect(() => validatePasswordStrength("Password123!"))
        .toThrow("common or insecure pattern");

      expect(() => validatePasswordStrength("12345678901!"))
        .toThrow("common or insecure pattern");
    });

    it("should allow custom policy", () => {
      const policy = {
        minLength: 8,
        requireUppercase: false,
        requireLowercase: true,
        requireNumbers: true,
        requireSymbols: false,
        minStrengthScore: 2
      };

      expect(() => validatePasswordStrength("lower123", policy))
        .not.toThrow();

      expect(() => validatePasswordStrength("lower", policy))
        .toThrow();
    });
  });

  describe("Mock Mode", () => {
    it("should save content to bundle directory only (no duplicate)", async () => {
      const ipfs = new IpfsManager({ useRealIpfs: false });
      const content = "test content";

      const cid = await ipfs.upload({ content });

      // Should exist in bundle directory
      const bundleDir = path.join(mockStorageDir, `${cid}_bundle`);
      expect(fs.existsSync(bundleDir)).toBe(true);
      expect(fs.existsSync(path.join(bundleDir, "block.yamo"))).toBe(true);

      // Should NOT exist as duplicate {cid} file
      const legacyPath = path.join(mockStorageDir, cid);
      expect(fs.existsSync(legacyPath)).toBe(false);
    });

    it("should save deep bundles to local directory", async () => {
      const ipfs = new IpfsManager({ useRealIpfs: false });
      const content = "main content";
      const files = [{ name: "output.json", content: "{}" }];

      const cid = await ipfs.upload({ content, files });

      const bundleDir = path.join(mockStorageDir, `${cid}_bundle`);
      expect(fs.existsSync(bundleDir)).toBe(true);
      expect(fs.existsSync(path.join(bundleDir, "output.json"))).toBe(true);
    });

    it("should reject weak passwords for encryption", async () => {
      const ipfs = new IpfsManager({ useRealIpfs: false });

      await expect(ipfs.upload({
        content: "secret data",
        encryptionKey: "weak"  // Too short, missing complexity
      })).rejects.toThrow("Encryption key too weak");
    });

    it("should accept strong passwords for encryption", async () => {
      const ipfs = new IpfsManager({ useRealIpfs: false });

      const cid = await ipfs.upload({
        content: "secret data",
        encryptionKey: "MyStr0ng!Pass"
      });

      expect(cid).toContain("QmFake");

      // Should have encryption metadata
      const bundleDir = path.join(mockStorageDir, `${cid}_bundle`);
      expect(fs.existsSync(path.join(bundleDir, "encryption_metadata.json"))).toBe(true);
    });

    it("should reject path traversal attempts in filenames", async () => {
      const ipfs = new IpfsManager({ useRealIpfs: false });

      // Test various path traversal attempts
      const pathTraversalAttempts = [
        "../etc/passwd",
        "../../etc/passwd",
        "../../../malicious.txt",
        "subdir/../../../outside.txt",
        "./.hidden",
        ".env"
      ];

      for (const maliciousName of pathTraversalAttempts) {
        await expect(ipfs.upload({
          content: "test",
          files: [{ name: maliciousName, content: "malicious" }]
        })).rejects.toThrow(/Invalid filename/);
      }
    });

    it("should accept valid filenames", async () => {
      const ipfs = new IpfsManager({ useRealIpfs: false });

      const validNames = [
        "output.json",
        "result.txt",
        "data_file.csv",
        "image-2024.png"
      ];

      for (const validName of validNames) {
        const cid = await ipfs.upload({
          content: "test",
          files: [{ name: validName, content: "valid content" }]
        });

        const bundleDir = path.join(mockStorageDir, `${cid}_bundle`);
        expect(fs.existsSync(path.join(bundleDir, validName))).toBe(true);
      }
    });
  });

  describe("Bundle Download", () => {
    it("should download unencrypted bundle with all files", async () => {
      const ipfs = new IpfsManager({ useRealIpfs: false });

      // First upload a bundle
      const content = "main content";
      const files = [
        { name: "output.json", content: '{"result": "success"}' },
        { name: "log.txt", content: "some logs" }
      ];

      const cid = await ipfs.upload({ content, files });

      // Now download the bundle
      const bundle = await ipfs.downloadBundle(cid);

      expect(bundle.block).toBe(content);
      expect(bundle.files["output.json"]).toBe('{"result": "success"}');
      expect(bundle.files["log.txt"]).toBe("some logs");
      expect(bundle.metadata?.hasEncryption).toBe(false);
    });

    it("should download encrypted bundle with decryption", async () => {
      const ipfs = new IpfsManager({ useRealIpfs: false });

      // Upload encrypted bundle
      const content = "secret content";
      const files = [{ name: "secret.json", content: '{"secret": "data"}' }];
      const key = "MyStr0ng!Pass";

      const cid = await ipfs.upload({ content, files, encryptionKey: key });

      // Download with correct key
      const bundle = await ipfs.downloadBundle(cid, key);

      expect(bundle.block).toBe(content);
      expect(bundle.files["secret.json"]).toBe('{"secret": "data"}');
      expect(bundle.metadata?.hasEncryption).toBe(true);
    });

    it("should fail to download encrypted bundle without key", async () => {
      const ipfs = new IpfsManager({ useRealIpfs: false });

      // Upload encrypted bundle
      const cid = await ipfs.upload({
        content: "secret content",
        encryptionKey: "MyStr0ng!Pass"
      });

      // Try to download without key
      await expect(ipfs.downloadBundle(cid))
        .rejects.toThrow("is encrypted. Please provide an encryption key");
    });

    it("should fail to download encrypted bundle with wrong key", async () => {
      const ipfs = new IpfsManager({ useRealIpfs: false });

      // Upload encrypted bundle
      const cid = await ipfs.upload({
        content: "secret content",
        encryptionKey: "MyStr0ng!Pass"
      });

      // Try to download with wrong key
      await expect(ipfs.downloadBundle(cid, "Wr0ng!Pass123"))
        .rejects.toThrow("Failed to decrypt");
    });
  });

  describe("Real Mode (Pinata)", () => {
    it("should post to Pinata API", async () => {
      const ipfs = new IpfsManager({
        useRealIpfs: true,
        apiKey: "test",
        apiSecret: "test"
      });

      // Mock successful response
      (axios.post as any).mockResolvedValue({
        data: { IpfsHash: "QmRealHash123" }
      });

      const cid = await ipfs.upload({ content: "real data" });

      expect(cid).toBe("QmRealHash123");
      expect(axios.post).toHaveBeenCalledWith(
        expect.stringContaining("pinning/pinFileToIPFS"),
        expect.any(Object), // FormData
        expect.objectContaining({
          headers: expect.objectContaining({
            pinata_api_key: "test"
          })
        })
      );
    });

    it("should use JWT if provided", async () => {
      const ipfs = new IpfsManager({
        useRealIpfs: true,
        jwt: "fake-jwt"
      });

      (axios.post as any).mockResolvedValue({
        data: { IpfsHash: "QmJWT" }
      });

      await ipfs.upload({ content: "jwt data" });

      expect(axios.post).toHaveBeenCalledWith(
        expect.any(String),
        expect.any(Object),
        expect.objectContaining({
          headers: expect.objectContaining({
            Authorization: "Bearer fake-jwt"
          })
        })
      );
    });

    it("should reject weak passwords in real mode", async () => {
      const ipfs = new IpfsManager({
        useRealIpfs: true,
        apiKey: "test",
        apiSecret: "test"
      });

      await expect(ipfs.upload({
        content: "data",
        encryptionKey: "weak"
      })).rejects.toThrow("Encryption key too weak");
    });
  });
});
