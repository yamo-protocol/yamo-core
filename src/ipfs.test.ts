import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { IpfsManager } from "./ipfs.js";
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

  describe("Mock Mode", () => {
    it("should save content to local file system", async () => {
      const ipfs = new IpfsManager({ useRealIpfs: false });
      const content = "test content";
      
      const cid = await ipfs.upload({ content });
      
      expect(cid).toContain("QmFake");
      const savedPath = path.join(mockStorageDir, cid);
      expect(fs.existsSync(savedPath)).toBe(true);
      expect(fs.readFileSync(savedPath, "utf8")).toBe(content);
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
  });
});
