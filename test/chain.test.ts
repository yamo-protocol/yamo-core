import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { YamoChainClient, YAMO_REGISTRY_ABI } from "../src/chain.js";

describe("YamoChainClient", () => {
  let originalEnv: typeof process.env;

  beforeEach(() => {
    // Save original environment
    originalEnv = { ...process.env };
  });

  afterEach(() => {
    // Restore original environment
    process.env = originalEnv;
  });

  describe("Constructor and Basic Methods", () => {
    it("should create client instance without errors", () => {
      expect(() => new YamoChainClient()).not.toThrow();
    });

    it("should store and return contract address when provided", () => {
      const contractAddress = "0x" + "a".repeat(40);
      const client = new YamoChainClient(undefined, undefined, contractAddress);
      expect(client.getContractAddress()).toBe(contractAddress);
    });

    it("should use environment variable for contract address when not provided", () => {
      process.env.CONTRACT_ADDRESS = "0x" + "b".repeat(40);

      const client = new YamoChainClient();
      expect(client.getContractAddress()).toBe("0x" + "b".repeat(40));
    });

    it("should return empty string when no contract address configured", () => {
      delete process.env.CONTRACT_ADDRESS;
      const client = new YamoChainClient();
      expect(client.getContractAddress()).toBe("");
    });
  });

  describe("getContract", () => {
    it("should throw error when contract address not configured", () => {
      delete process.env.CONTRACT_ADDRESS;
      const client = new YamoChainClient(undefined, undefined, "");
      expect(() => client.getContract()).toThrow("Contract address not configured");
    });

    it("should throw error when withSigner is true but no private key", () => {
      const contractAddress = "0x" + "a".repeat(40);
      const client = new YamoChainClient(undefined, undefined, contractAddress);

      expect(() => client.getContract(true)).toThrow("Private key required for write operations");
    });

    it("should return contract instance when configured correctly", () => {
      const contractAddress = "0x" + "a".repeat(40);
      const client = new YamoChainClient(undefined, undefined, contractAddress);

      const contract = client.getContract(false);
      expect(contract).toBeDefined();
      expect(contract.target).toBe(contractAddress);
    });

    it("should return contract instance with signer when private key provided", () => {
      const contractAddress = "0x" + "a".repeat(40);
      const privateKey = "0x" + "1".repeat(64);
      const client = new YamoChainClient(undefined, privateKey, contractAddress);

      const contract = client.getContract(true);
      expect(contract).toBeDefined();
      expect(contract.target).toBe(contractAddress);
      expect(contract.runner).toBeDefined();
    });
  });

  describe("ABI and Constants", () => {
    it("should export YAMO_REGISTRY_ABI with required functions", () => {
      expect(YAMO_REGISTRY_ABI).toBeDefined();
      expect(Array.isArray(YAMO_REGISTRY_ABI)).toBe(true);
      expect(YAMO_REGISTRY_ABI.length).toBeGreaterThan(0);

      // Check for key function signatures
      const abiString = YAMO_REGISTRY_ABI.join(" ");
      expect(abiString).toContain("submitBlock");
      expect(abiString).toContain("submitBlockV2");
      expect(abiString).toContain("verifyBlock");
      expect(abiString).toContain("blockCIDs");
      expect(abiString).toContain("blocks");
      expect(abiString).toContain("latestBlockHash");
    });

    it("should include event definitions in ABI", () => {
      const abiString = YAMO_REGISTRY_ABI.join(" ");
      expect(abiString).toContain("YAMOBlockSubmitted");
      expect(abiString).toContain("YAMOBlockSubmittedV2");
    });
  });
});
