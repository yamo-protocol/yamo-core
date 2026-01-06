import { ethers } from "ethers";
import chalk from "chalk";

export const YAMO_REGISTRY_ABI = [
  "function submitBlock(string blockId, string previousBlock, bytes32 contentHash, string consensusType, string ledger) public",
  "function submitBlockV2(string blockId, string previousBlock, bytes32 contentHash, string consensusType, string ledger, string ipfsCID) public",
  "function verifyBlock(string blockId, bytes32 contentHash) public view returns (bool)",
  "function blockCIDs(string) view returns (string)",
  "function blocks(string) view returns (string, string, address, bytes32, uint256, string, string)",
  "function latestBlockHash() view returns (bytes32)",
  "event YAMOBlockSubmitted(string indexed blockId, string previousBlock, address indexed agent, bytes32 contentHash)",
  "event YAMOBlockSubmittedV2(string indexed blockId, bytes32 contentHash, string ipfsCID)"
];

/**
 * Client for interacting with the YAMO Registry smart contract on the blockchain.
 * Provides methods for submitting blocks, retrieving block data, and querying the chain state.
 */
export class YamoChainClient {
  private provider: ethers.Provider;
  private wallet?: ethers.Wallet;
  private contractAddress: string;

  /**
   * Creates a new YamoChainClient instance.
   * @param rpcUrl - The RPC URL for connecting to the blockchain. Defaults to RPC_URL environment variable or "http://127.0.0.1:8545"
   * @param privateKey - Private key for signing transactions. If not provided, write operations will fail. Defaults to PRIVATE_KEY environment variable
   * @param contractAddress - Address of the YAMO Registry contract. Defaults to CONTRACT_ADDRESS environment variable
   * @example
   * ```typescript
   * // Read-only client
   * const client = new YamoChainClient("https://rpc.example.com");
   *
   * // Client with write capabilities
   * const client = new YamoChainClient(
   *   "https://rpc.example.com",
   *   "0x1234...",
   *   "0xabcd..."
   * );
   * ```
   */
  constructor(rpcUrl?: string, privateKey?: string, contractAddress?: string) {
    this.contractAddress = contractAddress ?? process.env.CONTRACT_ADDRESS ?? "";
    const url = rpcUrl ?? process.env.RPC_URL ?? "http://127.0.0.1:8545";

    this.provider = new ethers.JsonRpcProvider(url);

    const pk = privateKey ?? process.env.PRIVATE_KEY;
    if (pk) {
      this.wallet = new ethers.Wallet(pk, this.provider);
    }
  }

  getContract(withSigner = false) {
    if (!this.contractAddress) throw new Error("Contract address not configured");

    if (withSigner && !this.wallet) {
        throw new Error("Private key required for write operations");
    }

    return new ethers.Contract(
      this.contractAddress,
      YAMO_REGISTRY_ABI,
      withSigner ? this.wallet : this.provider
    );
  }

  /**
   * Returns the configured contract address.
   * @returns The YAMO Registry contract address
   */
  getContractAddress(): string {
    return this.contractAddress;
  }

  /**
   * Submits a new YAMO block to the blockchain registry.
   * Uses V2 submission if ipfsCID is provided, otherwise uses V1.
   * @param blockId - Unique identifier for the block
   * @param previousBlock - Hash of the previous block (use "0x0000..." for genesis block)
   * @param contentHash - SHA-256 hash of the block content (as hex string, with or without "0x" prefix)
   * @param consensusType - Type of consensus mechanism used (e.g., "ai", "pow", "pos")
   * @param ledger - Ledger identifier (e.g., "main", "test")
   * @param ipfsCID - Optional IPFS CID for V2 blocks with off-chain storage
   * @returns Transaction receipt
   * @throws {Error} If contract address not configured or private key missing
   * @example
   * ```typescript
   * // Submit V1 block
   * await client.submitBlock(
   *   "block-1",
   *   "0x0000000000000000000000000000000000000000000000000000000000000000",
   *   "0xabcd1234...",
   *   "ai",
   *   "main"
   * );
   *
   * // Submit V2 block with IPFS
   * await client.submitBlock(
   *   "block-2",
   *   "0x1234...",
   *   "0xabcd...",
   *   "ai",
   *   "main",
   *   "QmTest123..."
   * );
   * ```
   */
  async submitBlock(
    blockId: string,
    previousBlock: string,
    contentHash: string,
    consensusType: string,
    ledger: string,
    ipfsCID?: string
  ) {
    const contract = this.getContract(true);
    const hashBytes = contentHash.startsWith("0x") ? contentHash : `0x${contentHash}`;

    console.log(chalk.blue(`Submitting Block ${blockId} to ${this.contractAddress}...`));

    let tx;
    if (ipfsCID) {
      tx = await contract.submitBlockV2(blockId, previousBlock, hashBytes, consensusType, ledger, ipfsCID);
    } else {
      tx = await contract.submitBlock(blockId, previousBlock, hashBytes, consensusType, ledger);
    }

    console.log(chalk.yellow("Waiting for confirmation..."));
    await tx.wait();
    console.log(chalk.green(`Confirmed! Tx: ${tx.hash}`));
    return tx;
  }

  /**
   * Retrieves block data from the blockchain registry by block ID.
   * @param blockId - The unique identifier of the block to retrieve
   * @returns Block data including metadata and IPFS CID (for V2 blocks), or null if block not found
   * @example
   * ```typescript
   * const block = await client.getBlock("block-1");
   * if (block) {
   *   console.log("Block:", block.blockId);
   *   console.log("Content Hash:", block.contentHash);
   *   console.log("IPFS CID:", block.ipfsCID);
   * }
   * ```
   */
  async getBlock(blockId: string) {
    const contract = this.getContract(false);
    try {
      const data = await contract.blocks(blockId);
      // Contract returns struct as array-like object
      // [blockId, previousBlock, agentAddress, contentHash, timestamp, consensusType, ledger]

      if (!data[0]) return null;

      // Try to get CID (V2)
      let ipfsCID = undefined;
      try {
        ipfsCID = await contract.blockCIDs(blockId);
      } catch (e) {
        // V1 contract or no CID
      }

      return {
        blockId: data[0],
        previousBlock: data[1],
        agentAddress: data[2],
        contentHash: data[3],
        timestamp: Number(data[4]),
        consensusType: data[5],
        ledger: data[6],
        ipfsCID: ipfsCID
      };
    } catch (e) {
      return null;
    }
  }

  /**
   * Gets the latest block's content hash directly from contract state.
   * This is the recommended method for chain continuation as it's more efficient than getLatestBlock().
   * @returns The content hash of the most recently submitted block as a hex string
   * @throws {Error} If contract address not configured
   * @example
   * ```typescript
   * const latestHash = await client.getLatestBlockHash();
   * console.log("Latest block hash:", latestHash);
   *
   * // Use as previousBlock for next submission
   * await client.submitBlock("new-block", latestHash, ...);
   * ```
   */
  async getLatestBlockHash(): Promise<string> {
    const contract = this.getContract(false);
    const hash = await contract.latestBlockHash();
    return hash;
  }

  /**
   * Retrieves the complete latest block data by querying blockchain events.
   * This method is more expensive than getLatestBlockHash() but returns full block metadata.
   * Attempts to find V2 events first, then falls back to V1 events if not found.
   * @returns Complete block data including all metadata and optional IPFS CID, or null if no blocks exist
   * @example
   * ```typescript
   * const latestBlock = await client.getLatestBlock();
   * if (latestBlock) {
   *   console.log("Latest block ID:", latestBlock.blockId);
   *   console.log("Timestamp:", latestBlock.timestamp);
   *   console.log("Consensus:", latestBlock.consensusType);
   * }
   * ```
   */
  async getLatestBlock(): Promise<{
    blockId: string;
    previousBlock: string;
    agentAddress: string;
    contentHash: string;
    timestamp: number;
    consensusType: string;
    ledger: string;
    ipfsCID?: string;
  } | null> {
    const contract = this.getContract(false);

    try {
      let latestEvent: ethers.EventLog | null = null;
      let latestBlockNumber = 0;

      const currentBlock = await this.provider.getBlockNumber();
      const PAGE_SIZE = 40000; // Under most limits
      const MAX_LOOKBACK = 200000; // 0.2M blocks ~ 1 month
      const startBlock = Math.max(0, currentBlock - MAX_LOOKBACK);

      // Helper for paginated query
      const queryPaginated = async (filter: any) => {
        let events: (ethers.EventLog | ethers.Log)[] = [];
        for (let from = currentBlock; from > startBlock; from -= PAGE_SIZE) {
            const to = from;
            const fromActual = Math.max(startBlock, from - PAGE_SIZE);
            try {
                const batch = await contract.queryFilter(filter, fromActual, to);
                if (batch.length > 0) {
                    events = batch;
                    break; // Found recent events in this batch
                }
            } catch (e) {
                console.warn(`[YamoChainClient] Batch query failed (${fromActual}-${to}): ${e}`);
            }
        }
        return events;
      };

      // Try V2 events first
      const v2Events = await queryPaginated(contract.filters.YAMOBlockSubmittedV2());
      
      for (const event of v2Events) {
        if (event instanceof ethers.EventLog && event.blockNumber > latestBlockNumber) {
          latestBlockNumber = event.blockNumber;
          latestEvent = event;
        }
      }

      // If no V2 events found, try V1 events
      if (!latestEvent) {
        const v1Events = await queryPaginated(contract.filters.YAMOBlockSubmitted());
        for (const event of v1Events) {
          if (event instanceof ethers.EventLog && event.blockNumber > latestBlockNumber) {
            latestBlockNumber = event.blockNumber;
            latestEvent = event;
          }
        }
      }

      if (!latestEvent) {
        return null;
      }

      // The event's blockId is indexed (keccak256 hash), but we can get the actual blockId
      // by looking at the transaction that emitted the event
      // For now, we need to iterate through known blockIds or use a different approach
      // As a workaround, let's get the transaction receipt and decode the input data

      const txReceipt = await this.provider.getTransactionReceipt(latestEvent.transactionHash);
      if (!txReceipt) return null;

      // Decode the transaction input to get the blockId
      // submitBlock(string blockId, string previousBlock, bytes32 contentHash, string consensusType, string ledger)
      const tx = await this.provider.getTransaction(latestEvent.transactionHash);
      if (!tx) return null;

      const iface = new ethers.Interface(YAMO_REGISTRY_ABI);
      const decoded = iface.parseTransaction(tx);
      if (!decoded) return null;

      const blockId = decoded.args[0] as string;
      return await this.getBlock(blockId);
    } catch (e) {
      const errorMessage = e instanceof Error ? e.message : String(e);
      console.error(`[YamoChainClient] getLatestBlock failed: ${errorMessage}`);
      if (e instanceof Error && e.stack) {
        console.error(`[YamoChainClient] Stack trace: ${e.stack}`);
      }
      throw e;
    }
  }
}
