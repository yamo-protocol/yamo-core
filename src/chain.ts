import { ethers } from "ethers";
import chalk from "chalk";

export const YAMO_REGISTRY_ABI = [
  "function submitBlock(string blockId, string previousBlock, bytes32 contentHash, string consensusType, string ledger) public",
  "function submitBlockV2(string blockId, string previousBlock, bytes32 contentHash, string consensusType, string ledger, string ipfsCID) public",
  "function verifyBlock(string blockId, bytes32 contentHash) public view returns (bool)",
  "function blockCIDs(string) view returns (string)",
  "function blocks(string) view returns (string, string, address, bytes32, uint256, string, string)",
  "event YAMOBlockSubmitted(string indexed blockId, string previousBlock, address indexed agent, bytes32 contentHash)",
  "event YAMOBlockSubmittedV2(string indexed blockId, bytes32 contentHash, string ipfsCID)"
];

export class YamoChainClient {
  private provider: ethers.Provider;
  private wallet?: ethers.Wallet;
  private contractAddress: string;

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

  getContractAddress(): string {
    return this.contractAddress;
  }

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
      let latestEvent: any = null;
      let latestBlockNumber = 0;

      // Try V2 events first (with IPFS)
      try {
        const v2Filter = contract.filters.YAMOBlockSubmittedV2();
        const v2Events = await contract.queryFilter(v2Filter);

        for (const event of v2Events) {
          if (event instanceof ethers.EventLog && event.blockNumber > latestBlockNumber) {
            latestBlockNumber = event.blockNumber;
            latestEvent = event;
          }
        }
      } catch (e) {
        // V2 events might not exist, fall back to V1
      }

      // If no V2 events found or V2 didn't find any blocks, try V1 events
      if (!latestEvent) {
        try {
          const v1Filter = contract.filters.YAMOBlockSubmitted();
          const v1Events = await contract.queryFilter(v1Filter);

          for (const event of v1Events) {
            if (event instanceof ethers.EventLog && event.blockNumber > latestBlockNumber) {
              latestBlockNumber = event.blockNumber;
              latestEvent = event;
            }
          }
        } catch (e) {
          // V1 events might not exist either
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
      return null;
    }
  }
}
