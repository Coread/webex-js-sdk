/* eslint-disable require-jsdoc */
/* eslint-disable valid-jsdoc */
import {XXHash128} from 'xxhash-addon';
import {EMPTY_HASH} from './constants';

type LeafDataItem = {
  type: string;
  id: number;
  version: number;
};

class HashTree {
  buckets: Array<Record<string, Record<number, LeafDataItem>>>;

  leafHashes: Array<string>;
  readonly numLeaves: number; // Made numLeaves readonly as it's set in constructor

  constructor(leafData: LeafDataItem[], numLeaves: number) {
    // check num leaves is either 0 or a power of 2
    // eslint-disable-next-line no-bitwise
    if (numLeaves < 0 || (numLeaves !== 0 && (numLeaves & (numLeaves - 1)) !== 0)) {
      // Allow 0 leaves
      throw new Error('Number of leaves must be 0 or a power of 2');
    }

    this.numLeaves = numLeaves;
    this.leafHashes = new Array(numLeaves).fill(EMPTY_HASH);

    this.buckets = new Array(numLeaves).fill(null).map(() => {
      return {};
    });

    if (leafData) {
      this.putItems(leafData);
    }
  }

  /**
   * Adds or updates a single item in the hash tree.
   * @param item The item to add or update.
   * @returns True if the item was added or updated, false otherwise (e.g., older version).
   */
  putItem(item: LeafDataItem): boolean {
    if (this.numLeaves === 0) {
      return false; // Cannot add to a tree with 0 leaves
    }

    const index = item.id % this.numLeaves;

    if (!this.buckets[index][item.type]) {
      this.buckets[index][item.type] = {};
    }

    const existingItem = this.buckets[index][item.type][item.id];

    if (!existingItem || existingItem.version < item.version) {
      this.buckets[index][item.type][item.id] = item;
      this.computeBucketHash(index);

      return true;
    }

    return false;
  }

  /**
   * Adds or updates multiple items in the hash tree.
   * @param items The array of items to add or update.
   * @returns An array of booleans indicating success for each item.
   */
  putItems(items: LeafDataItem[]): boolean[] {
    if (this.numLeaves === 0 && items.length > 0) {
      // Or throw error, or return array of false based on desired behavior for 0 leaves

      return items.map(() => false);
    }
    const results: boolean[] = [];
    const changedBucketIndexes = new Set<number>();

    items.forEach((item) => {
      const index = item.id % this.numLeaves;

      if (!this.buckets[index][item.type]) {
        this.buckets[index][item.type] = {};
      }

      const existingItem = this.buckets[index][item.type][item.id];

      if (!existingItem || existingItem.version < item.version) {
        this.buckets[index][item.type][item.id] = item;
        changedBucketIndexes.add(index);
        results.push(true);
      } else {
        results.push(false);
      }
    });

    changedBucketIndexes.forEach((index) => {
      this.computeBucketHash(index);
    });

    return results;
  }

  /**
   * Removes a single item from the hash tree.
   * The removal is based on matching type, id, and the provided item's version
   * being greater than or equal to the existing item's version.
   * @param item The item to remove.
   * @returns True if the item was removed, false otherwise.
   */
  removeItem(item: LeafDataItem): boolean {
    if (this.numLeaves === 0) {
      return false;
    }

    const index = item.id % this.numLeaves;

    if (
      this.buckets[index] &&
      this.buckets[index][item.type] &&
      this.buckets[index][item.type][item.id]
    ) {
      const existingItem = this.buckets[index][item.type][item.id];
      // In Java, removeSate version check is existingItem.version() < objectId.version()
      // To align, we can decide if removal requires exact version or if newer version in request can remove older.
      // Assuming removal if item exists and version in request is same or newer.
      // For strict "version must be greater" as in original removeItems:
      // if (existingItem.version < item.version) {
      // For typical "remove this specific version or if it's older":
      if (
        existingItem.id === item.id &&
        existingItem.type === item.type &&
        existingItem.version <= item.version
      ) {
        delete this.buckets[index][item.type][item.id];
        if (Object.keys(this.buckets[index][item.type]).length === 0) {
          delete this.buckets[index][item.type];
        }
        this.computeBucketHash(index);

        return true;
      }
    }

    return false;
  }

  /**
   * Removes multiple items from the hash tree.
   * @param items The array of items to remove.
   * @returns An array of booleans indicating success for each item.
   */
  removeItems(items: LeafDataItem[]): boolean[] {
    if (this.numLeaves === 0 && items.length > 0) {
      return items.map(() => false);
    }
    const results: boolean[] = [];
    const changedBucketIndexes = new Set<number>();

    items.forEach((item) => {
      const index = item.id % this.numLeaves;

      if (
        this.buckets[index] &&
        this.buckets[index][item.type] &&
        this.buckets[index][item.type][item.id]
      ) {
        const existingItem = this.buckets[index][item.type][item.id];
        // Original logic: if (existingItem && existingItem.version < item.version)
        // This means a new "removal" operation with a higher version number removes the old one.
        // Let's stick to that for removeItems, and use a more direct match for removeItem.
        if (existingItem.version < item.version) {
          // This implies the 'item' acts as a tombstone with a newer version
          delete this.buckets[index][item.type][item.id];
          if (Object.keys(this.buckets[index][item.type]).length === 0) {
            delete this.buckets[index][item.type];
          }
          changedBucketIndexes.add(index);
          results.push(true);
        } else {
          results.push(false);
        }
      } else {
        results.push(false);
      }
    });

    changedBucketIndexes.forEach((index) => {
      this.computeBucketHash(index);
    });

    return results;
  }

  computeBucketHash(index) {
    const bucket = this.buckets[index];

    // create a hasher
    const hasher = new XXHash128(Buffer.from([0, 0, 0, 0]));

    // iterate through the item types lexicographically
    const itemTypes = Object.keys(bucket).sort();
    itemTypes.forEach((type) => {
      // iterate through the items of this type in ascending order of ID
      const items = Object.values(bucket[type]).sort(
        (a: LeafDataItem, b: LeafDataItem) => a.id - b.id
      );

      // add all the items id and version to the hasher
      items.forEach((item: LeafDataItem) => {
        const idBuffer = Buffer.alloc(8);
        idBuffer.writeBigInt64LE(BigInt(item.id));

        const versionBuffer = Buffer.alloc(8);
        versionBuffer.writeBigInt64LE(BigInt(item.version));

        hasher.update(idBuffer);
        hasher.update(versionBuffer);
      });
    });

    this.leafHashes[index] = hasher.digest().toString('hex');
  }

  computeTreeHashes(): string[] {
    if (this.numLeaves === 0) {
      return [EMPTY_HASH];
    }

    let currentLevelHashes = [...this.leafHashes];
    const allHashes = [];

    while (currentLevelHashes.length > 1) {
      const nextLevelHashes: string[] = [];
      for (let i = 0; i < currentLevelHashes.length; i += 2) {
        const leftHash = currentLevelHashes[i];
        const rightHash = i + 1 < currentLevelHashes.length ? currentLevelHashes[i + 1] : leftHash;

        const hasher = new XXHash128(Buffer.from([0, 0, 0, 0]));

        const input = Buffer.concat([
          Buffer.from(leftHash, 'hex').subarray(0, 8).reverse(),
          Buffer.from(leftHash, 'hex').subarray(8, 16).reverse(),
          Buffer.from(rightHash, 'hex').subarray(0, 8).reverse(),
          Buffer.from(rightHash, 'hex').subarray(8, 16).reverse(),
        ]);

        hasher.update(input);

        nextLevelHashes.push(hasher.digest().toString('hex'));
      }
      currentLevelHashes = nextLevelHashes;
      allHashes.unshift(...currentLevelHashes);
    }

    return [...allHashes, ...this.leafHashes];
  }

  /**
   * Returns all hashes in the tree (internal nodes then leaf nodes).
   * @returns An array of hash strings.
   */
  getHashes(): string[] {
    return this.computeTreeHashes();
  }

  /**
   * Computes and returns the hash value of the root node.
   * @returns The root hash of the entire tree.
   */
  getRootHash(): string {
    if (this.numLeaves === 0) {
      return EMPTY_HASH;
    }

    return this.computeTreeHashes()[0];
  }

  /**
   * Gets the number of leaf buckets in the tree.
   * @returns The number of leaves.
   */
  getLeafCount(): number {
    return this.numLeaves;
  }

  /**
   * Calculates the total number of items stored in the tree.
   * @returns The total number of items.
   */
  getTotalItemCount(): number {
    let count = 0;
    for (const bucket of this.buckets) {
      for (const type of Object.keys(bucket)) {
        // Changed from for...in
        count += Object.keys(bucket[type]).length;
      }
    }

    return count;
  }

  /**
   * Retrieves all data items from a specific leaf bucket.
   * @param leafIndex The index of the leaf bucket.
   * @returns An array of LeafDataItem in the specified bucket, or an empty array if the index is invalid or bucket is empty.
   */
  getLeafData(leafIndex: number): LeafDataItem[] {
    if (leafIndex < 0 || leafIndex >= this.numLeaves) {
      return [];
    }
    const bucket = this.buckets[leafIndex];
    const items: LeafDataItem[] = [];
    for (const type of Object.keys(bucket)) {
      // Changed from for...in
      items.push(...Object.values(bucket[type]));
    }
    // Optionally sort them if a specific order is required, e.g., by ID
    items.sort((a, b) => a.id - b.id);

    return items;
  }

  /**
   * Resizes the HashTree to have a new number of leaf nodes, redistributing all existing items.
   * @param newNumLeaves The new number of leaf nodes (must be 0 or a power of 2).
   * @returns true if the tree was resized, false if the size didn't change.
   * @throws Error if newNumLeaves is not 0 or a power of 2.
   */
  resize(newNumLeaves: number): boolean {
    // eslint-disable-next-line no-bitwise
    if (newNumLeaves < 0 || (newNumLeaves !== 0 && (newNumLeaves & (newNumLeaves - 1)) !== 0)) {
      throw new Error('New number of leaves must be 0 or a power of 2');
    }

    if (newNumLeaves === this.numLeaves) {
      return false;
    }

    const allItems: LeafDataItem[] = [];
    for (const bucket of this.buckets) {
      for (const type of Object.keys(bucket)) {
        // Changed from for...in
        allItems.push(...Object.values(bucket[type]));
      }
    }

    // Re-initialize
    (this as any).numLeaves = newNumLeaves; // Workaround for readonly, or remove readonly for resize
    this.leafHashes = new Array(newNumLeaves).fill(EMPTY_HASH);
    this.buckets = new Array(newNumLeaves).fill(null).map(() => ({}));

    if (newNumLeaves > 0) {
      this.putItems(allItems); // Re-add items which will re-bucket and re-hash
    }

    return true;
  }

  /**
   * Compares the tree's leaf hashes with an external set of hashes and returns the indices of differing leaf nodes.
   * The externalHashes array is expected to contain all node hashes (internal followed by leaves),
   * similar to the output of getHashes().
   * @param externalHashes An array of hash strings (internal node hashes then leaf hashes).
   * @returns An array of indices of the leaf nodes that have different hashes.
   */
  diffHashes(externalHashes: string[]): number[] {
    if (this.numLeaves === 0) {
      // If the tree is empty, its hash is EMPTY_HASH.
      // It differs if externalHashes is not a single EMPTY_HASH.
      if (externalHashes && externalHashes.length === 1 && externalHashes[0] === EMPTY_HASH) {
        return []; // No differences
      }
      // If externalHashes is empty or different, it implies a difference.
      // However, diffHashes is about leaf differences. An empty tree has no leaves to differ.
      // So, an empty array is appropriate as no specific leaf indexes are different.

      return [];
    }

    const ownHashes = this.getHashes();
    // The number of internal nodes can be derived.
    // Total nodes = 2 * numLeaves - 1 (for numLeaves > 0)
    // If numLeaves = 1, totalNodes = 1 (only leaf), internal = 0
    // If numLeaves = 0, totalNodes = 1 ( conceptually, for the EMPTY_HASH root)
    // Number of leaf hashes = numLeaves
    // Number of internal hashes = totalHashes - numLeaves

    const numInternalHashesOwn = ownHashes.length - this.numLeaves;

    // We are interested in comparing the leaf hashes part.
    // The externalHashes array should also have its leaf hashes at the end.
    if (externalHashes.length < this.numLeaves) {
      // Not enough external hashes to compare all leaves, consider all leaves as potentially different
      // or throw an error. For now, let's assume this means all are different.
      // Or, more robustly, only compare up to the shorter length if that makes sense.
      // The Java version implies externalHashes matches the tree's full hash structure.
      // If externalHashes.length != ownHashes.length, it's a structural mismatch.
      // For simplicity, if lengths differ significantly, it implies major differences.
      // Let's assume externalHashes has at least numInternalHashes + numLeaves.
      // Consider what to do if externalHashes.length !== ownHashes.length
      // For now, let's assume externalHashes has a compatible structure.
    }

    const differingLeafIndexes: number[] = [];
    const externalLeafHashesStart = externalHashes.length - this.numLeaves;

    if (externalLeafHashesStart < 0) {
      // externalHashes is too short to contain leaf hashes for this tree.
      // All our leaves are "different" or this is an error condition.
      for (let i = 0; i < this.numLeaves; i += 1) {
        differingLeafIndexes.push(i);
      }

      return differingLeafIndexes;
    }

    for (let i = 0; i < this.numLeaves; i += 1) {
      const ownLeafHash = this.leafHashes[i];
      const externalLeafHash = externalHashes[externalLeafHashesStart + i];
      if (ownLeafHash !== externalLeafHash) {
        differingLeafIndexes.push(i);
      }
    }

    return differingLeafIndexes;
  }
}

export default HashTree;
