/* eslint-disable require-jsdoc */
import {XXHash128} from 'xxhash-addon';
import {EMPTY_HASH, ITEM_TYPES} from './constants';

type LeafDataItem = {
  type: string;
  id: number;
  version: number;
};

class HashTree {
  buckets: Array<
    Record<(typeof ITEM_TYPES)[keyof typeof ITEM_TYPES], Record<number, LeafDataItem>>
  >;

  leafHashes: Array<string>;
  numLeaves: number;

  constructor(leafData, numLeaves: number) {
    // check num leaves is either 0 or a power of 2
    // eslint-disable-next-line no-bitwise
    if (numLeaves < 0 || (numLeaves & (numLeaves - 1)) !== 0) {
      throw new Error('Number of leaves must be a power of 2');
    }

    this.numLeaves = numLeaves;
    this.leafHashes = new Array(numLeaves).fill(EMPTY_HASH);

    // TODO: Consider whether we need to support dynamic types
    this.buckets = new Array(numLeaves).fill(null).map(() => {
      const bucketInstance: Partial<
        Record<(typeof ITEM_TYPES)[keyof typeof ITEM_TYPES], Record<number, LeafDataItem>>
      > = {};
      // Initialize an empty record for each item type defined in ITEM_TYPES
      (Object.values(ITEM_TYPES) as Array<(typeof ITEM_TYPES)[keyof typeof ITEM_TYPES]>).forEach(
        (itemTypeValue) => {
          bucketInstance[itemTypeValue] = {};
        }
      );

      return bucketInstance as Record<
        (typeof ITEM_TYPES)[keyof typeof ITEM_TYPES],
        Record<number, LeafDataItem>
      >;
    });

    this.addItems(leafData);
  }

  addItems(leafData) {
    const changedBucketIndexes = new Set();

    leafData.forEach((item) => {
      const index = item.id % this.numLeaves;

      const existingItem = this.buckets[index][item.type][item.id];

      if (!existingItem || existingItem.version < item.version) {
        this.buckets[index][item.type][item.id] = item;

        changedBucketIndexes.add(index);
      }
    });

    // for each changed bucket, compute the hash
    changedBucketIndexes.forEach((index) => {
      this.computeBucketHash(index);
    });
  }

  removeItems(leafData) {
    const changedBucketIndexes = new Set();

    leafData.forEach((item) => {
      const index = item.id % this.numLeaves;

      const existingItem = this.buckets[index][item.type][item.id];

      if (existingItem && existingItem.version < item.version) {
        delete this.buckets[index][item.type][item.id];
        changedBucketIndexes.add(index);
      }
    });

    // for each changed bucket, compute the hash
    changedBucketIndexes.forEach((index) => {
      this.computeBucketHash(index);
    });
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

  getRouteHash() {
    return this.computeTreeHashes()[0];
  }
}

export default HashTree;
