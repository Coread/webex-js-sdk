/* eslint-disable require-jsdoc */
import {XXHash128} from 'xxhash-addon';

const NULL_HASH = '99aa06d3014798d86001c324468d497f';

const ITEM_TYPES = {
  PARTICIPANT: 'participant',
};

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

  constructor(leafData, numLeaves) {
    this.numLeaves = numLeaves;
    this.leafHashes = new Array(numLeaves).fill(NULL_HASH);

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
        hasher.update(Buffer.from(item.id.toString()));
        hasher.update(Buffer.from(item.version.toString()));
      });
    });

    this.leafHashes[index] = hasher.digest().toString('hex');
  }

  computeTreeHash(): string {
    if (this.numLeaves === 0) {
      return NULL_HASH;
    }

    if (this.numLeaves === 1) {
      return this.leafHashes[0];
    }

    let currentLevelHashes = [...this.leafHashes];

    while (currentLevelHashes.length > 1) {
      const nextLevelHashes: string[] = [];
      for (let i = 0; i < currentLevelHashes.length; i += 2) {
        const leftHash = currentLevelHashes[i];
        const rightHash = i + 1 < currentLevelHashes.length ? currentLevelHashes[i + 1] : leftHash;

        const hasher = new XXHash128(Buffer.from([0, 0, 0, 0]));

        // TODO: double check this is correct, not sure about how we are unpacking the hashes
        // in order to create the next level hash
        // Convert hex strings to Buffers for hashing
        hasher.update(Buffer.from(leftHash, 'hex'));
        hasher.update(Buffer.from(rightHash, 'hex'));

        nextLevelHashes.push(hasher.digest().toString('hex'));
      }
      currentLevelHashes = nextLevelHashes;
    }

    return currentLevelHashes[0];
  }
}

export default HashTree;
