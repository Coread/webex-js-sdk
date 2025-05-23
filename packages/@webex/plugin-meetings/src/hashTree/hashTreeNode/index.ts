import {XXHash128} from 'xxhash-addon';

/**
 * HashTreeNode
 */
abstract class HashTreeNode {
  index: number;
  nodes: any[];
  hashes: any[];

  /**
   * The HashTreeNode constructor
   * @param {number} index The index of the node in the tree
   * @param {HashTreeNode[]} nodes The children of this node
   * @param {any} hashes The hashes of all the nodes
   */
  constructor(index: number, nodes: HashTreeNode[], hashes: any) {
    this.index = index;
    this.nodes = nodes;
    this.hashes = hashes;
  }

  /**
   * Returns the parent node of this node
   * @returns {HashTreeNode} The parent node of this node
   */
  get parent(): HashTreeNode | undefined {
    if (this.index) {
      return this.nodes[Math.floor((this.index - 1) / 2)];
    }

    return undefined;
  }

  /**
   * Returns the children of this node
   * @returns {HashTreeNode[]} The children of this node
   */
  get children(): HashTreeNode[] {
    const index = 2 * this.index + 1;

    return this.nodes.slice(index, index + 2);
  }

  /**
   * Returns the cached hash value of this node
   */
  get cache() {
    return this.hashes[this.index];
  }

  /**
   * Sets the cached hash value of this node
   * @param {string} value The hash value to set
   */
  set cache(value: any) {
    this.hashes[this.index] = value;
  }

  /**
   * Returns the hash value of this node
   * @returns {string} The hash value of this node
   */
  get hash() {
    if (!this.cache) {
      const childHashes = this.children.map((child) => child.hash);
      if (childHashes.length) {
        const currentHash = new XXHash128(Buffer.from([0, 0, 0, 0]));
        for (const hash of childHashes) {
          currentHash.update(Buffer.from(hash));
        }
        this.cache = currentHash.digest().toString('hex');
      }
    }

    return this.cache;
  }

  /**
   * Compares this node with another node - not implemented on the base class
   * @param {any} other
   * @param {any} missing
   * @param {any} updated
   * @param {any} deleted
   * @returns {void}
   */
  compare(other: any, missing: any[], updated, deleted): void {
    throw new Error(`Not implemented on hash tree node ${this.index}`);
  }

  /**
   * invalidates the cache of this node and its parent
   * @returns {void}
   */
  invalidate(): void {
    this.cache = '';
    if (this.parent) {
      this.parent.invalidate();
    }
  }

  /**
   * diffs the hashes between this tree and another tree
   * @param {any} hashes
   * @param {any} different
   * @returns {boolean} whether the hashes are different
   */
  diff(hashes, different) {
    if (this.hash !== hashes[this.index]) {
      this.children[0].diff(hashes, different);
      this.children[1].diff(hashes, different);
    }

    return different;
  }
}

export default HashTreeNode;
