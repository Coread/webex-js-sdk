import HashTreeNode from '../hashTreeNode';

type LeafData = {
  type: string;
  id: string;
  version: number;
};

/**
 * Leaf
 * @extends HashTreeNode
 */
class Leaf extends HashTreeNode {
  data: LeafData[];

  /**
   * Constructor
   * @param {number} index The index of this leaf node in the tree
   * @param {HashTreeNode[]} nodes The children of this node - this should be empty
   * @param {any} hashes The hashes of all the nodes
   */
  constructor(index: number, nodes: HashTreeNode[], hashes: any) {
    super(index, nodes, hashes);
    this.data = [];
  }

  /**
   * Returns the length of the data stored in this leaf node
   * @returns {number} The length of the data stored in this leaf node
   */
  get length() {
    return this.data.length;
  }

  /**
   * Returns the leaf number of this leaf node
   * This differs from index
   * @returns {number} The leaf number of this leaf node
   */
  get number() {
    return this.index - Math.floor(this.nodes.length / 2);
  }

  /**
   * get the hash of value of this leaf node which is based on its contents
   * @returns {string} The hash value of this leaf node
   */
  get hash() {
    if (!this.cache && this.length) {
      // create a hasher
      // sort the content lexicographically by type
      // then sort by id in ascending order
    }

    return this.cache;
  }

  /**
   * Returns if the hash of this leaf is different from the corresponding has in another array of hashes
   * @param {any} hashes
   * @param {any} different
   * @returns {boolean}
   */
  diff(hashes, different) {
    if (this.hash !== hashes[this.index]) {
      different.push(this.number);
    }

    return different;
  }

  /**
   * Deletes an object from the data array
   * @param {string} id the id of the object
   * @param {number} version the version of the object
   * @returns {boolean} true if the object was deleted, false otherwise
   */
  delete(id, version) {
    let deleted = false;

    // FIXME: this if statement needs fixing
    if (
      // if the id exists in the data AND
      id in this.data &&
      // if the version is empty or the version is greater than the one in the data
      (!version || this.data[id].version === version)
    ) {
      // remove this object from the data array

      // invalidate the hash
      this.invalidate();

      // mark as deleted
      deleted = true;
    }

    return deleted;
  }

  // update(position, sequence) {
  //   let updated = false;

  //   if (!(position in this.states) || sequence > this.states[position]) {
  //     this.states[position] = sequence;
  //     this.invalidate();
  //     updated = true;
  //   }

  //   return updated;
  // }

  // compare(other, missing: any[], updated, deleted) {
  //   const mine = Object.keys(this.states);
  //   const theirs = Object.keys(other);

  //   const both = theirs.filter((position) => mine.includes(position));

  //   missing.push(...theirs.filter((position) => !mine.includes(position)));
  //   updated.push(...both.filter((position) => this.states[position] < other[position]));
  //   deleted.push(...mine.filter((position) => !theirs.includes(position)));
  // }
}

export default Leaf;
