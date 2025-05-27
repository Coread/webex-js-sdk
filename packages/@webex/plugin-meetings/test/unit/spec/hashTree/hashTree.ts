import HashTree from '@webex/plugin-meetings/src/hashTree/hashTree';

import { expect } from "@webex/test-helper-chai";

describe('HashTree', () => {
  it('should initialize with empty buckets and hashes', () => {
    const leafData = [];
    const numLeaves = 4;
    const hashTree = new HashTree(leafData, numLeaves);

    expect(hashTree.buckets).to.deep.equal(new Array(numLeaves).fill(null).map(() => ({
      'participant': {},
    })));
    expect(hashTree.leafHashes).to.deep.equal(new Array(numLeaves).fill('99aa06d3014798d86001c324468d497f'));
  })

  it('number of leaves must be a power of 2', () => {
    const leafData = [];
    const numLeaves = 3; // Not a power of 2
    expect(() => new HashTree(leafData, numLeaves)).to.throw('Number of leaves must be a power of 2');
  });

  it('should add items and compute hashes correctly', () => {
    const leafData = [
      { type: 'participant', id: 1, version: 1 },
      { type: 'participant', id: 2, version: 1 },
    ];
    const numLeaves = 4;
    const hashTree = new HashTree(leafData, numLeaves);

    expect(hashTree.buckets[1]['participant'][1]).to.deep.equal({ type: 'participant', id: 1, version: 1 });
    expect(hashTree.buckets[2]['participant'][2]).to.deep.equal({ type: 'participant', id: 2, version: 1 });
    expect(hashTree.leafHashes[1]).to.not.equal('99aa06d3014798d86001c324468d497f');
    expect(hashTree.leafHashes[2]).to.not.equal('99aa06d3014798d86001c324468d497f');
  });

  it('should have correct hash', () => {
    const leafData = [{type: 'participant', id: 1, version: 10}];
    const numLeaves = 2;
    const hashTree = new HashTree(leafData, numLeaves);

    expect(hashTree.buckets[1]['participant'][1]).to.deep.equal({
      type: 'participant',
      id: 1,
      version: 10,
    });

    expect(hashTree.computeTreeHash()).to.equal('14c02026daa1dddba53e718919da4fa7');
  });

  it('returns the correct tree hash for an empty tree', () => {
    const hashTree = new HashTree([], 0);

    const expectedHash = '99aa06d3014798d86001c324468d497f';
    expect(hashTree.computeTreeHash()).to.equal(expectedHash);
  });

  it('returns the correct tree hash for an empty tree with 2 leaves', () => {
    const hashTree = new HashTree([], 2);

    const expectedHash = '590350119ab0222f04245739b8563505';
    expect(hashTree.computeTreeHash()).to.equal(expectedHash);
  });

  it('returns the correct tree hash for an empty tree with 4 leaves', () => {
    const hashTree = new HashTree([], 4);

    const expectedHash = '1ed4395223d8a752ec2c3c83a43bc68d';
    expect(hashTree.computeTreeHash()).to.equal(expectedHash);
  });
});