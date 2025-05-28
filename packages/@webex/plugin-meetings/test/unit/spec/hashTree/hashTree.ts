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

  // it('should have the correct hashes after adding ObjectIds', () => {
  //     const tree = new HashTree(4);
  //     const oids = [
  //       new ObjectId("typeA", 1n, 3n), // Leaf 0
  //     ];

  //     tree.putStates(oids);

  //     expect(tree.getHashArray()).toEqual([
  //         "24a75d115a0a90ddb376a02b435c780f",
  //         "457eeb22808eadfcff92ee47d67acbbf",
  //         "b113a76304e3a7121afecfe1606ee1c1",
  //         "99aa06d3014798d86001c324468d497f",
  //         "42df811f5a902c5b6bfcf50c7004e275",
  //         "99aa06d3014798d86001c324468d497f",
  //         "99aa06d3014798d86001c324468d497f"
  //     ]);
  // });

  // it('should have the correct hashes after adding ObjectIds', () => {
  //     const tree = new HashTree(4);
  //     const oids = [
  //       new ObjectId("typeA", 1n, 3n), // Leaf 0
  //       new ObjectId("typeA", 6n, 2n), // Leaf 1
  //       new ObjectId("typeA", 7n, 1n), // Leaf 0
  //       new ObjectId("typeB", 11n, 4n), // Leaf 0
  //     ];

  //     tree.putStates(oids);

  //     expect(tree.getHashArray()).toEqual([
  //         "c8415198d4abca6f885fe974e9b3729d",
  //         "457eeb22808eadfcff92ee47d67acbbf",
  //         "5c9ba182a069c16a77a1928fce52dad8",
  //         "99aa06d3014798d86001c324468d497f",
  //         "42df811f5a902c5b6bfcf50c7004e275",
  //         "feb384d8ac6374ffdbee92a9f48f2b40",
  //         "ebfa4f7e104e1e30fbb6b8857ccb685d"
  //     ]);
  // });

  it('should have the correct hashes after adding ObjectIds', () => {
    const oids = [
      {type: 'participant', id: 1, version: 3}
    ];
    const tree = new HashTree(oids, 4);


    expect(tree.computeTreeHashes()).to.deep.equal([
        "24a75d115a0a90ddb376a02b435c780f",
        "457eeb22808eadfcff92ee47d67acbbf",
        "b113a76304e3a7121afecfe1606ee1c1",
        "99aa06d3014798d86001c324468d497f",
        "42df811f5a902c5b6bfcf50c7004e275",
        "99aa06d3014798d86001c324468d497f",
        "99aa06d3014798d86001c324468d497f"
    ]);
  });

  it('should have the correct hashes after adding ObjectIds', () => {
    const oids = [
      {type: "typeA", id: 1, version: 3}, // Leaf 0
      {type: "typeA", id: 6, version: 2}, // Leaf 1
      {type: "typeA", id: 7, version: 1}, // Leaf 0
      {type: "typeB", id: 11, version: 4}, // Leaf 0
    ];
    const tree = new HashTree(oids, 4);


      expect(tree.computeTreeHashes()).to.deep.equal([
          "c8415198d4abca6f885fe974e9b3729d",
          "457eeb22808eadfcff92ee47d67acbbf",
          "5c9ba182a069c16a77a1928fce52dad8",
          "99aa06d3014798d86001c324468d497f",
          "42df811f5a902c5b6bfcf50c7004e275",
          "feb384d8ac6374ffdbee92a9f48f2b40",
          "ebfa4f7e104e1e30fbb6b8857ccb685d"
      ]);
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

    expect(hashTree.getRouteHash()).to.equal('e1cb70c75b488d87cbc8f74934a4290b');
  });

  it('returns the correct tree hash for an empty tree', () => {
    const hashTree = new HashTree([], 0);

    const expectedHash = '99aa06d3014798d86001c324468d497f';
    expect(hashTree.getRouteHash()).to.equal(expectedHash);
  });

  it('returns the correct tree hash for an empty tree with 2 leaves', () => {
    const hashTree = new HashTree([], 2);

    const expectedHash = 'b113a76304e3a7121afecfe1606ee1c1';
    expect(hashTree.getRouteHash()).to.equal(expectedHash);
  });

  it('returns the correct tree hash for an empty tree with 4 leaves', () => {
    const hashTree = new HashTree([], 4);

    const expectedHash = 'b5df9b92242752424d87053a14e6222d';
    expect(hashTree.getRouteHash()).to.equal(expectedHash);
  });
});