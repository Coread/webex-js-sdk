import HashTreeParser, { exampleInitialLocus } from '@webex/plugin-meetings/src/hashTree/hashTreeParser';
import HashTree from '@webex/plugin-meetings/src/hashTree/hashTree';
import { expect } from "@webex/test-helper-chai";


describe('HashTreeParser', () => {
  it('should correctly initialize trees from initialLocus data', () => {
    const parser = new HashTreeParser(exampleInitialLocus);

    // Check that the correct number of trees are created
    expect(Object.keys(parser.trees).length).to.equal(3);

    // Verify the 'main' tree
    const mainTree = parser.trees.main;
    expect(mainTree).to.be.instanceOf(HashTree);
    const expectedMainLeaves = new Array(16).fill(null).map(() => ({}));
    expectedMainLeaves[0 % 16] = { LOCUS: { 0: { type: 'LOCUS', id: 0, version: 5678 } } };
    expect(mainTree.leaves).to.deep.equal(expectedMainLeaves);
    expect(mainTree.numLeaves).to.equal(16);

    // Verify the 'self' tree
    const selfTree = parser.trees.self;
    expect(selfTree).to.be.instanceOf(HashTree);
    const expectedSelfLeaves = new Array(1).fill(null).map(() => ({}));
    expectedSelfLeaves[4 % 1] = { SELF: { 4: { type: 'SELF', id: 4, version: 5678 } } };
    expect(selfTree.leaves).to.deep.equal(expectedSelfLeaves);
    expect(selfTree.numLeaves).to.equal(1);

    // Verify the 'atd-unmuted' tree
    const atdUnmutedTree = parser.trees['atd-unmuted'];
    expect(atdUnmutedTree).to.be.instanceOf(HashTree);
    const expectedAtdUnmutedLeaves = new Array(16).fill(null).map(() => ({}));
    expectedAtdUnmutedLeaves[14 % 16] = { PARTICIPANT: { 14: { type: 'PARTICIPANT', id: 14, version: 5678 } } };
    expect(atdUnmutedTree.leaves).to.deep.equal(expectedAtdUnmutedLeaves);
    expect(atdUnmutedTree.numLeaves).to.equal(16);

    // Ensure no other trees were created
    expect(parser.trees['atd-active']).to.be.undefined;
    expect(parser.trees.attendees).to.be.undefined;
  });

  it('should handle datasets with no corresponding metadata found', () => {
    const modifiedLocus = JSON.parse(JSON.stringify(exampleInitialLocus));
    // Remove a participant meta to simulate missing data for 'atd-unmuted'
    modifiedLocus.locus.participants = []; 
    // Add a new dataset that won't have corresponding metadata
    modifiedLocus.dataSets.push({
        url: 'https://locus-a.wbx2.com/locus/api/v1/loci/97d64a5f/datasets/empty-set',
        root: 'f00f00f00f00f00f00f00f00f00f00f0',
        version: 1,
        leafCount: 4,
        name: 'empty-set',
    });


    const parser = new HashTreeParser(modifiedLocus);

    expect(Object.keys(parser.trees).length).to.equal(4); // main, self, atd-unmuted (now empty), empty-set

    // 'main' and 'self' should be populated as before
    const mainTree = parser.trees.main;
    const expectedMainLeaves = new Array(16).fill(null).map(() => ({}));
    expectedMainLeaves[0 % 16] = { LOCUS: { 0: { type: 'LOCUS', id: 0, version: 5678 } } };
    expect(mainTree.leaves).to.deep.equal(expectedMainLeaves);
    expect(mainTree.numLeaves).to.equal(16);

    const selfTree = parser.trees.self;
    const expectedSelfLeaves = new Array(1).fill(null).map(() => ({}));
    expectedSelfLeaves[4 % 1] = { SELF: { 4: { type: 'SELF', id: 4, version: 5678 } } };
    expect(selfTree.leaves).to.deep.equal(expectedSelfLeaves);
    expect(selfTree.numLeaves).to.equal(1);
    
    // 'atd-unmuted' metadata was removed from locus, so leaves should be empty
    const atdUnmutedTree = parser.trees['atd-unmuted'];
    expect(atdUnmutedTree).to.be.instanceOf(HashTree);
    const expectedAtdUnmutedEmptyLeaves = new Array(16).fill(null).map(() => ({}));
    expect(atdUnmutedTree.leaves).to.deep.equal(expectedAtdUnmutedEmptyLeaves);
    expect(atdUnmutedTree.numLeaves).to.equal(16); // leafCount from dataSet definition

    // 'empty-set' was added to dataSets but has no metadata in locus
    const emptySetTree = parser.trees['empty-set'];
    expect(emptySetTree).to.be.instanceOf(HashTree);
    const expectedEmptySetLeaves = new Array(4).fill(null).map(() => ({})); // leafCount is 4
    expect(emptySetTree.leaves).to.deep.equal(expectedEmptySetLeaves);
    expect(emptySetTree.numLeaves).to.equal(4);
  });
});
