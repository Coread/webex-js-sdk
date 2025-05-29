import HashTree from './hashTree';

export const exampleInitialLocus = {
  dataSets: [
    {
      url: 'https://locus-a.wbx2.com/locus/api/v1/loci/97d64a5f/datasets/main',
      root: '9bb9d5a911a74d53a915b4dfbec7329f',
      version: 51118,
      leafCount: 16,
      name: 'main',
    },
    {
      url: 'https://locus-a.wbx2.com/locus/api/v1/loci/97d64a5f/participant/713e9f99/datasets/self',
      root: '5b8cc7ffda1346d2bfb1c0b60b8ab601',
      version: 89891,
      leafCount: 1,
      name: 'self',
    },
    {
      url: 'https://locus-a.wbx2.com/locus/api/v1/loci/97d64a5f/datasets/atd-unmuted',
      root: '9279d2e149da43a1b8e2cd7cbf77f9f0',
      version: 91277,
      leafCount: 16,
      name: 'atd-unmuted',
    },
  ],
  locus: {
    url: 'https://locus-a.wbx2.com/locus/api/v1/loci/97d64a5f',
    meta: {
      type: 'LOCUS',
      id: 0,
      version: 5678,
      dataSets: ['main'],
    },
    participants: [
      {
        url: 'https://locus-a.wbx2.com/locus/api/v1/loci/97d64a5f/participant/11941033',
        person: {},
        meta: {
          type: 'PARTICIPANT',
          id: 14,
          version: 5678,
          dataSets: ['atd-active', 'attendees', 'atd-unmuted'],
        },
      },
    ],
    self: {
      url: 'https://locus-a.wbx2.com/locus/api/v1/loci/97d64a5f/participant/11941033',
      visibleDataSets: ['main', 'self', 'atd-unmuted'],
      person: {},
      meta: {
        type: 'SELF',
        id: 4,
        version: 5678,
        dataSets: ['self'],
      },
    },
  },
};

/**
 * Parses hash tree eventing locus data
 */
class HashTreeParser {
  trees: Record<string, HashTree> = {};

  /**
   * Constructor for HashTreeParser
   * @param {Object} initialLocus - The initial locus data containing the hash tree information
   */
  constructor(initialLocus: any) {
    const {dataSets, locus} = initialLocus; // extract dataSets from initialLocus

    // object mapping dataset names to arrays of leaf data
    const leafData: Record<string, Array<{type: string; id: number; version: number}>> = {};

    // each dataset exists at a different place in the dto
    // iterate recursively over the locus and if it has a meta key,
    // create an object with the type, id and version and add it to the appropriate leafData array

    const findAndStoreMetaData = (currentLocusPart: any) => {
      if (typeof currentLocusPart !== 'object' || currentLocusPart === null) {
        return;
      }

      if (currentLocusPart.meta && currentLocusPart.meta.dataSets) {
        const {type, id, version, dataSets: metaDataSets} = currentLocusPart.meta;
        const leafInfo = {type, id, version};

        for (const dataSetName of metaDataSets) {
          if (!leafData[dataSetName]) {
            leafData[dataSetName] = [];
          }
          leafData[dataSetName].push(leafInfo);
        }
      }

      if (Array.isArray(currentLocusPart)) {
        for (const item of currentLocusPart) {
          findAndStoreMetaData(item);
        }
      } else {
        for (const key of Object.keys(currentLocusPart)) {
          if (Object.prototype.hasOwnProperty.call(currentLocusPart, key)) {
            findAndStoreMetaData(currentLocusPart[key]);
          }
        }
      }
    };

    findAndStoreMetaData(locus);

    for (const dataSet of dataSets) {
      const {name, leafCount} = dataSet;

      const hashTree = new HashTree(leafData[name] || [], leafCount);

      this.trees[name] = hashTree;
    }
  }
}

export default HashTreeParser;
