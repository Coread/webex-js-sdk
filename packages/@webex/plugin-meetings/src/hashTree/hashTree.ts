import {XXHash128} from 'xxhash-addon';

export const hash = (data) => {
  const buf = Buffer.from(data);
  const result = XXHash128.hash(buf).toString('hex');

  return result;
};
