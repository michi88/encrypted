import * as index from '../src/index';

test('Should have encrypted and decrypted available', () => {
  expect(index.encrypted).toBeTruthy();
  expect(index.decrypted).toBeTruthy();
});
