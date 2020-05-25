import {
  encrypted,
  decrypted,
  EncryptedOptions,
  EncryptableData,
  generateKey,
  newRandomSalt,
  SecretboxEncryptedDocument,
  encrypt,
} from "../src";
import * as Encrypted from "../src/encrypted";
import { secretbox } from "tweetnacl";

test("Should encrypt and decrypt data with a password", async () => {
  const secretOpts = { password: "test" } as EncryptedOptions;
  const result = (await decrypted(
    await encrypted({ test: "data" }, secretOpts),
    secretOpts
  )) as EncryptableData;
  console.log(await encrypted({ test: "data" }, secretOpts));
  expect(result["test"]).toBe("data");
});

test("Should encrypt and decrypt data with a key", async () => {
  for (const key of [
    "1".repeat(secretbox.keyLength), // string key
    await generateKey("test", newRandomSalt()), // binary key
  ]) {
    const secretOpts = {
      key: key,
    } as EncryptedOptions;
    const result = (await decrypted(
      await encrypted({ test: "data" }, secretOpts),
      secretOpts
    )) as EncryptableData;
    expect(result["test"]).toBe("data");
  }
});

test("Should fail when no password / key is set", async () => {
  await expect(encrypted({ test: "data" }, {})).rejects.toThrow(
    new Error("A key, or a password/salt to generate a key from, is required!")
  );
});

test("Should fail with wrong password", async () => {
  const secretOpts = { password: "test" } as EncryptedOptions;
  const secretOptsWrong = { password: "wrong" } as EncryptedOptions;
  const result = decrypted(
    await encrypted({ test: "data" }, secretOpts),
    secretOptsWrong
  );
  await expect(result).rejects.toThrow(new Error("Could not decrypt message"));
});

test("Storing documents as 'plain text' should work", async () => {
  const secretOpts = { type: "plaintext" } as EncryptedOptions;
  const result = (await decrypted(
    await encrypted({ test: "data" }, secretOpts),
    secretOpts
  )) as EncryptableData;
  expect(result["test"]).toBe("data");
});

test("A passed salt should be used", async () => {
  const spyRandomSalt = jest.spyOn(Encrypted, "newRandomSalt");
  const secretOpts = { password: "test", salt: "my salt" } as EncryptedOptions;
  const result = (await Encrypted.encrypted(
    { test: "data" },
    secretOpts
  )) as SecretboxEncryptedDocument;
  expect(result.encryption.salt).toBe("my salt");
  expect(spyRandomSalt).not.toHaveBeenCalled();
});

test("A passed nonce should be validated", async () => {
  await expect(
    encrypt(
      { test: "data" },
      { password: "123", nonce: Uint8Array.from([1, 2, 3, 4]) }
    )
  ).rejects.toThrow(
    new Error(
      `Invalid nonce, must be a Uint8Array of length ${secretbox.nonceLength}`
    )
  );
});

test("Passing no nonce should work", async () => {
  await expect(
    encrypt({ test: "data" }, { password: "123" })
  ).rejects.not.toThrow(
    new Error(
      `Invalid nonce, must be a Uint8Array of length ${secretbox.nonceLength}`
    )
  );
});
