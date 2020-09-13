import { secretbox, randomBytes } from "tweetnacl";
import {
  decodeUTF8,
  encodeUTF8,
  encodeBase64,
  decodeBase64,
} from "tweetnacl-util";
import scrypt, { Options as ScryptOptions } from "scrypt-async";

export { decodeUTF8, encodeUTF8, encodeBase64, decodeBase64 };

type Json =
  | null
  | boolean
  | number
  | string
  | Json[]
  | { [prop: string]: Json };

type JsonCompatible<T> = {
  [P in keyof T]: T[P] extends Json
    ? T[P]
    : Pick<T, P> extends Required<Pick<T, P>>
    ? never
    : T[P] extends (() => any) | undefined
    ? never
    : JsonCompatible<T[P]>;
};

export interface SecretboxEncryptionOptions {
  salt: string;
  type: "secretbox";
  scrypt: ScryptOptions;
}
export interface PlaintextEncryptionOptions {
  type: "plaintext";
}

export type EncryptableData = JsonCompatible<any>;

export interface EncryptedDocument<EncryptionOptions, DataType> {
  encryption: EncryptionOptions;
  data: DataType; // will be a string when encrypted
}

export type SecretboxEncryptedDocument = EncryptedDocument<
  SecretboxEncryptionOptions,
  string
>;
// not encrypted...
export type PlaintextDocument = EncryptedDocument<
  PlaintextEncryptionOptions,
  EncryptableData
>;

export type MaybeEncryptedDocument =
  | SecretboxEncryptedDocument
  | PlaintextDocument;

const newNonce = () => randomBytes(secretbox.nonceLength);

export const newRandomSalt = () =>
  encodeBase64(randomBytes(secretbox.nonceLength));

const latestScryptOptions = {
  N: 16384,
  r: 8,
  p: 1,
  dkLen: secretbox.keyLength,
  interruptStep: 0,
};

export const generateKey = (
  password: string,
  salt: string,
  scryptOpts: ScryptOptions = latestScryptOptions
): Promise<Uint8Array> => {
  return new Promise((resolve) => {
    scrypt(
      //@ts-ignore
      password,
      salt,
      {
        ...scryptOpts,
        encoding: "binary",
      } as ScryptOptions,
      function (derivedKey: Uint8Array) {
        resolve(derivedKey);
      }
    );
  });
};

export interface SecretOptions {
  salt?: string | null;
  password?: string | null;
  key?: null | string | Uint8Array;
  nonce?: Uint8Array;
  scrypt?: ScryptOptions;
}

export interface EncryptedOptions extends SecretOptions {
  type?: "secretbox" | "plaintext";
}

const getUint8ArrayKeyFromOpts = async (
  opts: SecretOptions
): Promise<Uint8Array> => {
  const { password, salt } = opts;
  let { key } = opts;

  if (!key && password && salt) {
    return await generateKey(password, salt, opts.scrypt);
  }
  if (!key) {
    throw new Error(
      "A key, or a password/salt to generate a key from, is required!"
    );
  }
  if (typeof key === "string") {
    key = decodeUTF8(key);
  }
  return key;
};

export const encrypt = async (
  obj: EncryptableData,
  secretOpts: SecretOptions
): Promise<string> => {
  const nonce = secretOpts.nonce || newNonce();
  if (nonce.length !== secretbox.nonceLength) {
    throw new Error(
      `Invalid nonce, must be a Uint8Array of length ${secretbox.nonceLength}`
    );
  }
  const keyUint8Array = await getUint8ArrayKeyFromOpts(secretOpts);
  const messageUint8 = decodeUTF8(JSON.stringify(obj));
  const box = secretbox(messageUint8, nonce, keyUint8Array);

  const fullMessage = new Uint8Array(nonce.length + box.length);
  fullMessage.set(nonce);
  fullMessage.set(box, nonce.length);

  return encodeBase64(fullMessage);
};

export const decrypt = async (
  messageWithNonce: string,
  secretOpts: SecretOptions
): Promise<EncryptableData> => {
  const keyUint8Array = await getUint8ArrayKeyFromOpts(secretOpts);
  const messageWithNonceAsUint8Array = decodeBase64(messageWithNonce);
  const nonce = messageWithNonceAsUint8Array.slice(0, secretbox.nonceLength);
  const message = messageWithNonceAsUint8Array.slice(
    secretbox.nonceLength,
    messageWithNonce.length
  );

  const decryptedData = secretbox.open(message, nonce, keyUint8Array);

  if (!decryptedData) {
    throw new Error("Could not decrypt message");
  }

  const base64DecryptedMessage = encodeUTF8(decryptedData);
  return JSON.parse(base64DecryptedMessage);
};

export const encrypted = async (
  data: EncryptableData,
  secretOpts: EncryptedOptions
): Promise<MaybeEncryptedDocument> => {
  if (typeof secretOpts.salt !== "string") {
    secretOpts.salt = newRandomSalt();
  }
  if (secretOpts.type === "plaintext") {
    return {
      encryption: { type: "plaintext" },
      data: data,
    } as PlaintextDocument;
  } else {
    // default is using secretbox
    secretOpts.nonce = newNonce();
    return {
      encryption: {
        type: "secretbox",
        salt: secretOpts.salt,
        nonce: encodeBase64(secretOpts.nonce),
        scrypt: { ...latestScryptOptions },
      },
      data: await encrypt(data, secretOpts),
    } as SecretboxEncryptedDocument;
  }
};

export const decrypted = async (
  encryptedData: MaybeEncryptedDocument,
  secretOpts: SecretOptions
): Promise<EncryptableData> => {
  if (encryptedData.encryption.type === "secretbox") {
    return decrypt(encryptedData.data as string, {
      salt: encryptedData.encryption.salt,
      password: secretOpts.password,
      key: secretOpts.key,
      scrypt: encryptedData.encryption.scrypt,
    });
  } else {
    return encryptedData.data as EncryptableData;
  }
};
