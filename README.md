[![MIT license](http://img.shields.io/badge/license-MIT-brightgreen.svg)](http://opensource.org/licenses/MIT)

# Encrypted, just some client side encryption helpers

Decided to publish these helpers as it was not trivial to me how to encrypt a Javascript object, or any data in general, client side in a browser context using a password (or key).

```
npm install encrypted --save
```

Using a password only some data can be encrypted like this:
```ts
import { encrypted, decrypted } from "encrypted";

const encryptedObject = encrypted({my: ['secret', 'object']}, {'password': 'my pass'});
console.log(encryptedObject); // store this in some database
//{
//    encryption: {
//      type: 'secretbox',
//      salt: '1Ng96y/+JIHW+PiDM+sxk9bnyBWt0aoV',
//      nonce: 'cwudxtH26BhEhGlvT2lcUGz74uBBeVzY',
//      scrypt: { N: 16384, r: 8, p: 1, dkLen: 32, interruptStep: 0 }
//    },
//    data: 'cwudxtH26BhEhGlvT2lcUGz74uBBeVzYUylw9jxZUZSuvksfeGvp1rHCJetE4UxA/X/Y0rhSlg=='
//}
const decryptedObject = decrypted(encryptedObject, {'password': 'my pass'});
console.log(decryptedObject);
// {my: ['secret', 'object']}
```

Or create a key yourself:
```ts
import { encrypted, decrypted, generateKey, encodeBase64, decodeBase64, newRandomSalt } from "encrypted";
const key = await generateKey("some test password", newRandomSalt());
// You can also base64 encode this key if you want to use it in the #hash part of a link 
// for example (the good part about that is that the hash is never transmitted to your 
// server so you won't need to worry about it ending up in your logs. 
// Do worry about analytics libraries though.
const encodedKey = encodeBase64(key);
const decodedKey = decodeBase64(encodedKey);
const encryptedObject = encrypted({my: ['secret', 'object']}, {'key': decodedKey});
```

A convenience wrapper around:
 - https://github.com/dchest/tweetnacl-js
 - https://github.com/dchest/scrypt-async-js

Inspired by:
 - https://github.com/stellarport/stellar-keystore
