[![MIT license](http://img.shields.io/badge/license-MIT-brightgreen.svg)](http://opensource.org/licenses/MIT)

# Encrypted, just some client side encryption helpers

```
npm install encrypted --save
```

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

A convenience wrapper around:
 - https://github.com/dchest/tweetnacl-js
 - https://github.com/dchest/scrypt-async-js

Inspired by:
 - https://github.com/stellarport/stellar-keystore
