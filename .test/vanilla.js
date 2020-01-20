"use strict";

const crypto = require('crypto');

let secret = "squirrel", kruptein,
    ciphers = [], hashes = [],
    encoding = ['binary'];

const options = {
  use_scrypt: true
};


// Filter getCiphers()
ciphers = crypto.getCiphers().filter(cipher => {
  if (cipher.match(/^aes/i) && !cipher.match(/hmac|wrap|ccm|ecb/))
    return cipher;
});


// Filter getHashes()
hashes = crypto.getHashes().filter(hash => {
  if (hash.match(/^sha[2-5]/i) && !hash.match(/rsa/i))
    return hash;
});

for (let cipher in ciphers) {
  options.algorithm = ciphers[cipher];

  for (let hash in hashes) {
    options.hashing = hashes[hash];

    for (let enc in encoding) {
      options.encodeas = encoding[enc];

      kruptein = require("../index.js")(options);

      console.log('kruptein: { algorithm: "'+options.algorithm+'", hashing: "'+options.hashing+'", encodeas: "'+options.encodeas+'" }');
      let ct, pt;

      kruptein.set(secret, "123, easy as ABC. ABC, easy as 123", (err, res) => {
        if (err)
          console.log(err);

        ct = res;
      });

      console.log(JSON.stringify(ct));

      kruptein.get(secret, ct, (err, res) => {
        if (err)
          console.log(err);

        pt = res;
      });

      console.log(pt);
      console.log("");
    }
  }
}

