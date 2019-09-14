"use strict"

const crypto = require('crypto');

let hmac, secret = "squirrel", kruptein,
    ciphers = [], hashes = [],
    ciphers_tmp = [], hashes_tmp = [],
    encoding = ['binary'];

const options = {
  debug: true
};


// Filter getCiphers()
ciphers = crypto.getCiphers().filter(cipher => {
  if (cipher.match(/^aes/i) && !cipher.match(/hmac|wrap|ccm/))
    return cipher;
})


// Filter getHashes()
hashes = crypto.getHashes().filter(hash => {
  if (hash.match(/^sha[2-5]/i) && !hash.match(/rsa/i))
    return hash;
})


for (let cipher in ciphers) {
  options.algorithm = ciphers[cipher];

  for (let hash in hashes) {
    options.hashing = hashes[hash];

    for (let enc in encoding) {
      options.encodeas = encoding[enc];

      kruptein = require("../lib/kruptein.js")(options);

      console.log('kruptein: { algorithm: "'+options.algorithm+'", hashing: "'+options.hashing+'", encodeas: "'+options.encodeas+'" }');
      let ct, pt;

      try {
        ct = JSON.parse(kruptein.set(secret, "123, easy as ABC. ABC, easy as 123"));
      } catch(err) {
        console.log(err);
      }

      console.log(JSON.stringify(ct));

      try {
        pt = kruptein.get(secret, JSON.stringify(ct));
      } catch(err) {
        console.log(err);
      }

      console.log(pt);
      console.log("");
    }
  }
}