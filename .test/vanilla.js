"use strict";

const crypto = require('crypto');

let secret = "S3cre+_Squ1rr3l", kruptein,
    ciphers = [], hashes = [],
    encoding = ['binary', 'hex', 'base64'],
    key_derivation = ['default', 'scrypt', 'argon2'],
    phrases = [
      "Secret Squirrel",
      "écureuil secret",
      "गुप्त गिलहरी",
      "ਗੁਪਤ ਗਿੱਠੀ",
      "veverița secretă",
      "секретная белка",
      "leyndur íkorna",
      "السنجاب السري",
      "գաղտնի սկյուռ",
      "feòrag dìomhair",
      "গোপন কাঠবিড়ালি",
      "秘密のリス",
      "таемная вавёрка",
    ];


const options = {
  use_asn1: true
};


// Filter getCiphers()
ciphers = crypto.getCiphers().filter(cipher => {
  if (cipher.match(/^aes/i) && cipher.match(/256/i)&& !cipher.match(/hmac|wrap|ccm|ecb/))
    return cipher;
});


// Filter getHashes()
hashes = crypto.getHashes().filter(hash => {
  if (hash.match(/^sha[2-5]/i) && !hash.match(/rsa/i))
    return hash;
});


// Because we want a quick test
//ciphers=["aes-256-gcm"];
//hashes=["sha384"];
//encoding=["base64"];



for (let cipher in ciphers) {
  options.algorithm = ciphers[cipher];

  for (let hash in hashes) {
    options.hashing = hashes[hash];

    for (let enc in encoding) {
      options.encodeas = encoding[enc];

      for (let kd in key_derivation) {

        // Don't do this in production! `eval()` is not safe!!
        if (key_derivation[kd] != "default") {
          options.use_argon2 = false;
          options.use_scrypt = false;
          eval("options.use_" + key_derivation[kd] + " = true");
        }

        kruptein = require("../index.js")(options);

        console.log('kruptein: { key_derivation: "'+key_derivation[kd]+'", algorithm: "'+options.algorithm+'", hashing: "'+options.hashing+'", encodeas: "'+options.encodeas+'" }');

        let ct, pt;

        for (let phrase in phrases) {

          console.log(phrases[phrase])

          kruptein.set(secret, phrases[phrase], (err, res) => {
            if (err)
              console.log(err);

            ct = res;
          });

          console.log(ct);

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
  }
}
