/*!
 * kruptein
 * Copyright(c) 2019 Jason Gerfen <jason.gerfen@gmail.com>
 * License: MIT
 */

"use strict";

class Kruptein {

  constructor(options) {
    this.crypto = require("crypto");

    this.algorithm = options.algorithm || "aes-256-gcm";
    this.hashing = options.hashing || "sha512";
    this.encodeas = options.encodeas || "binary";

    this.aead_mode = this.algorithm.match(/ccm|gcm|ocb/) ? true : false;

    this.at_size = options.at_size || this._matrix(this.algorithm).at_size;
    this.iv_size = options.iv_size || this._matrix(this.algorithm).iv_size;
    this.key_size = options.key_size || this._matrix(this.algorithm).key_size;

    this.use_scrypt = options.use_scrypt || false;
  }


  set(secret, plaintext, aad, cb) {
    cb = cb || aad;

    let iv, ct, hmac, obj, key;


    if (!secret)
      return cb("Must supply a secret!");


    this._derive_key(secret, (err, secret) => {
      if (err)
        return cb("Unable to derive key!");

      key = secret;
    });

    this.secret = key;


    iv = this._iv(this.iv_size);
    

    aad = (this.aead_mode && !aad) ?
      this._digest(iv+this.secret.key, JSON.stringify(plaintext),
                   this.hashing, this.encodeas) : false;


    this._encrypt(this.secret.key, JSON.stringify(plaintext), this.algorithm,
                  this.encodeas, iv, aad, (err, ciphertext) => {
                    if (err)
                      return cb("Unable to create ciphertext!");

                      ct = ciphertext;
                  });


    this._digest(this.secret.key, ct.ct, this.hashing,
                 this.encodeas, (err, digest) => {
                    if (err)
                      return cb("Unable to create digest!");
                    
                    hmac = digest;
                 });


    obj = { hmac: hmac, ct: ct.ct, iv: iv, salt: this.secret.salt };


    if (aad)
      obj.aad = aad;


    if (ct.at)
      obj.at = ct.at;


    return cb(null, JSON.stringify(obj));
  }


  get(secret, ciphertext, opts, cb) {
    cb = cb || opts;

    let ct, hmac, pt, key, tmp_ct;


    if (!secret)
      return cb("Must supply a secret!");


    try {
      ct = JSON.parse(ciphertext);
    } catch(err) {
      return cb("Unable to parse ciphertext object!");
    }


    this._derive_key(secret, ct.salt, (err, secret) => {
      if (err)
        return cb("Unable to derive key!");

      key = secret;
    });

    this.secret = key;

    this._digest(this.secret.key, ct.ct, this.hashing,
                 this.encodeas, (err, res) => {
                   if (err)
                     cb("Unable to generate HMAC!");
                    
                    hmac = res;
                 });


    if (hmac !== ct.hmac)
      return cb("Encrypted session was tampered with!");


    if (opts) {
      ct.aad = (opts.aad) ? opts.aad : false;
      ct.at = (opts.at && !ct.at) ?
        opts.at : (ct.at) ?
          ct.at : false;
    }


    if (ct.at)
      ct.at = Buffer.from(ct.at, this.encodeas);


    this._decrypt(this.secret.key, ct.ct, this.algorithm, this.encodeas,
                       Buffer.from(ct.iv, this.encodeas),
                       ct.at, ct.aad, (err, res) => {
                         if (err)
                           return cb("Unable to decrypt ciphertext!");
                           
                         pt = res;
                       });


    return cb(null, pt);
  }


  _encrypt(key, pt, algo, encodeas, iv, aad, cb) {
    cb = cb || aad;

    let cipher, ct, at;
    
    cipher = this.crypto.createCipheriv(algo, key, iv, {
      authTagLength: this.at_size
    });

    if (this.aead_mode && aad) {
      try {
        cipher.setAAD(Buffer.from(aad, encodeas), {
          plaintextLength: Buffer.byteLength(pt)
        });
      } catch(err) {
        return cb("Unable to set AAD");
      }
    }

    ct = cipher.update(Buffer.from(pt, this.encodeas), "utf8", encodeas);
    ct += cipher.final(encodeas);

    if (this.aead_mode) {
      try {
        at = cipher.getAuthTag();
      } catch(err) {
        return cb("Unable to obtain authentication tag");
      }
    }

    return cb(null, (at) ? {"ct": ct, "at": at} : {"ct": ct});
  }


  _decrypt(key, ct, algo, encodeas, iv, at, aad, cb) {
    cb = cb || aad;

    let cipher, pt;

    cipher = this.crypto.createDecipheriv(algo, key, iv, {
      authTagLength: this.at_size
    });

    if (this.aead_mode && at) {
      try {
        cipher.setAuthTag(Buffer.from(at, encodeas));
      } catch(err) {
        return cb("Unable to set authentication tag");
      }
    }

    if (this.aead_mode && aad) {
      try {
        cipher.setAAD(Buffer.from(aad, encodeas), {
          plaintextLength: Buffer.byteLength(ct)
        });
      } catch(err) {
        return cb("Unable to set additional authentication data");
      }
    }

    pt = cipher.update(ct, encodeas, "utf8");
    pt += cipher.final("utf8");

    return cb(null, pt);
  }


  _derive_key(secret, salt, cb) {
    cb = cb || salt;

    let key;

    salt = (typeof salt !== "function") ?
      Buffer.from(salt) : this.crypto.randomBytes(128);

    if (!this.use_scrypt) {
      key = this.crypto.pbkdf2Sync(secret, salt, 10000, this.key_size, this.hashing);
    } else {
      key = this.crypto.scryptSync(secret, salt, this.key_size);
    }


    return cb(null, {
      key: key,
      salt: salt
    });
  }
  

  _digest(key, obj, hashing, encodeas, cb) {
    let hmac;
    
    try {
      hmac = this.crypto.createHmac(hashing, key);
      hmac.setEncoding(encodeas);
      hmac.write(obj);
      hmac.end();
    } catch(err) {
      return cb("Unable to generate digest");
    }

    return cb(null, hmac.read().toString(encodeas));
  }


  _iv(iv_size) {
    return this.crypto.randomBytes(iv_size);
  }
  

  _matrix(algo) {
    let obj = {
      at_size: 16,
      iv_size: 16,
      key_size: 32
    };

    if (algo.match(/ccm|ocb|gcm/i))
      obj.iv_size = 12;

    if (algo.match(/aes/) && algo.match(/ecb/))
      obj.iv_size = 0;

    if (algo.match(/aes/) && algo.match(/128/))
      obj.key_size = 16;

    if (algo.match(/aes/) && algo.match(/192/))
      obj.key_size = 24;

    if (algo.match(/aes/) && algo.match(/xts/))
      obj.key_size = 32;

    if (algo.match(/aes/) && algo.match(/xts/) && algo.match(/256/))
      obj.key_size = 64;

    return obj;
  }
}


module.exports = function(options) {
  return new Kruptein(options);
};
