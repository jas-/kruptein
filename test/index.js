"use strict";

// Dependencies
const crypto = require("crypto");
const expect = require("expect.js");


// Inits
let kruptein, hmac, secret = "squirrel",
    ciphers = [], hashes = [],
    ciphers_tmp = [], hashes_tmp = [],
    tests = [], encoding = ["binary"],
    plaintext = "123, easy as ABC. ABC, easy as 123";


// Filter getCiphers()
ciphers = crypto.getCiphers().filter(cipher => {
  if (cipher.match(/^aes/i) && !cipher.match(/hmac|wrap|ccm/))
    return cipher;
});

// Filter getHashes()
hashes = crypto.getHashes().filter(hash => {
  if (hash.match(/^sha[2-5]/i) && !hash.match(/rsa/i))
    return hash;
});


// Build tests array"s
ciphers.forEach(cipher => {
  hashes.forEach(hash => {
    encoding.forEach(encode => {
      tests.push(
        {
          "title": "{ algorithm: "+cipher+", hashing: "+hash+", encodeas: "+encode+" }",
          "options": {
            "algorithm": cipher,
            "hashing": hash,
            "encodeas": encode
          }
        }
      );
    });
  });
});


// Begin iterator
tests.forEach(test => {
  describe("kruptein: "+test.title, () => {
    let ct, pt;

    // Init kruptein with the test options
    beforeEach(done => {
      kruptein = require("../index.js")(test.options);
      done();
    });


    describe("Private Function Tests", () => {

      it("Validate IV Size: ._iv()", done => {
        let tmp_iv = kruptein._iv(kruptein._iv_size);

        expect(Buffer.byteLength(tmp_iv)).to.equal(kruptein._iv_size);

        done();
      });


      it("Validate Key Size: ._derive_key() => .pbkdf2()", done => {
        kruptein._derive_key(secret, (err, res) => {
          expect(err).to.be.null;

          expect(Buffer.byteLength(res.key)).to.equal(kruptein._key_size);
        });

        done();
      });


      it("Validate Key Size: ._derive_key() => .scrypt()", done => {
        let opts = {
          use_scrypt: true
        }, tmp = require("../index.js")(opts);

        tmp._derive_key(secret, (err, res) => {
          expect(err).to.be.null;

          expect(Buffer.byteLength(res.key)).to.equal(tmp._key_size);
        });

        done();
      });


      it("Key Derivation: ._derive_key() => .pbkdf2()", done => {
        let opts = {
          hashing: "w00t"
        }, tmp = require("../index.js")(opts);

        tmp._derive_key(secret, (err, res) => {
          expect(err).to.equal("Unable to derive key!");
          expect(res).to.equal.null;
        });

        done();
      });


      it("Key Derivation: ._derive_key() => .scrypt()", done => {
        let opts = {
          use_scrypt: true
        }, scrypt_limits = {
          N: 2 ** 16, p: 1, r: 1
        }, tmp = require("../index.js")(opts);

        tmp._derive_key({secret: secret, opts: scrypt_limits}, (err, res) => {
          if (typeof crypto.scryptSync === "function") {
            expect(err).to.equal("Unable to derive key!");
            expect(res).to.equal.null;
          } else {
            expect(err).to.equal.null;
            expect(Buffer.byteLength(res.key)).to.equal(tmp._key_size);
          }
        });

        done();
      });


      it("Digest Validation: ._digest()", done => {
        kruptein._digest(test.options.secret, plaintext, "w00t",
                         test.options.encodeas, (err, res) => {
                          expect(err).to.equal("Unable to generate digest!");
                          expect(res).to.equal.null;
                        });

        done();
      });


      it("Validate Ciphertext: ._encrypt()", done => {
        let iv = kruptein._iv(kruptein._iv_size);

        kruptein._derive_key(secret, (err, res) => {
          expect(err).to.be.null;

          kruptein._encrypt(res.key, plaintext, kruptein.algorithm,
                            kruptein.encodeas, iv, (err, res) => {
                              expect(err).to.be.null;

                              expect(res).to.have.property("ct");

                              if (kruptein._aead_mode)
                                expect(res).to.have.property("at");
                            });
        });

        done();
      });


      it("Validate Ciphertext (AAD): ._encrypt()", done => {
        if (!kruptein._aead_mode)
          return done();

        let iv = kruptein._iv(kruptein._iv_size),
            aad_size = (1 << (8 * (15 - iv.byteLength))) - 1;

        kruptein._derive_key(secret, (err, res) => {
          expect(err).to.be.null;

          kruptein._encrypt(res.key, plaintext, kruptein.algorithm,
                            kruptein.encodeas, iv,
                            {aad: plaintext, size: aad_size}, (err, res) => {
                              console.log(err)
                              console.log(res)
                              expect(err).to.be.null;

                              expect(res).to.have.property("ct");
                              expect(res).to.have.property("at");
                            });
        });

        done();
      });
    });


    describe("Public Function Tests", () => {

      it.skip("Missing Secret: .set()", done => {
        kruptein.set("", plaintext, (err, res) => {
          expect(err).to.equal("Must supply a secret!");
          expect(res).to.be.null;
        });

        done();
      });


      it.skip("Missing Secret: .get()", done => {
        kruptein.get("", plaintext, (err, res) => {
          expect(err).to.equal("Must supply a secret!");
          expect(res).to.be.null;
        });

        done();
      });


      it.skip("Encrypt Validation", done => {
        try {
          ct = JSON.parse(kruptein.set(secret, plaintext));
        } catch(err) {
          expect(err).to.be.null;
        }

        expect(ct).to.have.property("ct");
        expect(ct).to.have.property("iv");
        expect(ct).to.have.property("hmac");

        if (kruptein.aead_mode)
          expect(ct).to.have.property("at");

        done();
      });


      it.skip("HMAC Validation", done => {
        try {
          ct = JSON.parse(kruptein.set(secret, plaintext));
        } catch(err) {
          expect(err).to.be.null;
        }

        expect(ct).to.have.property("ct");
        expect(ct).to.have.property("iv");
        expect(ct).to.have.property("hmac");

        if (kruptein.aead_mode)
          expect(ct).to.have.property("at");

        ct.hmac = "funky chicken";
        ct = JSON.stringify(ct);

        try {
          pt = kruptein.get(secret, ct);

          if (kruptein.aead_mode) {
            expect(pt).to.match(/invalid key length|Unsupported state or unable to authenticate data/);
          }
        } catch(err) {
          expect(err).to.equal("Encrypted session was tampered with!");
        }

        done();
      });


      it.skip("Authentication Tag Validation", done => {
        try {
          ct = JSON.parse(kruptein.set(secret, plaintext));
        } catch(err) {
          expect(err).to.be.null;
        }

        expect(ct).to.have.property("ct");
        expect(ct).to.have.property("iv");
        expect(ct).to.have.property("hmac");

        if (!kruptein.aead_mode)
          done();

        expect(ct).to.have.property("at");

        ct.at = crypto.randomBytes(16);
        ct = JSON.stringify(ct);

        try {
          pt = kruptein.get(secret, ct);
        } catch(err) {
          expect(err).to.match(/invalid key length|Unsupported state or unable to authenticate data/);
        }

        done();
      });


      it.skip("Authentication Tag Validation (option)", done => {
        try {
          ct = JSON.parse(kruptein.set(secret, plaintext));
        } catch(err) {
          expect(err).to.be.null;
        }

        expect(ct).to.have.property("ct");
        expect(ct).to.have.property("iv");
        expect(ct).to.have.property("hmac");

        if (!kruptein.aead_mode)
          done();

        expect(ct).to.have.property("at");

        let opts = {at: ct.at};
        ct = JSON.stringify(ct);

        try {
          pt = kruptein.get(secret, ct, opts);
        } catch(err) {
          expect(err).to.match(/invalid key length|Unsupported state or unable to authenticate data/);
        }

        done();
      });


      it.skip("Additional Authentication Data Validation", done => {
        try {
          ct = JSON.parse(kruptein.set(secret, plaintext));
        } catch(err) {
          expect(err).to.be.null;
        }

        expect(ct).to.have.property("ct");
        expect(ct).to.have.property("iv");
        expect(ct).to.have.property("hmac");

        if (!kruptein.aead_mode)
          done();

        expect(ct).to.have.property("at");

        ct.aad = crypto.randomBytes(16);
        ct = JSON.stringify(ct);

        try {
          pt = kruptein.get(secret, ct);
        } catch(err) {
          expect(err).to.match(/invalid key length|Unsupported state or unable to authenticate data/);
        }

        done();
      });


      it.skip("Additional Authentication Data Validation (option)", done => {
        try {
          ct = JSON.parse(kruptein.set(secret, plaintext));
        } catch(err) {
          expect(err).to.be.null;
        }

        if (!ct.aad)
          return done();

        expect(ct).to.have.property("ct");
        expect(ct).to.have.property("iv");
        expect(ct).to.have.property("hmac");

        if (!kruptein.aead_mode)
          done();

        expect(ct).to.have.property("at");

        let opts = {aad: ct.aad};
        ct = JSON.stringify(ct);

        try {
          pt = kruptein.get(secret, ct, opts);
        } catch(err) {
          expect(err).to.match(/invalid key length|Unsupported state or unable to authenticate data/);
        }

        done();
      });


      it.skip("Decrypt Validation", done => {
        try {
          ct = JSON.parse(kruptein.set(secret, plaintext));
        } catch(err) {
          expect(err).to.be.null;
        }

        expect(ct).to.have.property("ct");
        expect(ct).to.have.property("iv");
        expect(ct).to.have.property("hmac");

        if (kruptein.aead_mode)
          expect(ct).to.have.property("at");

        try {
          pt = kruptein.get(secret, JSON.stringify(ct)).replace(/"/g, "");
        } catch(err) {
          expect(err).to.be.null;
        }

        expect(pt).to.equal(plaintext);

        done();
      });
    });
  });
});
