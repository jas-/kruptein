"use strict";

// Dependencies
const crypto = require("crypto");
const expect = require("expect.js");


// Inits
let kruptein, hmac, secret = "squirrel",
    ciphers = [], hashes = [],
    ciphers_tmp = [], hashes_tmp = [],
    tests = [], encoding = ["binary", "hex", "base64"],
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


// Filter getCiphers()
ciphers = crypto.getCiphers().filter(cipher => {
  if (cipher.match(/^aes/i) && cipher.match(/256/i) && !cipher.match(/hmac|wrap|ccm|ecb|ocb2/))
    return cipher;
});

// Filter getHashes()
hashes = crypto.getHashes().filter(hash => {
  if (hash.match(/^sha[2-5]/i) && !hash.match(/rsa/i))
    return hash;
});


// Because we want a quick test
ciphers=["aes-256-gcm"];
hashes=["sha512"];


// Build tests array
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

    // Init kruptein with the test options
    beforeEach(done => {
      kruptein = require("../index.js")(test.options);
      done();
    });


    describe("Private Functions", () => {

      describe("Validator Tests", () => {

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
      });


      describe("Key Derivation Tests", () => {

        it("Key Derivation: ._derive_key() => .pbkdf2(\""+secret+"\")", done => {
          let opts = {
            hashing: "w00t"
          }, tmp = require("../index.js")(opts);

          tmp._derive_key(secret, (err, res) => {
            expect(err).to.equal("Unable to derive key!");
            expect(res).to.equal.null;
          });

          done();
        });


        it("Key Derivation: ._derive_key() => .scrypt(\""+secret+"\")", done => {
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


        it("Digest Validation: ._digest(\""+phrases[0]+"\")", done => {
          kruptein._digest(test.options.secret, phrases[0], "w00t",
                           test.options.encodeas, (err, res) => {
                             expect(err).to.equal("Unable to generate digest!");
                             expect(res).to.equal.null;
                           });

          done();
        });
      });
    });


    describe("Public Functions", () => {

      describe("Encryption Tests", () => {

        it("Insecure Cipher: .set(\""+phrases[0]+"\")", done => {
          let opts = {
            algorithm: "aes-128-ccm"
          }, tmp = require("../index.js")(opts);

          tmp.set(secret, phrases[0], (err, res) => {
            expect(err).to.equal("Insecure cipher mode not supported!");
            expect(res).to.be.null;
          });

          done();
        });


        it("Missing Secret: .set(\""+phrases[0]+"\")", done => {
          kruptein.set("", phrases[0], (err, res) => {
            expect(err).to.equal("Must supply a secret!");
            expect(res).to.be.null;
          });

          done();
        });


        it("Validate Ciphertext: .set(\""+phrases[0]+"\")", done => {
          kruptein.set(secret, phrases[0], (err, res) => {
            expect(err).to.be.null;

            res = JSON.parse(res);

            expect(res).to.have.property("ct");
            expect(res).to.have.property("iv");
            expect(res).to.have.property("hmac");

            if (kruptein.aead_mode)
              expect(res).to.have.property("at");
          });

          done();
        });


        it("Validate Ciphertext: (scrypt) .set(\""+phrases[0]+"\")", done => {
          kruptein._use_scrypt = true;

          kruptein.set(secret, phrases[0], (err, res) => {
            expect(err).to.be.null;

            res = JSON.parse(res);

            expect(res).to.have.property("ct");
            expect(res).to.have.property("iv");
            expect(res).to.have.property("hmac");

            if (kruptein.aead_mode)
              expect(res).to.have.property("at");
          });

          done();
        });


        it("Validate Ciphertext: (ASN.1) .set(\""+phrases[0]+"\")", done => {
          let opts = {
            use_asn1: true
          }, tmp = require("../index.js")(opts);

          tmp.set(secret, phrases[0], (err, res) => {
            expect(err).to.be.null;

            expect(res).to.not.be.null;
          });

          done();
        });
      });


      describe("Decryption Tests", () => {

        it("Insecure Cipher: .get(\""+phrases[0]+"\")", done => {
          let opts = {
            algorithm: "aes-128-ccm"
          }, tmp = require("../index.js")(opts);

          tmp.get(secret, phrases[0], (err, res) => {
            expect(err).to.equal("Insecure cipher mode not supported!");
            expect(res).to.be.null;
          });

          done();
        });


        it("Missing Secret: .get(\""+phrases[0]+"\")", done => {
          kruptein.get("", phrases[0], (err, res) => {
            expect(err).to.equal("Must supply a secret!");
            expect(res).to.be.null;
          });

          done();
        });


        it("Ciphertext parsing: .set(\""+phrases[0]+"\")", done => {
          let ct;

          kruptein.set(secret, phrases[0], (err, res) => {
            expect(err).to.be.null;

            res = JSON.parse(res);

            expect(res).to.have.property("ct");
            expect(res).to.have.property("iv");
            expect(res).to.have.property("hmac");

            if (kruptein.aead_mode)
              expect(res).to.have.property("at");

            ct = res;
          });

          kruptein.get(secret, ct, (err, res) => {
            expect(err).to.equal("Unable to parse ciphertext object!");
            expect(res).to.be.null;
          });

          done();
        });


        it("HMAC Validation: .set(\""+phrases[0]+"\")", done => {
          let ct;

          kruptein.set(secret, phrases[0], (err, res) => {
            expect(err).to.be.null;

            res = JSON.parse(res);

            expect(res).to.have.property("ct");
            expect(res).to.have.property("iv");
            expect(res).to.have.property("hmac");

            if (kruptein.aead_mode)
              expect(res).to.have.property("at");

            ct = res;
          });

          ct.hmac = "funky chicken";
          ct = JSON.stringify(ct);

          kruptein.get(secret, ct, (err, res) => {
            expect(err).to.equal("Encrypted session was tampered with!");
            expect(res).to.be.null;
          });

          done();
        });


        it("AT Validation: .get(\""+phrases[0]+"\")", done => {
          let ct;

          kruptein.set(secret, phrases[0], (err, res) => {
            expect(err).to.be.null;

            res = JSON.parse(res);

            expect(res).to.have.property("ct");
            expect(res).to.have.property("iv");
            expect(res).to.have.property("hmac");

            if (kruptein.aead_mode)
              expect(res).to.have.property("at");

            ct = res;
          });

          if (!kruptein._aead_mode)
            done();

          expect(ct).to.have.property("at");

          ct.at = crypto.randomBytes(kruptein._at_size);
          ct = JSON.stringify(ct);

          kruptein.get(secret, ct, (err, res) => {
            expect(err).to.match(/Unable to decrypt ciphertext!|null/);
            expect(res).to.be.null;
          });

          done();
        });


        it("AT Validation (opts): .get(\""+phrases[0]+"\")", done => {
          let ct, at;

          kruptein.set(secret, phrases[0], (err, res) => {
            expect(err).to.be.null;

            res = JSON.parse(res);

            expect(res).to.have.property("ct");
            expect(res).to.have.property("iv");
            expect(res).to.have.property("hmac");

            if (kruptein.aead_mode)
              expect(res).to.have.property("at");

            ct = res;
          });

          if (!kruptein._aead_mode)
            done();

          expect(ct).to.have.property("at");

          at = ct.at;
          ct = JSON.stringify(ct);

          kruptein.get(secret, ct, {at: at}, (err, res) => {
            expect(err).to.be.null;
            expect(res.replace(/\"/g, "")).to.equal(phrases[0]);
          });

          done();
        });


        it("AAD Validation: .get(\""+phrases[0]+"\")", done => {
          let ct;

          kruptein.set(secret, phrases[0], (err, res) => {
            expect(err).to.be.null;

            res = JSON.parse(res);

            expect(res).to.have.property("ct");
            expect(res).to.have.property("iv");
            expect(res).to.have.property("hmac");

            if (kruptein.aead_mode)
              expect(res).to.have.property("at");

            ct = res;
          });

          if (!kruptein._aead_mode)
            done();

          expect(ct).to.have.property("at");

          ct.aad = crypto.randomBytes(ct.aad.length + 1);
          ct = JSON.stringify(ct);

          kruptein.get(secret, ct, (err, res) => {
            expect(err).to.match(/Unable to decrypt ciphertext!|null/);
            expect(res).to.be.null;
          });

          done();
        });


        it("AAD Validation (opts): .get(\""+phrases[0]+"\")", done => {
          let ct, aad;

          kruptein.set(secret, phrases[0], (err, res) => {
            expect(err).to.be.null;

            res = JSON.parse(res);

            expect(res).to.have.property("ct");
            expect(res).to.have.property("iv");
            expect(res).to.have.property("hmac");

            if (kruptein.aead_mode)
              expect(res).to.have.property("at");

            ct = res;
          });

          if (!kruptein._aead_mode)
            done();

          expect(ct).to.have.property("at");

          aad = ct.aad;
          ct = JSON.stringify(ct);

          kruptein.get(secret, ct, {aad: aad}, (err, res) => {
            expect(err).to.be.null;
            expect(res.replace(/\"/g, "")).to.equal(phrases[0]);
          });

          done();
        });


        for (let phrase in phrases) {
          it("Validate Plaintext: .get(\""+phrases[phrase]+"\")", done => {
            let ct;

            kruptein.set(secret, phrases[phrase], (err, res) => {
              expect(err).to.be.null;

              res = JSON.parse(res);

              expect(res).to.have.property("ct");
              expect(res).to.have.property("iv");
              expect(res).to.have.property("hmac");

              if (kruptein._aead_mode)
                expect(res).to.have.property("at");

              ct = res;
            });

            ct = JSON.stringify(ct);

            kruptein.get(secret, ct, (err, res) => {
              expect(err).to.be.null;
              expect(res.replace(/\"/g, "")).to.equal(phrases[phrase]);
            });

            done();
          });


          it("Validate Plaintext (scrypt): .get(\""+phrases[phrase]+"\")", done => {
            let ct;

            kruptein._use_scrypt = true;

            kruptein.set(secret, phrases[0], (err, res) => {
              expect(err).to.be.null;

              res = JSON.parse(res);

              expect(res).to.have.property("ct");
              expect(res).to.have.property("iv");
              expect(res).to.have.property("hmac");

              if (kruptein._aead_mode)
                expect(res).to.have.property("at");

              ct = res;
            });

            ct = JSON.stringify(ct);

            kruptein.get(secret, ct, (err, res) => {
              expect(err).to.be.null;
              expect(res.replace(/\"/g, "")).to.equal(phrases[0]);
            });

            done();
          });


          it("Validate Plaintext (ASN.1): .get(\""+phrases[phrase]+"\")", done => {

            let ct,
                opts = {
                  use_asn1: true
                },
                tmp = require("../index.js")(opts);

            tmp.set(secret, phrases[0], (err, res) => {
              expect(err).to.be.null;

              expect(res).to.not.be.null;

              ct = res;
            });

            tmp.get(secret, ct, (err, res) => {
              expect(err).to.be.null;

              expect(res.replace(/\"/g, "")).to.equal(phrases[0]);
            });

            done();
          });
        }
      });
    });
  });
});
