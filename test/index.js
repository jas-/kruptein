"use strict";

// Dependencies
const crypto = require("crypto");
const expect = require("expect.js");


// Inits
let kruptein, hmac, secret = "S3cre+_Squ1rr3l",
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
  if (cipher.match(/^aes/i) && cipher.match(/256|192/i) && !cipher.match(/hmac|wrap|ecb|ofb|xts|ccm/))
    return cipher;
});

// Filter getHashes()
hashes = crypto.getHashes().filter(hash => {
  if (hash.match(/^sha[2-5]/i) && !hash.match(/rsa/i))
    return hash;
});


// Because we want a quick test
ciphers=["aes-256-gcm"];
hashes=["sha384"];
encoding=["base64"];


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
    beforeEach(function(done) {
      this.timeout(50000);
      kruptein = require("../index.js")(test.options);
      done();
    });


    describe("Private Functions", () => {

      describe("Validator Tests", () => {

        it("Validate supplied secrets complexity: ._complexity()", done => {
          let complexity = kruptein._complexity(secret);
          expect(complexity).to.equal(true);
          done();
        });


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
          };
          let tmp = require("../index.js")(opts);

          tmp._derive_key(secret, (err, res) => {
            expect(err).to.be.null;
            expect(Buffer.byteLength(res.key)).to.equal(tmp._key_size);
          });

          done();
        });

        it("Validate Key Size: ._derive_key() => .argon2()", done => {
          let opts = {
            use_argon2: true
          };
          let tmp = require("../index.js")(opts);

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
          };
          let tmp = require("../index.js")(opts);

          tmp._derive_key(secret, (err, res) => {
            expect(err).to.equal("Unable to derive key!");
            expect(res).to.equal.null;
          });

          done();
        });


        it("Key Derivation: ._derive_key() => .scrypt(\""+secret+"\")", done => {
          let opts = {
            use_scrypt: true
          };
          let scrypt_limits = {
            N: 2 ** 16, p: 1, r: 1
          };
          let tmp = require("../index.js")(opts);

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


        it("Key Derivation: ._derive_key() => .argon2(\""+secret+"\")", done => {
          let opts = {
            use_argon2: true
          }, tmp = require("../index.js")(opts);

          tmp._derive_key(secret, (err, res) => {
            if (typeof crypto.argon2Sync === "function") {
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
            expect(err).to.equal("The supplied secret failed to meet complexity requirements!");
            expect(res).to.be.null;
          });

          done();
        });


        it("Validate Ciphertext (pbkdf2): .set(\""+phrases[0]+"\")", done => {
          kruptein.set(secret, phrases[0], (err, res) => {
            expect(err).to.be.null;
            expect(res).to.not.be.empty;
          });

          done();
        });


        it("Validate Ciphertext (scrypt): .set(\""+phrases[0]+"\")", done => {
          kruptein._use_scrypt = true;

          kruptein.set(secret, phrases[0], (err, res) => {
            expect(err).to.be.null;
            expect(res).to.not.be.empty;
          });

          done();
        });


        it("Validate Ciphertext (argon2): .set(\""+phrases[0]+"\")", done => {
          kruptein._use_argon2 = true;

          kruptein.set(secret, phrases[0], (err, res) => {
            expect(err).to.be.null;
            expect(res).to.not.be.empty;
          });

          done();
        });


        it("Validate Ciphertext: (Non-ASN.1) .set(\""+phrases[0]+"\")", done => {
          let opts = {
            use_asn1: false
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
            expect(res).to.not.be.empty;
            ct = res;
          });

          kruptein.get(secret, ct, (err, res) => {
            expect(err).to.be.null;
            expect(res).to.not.be.empty;
          });

          done();
        });


        it("HMAC Validation: .set(\""+phrases[0]+"\")", done => {
          let ct;

          kruptein.set(secret, phrases[0], (err, res) => {
            expect(err).to.be.null;
            expect(res).to.not.be.empty;
            ct = res;
          });

          ct = kruptein.schema.decode(Buffer.from(ct, kruptein._encodeas));
          expect(ct).to.have.property("hmac");
          ct.hmac = "funky chicken";
          ct = kruptein.schema.encode(ct).toString(kruptein._encodeas);

          kruptein.get(secret, ct, (err, res) => {
            expect(err).to.match(/Encrypted session was tampered with!|null/);
            expect(res).to.be.null;
          });

          done();
        });


        it("AT Validation: .get(\""+phrases[0]+"\")", done => {
          let ct;

          kruptein.set(secret, phrases[0], (err, res) => {
            expect(err).to.be.null;
            expect(res).to.not.be.empty;
            ct = res;
          });

          if (!kruptein._aead_mode)
            done();

          ct = kruptein.schema.decode(Buffer.from(ct, kruptein._encodeas));
          expect(ct).to.have.property("at");
          ct.at = crypto.randomBytes(kruptein._at_size);
          ct = kruptein.schema.encode(ct).toString(kruptein._encodeas);

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
            expect(res).to.not.be.empty;
            ct = res;
          });

          if (!kruptein._aead_mode)
            done();

          ct = kruptein.schema.decode(Buffer.from(ct, kruptein._encodeas));
          expect(ct).to.have.property("at");
          at = ct.at;
          ct = kruptein.schema.encode(ct).toString(kruptein._encodeas);

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
            expect(res).to.not.be.empty;
            ct = res;
          });

          if (!kruptein._aead_mode)
            done();

          ct = kruptein.schema.decode(Buffer.from(ct, kruptein._encodeas));
          expect(ct).to.have.property("at");
          ct.aad = crypto.randomBytes(ct.aad.length + 1);
          ct = kruptein.schema.encode(ct).toString(kruptein._encodeas);

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
            expect(res).to.not.be.empty;
            ct = res;
          });

          if (!kruptein._aead_mode)
            done();

          ct = kruptein.schema.decode(Buffer.from(ct, kruptein._encodeas));
          expect(ct).to.have.property("aad");
          aad = ct.aad.toString();
          ct = kruptein.schema.encode(ct).toString(kruptein._encodeas);

          kruptein.get(secret, ct, {aad: aad}, (err, res) => {
            expect(err).to.be.null;
            expect(res.replace(/\"/g, "")).to.equal(phrases[0]);
          });

          done();
        });


        for (let phrase in phrases) {
          it("Validate Plaintext (pbkdf2): .get(\""+phrases[phrase]+"\")", done => {
            let ct;

            kruptein.set(secret, phrases[phrase], (err, res) => {
              expect(err).to.be.null;
              expect(res).to.not.be.empty;
              ct = res;
            });

            if (typeof ct === "object")
              ct = JSON.stringify(ct)

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
              expect(res).to.not.be.empty;
              ct = res;
            });

            if (typeof ct === "object")
              ct = JSON.stringify(ct)

            kruptein.get(secret, ct, (err, res) => {
              expect(err).to.be.null;
              expect(res.replace(/\"/g, "")).to.equal(phrases[0]);
            });

            done();
          });


          it("Validate Plaintext (argon2): .get(\""+phrases[phrase]+"\")", done => {
            let ct;

            kruptein._use_argon2 = true;

            kruptein.set(secret, phrases[0], (err, res) => {
              expect(err).to.be.null;
              expect(res).to.not.be.empty;
              ct = res;
            });

            if (typeof ct === "object")
              ct = JSON.stringify(ct)

            kruptein.get(secret, ct, (err, res) => {
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
