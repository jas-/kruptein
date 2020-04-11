"use strict";

// Dependencies
const crypto = require("crypto");
const expect = require("expect.js");


// Inits
let kruptein, hmac, secret = "squirrel",
    ciphers = [], hashes = [],
    ciphers_tmp = [], hashes_tmp = [],
    tests = [], encoding = ["binary", "hex", "base64", "utf16le"],
    plaintext = "Operation mincemeat was an example of deception.",
    phrases = [
      "Operation mincemeat was an example of deception",
      "Krimbi i operacionit ishte një shembull mashtrimi",
      "ye’opirēshini mīnī-serashi yemataleli misalē neberi",
      "كانت عملية اللحم المفروم مثالا للخداع",
      "Գործողության աղանդը խաբեության օրինակ էր",
      "অপারেশন মিনসমেট প্রতারণার উদাহরণ ছিল",
      "ऑपरेशन कीमाईट धोखे का एक उदाहरण था",
      "A darált sertéshús volt a megtévesztés egyik példája",
      "Aðgerð kjötkjöt var dæmi um blekkingar",
      "Sampla de mheabhlaireacht ab ea mincemeat oibríochta",
      "L'operazione carne tritata era un esempio di inganno",
      "Picadinho de operação foi um exemplo de engano",
      "ਓਪਰੇਸ਼ਨ ਮੀਨਮੀਟ ਧੋਖਾ ਖਾਣ ਦੀ ਇੱਕ ਉਦਾਹਰਣ ਸੀ",
      "Operațiunea mincemeat a fost un exemplu de înșelăciune",
      "Операционный фарш был примером обмана",
      "Операција мљевеног меса била је пример обмане",
      "Chiến dịch mincemeat là một ví dụ về sự lừa dối",
      "Mincemeat-ийг ажиллуулах нь хууран мэхлэх жишээ байв",
      "Operation Hackfleisch war ein Beispiel für Täuschung",
      "ოპერაციის მინერალმა მოტყუების მაგალითი იყო", 
    ];


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
      });
    });


    describe("Public Functions", () => {

      describe("Encryption Tests", () => {

        it("Insecure Cipher: .set()", done => {
          let opts = {
            algorithm: "aes-128-ccm"
          }, tmp = require("../index.js")(opts);

          tmp.set(secret, plaintext, (err, res) => {
            expect(err).to.equal("Insecure cipher mode not supported!");
            expect(res).to.be.null;
          });

          done();
        });


        it("Missing Secret: .set()", done => {
          kruptein.set("", plaintext, (err, res) => {
            expect(err).to.equal("Must supply a secret!");
            expect(res).to.be.null;
          });

          done();
        });


        it("Validate Ciphertext: .set()", done => {
          kruptein.set(secret, plaintext, (err, res) => {
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


        it("Validate Ciphertext: (scrypt) .set()", done => {
          kruptein._use_scrypt = true;

          kruptein.set(secret, plaintext, (err, res) => {
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
      });


      describe("Decryption Tests", () => {

        it("Insecure Cipher: .get()", done => {
          let opts = {
            algorithm: "aes-128-ccm"
          }, tmp = require("../index.js")(opts);

          tmp.get(secret, plaintext, (err, res) => {
            expect(err).to.equal("Insecure cipher mode not supported!");
            expect(res).to.be.null;
          });

          done();
        });


        it("Missing Secret: .get()", done => {
          kruptein.get("", plaintext, (err, res) => {
            expect(err).to.equal("Must supply a secret!");
            expect(res).to.be.null;
          });

          done();
        });


        it("Ciphertext parsing: .set()", done => {
          let ct;

          kruptein.set(secret, plaintext, (err, res) => {
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


        it("HMAC Validation: .set()", done => {
          let ct;

          kruptein.set(secret, plaintext, (err, res) => {
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


        it("AT Validation: .get()", done => {
          let ct;

          kruptein.set(secret, plaintext, (err, res) => {
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


        it("AT Validation (opts): .get()", done => {
          let ct, at;

          kruptein.set(secret, plaintext, (err, res) => {
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
            expect(res.replace(/\"/g, "")).to.equal(plaintext);
          });

          done();
        });


        it("AAD Validation: .get()", done => {
          let ct;

          kruptein.set(secret, plaintext, (err, res) => {
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


        it("AAD Validation (opts): .get()", done => {
          let ct, aad;

          kruptein.set(secret, plaintext, (err, res) => {
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
            expect(res.replace(/\"/g, "")).to.equal(plaintext);
          });

          done();
        });


        it("Validate Plaintext: .get()", done => {
          let ct;

          kruptein.set(secret, plaintext, (err, res) => {
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
            expect(res.replace(/\"/g, "")).to.equal(plaintext);
          });

          done();
        });


        it("Validate Plaintext (scrypt): .get()", done => {
          let ct;

          kruptein._use_scrypt = true;

          kruptein.set(secret, plaintext, (err, res) => {
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
            expect(res.replace(/\"/g, "")).to.equal(plaintext);
          });

          done();
        });
      });
    });
  });
});
