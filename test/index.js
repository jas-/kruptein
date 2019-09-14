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


    it("Missing Secret", done => {
      try {
        ct = kruptein.set(secret, plaintext);
      } catch(err) {
        expect(err).to.throw("Must supply a secret!");
      }

      done();
    });


    it("Invalid Key Size", done => {
      let opts = {
        key_size: 99999
      }, tmp;

      try {
        tmp = require("../index.js")(opts);
        expect(tmp).to.throw("Invalid key size!");
      } catch(err) {
        expect(err).to.be.null;
      }

      done();
    });


    it("Invalid IV Size", done => {
      let opts = {
        iv_size: 99999
      }, tmp;

      try {
        tmp = require("../index.js")(opts);
        expect(tmp).to.throw("Invalid IV size!");
      } catch(err) {
        expect(err).to.be.null;
      }

      done();
    });


    it("Key Derivation", done => {
      let opts = {
        hashing: "w00t"
      }, tmp;

      try {
        require("../index.js")(opts);
      } catch(err) {
        expect(err).to.match(/Unable to generate key material/);
      }

      done();
    });


    it("Key Derivation (.scrypt())", done => {
      let opts = {
        use_scrypt: true
      }, tmp = require("../index.js")(opts);

      try {
        tmp._derive_key(secret);
      } catch(err) {
        expect(err).to.match(/Unable to generate key material/);
      }

      done();
    });


    it("Digest Validation", done => {
      let kruptein_copy = require("../index.js")(test.options);

      try {
        kruptein_copy._digest(test.options.secret, plaintext,
                              "w00t", test.options.encodeas);
      } catch(err) {
        expect(err).to.match(/Unable to generate digest/);
      }

      done();
    });


    it("Encrypt Validation", done => {
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


    it("HMAC Validation", done => {
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


    it("Authentication Tag Validation", done => {
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


    it("Authentication Tag Validation (option)", done => {
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


    it("Additional Authentication Data Validation", done => {
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


    it("Additional Authentication Data Validation (option)", done => {
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


    it("Decrypt Validation", done => {
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
