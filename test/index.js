"use strict";

// Dependencies
const crypto = require("crypto");
const expect = require("expect.js");


// Inits
let kruptein, hmac, ciphers = [], hashes = [],
    ciphers_tmp = [], hashes_tmp = [],
    encoding = ["binary"],
    tests = [],
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
            "encodeas": encode,
            "secret": "squirrel"
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
      test.options.secret = "";

      let kruptein_copy = require("../index.js")(test.options);

      try {
        ct = kruptein_copy.set(plaintext);
      } catch(err) {
        expect(err).to.throw("Must supply a secret!");
      }

      try {
        pt = kruptein_copy.get(ct);
      } catch(err) {
        expect(err).to.throw("Must supply a secret!");
      }

      done();
    });


    it("Invalid Key Size", done => {
      let opts = {
        key_size: 99999,
        secret: "squirrel"
      }, tmp;

      try {
        tmp = require("../index.js")(opts);
        expect(tmp).to.throw("Invalid key size!");
      } catch(err) {
        expect(err).to.be.null;
      }

      try {
        ct = JSON.parse(tmp.set(plaintext));
      } catch(err) {
        expect(err).to.be.null;
      }

      done();
    });


    it("Invalid IV Size", done => {
      let opts = {
        iv_size: 99999,
        secret: "squirrel"
      }, tmp;

      try {
        tmp = require("../index.js")(opts);
        expect(tmp).to.throw("Invalid IV size!");
      } catch(err) {
        expect(err).to.be.null;
      }

      try {
        ct = JSON.parse(tmp.set(plaintext));
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
        ct = JSON.parse(kruptein.set(plaintext));
      } catch(err) {
        expect(err).to.be.null;
      }

      expect(ct).to.have.property("ct");
      expect(ct).to.have.property("iv");
      expect(ct).to.have.property("hmac");

      if (kruptein.flag)
        expect(ct).to.have.property("at");

      done();
    });


    it("HMAC Validation", done => {
      try {
        ct = JSON.parse(kruptein.set(plaintext));
      } catch(err) {
        expect(err).to.be.null;
      }

      expect(ct).to.have.property("ct");
      expect(ct).to.have.property("iv");
      expect(ct).to.have.property("hmac");

      if (kruptein.flag)
        expect(ct).to.have.property("at");

      ct.hmac = "funky chicken";
      ct = JSON.stringify(ct);

      try {
        pt = kruptein.get(ct);

        if (kruptein.flag) {
          expect(pt).to.match(/invalid key length|Unsupported state or unable to authenticate data/);
        }
      } catch(err) {
        expect(err).to.equal("Encrypted session was tampered with!");
      }

      done();
    });


    it("Authentication Tag Validation", done => {
      try {
        ct = JSON.parse(kruptein.set(plaintext));
      } catch(err) {
        expect(err).to.be.null;
      }

      expect(ct).to.have.property("ct");
      expect(ct).to.have.property("iv");
      expect(ct).to.have.property("hmac");

      if (!kruptein.flag)
        done();

      expect(ct).to.have.property("at");

      ct.at = crypto.randomBytes(16);
      ct = JSON.stringify(ct);

      try {
        pt = kruptein.get(ct);
      } catch(err) {
        expect(err).to.match(/invalid key length|Unsupported state or unable to authenticate data/);
      }

      done();
    });


    it("Authentication Tag Validation (option)", done => {
      try {
        ct = JSON.parse(kruptein.set(plaintext));
      } catch(err) {
        expect(err).to.be.null;
      }

      expect(ct).to.have.property("ct");
      expect(ct).to.have.property("iv");
      expect(ct).to.have.property("hmac");

      if (!kruptein.flag)
        done();

      expect(ct).to.have.property("at");

      let opts = {at: ct.at};
      ct = JSON.stringify(ct);

      try {
        pt = kruptein.get(ct, opts);
      } catch(err) {
        expect(err).to.match(/invalid key length|Unsupported state or unable to authenticate data/);
      }

      done();
    });


    it("Additional Authentication Data Validation", done => {
      try {
        ct = JSON.parse(kruptein.set(plaintext));
      } catch(err) {
        expect(err).to.be.null;
      }

      expect(ct).to.have.property("ct");
      expect(ct).to.have.property("iv");
      expect(ct).to.have.property("hmac");

      if (!kruptein.flag)
        done();

      expect(ct).to.have.property("at");

      ct.aad = crypto.randomBytes(16);
      ct = JSON.stringify(ct);

      try {
        pt = kruptein.get(ct);
      } catch(err) {
        expect(err).to.match(/invalid key length|Unsupported state or unable to authenticate data/);
      }

      done();
    });


    it("Additional Authentication Data Validation (option)", done => {
      try {
        ct = JSON.parse(kruptein.set(plaintext));
      } catch(err) {
        expect(err).to.be.null;
      }

      if (!ct.aad)
        return done();

      expect(ct).to.have.property("ct");
      expect(ct).to.have.property("iv");
      expect(ct).to.have.property("hmac");

      if (!kruptein.flag)
        done();

      expect(ct).to.have.property("at");

      let opts = {aad: ct.aad};
      ct = JSON.stringify(ct);

      try {
        pt = kruptein.get(ct, opts);
      } catch(err) {
        expect(err).to.match(/invalid key length|Unsupported state or unable to authenticate data/);
      }

      done();
    });


    it("Decrypt Validation", done => {
      try {
        ct = JSON.parse(kruptein.set(plaintext));
      } catch(err) {
        expect(err).to.be.null;
      }

      expect(ct).to.have.property("ct");
      expect(ct).to.have.property("iv");
      expect(ct).to.have.property("hmac");

      if (kruptein.flag)
        expect(ct).to.have.property("at");

      try {
        pt = kruptein.get(JSON.stringify(ct)).replace(/"/g, "");
      } catch(err) {
        expect(err).to.be.null;
      }

      expect(pt).to.equal(plaintext);

      done();
    });
  });
});
