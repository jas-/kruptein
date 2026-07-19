"use strict";

const assert = require("node:assert");
const kruptein = require("../index.js")();

const secret = "S3cre+_Squ1rr3l";
const message = "Some kind of wonderfully private message";

kruptein.set(secret, message, (error, ciphertext) => {
  if (error) {
    throw new Error(error);
  }

  console.log("Encrypted:", ciphertext);

  kruptein.get(secret, ciphertext, (error, plaintext) => {
    if (error) {
      throw new Error(error);
    }

    assert.strictEqual(plaintext, message);
    console.log("Decrypted:", plaintext);
  });
});
