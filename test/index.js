"use strict";

const assert = require("node:assert");
const crypto = require("node:crypto");
const test = require("node:test");

const createKruptein = require("../index.js");
const {
  isFullMatrixRequested,
  selectCryptoMatrix,
} = require("../.test/vanilla.js");

const {
  algorithms: supportedAlgorithms,
  hashes: supportedHashes,
  encodings: supportedEncodings,
} = selectCryptoMatrix();

const defaultSecret = "S3cre+_Squ1rr3l";
const alternateSecret = "An0th#r_Squ1rr3l";
const keyDerivationModes = ["default", "scrypt", "argon2"];
const samplePhrases = [
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
  "таемная вавёрка"
];

function createOptions(overrides = {}) {
  return {
    algorithm: "aes-256-gcm",
    hashing: "sha384",
    encodeas: "base64",
    use_asn1: true,
    ...overrides,
  };
}

function createInstance(overrides = {}) {
  return createKruptein(createOptions(overrides));
}

function encrypt(instance, secret, plaintext, aad) {
  return new Promise((resolve, reject) => {
    const callback = (error, ciphertext) => {
      if (error) {
        reject(new Error(error));
        return;
      }

      resolve(ciphertext);
    };

    if (typeof aad === "undefined") {
      instance.set(secret, plaintext, callback);
      return;
    }

    instance.set(secret, plaintext, aad, callback);
  });
}

function decrypt(instance, secret, ciphertext, options) {
  return new Promise((resolve, reject) => {
    const callback = (error, plaintext) => {
      if (error) {
        reject(new Error(error));
        return;
      }

      resolve(plaintext);
    };

    if (typeof options === "undefined") {
      instance.get(secret, ciphertext, callback);
      return;
    }

    instance.get(secret, ciphertext, options, callback);
  });
}

function mutateBase64String(value) {
  const replacement = value[0] === "A" ? "B" : "A";
  return replacement + value.slice(1);
}

test("selects the quick matrix by default", () => {
  assert.deepStrictEqual(selectCryptoMatrix({ full: false }), {
    algorithms: ["aes-256-gcm"],
    hashes: ["sha384"],
    encodings: ["base64"],
  });
});

test("enables the full matrix with the CLI flag", () => {
  assert.strictEqual(isFullMatrixRequested({
    argv: ["node", "test/index.js", "--full"],
    env: {},
  }), true);
});

test("enables the full matrix with the environment variable", () => {
  assert.strictEqual(isFullMatrixRequested({
    argv: ["node", "test/index.js"],
    env: { KRUPTEIN_FULL_MATRIX: "1" },
  }), true);
});

test("filters discovered algorithms for the full matrix", () => {
  const matrix = selectCryptoMatrix({
    full: true,
    availableCiphers: [
      "aes-256-gcm",
      "AES-192-CBC",
      "aes-256-ccm",
      "aes-256-ecb",
      "aes-256-wrap",
      "aes-256-xts",
      "aes-128-gcm",
      "chacha20-poly1305",
    ],
    availableHashes: [
      "sha224",
      "SHA3-256",
      "sha384",
      "sha512",
      "RSA-SHA256",
      "md5",
    ],
  });

  assert.deepStrictEqual(matrix, {
    algorithms: ["aes-256-gcm", "AES-192-CBC"],
    hashes: ["sha224", "SHA3-256", "sha384", "sha512"],
    encodings: ["binary", "hex", "base64"],
  });
});

test("rejects an empty discovered full matrix", () => {
  assert.throws(
    () => selectCryptoMatrix({
      full: true,
      availableCiphers: ["chacha20-poly1305"],
      availableHashes: ["md5"],
    }),
    { message: "No compatible ciphers or hashes were discovered for the full matrix" }
  );
});

test("round-trips unicode strings for supported key derivation modes", async (suite) => {
  for (const algorithm of supportedAlgorithms) {
    for (const hashing of supportedHashes) {
      for (const encodeAs of supportedEncodings) {
        for (const keyDerivationMode of keyDerivationModes) {
          await suite.test(
            `algorithm=${algorithm} hashing=${hashing} encoding=${encodeAs} kdf=${keyDerivationMode}`,
            async (subsuite) => {
              const instance = createKruptein({
                algorithm,
                hashing,
                encodeas: encodeAs,
                use_asn1: true,
                use_scrypt: keyDerivationMode === "scrypt",
                use_argon2: keyDerivationMode === "argon2",
              });

              for (const phrase of samplePhrases) {
                await subsuite.test(`phrase=${phrase}`, async () => {
                  const ciphertext = await encrypt(instance, defaultSecret, phrase);
                  const plaintext = await decrypt(instance, defaultSecret, ciphertext);

                  assert.strictEqual(plaintext, phrase);
                });
              }
            }
          );
        }
      }
    }
  }
});

test("returns exact string plaintext without JSON quoting artifacts", async () => {
  const instance = createInstance();
  const plaintext = "already-a-string";
  const ciphertext = await encrypt(instance, defaultSecret, plaintext);

  assert.strictEqual(await decrypt(instance, defaultSecret, ciphertext), plaintext);
});

test("rejects secrets that fail complexity rules without throwing runtime errors", async () => {
  const instance = createInstance();

  await assert.rejects(
    encrypt(instance, "lowercase12!!", "test phrase"),
    { message: "The supplied secret failed to meet complexity requirements!" }
  );
});

test("supports multiple secrets on the same instance", async () => {
  const instance = createInstance();
  const firstCiphertext = await encrypt(instance, defaultSecret, "first message");
  const secondCiphertext = await encrypt(instance, alternateSecret, "second message");

  const verifier = createInstance();
  assert.strictEqual(await decrypt(verifier, defaultSecret, firstCiphertext), "first message");
  assert.strictEqual(await decrypt(verifier, alternateSecret, secondCiphertext), "second message");
});

test("round-trips JSON payload output when ASN.1 encoding is disabled", async () => {
  const instance = createInstance({ use_asn1: false });
  const ciphertext = await encrypt(instance, defaultSecret, "json payload");
  const payload = JSON.parse(ciphertext);

  assert.strictEqual(typeof payload.ct, "string");
  assert.strictEqual(typeof payload.hmac, "string");
  assert.strictEqual(typeof payload.iv, "string");
  assert.strictEqual(typeof payload.salt, "string");
  assert.strictEqual(typeof payload.at, "string");
  assert.strictEqual(await decrypt(instance, defaultSecret, ciphertext), "json payload");
});

test("rejects ciphertext when the HMAC is tampered but its length is unchanged", async () => {
  const instance = createInstance({ use_asn1: false });
  const ciphertext = await encrypt(instance, defaultSecret, "integrity check");
  const payload = JSON.parse(ciphertext);

  payload.hmac = mutateBase64String(payload.hmac);

  await assert.rejects(
    decrypt(instance, defaultSecret, JSON.stringify(payload)),
    { message: "Encrypted session was tampered with!" }
  );
});

test("applies public iv_size and at_size overrides", async () => {
  const instance = createInstance({ use_asn1: false, iv_size: 16, at_size: 12 });
  const ciphertext = await encrypt(instance, defaultSecret, "override lengths");
  const payload = JSON.parse(ciphertext);

  assert.strictEqual(Buffer.from(payload.iv, "base64").length, 16);
  assert.strictEqual(Buffer.from(payload.at, "base64").length, 12);
  assert.strictEqual(await decrypt(instance, defaultSecret, ciphertext), "override lengths");
});

test("applies the public key_size override", async () => {
  const instance = createInstance({ key_size: 16 });

  await assert.rejects(
    encrypt(instance, defaultSecret, "invalid key size"),
    { message: "Unable to create ciphertext!" }
  );
});

test("rejects insecure cipher modes", async () => {
  const instance = createInstance({ algorithm: "aes-256-ecb" });

  await assert.rejects(
    encrypt(instance, defaultSecret, "test phrase"),
    { message: "Insecure cipher mode not supported!" }
  );
});

test("rejects malformed ciphertext", async () => {
  const instance = createInstance();

  await assert.rejects(
    decrypt(instance, defaultSecret, "invalid ciphertext"),
    { message: "Unable to parse ciphertext object!" }
  );
});

test("rejects decryption with the wrong secret", async () => {
  const encryptor = createInstance();
  const decryptor = createInstance();
  const ciphertext = await encrypt(encryptor, defaultSecret, "test phrase");

  await assert.rejects(
    decrypt(decryptor, alternateSecret, ciphertext),
    (error) => error.message.includes("tampered") || error.message.includes("decrypt")
  );
});

test("uses the async scrypt API when available", async () => {
  const originalScrypt = crypto.scrypt;
  const originalScryptSync = crypto.scryptSync;
  let asyncScryptCalls = 0;

  crypto.scrypt = (secret, salt, keyLength, options, callback) => {
    asyncScryptCalls += 1;
    return originalScrypt(secret, salt, keyLength, options, callback);
  };

  crypto.scryptSync = () => {
    throw new Error("scryptSync should not be used");
  };

  try {
    const instance = createInstance({ use_scrypt: true });
    const ciphertext = await encrypt(instance, defaultSecret, "async scrypt");

    assert.strictEqual(await decrypt(instance, defaultSecret, ciphertext), "async scrypt");
    assert.ok(asyncScryptCalls >= 2);
  } finally {
    crypto.scrypt = originalScrypt;
    crypto.scryptSync = originalScryptSync;
  }
});
