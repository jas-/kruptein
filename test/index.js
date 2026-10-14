"use strict";

const assert = require("node:assert");
const crypto = require("node:crypto");
const test = require("node:test");

const createKruptein = require("../index.js");
const {
  isFullMatrixRequested,
  selectCryptoMatrix,
  unsupportedMessage,
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

test("passes every discovered cipher and hash through for the full matrix", () => {
  const matrix = selectCryptoMatrix({
    full: true,
    availableCiphers: ["aes-256-gcm", "aes-256-ecb", "md5"],
    availableHashes: ["sha384", "RSA-SHA256", "md5"],
  });

  assert.deepStrictEqual(matrix, {
    algorithms: ["aes-256-gcm", "aes-256-ecb", "md5"],
    hashes: ["sha384", "RSA-SHA256", "md5"],
    encodings: ["ascii", "base64", "base64url", "binary", "hex", "latin1", "ucs2", "utf8", "utf16le"],
  });
});

test("selects everything node reports with full: true", () => {
  const matrix = selectCryptoMatrix({ full: true });

  assert.deepStrictEqual(matrix.algorithms, crypto.getCiphers());
  assert.deepStrictEqual(matrix.hashes, crypto.getHashes());
  for (const encodeas of matrix.encodings) {
    assert.ok(Buffer.isEncoding(encodeas), `${encodeas} is a buffer encoding`);
  }
});

test("rejects an empty discovered full matrix", () => {
  assert.throws(
    () => selectCryptoMatrix({
      full: true,
      availableCiphers: [],
      availableHashes: [],
    }),
    { message: "No compatible ciphers or hashes were discovered for the full matrix" }
  );
});

async function unsupportedReason(options) {
  try {
    await encrypt(createKruptein(createOptions(options)), defaultSecret, samplePhrases[0]);
    return null;
  } catch (error) {
    return error.message;
  }
}

test("round-trips unicode strings for supported key derivation modes", async (suite) => {
  for (const algorithm of supportedAlgorithms) {
    const algorithmReason = await unsupportedReason({ algorithm });
    if (algorithmReason) {
      await suite.test(`algorithm=${algorithm} rejected`, () => assert.match(algorithmReason, unsupportedMessage));
      continue;
    }

    for (const hashing of supportedHashes) {
      const hashingReason = await unsupportedReason({ algorithm, hashing });
      if (hashingReason) {
        await suite.test(`algorithm=${algorithm} hashing=${hashing} rejected`, () => assert.match(hashingReason, unsupportedMessage));
        continue;
      }

      for (const encodeAs of supportedEncodings) {
        const encodingReason = await unsupportedReason({ algorithm, hashing, encodeas: encodeAs });
        if (encodingReason) {
          await suite.test(`algorithm=${algorithm} hashing=${hashing} encoding=${encodeAs} rejected`, () => assert.match(encodingReason, unsupportedMessage));
          continue;
        }

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

test("accepts the object secret form with scrypt options in set()", async () => {
  const secret = { secret: defaultSecret, opts: { N: 1024, r: 8, p: 1 } };
  const ciphertext = await encrypt(createInstance({ use_scrypt: true }), secret, "object secret");

  assert.strictEqual(await decrypt(createInstance({ use_scrypt: true }), secret, ciphertext), "object secret");
  await assert.rejects(
    decrypt(createInstance({ use_scrypt: true }), { secret: defaultSecret, opts: { N: 2048, r: 8, p: 1 } }, ciphertext),
    { message: "Encrypted session was tampered with!" }
  );
  await assert.rejects(
    encrypt(createInstance({ use_scrypt: true }), { secret: "weak", opts: {} }, "test phrase"),
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
  assert.strictEqual(typeof payload.nonce, "string");
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

test("string AAD is bound byte for byte", async () => {
  for (const encodeas of ["base64", "hex"]) {
    const instance = createInstance({ use_asn1: false, encodeas });
    const ciphertext = await encrypt(instance, defaultSecret, "aad check", "admin");

    assert.strictEqual(await decrypt(instance, defaultSecret, ciphertext, { aad: "admin" }), "aad check");
    for (const aad of ["admin!", "admin?", "ad min", "bob"]) {
      await assert.rejects(decrypt(instance, defaultSecret, ciphertext, { aad }));
    }
  }
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

test("round-trips and authenticates every AEAD cipher", async (suite) => {
  const ciphers = crypto.getCiphers();

  for (const algorithm of ["chacha20-poly1305", "aes-256-ccm", "aes-256-ocb", "aes-192-gcm", "aria-256-gcm"]) {
    await suite.test(algorithm, async (t) => {
      if (!ciphers.includes(algorithm)) {
        t.skip(`${algorithm} is not available on ${process.version}`);
        return;
      }

      const instance = createInstance({ use_asn1: false, algorithm });
      const ciphertext = await encrypt(instance, defaultSecret, "aead check", "aad");
      const payload = JSON.parse(ciphertext);

      assert.strictEqual(instance.isAeadMode, true);
      assert.strictEqual(Buffer.from(payload.at, "base64").length, 16);
      assert.strictEqual(await decrypt(instance, defaultSecret, ciphertext, { aad: "aad" }), "aead check");

      await assert.rejects(decrypt(instance, defaultSecret, ciphertext, { aad: "other" }));
      await assert.rejects(decrypt(instance, defaultSecret, ciphertext, { at: mutateBase64String(payload.at) }));
    });
  }
});

test("rejects insecure cipher modes", async () => {
  const instance = createInstance({ algorithm: "aes-256-ecb" });

  await assert.rejects(
    encrypt(instance, defaultSecret, "test phrase"),
    { message: "Insecure cipher mode not supported!" }
  );
});

test("rejects insecure hash algorithms", async () => {
  for (const hashing of ["md5", "sha1", "RSA-SHA256", "shake256"]) {
    await assert.rejects(
      encrypt(createInstance({ hashing }), defaultSecret, "test phrase"),
      { message: "Insecure hash algorithm not supported!" }
    );
  }
});

test("rejects unsupported encodings", async () => {
  for (const encodeas of ["utf8", "ascii", "ucs2"]) {
    await assert.rejects(
      encrypt(createInstance({ encodeas }), defaultSecret, "test phrase"),
      { message: "Unsupported encoding!" }
    );
  }
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
    assert.strictEqual(asyncScryptCalls, 1);
  } finally {
    crypto.scrypt = originalScrypt;
    crypto.scryptSync = originalScryptSync;
  }
});

function countPbkdf2Calls(run) {
  const originalPbkdf2 = crypto.pbkdf2;
  let calls = 0;

  crypto.pbkdf2 = (...args) => {
    calls += 1;
    return originalPbkdf2(...args);
  };

  return run().then(
    (result) => {
      crypto.pbkdf2 = originalPbkdf2;
      return { result, calls };
    },
    (error) => {
      crypto.pbkdf2 = originalPbkdf2;
      throw error;
    }
  );
}

test("derives the key once per secret per instance", async () => {
  const instance = createInstance({ use_asn1: false });
  const { calls, result } = await countPbkdf2Calls(async () => {
    const payloads = [];
    for (let index = 0; index < 5; index += 1) {
      payloads.push(JSON.parse(await encrypt(instance, defaultSecret, `message ${index}`)));
    }

    for (const [index, payload] of payloads.entries()) {
      assert.strictEqual(await decrypt(instance, defaultSecret, JSON.stringify(payload)), `message ${index}`);
    }

    return payloads;
  });

  assert.strictEqual(calls, 1);
  assert.strictEqual(new Set(result.map((payload) => payload.salt)).size, 1, "salt is reused");
  assert.strictEqual(new Set(result.map((payload) => payload.nonce)).size, 5, "every nonce is unique");
  assert.strictEqual(new Set(result.map((payload) => payload.iv)).size, 5, "every IV is unique");
  assert.strictEqual(new Set(result.map((payload) => payload.ct)).size, 5, "every ciphertext differs");
});

test("concurrent first calls share a single derivation", async () => {
  const instance = createInstance();
  const { calls } = await countPbkdf2Calls(() => Promise.all(
    Array.from({ length: 25 }, (_, index) => encrypt(instance, defaultSecret, `burst ${index}`))
  ));

  assert.strictEqual(calls, 1);
});

test("the slot is per instance", async () => {
  const { calls } = await countPbkdf2Calls(async () => {
    await encrypt(createInstance(), defaultSecret, "instance one");
    await encrypt(createInstance(), defaultSecret, "instance two");
  });

  assert.strictEqual(calls, 2);
});

test("switching back to a cached secret does not re-derive", async () => {
  const instance = createInstance();
  const { calls } = await countPbkdf2Calls(async () => {
    await encrypt(instance, defaultSecret, "first");
    await encrypt(instance, alternateSecret, "second");
    await encrypt(instance, defaultSecret, "third");
  });

  assert.strictEqual(calls, 2);
});

test("switching secrets re-derives when the cache is full", async () => {
  const instance = createInstance();
  instance.keyCacheSize = 1;
  const { calls } = await countPbkdf2Calls(async () => {
    await encrypt(instance, defaultSecret, "first");
    await encrypt(instance, alternateSecret, "second");
    await encrypt(instance, defaultSecret, "third");
  });

  assert.strictEqual(calls, 3);
});

test("reads of several foreign salts stay cached", async () => {
  // Restart or cluster: the store holds ciphertext from other processes.
  const first = await encrypt(createInstance(), defaultSecret, "from process one");
  const second = await encrypt(createInstance(), defaultSecret, "from process two");
  const instance = createInstance();

  const { calls } = await countPbkdf2Calls(async () => {
    for (let round = 0; round < 3; round++) {
      assert.strictEqual(await decrypt(instance, defaultSecret, first), "from process one");
      assert.strictEqual(await decrypt(instance, defaultSecret, second), "from process two");
      const own = await encrypt(instance, defaultSecret, `own ${round}`);
      assert.strictEqual(await decrypt(instance, defaultSecret, own), `own ${round}`);
    }
  });

  assert.strictEqual(calls, 3);
});

test("a write after a foreign read keeps the write salt", async () => {
  const foreign = await encrypt(createInstance({ use_asn1: false }), defaultSecret, "foreign");
  const instance = createInstance({ use_asn1: false });

  const before = JSON.parse(await encrypt(instance, defaultSecret, "before"));
  await decrypt(instance, defaultSecret, foreign);
  const after = JSON.parse(await encrypt(instance, defaultSecret, "after"));

  assert.strictEqual(after.salt, before.salt);
});

test("the cache stays within its size", async () => {
  const instance = createInstance();
  instance.keyCacheSize = 4;
  const ciphertexts = [];
  for (let i = 0; i < 6; i++) {
    ciphertexts.push(await encrypt(createInstance(), defaultSecret, `salt ${i}`));
  }

  for (const ciphertext of ciphertexts) {
    await decrypt(instance, defaultSecret, ciphertext);
  }

  assert.strictEqual(instance.derivedKeys.size, 4);
});

test("the cache holds 128 entries", () => {
  assert.strictEqual(createInstance().keyCacheSize, 128);
});

test("decrypting a foreign salt derives once while the salt is unchanged", async () => {
  const encryptor = createInstance({ use_asn1: false });
  const first = await encrypt(encryptor, defaultSecret, "foreign one");
  const second = await encrypt(encryptor, defaultSecret, "foreign two");

  const decryptor = createInstance({ use_asn1: false });
  const { calls } = await countPbkdf2Calls(async () => {
    assert.strictEqual(await decrypt(decryptor, defaultSecret, first), "foreign one");
    assert.strictEqual(await decrypt(decryptor, defaultSecret, second), "foreign two");
  });

  assert.strictEqual(calls, 1);
});

test("a failed derivation is not kept in the slot", async () => {
  const originalPbkdf2 = crypto.pbkdf2;
  let failNext = true;

  crypto.pbkdf2 = (...args) => {
    if (failNext) {
      failNext = false;
      process.nextTick(() => args[args.length - 1](new Error("boom")));
      return undefined;
    }
    return originalPbkdf2(...args);
  };

  try {
    const instance = createInstance();
    await assert.rejects(encrypt(instance, defaultSecret, "fails"), { message: "Unable to derive key!" });
    const ciphertext = await encrypt(instance, defaultSecret, "recovers");
    assert.strictEqual(await decrypt(instance, defaultSecret, ciphertext), "recovers");
  } finally {
    crypto.pbkdf2 = originalPbkdf2;
  }
});

test("an exception thrown in the callback is not an unhandled rejection", () => {
  const script = `
    process.on("unhandledRejection", () => process.exit(2));
    process.on("uncaughtException", () => process.exit(3));
    require(${JSON.stringify(require.resolve("../index.js"))})().set(
      ${JSON.stringify(defaultSecret)},
      "throws",
      () => { throw new Error("callback failure"); }
    );
  `;
  const result = require("node:child_process").spawnSync(process.execPath, ["-e", script]);

  assert.strictEqual(result.status, 3);
});

test("the cache never holds the secret", async () => {
  const instance = createInstance();
  await encrypt(instance, defaultSecret, "fingerprint");

  assert.strictEqual(instance.derivedKeys.size, 1);
  for (const [fingerprint, slot] of instance.derivedKeys) {
    assert.match(fingerprint, /^[0-9a-f]{64}$/);
    assert.deepStrictEqual(Object.keys(slot), ["pending"]);
  }
});

test("output carries the salt and a per-message nonce", async () => {
  const instance = createInstance({ use_asn1: false });
  const payload = JSON.parse(await encrypt(instance, defaultSecret, "format check"));

  assert.deepStrictEqual(Object.keys(payload).sort(), ["aad", "at", "ct", "hmac", "iv", "nonce", "salt"]);
  assert.strictEqual(Buffer.from(payload.salt, "base64").length, 128);
  assert.strictEqual(Buffer.from(payload.nonce, "base64").length, 32);
});

test("message keys differ per nonce and per purpose", async () => {
  const instance = createInstance();
  const masterKey = crypto.randomBytes(instance.keySize);
  const first = instance.deriveMessageKeys(masterKey, crypto.randomBytes(instance.nonceSize));
  const second = instance.deriveMessageKeys(masterKey, crypto.randomBytes(instance.nonceSize));

  assert.strictEqual(first.key.length, instance.keySize);
  assert.ok(!first.key.equals(first.hmacKey), "cipher and hmac keys differ");
  assert.ok(!first.key.equals(second.key), "cipher keys differ across nonces");
  assert.ok(first.key.equals(instance.deriveMessageKeys(masterKey, first.nonce).key), "deterministic per nonce");
});

test("rejects ciphertext when the nonce is tampered", async () => {
  const instance = createInstance({ use_asn1: false });
  const ciphertext = await encrypt(instance, defaultSecret, "nonce check");
  const payload = JSON.parse(ciphertext);

  payload.nonce = mutateBase64String(payload.nonce);

  await assert.rejects(
    decrypt(instance, defaultSecret, JSON.stringify(payload)),
    { message: "Encrypted session was tampered with!" }
  );
});

test("scrypt and argon2 also derive once per secret", async (suite) => {
  for (const mode of ["scrypt", "argon2"]) {
    await suite.test(mode, async (t) => {
      if (typeof crypto[mode] !== "function") {
        t.skip(`crypto.${mode} is not available on ${process.version}`);
        return;
      }

      const instance = createInstance({ use_scrypt: mode === "scrypt", use_argon2: mode === "argon2" });
      const original = crypto[mode];
      let calls = 0;

      crypto[mode] = (...args) => {
        calls += 1;
        return original(...args);
      };

      try {
        const first = await encrypt(instance, defaultSecret, "kdf one");
        const second = await encrypt(instance, defaultSecret, "kdf two");
        assert.strictEqual(await decrypt(instance, defaultSecret, first), "kdf one");
        assert.strictEqual(await decrypt(instance, defaultSecret, second), "kdf two");
      } finally {
        crypto[mode] = original;
      }

      assert.strictEqual(calls, 1);
    });
  }
});

test("derived key material is non-empty, keySize bytes and salt-bound", async (suite) => {
  const derive = (instance, secret, salt) => new Promise((resolve, reject) => {
    instance.deriveKey(secret, salt, (error, keyMaterial) => (error ? reject(new Error(error)) : resolve(keyMaterial)));
  });

  for (const mode of keyDerivationModes) {
    await suite.test(mode, async () => {
      const options = { use_scrypt: mode === "scrypt", use_argon2: mode === "argon2" };
      const instance = createInstance(options);
      const first = await derive(instance, defaultSecret, instance.salt);

      assert.ok(Buffer.isBuffer(first.key));
      assert.strictEqual(first.key.length, instance.keySize);
      assert.ok(!first.key.every((byte) => byte === 0), "key is not all zero");
      assert.ok(new Set(first.key).size > 8, "key is not degenerate");
      assert.strictEqual(first.salt.length, 128);
      assert.ok(!first.salt.every((byte) => byte === 0), "salt is not all zero");

      const sameInputs = await derive(createInstance(options), defaultSecret, first.salt);
      assert.ok(first.key.equals(sameInputs.key), "deterministic for (secret, salt)");

      const otherSalt = await derive(createInstance(options), defaultSecret, crypto.randomBytes(128));
      assert.ok(!first.key.equals(otherSalt.key), "differs across salts");

      const otherSecret = await derive(createInstance(options), alternateSecret, first.salt);
      assert.ok(!first.key.equals(otherSecret.key), "differs across secrets");
    });
  }
});

test("a KDF that returns a wrong-length key is rejected and not cached", async () => {
  const originalPbkdf2 = crypto.pbkdf2;
  let bogus = true;

  crypto.pbkdf2 = (...args) => {
    if (bogus) {
      bogus = false;
      process.nextTick(() => args[args.length - 1](null, Buffer.alloc(0)));
      return undefined;
    }
    return originalPbkdf2(...args);
  };

  try {
    const instance = createInstance();
    await assert.rejects(encrypt(instance, defaultSecret, "empty key"), { message: "Unable to derive key!" });
    assert.strictEqual(instance.derivedKeys.size, 0, "cache is cleared");

    const ciphertext = await encrypt(instance, defaultSecret, "recovers");
    assert.strictEqual(await decrypt(instance, defaultSecret, ciphertext), "recovers");
  } finally {
    crypto.pbkdf2 = originalPbkdf2;
  }
});

test("IVs and nonces stay unique under a reused salt", async () => {
  const instance = createInstance({ use_asn1: false });
  const sampleSize = 20000;
  const nonces = new Set();
  const ivs = new Set();
  const ciphertexts = new Set();
  const authTags = new Set();
  let salt;

  for (let index = 0; index < sampleSize; index += 1) {
    const payload = JSON.parse(await encrypt(instance, defaultSecret, "identical plaintext"));
    salt = salt || payload.salt;

    assert.strictEqual(payload.salt, salt, "the derived key (salt) is reused");
    assert.strictEqual(Buffer.from(payload.iv, "base64").length, 12);
    nonces.add(payload.nonce);
    ivs.add(payload.iv);
    ciphertexts.add(payload.ct);
    authTags.add(payload.at);
  }

  assert.strictEqual(nonces.size, sampleSize, "no nonce collision");
  assert.strictEqual(ivs.size, sampleSize, "no IV collision");
  assert.strictEqual(ciphertexts.size, sampleSize, "identical plaintext never yields identical ciphertext");
  assert.strictEqual(authTags.size, sampleSize, "auth tags are unique");
});
