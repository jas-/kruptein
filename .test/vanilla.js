"use strict";

const assert = require("node:assert");
const crypto = require("node:crypto");
const createKruptein = require("../index.js");

const quickMatrix = {
  algorithms: ["aes-256-gcm"],
  hashes: ["sha384"],
  encodings: ["base64"],
};

const fullEncodings = ["binary", "hex", "base64"];

function isFullMatrixRequested({ argv = process.argv, env = process.env } = {}) {
  return argv.includes("--full") || env.KRUPTEIN_FULL_MATRIX === "1";
}

function selectCryptoMatrix({
  full = isFullMatrixRequested(),
  availableCiphers,
  availableHashes,
} = {}) {
  if (!full) {
    return {
      algorithms: [...quickMatrix.algorithms],
      hashes: [...quickMatrix.hashes],
      encodings: [...quickMatrix.encodings],
    };
  }

  const algorithms = (availableCiphers || crypto.getCiphers()).filter((cipher) => (
    /^aes/i.test(cipher)
      && !/hmac|wrap|ccm|ecb|ocb2|xts|^aes-?128(?:-|$)/i.test(cipher)
  ));
  const hashes = (availableHashes || crypto.getHashes()).filter((hash) => (
    /^sha[2-5]/i.test(hash) && !/rsa/i.test(hash)
  ));

  if (algorithms.length === 0 || hashes.length === 0) {
    throw new Error("No compatible ciphers or hashes were discovered for the full matrix");
  }

  return {
    algorithms,
    hashes,
    encodings: [...fullEncodings],
  };
}

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
    use_scrypt: false,
    use_argon2: false,
    ...overrides,
  };
}

function encrypt(instance, secret, plaintext, additionalAuthenticatedData) {
  return new Promise((resolve, reject) => {
    const callback = (error, ciphertext) => {
      if (error) {
        reject(new Error(error));
        return;
      }

      resolve(ciphertext);
    };

    if (typeof additionalAuthenticatedData === "undefined") {
      instance.set(secret, plaintext, callback);
      return;
    }

    instance.set(secret, plaintext, additionalAuthenticatedData, callback);
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

async function runRoundTripMatrix() {
  for (const algorithm of supportedAlgorithms) {
    for (const hashing of supportedHashes) {
      for (const encodeAs of supportedEncodings) {
        for (const keyDerivationMode of keyDerivationModes) {
          const instance = createKruptein(createOptions({
            algorithm,
            hashing,
            encodeas: encodeAs,
            use_scrypt: keyDerivationMode === "scrypt",
            use_argon2: keyDerivationMode === "argon2",
          }));

          console.log(`kruptein: { key_derivation: "${keyDerivationMode}", algorithm: "${algorithm}", hashing: "${hashing}", encodeas: "${encodeAs}" }`);

          for (const phrase of samplePhrases) {
            const ciphertext = await encrypt(instance, defaultSecret, phrase);
            const plaintext = await decrypt(instance, defaultSecret, ciphertext);

            assert.strictEqual(plaintext, phrase);
            console.log(`  plaintext: ${phrase}`);
            console.log(`  ciphertext: ${ciphertext}`);
            console.log(`  round-trip: ${plaintext}`);
          }
        }
      }
    }
  }
}

async function runJsonModeCheck() {
  const instance = createKruptein(createOptions({ use_asn1: false }));
  const ciphertext = await encrypt(instance, defaultSecret, "json payload");
  const payload = JSON.parse(ciphertext);

  assert.strictEqual(typeof payload.ct, "string");
  assert.strictEqual(typeof payload.hmac, "string");
  assert.strictEqual(await decrypt(instance, defaultSecret, ciphertext), "json payload");
  console.log(`json mode ciphertext: ${ciphertext}`);
  console.log("ok json payload mode");
}

async function runMultipleSecretsCheck() {
  const instance = createKruptein(createOptions());
  const firstCiphertext = await encrypt(instance, defaultSecret, "first message");
  const secondCiphertext = await encrypt(instance, alternateSecret, "second message");

  assert.strictEqual(await decrypt(instance, defaultSecret, firstCiphertext), "first message");
  assert.strictEqual(await decrypt(instance, alternateSecret, secondCiphertext), "second message");
  console.log(`first ciphertext: ${firstCiphertext}`);
  console.log(`second ciphertext: ${secondCiphertext}`);
  console.log("ok multiple secrets on one instance");
}

async function runTamperCheck() {
  const instance = createKruptein(createOptions({ use_asn1: false }));
  const ciphertext = await encrypt(instance, defaultSecret, "integrity check");
  const payload = JSON.parse(ciphertext);

  console.log(`tamper-check ciphertext: ${ciphertext}`);
  payload.hmac = mutateBase64String(payload.hmac);

  await assert.rejects(
    decrypt(instance, defaultSecret, JSON.stringify(payload)),
    { message: "Encrypted session was tampered with!" }
  );

  console.log("ok tamper rejection");
}

async function main() {
  await runRoundTripMatrix();
  await runJsonModeCheck();
  await runMultipleSecretsCheck();
  await runTamperCheck();
  console.log("vanilla harness completed");
}

if (require.main === module) {
  main().catch((error) => {
    console.error(error.stack || error.message);
    process.exitCode = 1;
  });
}

module.exports = {
  isFullMatrixRequested,
  selectCryptoMatrix,
};
