/*!
 * kruptein
 * Copyright(c) 2019 Jason Gerfen <jason.gerfen@gmail.com>
 * License: MIT
 */
"use strict";

const crypto = require("crypto");

class Kruptein {
  constructor(options = {}) {
    this.crypto = crypto;
    this.algorithm = options.algorithm || "aes-256-gcm";
    this.hashing = options.hashing || "sha384";
    this.encodeAs = options.encodeas || "base64";
    this.useAsn1 = options.use_asn1 ?? true;
    this.useScrypt = options.use_scrypt || false;
    this.useArgon2 = options.use_argon2 || false;
    this.isAeadMode = /ccm|gcm|ocb/i.test(this.algorithm);

    const defaultSizes = this.getAlgorithmDefaults(this.algorithm);
    this.authTagSize = options.at_size ?? options._at_size ?? defaultSizes.authTagSize;
    this.ivSize = options.iv_size ?? options._iv_size ?? defaultSizes.ivSize;
    this.keySize = options.key_size ?? options._key_size ?? defaultSizes.keySize;

    if (this.useArgon2) {
      this.argonParameters = {
        parallelism: 4,
        tagLength: this.keySize,
        memory: 65536,
        passes: 3,
      };
    }

    if (this.useAsn1) {
      this.asn1 = require("@jas-/asn.1");
      this.schema = this.createSchema();
    }
  }

  set(secret, plaintext, additionalAuthenticatedData, callback) {
    let aad = additionalAuthenticatedData;
    let done = callback;

    if (typeof aad === "function") {
      done = aad;
      aad = undefined;
    }

    if (typeof done !== "function") {
      throw new TypeError("A callback function is required");
    }

    if (this.isUnsupportedAlgorithm()) {
      done("Insecure cipher mode not supported!");
      return;
    }

    if (!this.meetsSecretComplexity(secret)) {
      done("The supplied secret failed to meet complexity requirements!");
      return;
    }

    let plaintextBuffer;
    try {
      plaintextBuffer = this.serializePlaintext(plaintext);
    } catch (error) {
      done("Unable to serialize plaintext!");
      return;
    }

    let normalizedAad;
    try {
      normalizedAad = this.getAadValue(aad, plaintextBuffer);
    } catch (error) {
      done(error.message);
      return;
    }

    this.deriveKey(secret, null, (deriveError, keyMaterial) => {
      if (deriveError) {
        done(deriveError);
        return;
      }

      let encrypted;
      try {
        encrypted = this.encryptPayload(keyMaterial.key, plaintextBuffer, keyMaterial.salt, normalizedAad);
      } catch (error) {
        done(error.message);
        return;
      }

      done(null, this.serializeCiphertextPayload(encrypted));
    });
  }

  get(secret, ciphertext, options, callback) {
    let decryptOptions = options;
    let done = callback;

    if (typeof decryptOptions === "function") {
      done = decryptOptions;
      decryptOptions = undefined;
    }

    if (typeof done !== "function") {
      throw new TypeError("A callback function is required");
    }

    if (this.isUnsupportedAlgorithm()) {
      done("Insecure cipher mode not supported!");
      return;
    }

    if (!secret) {
      done("Must supply a secret!");
      return;
    }

    let payload;
    try {
      payload = this.deserializeCiphertextPayload(ciphertext);
      payload = this.applyDecryptOptions(payload, decryptOptions);
    } catch (error) {
      done(error.message);
      return;
    }

    this.deriveKey(secret, payload.salt, (deriveError, keyMaterial) => {
      if (deriveError) {
        done(deriveError);
        return;
      }

      try {
        const expectedHmac = this.createDigest(
          keyMaterial.key,
          this.buildHmacMaterial(payload.ciphertext, payload.salt, payload.iv)
        );
        this.assertValidHmac(expectedHmac, payload.hmac);

        const serializedPlaintext = this.decryptPayload(keyMaterial.key, payload);
        done(null, this.deserializePlaintext(serializedPlaintext));
      } catch (error) {
        done(error.message);
      }
    });
  }

  encryptPayload(key, plaintextBuffer, salt, additionalAuthenticatedData) {
    const iv = this.createIv(this.ivSize);
    let cipher;

    try {
      cipher = this.crypto.createCipheriv(this.algorithm, key, iv, {
        authTagLength: this.authTagSize,
      });
    } catch (error) {
      throw new Error("Unable to create ciphertext!");
    }

    if (this.isAeadMode && additionalAuthenticatedData) {
      try {
        cipher.setAAD(Buffer.from(additionalAuthenticatedData, this.encodeAs), {
          plaintextLength: plaintextBuffer.length,
        });
      } catch (error) {
        throw new Error("Unable to set AAD!");
      }
    }

    let ciphertext = cipher.update(plaintextBuffer, undefined, this.encodeAs);
    cipher.setAutoPadding(true);
    ciphertext += cipher.final(this.encodeAs);

    let authTag;
    if (this.isAeadMode) {
      try {
        authTag = cipher.getAuthTag();
      } catch (error) {
        throw new Error("Unable to obtain authentication tag");
      }
    }

    const hmac = this.createDigest(
      key,
      this.buildHmacMaterial(ciphertext, salt, iv)
    );

    return {
      ciphertext,
      hmac,
      iv,
      salt,
      authTag,
      aad: additionalAuthenticatedData,
    };
  }

  decryptPayload(key, payload) {
    const decipher = this.crypto.createDecipheriv(this.algorithm, key, payload.iv, {
      authTagLength: this.authTagSize,
    });

    if (this.isAeadMode && payload.authTag) {
      try {
        decipher.setAuthTag(payload.authTag);
      } catch (error) {
        throw new Error("Unable to set authentication tag");
      }
    }

    if (this.isAeadMode && payload.aad) {
      try {
        decipher.setAAD(Buffer.from(payload.aad, this.encodeAs), {
          plaintextLength: Buffer.from(payload.ciphertext, this.encodeAs).length,
        });
      } catch (error) {
        throw new Error("Unable to set additional authentication data");
      }
    }

    try {
      let plaintext = decipher.update(payload.ciphertext, this.encodeAs, "utf8");
      plaintext += decipher.final("utf8");
      return plaintext;
    } catch (error) {
      throw new Error("Unable to decrypt ciphertext!");
    }
  }

  deriveKey(secretInput, salt, callback) {
    const { secret, options } = this.normalizeSecretInput(secretInput);
    const saltBuffer = salt || this.crypto.randomBytes(128);

    if (this.useScrypt && typeof this.crypto.scrypt === "function") {
      this.crypto.scrypt(secret, saltBuffer, this.keySize, options, (error, key) => {
        if (error) {
          callback("Unable to derive key!");
          return;
        }

        callback(null, { key, salt: saltBuffer });
      });
      return;
    }

    if (this.useArgon2 && typeof this.crypto.argon2 === "function") {
      try {
        const parameters = {
          ...this.argonParameters,
          message: Buffer.from(secret),
          nonce: saltBuffer,
        };

        this.crypto.argon2("argon2id", parameters, (error, key) => {
          if (error) {
            callback("Unable to derive key!");
            return;
          }

          callback(null, { key, salt: saltBuffer });
        });
        return;
      } catch (error) {
        callback("Unable to derive key!");
        return;
      }
    }

    if (this.useArgon2 && typeof this.crypto.argon2Sync === "function") {
      try {
        const parameters = {
          ...this.argonParameters,
          message: Buffer.from(secret),
          nonce: saltBuffer,
        };
        const key = this.crypto.argon2Sync("argon2id", parameters);
        callback(null, { key, salt: saltBuffer });
      } catch (error) {
        callback("Unable to derive key!");
      }
      return;
    }

    this.crypto.pbkdf2(secret, saltBuffer, 20000, this.keySize, this.hashing, (error, key) => {
      if (error) {
        callback("Unable to derive key!");
        return;
      }

      callback(null, { key, salt: saltBuffer });
    });
  }

  normalizeSecretInput(secretInput) {
    if (typeof secretInput === "object" && secretInput !== null && !Buffer.isBuffer(secretInput)) {
      return {
        secret: secretInput.secret,
        options: secretInput.opts || {},
      };
    }

    return {
      secret: secretInput,
      options: {},
    };
  }

  createDigest(key, value) {
    const hmac = this.crypto.createHmac(this.hashing, key);
    hmac.update(value);
    return hmac.digest(this.encodeAs);
  }

  createIv(size) {
    return this.crypto.randomBytes(size);
  }

  buildHmacMaterial(ciphertext, salt, iv) {
    return Buffer.concat([
      Buffer.from(ciphertext, this.encodeAs),
      salt,
      iv,
    ]);
  }

  serializePlaintext(plaintext) {
    if (Buffer.isBuffer(plaintext)) {
      return Buffer.from(JSON.stringify({ type: "buffer", value: plaintext.toString(this.encodeAs) }));
    }

    if (typeof plaintext === "string") {
      return Buffer.from(JSON.stringify({ type: "string", value: plaintext }));
    }

    return Buffer.from(JSON.stringify({ type: "json", value: plaintext }));
  }

  deserializePlaintext(serializedPlaintext) {
    try {
      const parsedValue = JSON.parse(serializedPlaintext);

      if (typeof parsedValue === "string") {
        return parsedValue;
      }

      if (parsedValue && typeof parsedValue === "object" && typeof parsedValue.type === "string") {
        if (parsedValue.type === "string") {
          return parsedValue.value;
        }

        if (parsedValue.type === "buffer") {
          return Buffer.from(parsedValue.value, this.encodeAs);
        }

        if (parsedValue.type === "json") {
          return parsedValue.value;
        }
      }

      return parsedValue;
    } catch (error) {
      return serializedPlaintext;
    }
  }

  getAadValue(additionalAuthenticatedData, plaintextBuffer) {
    if (!this.isAeadMode) {
      return undefined;
    }

    if (typeof additionalAuthenticatedData === "undefined") {
      return this.createDigest(this.crypto.randomBytes(128), plaintextBuffer);
    }

    if (Buffer.isBuffer(additionalAuthenticatedData)) {
      return additionalAuthenticatedData.toString(this.encodeAs);
    }

    if (typeof additionalAuthenticatedData === "string") {
      return additionalAuthenticatedData;
    }

    throw new Error("Unable to generate AAD!");
  }

  serializeCiphertextPayload(payload) {
    if (this.useAsn1) {
      return this.schema.encode({
        ct: Buffer.from(payload.ciphertext, this.encodeAs),
        hmac: Buffer.from(payload.hmac, this.encodeAs),
        iv: payload.iv,
        salt: payload.salt,
        at: payload.authTag || Buffer.alloc(0),
        aad: payload.aad ? Buffer.from(payload.aad, this.encodeAs) : Buffer.alloc(0),
      }).toString(this.encodeAs);
    }

    const serializedPayload = {
      ct: payload.ciphertext,
      hmac: payload.hmac,
      iv: payload.iv.toString(this.encodeAs),
      salt: payload.salt.toString(this.encodeAs),
    };

    if (payload.authTag) {
      serializedPayload.at = payload.authTag.toString(this.encodeAs);
    }

    if (payload.aad) {
      serializedPayload.aad = payload.aad;
    }

    return JSON.stringify(serializedPayload);
  }

  deserializeCiphertextPayload(ciphertext) {
    try {
      if (this.useAsn1) {
        const decodedPayload = this.schema.decode(Buffer.from(ciphertext, this.encodeAs));
        return {
          ciphertext: decodedPayload.ct.toString(this.encodeAs),
          hmac: decodedPayload.hmac.toString(this.encodeAs),
          iv: Buffer.from(decodedPayload.iv),
          salt: Buffer.from(decodedPayload.salt),
          authTag: decodedPayload.at && decodedPayload.at.length ? Buffer.from(decodedPayload.at) : undefined,
          aad: decodedPayload.aad && decodedPayload.aad.length ? decodedPayload.aad.toString(this.encodeAs) : undefined,
        };
      }

      const decodedPayload = JSON.parse(ciphertext);
      return {
        ciphertext: this.requireStringField(decodedPayload.ct, "Unable to parse ciphertext object!"),
        hmac: this.requireStringField(decodedPayload.hmac, "Unable to parse ciphertext object!"),
        iv: this.decodeBinaryField(decodedPayload.iv),
        salt: this.decodeBinaryField(decodedPayload.salt),
        authTag: decodedPayload.at ? this.decodeBinaryField(decodedPayload.at) : undefined,
        aad: decodedPayload.aad ? this.requireStringField(decodedPayload.aad, "Unable to parse ciphertext object!") : undefined,
      };
    } catch (error) {
      if (error.message === "Unable to parse ciphertext object!") {
        throw error;
      }

      throw new Error("Unable to parse ciphertext object!");
    }
  }

  decodeBinaryField(value) {
    if (typeof value === "string") {
      return Buffer.from(value, this.encodeAs);
    }

    if (value && value.type === "Buffer" && Array.isArray(value.data)) {
      return Buffer.from(value.data);
    }

    throw new Error("Unable to parse ciphertext object!");
  }

  requireStringField(value, errorMessage) {
    if (typeof value !== "string") {
      throw new Error(errorMessage);
    }

    return value;
  }

  applyDecryptOptions(payload, options = {}) {
    const updatedPayload = { ...payload };

    if (Object.prototype.hasOwnProperty.call(options, "aad")) {
      if (Buffer.isBuffer(options.aad)) {
        updatedPayload.aad = options.aad.toString(this.encodeAs);
      } else if (typeof options.aad === "string" || typeof options.aad === "undefined") {
        updatedPayload.aad = options.aad;
      } else {
        throw new Error("Unable to parse ciphertext object!");
      }
    }

    if (Object.prototype.hasOwnProperty.call(options, "at")) {
      updatedPayload.authTag = options.at ? this.decodeBinaryField(options.at) : undefined;
    }

    return updatedPayload;
  }

  assertValidHmac(expectedHmac, actualHmac) {
    const expectedBytes = Buffer.from(expectedHmac, this.encodeAs);
    const actualBytes = Buffer.from(actualHmac, this.encodeAs);

    if (expectedBytes.length != actualBytes.length) {
      throw new Error("Encrypted session was tampered with!");
    }

    if (typeof this.crypto.timingSafeEqual === "function") {
      if (!this.crypto.timingSafeEqual(expectedBytes, actualBytes)) {
        throw new Error("Encrypted session was tampered with!");
      }
      return;
    }

    if (expectedHmac !== actualHmac) {
      throw new Error("Encrypted session was tampered with!");
    }
  }

  getAlgorithmDefaults(algorithm) {
    const defaults = {
      authTagSize: 16,
      ivSize: 16,
      keySize: 32,
    };

    if (/ccm|ocb|gcm/i.test(algorithm)) {
      defaults.ivSize = 12;
    }

    if (/aes/i.test(algorithm) && /128/.test(algorithm)) {
      defaults.keySize = 16;
    }

    if (/aes/i.test(algorithm) && /192/.test(algorithm)) {
      defaults.keySize = 24;
    }

    if (/aes/i.test(algorithm) && /xts/i.test(algorithm)) {
      defaults.keySize = 32;
    }

    if (/aes/i.test(algorithm) && /xts/i.test(algorithm) && /256/.test(algorithm)) {
      defaults.keySize = 64;
    }

    return defaults;
  }

  isUnsupportedAlgorithm() {
    return /ccm|ecb|ocb2|xts|aes-128|aes128/i.test(this.algorithm);
  }

  createSchema() {
    return this.asn1.define("schema", function() {
      this.seq().obj(
        this.key("ct").octstr(),
        this.key("hmac").octstr(),
        this.key("iv").octstr(),
        this.key("salt").octstr(),
        this.key("at").octstr(),
        this.key("aad").octstr()
      );
    });
  }

  meetsSecretComplexity(secret) {
    const rules = {
      minimumLength: 8,
      minimumUppercase: 2,
      minimumLowercase: 2,
      minimumNumbers: 2,
      minimumSpecial: 2,
    };

    if (typeof secret !== "string" || secret.length < rules.minimumLength) {
      return false;
    }

    const uppercaseCount = (secret.match(/[A-Z]/g) || []).length;
    if (uppercaseCount < rules.minimumUppercase) {
      return false;
    }

    const lowercaseCount = (secret.match(/[a-z]/g) || []).length;
    if (lowercaseCount < rules.minimumLowercase) {
      return false;
    }

    const numberCount = (secret.match(/[0-9]/g) || []).length;
    if (numberCount < rules.minimumNumbers) {
      return false;
    }

    const specialCount = (secret.match(/[!@#$%^&*()_+\-=\[\]{};':"\|,.<>/?]/g) || []).length;
    if (specialCount < rules.minimumSpecial) {
      return false;
    }

    return true;
  }
}

module.exports = function createKruptein(options) {
  return new Kruptein(options || {});
};
