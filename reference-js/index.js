const { gunzip } = require("zlib");
const forge = require("node-forge");
const { promisify } = require("util");

function findRecipient(certificate, recipients) {
  for (const recipient of recipients) {
    const recipientCert = Buffer.from(recipient.certificate, "base64");
    if (certificate.equals(recipientCert)) {
      return recipient;
    }
  }
}

/**
 *
 * @param {string} mnemonic
 * @returns {string}
 */
function normalizeMnemonic(mnemonic) {
  return mnemonic.toLowerCase().replace(/\s/g, "");
}

/**
 *
 * @param {object} privateKeyData
 * @param {string} privateKeyData.encryptedKey
 * @param {string} privateKeyData.salt
 * @param {string} privateKeyData.nonce
 * @param {string} privateKeyData.authenticationTag
 * @param {string} mnemonic
 * @returns {Promise<Buffer>}a promise resolving to the decrypted private key
 */
async function decryptPrivateKey(privateKeyData, mnemonic) {
  const encryptedKey = forge.util.decode64(privateKeyData.encryptedKey);
  const salt = forge.util.decode64(privateKeyData.salt);
  const nonce = forge.util.decode64(privateKeyData.nonce);
  const authenticationTag = forge.util.decode64(
    privateKeyData.authenticationTag
  );
  const iterations = 1024;

  const kek = await promisify(forge.pkcs5.pbkdf2)(
    normalizeMnemonic(mnemonic),
    salt,
    iterations,
    32
  );

  const aesgcm = forge.cipher.createDecipher("AES-GCM", kek);
  aesgcm.start({
    iv: nonce,
    tag: authenticationTag
  });

  aesgcm.update(forge.util.createBuffer(encryptedKey));
  if (!aesgcm.finish()) {
    throw new TypeError("wrong tag");
  }

  return Buffer.from(aesgcm.output.data, "binary");
}

async function encryptPrivateKey(privateKey, mnemonic) {
  // NYI
}

async function unwrapMetadataKey(privateKey, ciphertext) {
  const pkcs8key = forge.asn1.fromDer(forge.util.createBuffer(privateKey));
  const forgeKey = forge.pki.privateKeyFromAsn1(pkcs8key);

  const plainBinary = forgeKey.decrypt(ciphertext, "RSA-OAEP", {
    md: forge.md.sha256.create(),
    mgf1: {
      md: forge.md.sha256.create()
    }
  });

  return Buffer.from(plainBinary, "binary");
}

async function wrapMetadataKey(publicKey, metadataKey) {
  // NYI
}

async function decryptMetadata(metadataKey, encryptedMetadata) {
  const aesgcm = forge.cipher.createDecipher(
    "AES-GCM",
    forge.util.createBuffer(metadataKey)
  );
  aesgcm.start({
    iv: forge.util.decode64(encryptedMetadata.nonce),
    tag: forge.util.decode64(encryptedMetadata.authenticationTag)
  });

  aesgcm.update(
    forge.util.createBuffer(forge.util.decode64(encryptedMetadata.ciphertext))
  );
  if (!aesgcm.finish()) {
    throw new TypeError("wrong tag");
  }

  const gzipped = aesgcm.output;

  const inflated = await promisify(gunzip)(Buffer.from(gzipped.data, "binary"));

  return JSON.parse(inflated.toString());
}

async function encryptMetadata(metadataKey, metadata) {
  // NYI
}

async function decryptFile(info, encryptedFile, target) {
  // NYI
}

async function encryptFile(plainFile, target, mimetype) {
  // NYI
}

module.exports = {
  findRecipient,
  decryptPrivateKey,
  encryptPrivateKey,
  unwrapMetadataKey,
  wrapMetadataKey,
  decryptMetadata,
  encryptMetadata,
  decryptFile,
  encryptFile
};
