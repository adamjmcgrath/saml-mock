import crypto from 'crypto'

const DATA_ENCRYPTION_ALGORITHM = 'http://www.w3.org/2001/04/xmlenc#aes256-cbc'

const KEY_ENCRYPTION_ALGORITHMS = {
  'rsa-1_5': 'http://www.w3.org/2001/04/xmlenc#rsa-1_5',
  'rsa-oaep-mgf1p': 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
}

const DIGEST_ALGORITHMS = {
  sha1: 'http://www.w3.org/2000/09/xmldsig#sha1',
  sha256: 'http://www.w3.org/2001/04/xmlenc#sha256',
  sha512: 'http://www.w3.org/2001/04/xmlenc#sha512',
}

const getPublicKey = (pem) => {
  if (pem.includes('BEGIN CERTIFICATE')) {
    return new crypto.X509Certificate(pem).publicKey
  }
  return crypto.createPublicKey(pem)
}

const encryptSymmetricKey = (key, opts) => {
  const publicKey = getPublicKey(opts.encryptionCert)

  if (opts.keyEncryptionAlgo === 'rsa-1_5') {
    return crypto.publicEncrypt(
      { key: publicKey, padding: crypto.constants.RSA_PKCS1_PADDING },
      key
    )
  }

  return crypto.publicEncrypt(
    {
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: opts.oaepDigestAlgo,
    },
    key
  )
}

const buildKeyEncryptionMethod = (opts) => {
  if (opts.keyEncryptionAlgo === 'rsa-oaep-mgf1p') {
    return (
      `<xenc:EncryptionMethod Algorithm="${KEY_ENCRYPTION_ALGORITHMS['rsa-oaep-mgf1p']}">` +
      `<ds:DigestMethod xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Algorithm="${
        DIGEST_ALGORITHMS[opts.oaepDigestAlgo]
      }"/>` +
      `</xenc:EncryptionMethod>`
    )
  }
  return `<xenc:EncryptionMethod Algorithm="${KEY_ENCRYPTION_ALGORITHMS['rsa-1_5']}"/>`
}

export const encryptAssertion = (assertionXml, opts) => {
  if (!opts || !opts.encryptAssertion) {
    return assertionXml
  }

  // Encrypt the assertion with a fresh AES-256-CBC key.
  // Per xmlenc, the IV is prepended to the ciphertext.
  const key = crypto.randomBytes(32)
  const iv = crypto.randomBytes(16)
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv)
  const encryptedData = Buffer.concat([
    iv,
    cipher.update(assertionXml, 'utf8'),
    cipher.final(),
  ]).toString('base64')

  // Wrap the AES key with the recipient's public key
  const encryptedKey = encryptSymmetricKey(key, opts).toString('base64')

  return (
    `<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">` +
    `<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Element">` +
    `<xenc:EncryptionMethod Algorithm="${DATA_ENCRYPTION_ALGORITHM}"/>` +
    `<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">` +
    `<xenc:EncryptedKey>` +
    buildKeyEncryptionMethod(opts) +
    `<xenc:CipherData><xenc:CipherValue>${encryptedKey}</xenc:CipherValue></xenc:CipherData>` +
    `</xenc:EncryptedKey>` +
    `</ds:KeyInfo>` +
    `<xenc:CipherData><xenc:CipherValue>${encryptedData}</xenc:CipherValue></xenc:CipherData>` +
    `</xenc:EncryptedData>` +
    `</saml:EncryptedAssertion>`
  )
}
