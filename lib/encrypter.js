import crypto from 'crypto'
import { execFileSync } from 'child_process'
import fs from 'fs'
import os from 'os'
import path from 'path'

// Data encryption algorithms, keyed by the short name used in the UI.
//
// GCM is the recommended mode: CBC provides no integrity guarantee and is
// vulnerable to the chosen-ciphertext attacks described in XML Encryption 1.1
// 6.1.1, which is why libraries such as xml-encryption treat the CBC entries as
// insecure. They are kept here because reproducing a legacy peer is the point of
// a mock IdP.
//
// keyLength is in bytes; ivLength differs by mode -- CBC uses a 16-byte IV,
// while GCM uses a 12-byte nonce per XML Encryption 1.1 5.2.4.
const DATA_ENCRYPTION_ALGORITHMS = {
  'aes128-cbc': {
    uri: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc',
    cipher: 'aes-128-cbc',
    keyLength: 16,
    ivLength: 16,
    gcm: false,
  },
  'aes256-cbc': {
    uri: 'http://www.w3.org/2001/04/xmlenc#aes256-cbc',
    cipher: 'aes-256-cbc',
    keyLength: 32,
    ivLength: 16,
    gcm: false,
  },
  'aes128-gcm': {
    uri: 'http://www.w3.org/2009/xmlenc11#aes128-gcm',
    cipher: 'aes-128-gcm',
    keyLength: 16,
    ivLength: 12,
    gcm: true,
  },
  'aes256-gcm': {
    uri: 'http://www.w3.org/2009/xmlenc11#aes256-gcm',
    cipher: 'aes-256-gcm',
    keyLength: 32,
    ivLength: 12,
    gcm: true,
  },
}

const DEFAULT_DATA_ENCRYPTION_ALGORITHM = 'aes256-cbc'

const KEY_ENCRYPTION_ALGORITHMS = {
  'rsa-1_5': 'http://www.w3.org/2001/04/xmlenc#rsa-1_5',
  'rsa-oaep-mgf1p': 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
  // XML Encryption 1.1 identifier. Unlike rsa-oaep-mgf1p, this one carries an
  // explicit <MGF> element, so MGF1 is not pinned to SHA-1.
  'rsa-oaep': 'http://www.w3.org/2009/xmlenc11#rsa-oaep',
}

// SHA-2 was published after 2000/09/xmldsig was locked, so sha256/sha512 live
// under 2001/04/xmlenc and sha224/sha384 under 2001/04/xmldsig-more (RFC 4051).
const DIGEST_ALGORITHMS = {
  sha1: 'http://www.w3.org/2000/09/xmldsig#sha1',
  sha224: 'http://www.w3.org/2001/04/xmldsig-more#sha224',
  sha256: 'http://www.w3.org/2001/04/xmlenc#sha256',
  sha384: 'http://www.w3.org/2001/04/xmldsig-more#sha384',
  sha512: 'http://www.w3.org/2001/04/xmlenc#sha512',
}

// XML Encryption 1.1 5.5.2.
const MGF_ALGORITHMS = {
  sha1: 'http://www.w3.org/2009/xmlenc11#mgf1sha1',
  sha224: 'http://www.w3.org/2009/xmlenc11#mgf1sha224',
  sha256: 'http://www.w3.org/2009/xmlenc11#mgf1sha256',
  sha384: 'http://www.w3.org/2009/xmlenc11#mgf1sha384',
  sha512: 'http://www.w3.org/2009/xmlenc11#mgf1sha512',
}

const getPublicKey = (pem) => {
  console.log('PEM', pem)
  if (pem.includes('BEGIN CERTIFICATE')) {
    return new crypto.X509Certificate(pem).publicKey
  }
  return crypto.createPublicKey(pem)
}

// Wrap the key with OAEP using an MGF1 digest that differs from the message
// digest. Node's crypto only exposes `oaepHash`, and OpenSSL then defaults MGF1
// to match it, so the two can never differ through the Node API. Shelling out to
// `openssl pkeyutl` is the only way to set them independently without pulling in
// a JS reimplementation of the padding.
//
// The plaintext (the AES key) goes over stdin and the ciphertext comes back on
// stdout, so no secret is written to disk or exposed in argv. Only the public
// key needs a file, which is not sensitive.
const encryptWithOpenssl = (
  key,
  publicKey,
  oaepDigest,
  mgf1Digest,
  oaepLabel
) => {
  console.log('encryptWithOpenssl', key, publicKey, oaepDigest, mgf1Digest)
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' })
  const tmpKeyPath = path.join(
    os.tmpdir(),
    `saml-mock-oaep-${crypto.randomBytes(8).toString('hex')}.pem`
  )

  try {
    fs.writeFileSync(tmpKeyPath, publicKeyPem, { mode: 0o600 })

    return execFileSync(
      'openssl',
      [
        'pkeyutl',
        '-encrypt',
        '-pubin',
        '-inkey',
        tmpKeyPath,
        '-pkeyopt',
        'rsa_padding_mode:oaep',
        '-pkeyopt',
        `rsa_oaep_md:${oaepDigest}`,
        '-pkeyopt',
        `rsa_mgf1_md:${mgf1Digest}`,
        // OAEP label (the "P" parameter). openssl takes it as a hex string.
        ...(oaepLabel && oaepLabel.length
          ? ['-pkeyopt', `rsa_oaep_label:${oaepLabel.toString('hex')}`]
          : []),
      ],
      { input: key, maxBuffer: 1024 * 1024 }
    )
  } catch (err) {
    const detail = err.stderr ? err.stderr.toString().trim() : err.message
    throw new Error(
      `openssl failed to wrap the symmetric key with OAEP ` +
        `(digest=${oaepDigest}, mgf1=${mgf1Digest}): ${detail}`
    )
  } finally {
    // Best effort: a leftover public key in tmp is harmless, and throwing here
    // would mask the real error.
    try {
      fs.unlinkSync(tmpKeyPath)
    } catch {
      /* ignore */
    }
  }
}

// The MGF1 digest actually used for a given set of options. rsa-oaep-mgf1p pins
// MGF1 to SHA-1 regardless of the message digest (XML Encryption 1.1 5.5.2);
// only the xmlenc11 identifier can carry a different one. `forceMgf1Mismatch`
// deliberately breaks that pinning so the mock can reproduce the non-compliant
// ciphertext that Node's crypto produces by default.
const resolveMgf1Digest = (opts) => {
  const oaepDigest = opts.oaepDigestAlgo || 'sha1'

  if (opts.keyEncryptionAlgo === 'rsa-oaep') {
    return opts.mgf1DigestAlgo || 'sha1'
  }
  if (opts.forceMgf1Mismatch) {
    return oaepDigest
  }
  return 'sha1'
}

// The OAEP label carried by <xenc:OAEPparams>, which is base64 in the XML. An
// empty/absent value means no label, which is the common case.
const resolveOaepLabel = (opts) => {
  if (!opts.oaepParams) {
    return Buffer.alloc(0)
  }
  return Buffer.from(opts.oaepParams, 'base64')
}

const encryptSymmetricKey = (key, opts) => {
  const publicKey = getPublicKey(opts.encryptionCert)

  if (opts.keyEncryptionAlgo === 'rsa-1_5') {
    return crypto.publicEncrypt(
      { key: publicKey, padding: crypto.constants.RSA_PKCS1_PADDING },
      key
    )
  }

  const oaepDigest = opts.oaepDigestAlgo || 'sha1'
  const mgf1Digest = resolveMgf1Digest(opts)
  const oaepLabel = resolveOaepLabel(opts)

  // When the two digests match, Node's own OAEP is equivalent, so avoid the
  // subprocess. Anything else has to go through openssl.
  if (oaepDigest === mgf1Digest) {
    return crypto.publicEncrypt(
      {
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: oaepDigest,
        ...(oaepLabel.length ? { oaepLabel } : {}),
      },
      key
    )
  }

  return encryptWithOpenssl(key, publicKey, oaepDigest, mgf1Digest, oaepLabel)
}

const buildKeyEncryptionMethod = (opts) => {
  if (opts.keyEncryptionAlgo === 'rsa-1_5') {
    return `<xenc:EncryptionMethod Algorithm="${KEY_ENCRYPTION_ALGORITHMS['rsa-1_5']}"/>`
  }

  const oaepDigest = opts.oaepDigestAlgo || 'sha1'
  const digestUri = DIGEST_ALGORITHMS[oaepDigest]
  if (!digestUri) {
    throw new Error(`unsupported OAEP digest algorithm: ${oaepDigest}`)
  }

  const algorithmUri = KEY_ENCRYPTION_ALGORITHMS[opts.keyEncryptionAlgo]
  if (!algorithmUri) {
    throw new Error(
      `unsupported key encryption algorithm: ${opts.keyEncryptionAlgo}`
    )
  }

  // The <MGF> element belongs only to xmlenc11#rsa-oaep. For rsa-oaep-mgf1p the
  // MGF is implied by the identifier and the element MUST NOT be present, so a
  // deliberately mismatched mgf1p document carries no MGF element either --
  // which is exactly what makes the legacy ciphertext undecryptable elsewhere.
  let mgfElement = ''
  if (opts.keyEncryptionAlgo === 'rsa-oaep') {
    const mgf1Digest = resolveMgf1Digest(opts)
    const mgfUri = MGF_ALGORITHMS[mgf1Digest]
    if (!mgfUri) {
      throw new Error(`unsupported MGF1 digest algorithm: ${mgf1Digest}`)
    }
    mgfElement = `<xenc11:MGF xmlns:xenc11="http://www.w3.org/2009/xmlenc11#" Algorithm="${mgfUri}"/>`
  }

  // The OAEP label, carried as base64 in <xenc:OAEPparams>. Per the xmlenc
  // EncryptionMethodType schema it precedes the <any> children (MGF,
  // DigestMethod). Omitted when no label is set (the common case).
  const oaepParamsElement = opts.oaepParams
    ? `<xenc:OAEPparams>${opts.oaepParams}</xenc:OAEPparams>`
    : ''

  return (
    `<xenc:EncryptionMethod Algorithm="${algorithmUri}">` +
    oaepParamsElement +
    mgfElement +
    `<ds:DigestMethod xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Algorithm="${digestUri}"/>` +
    `</xenc:EncryptionMethod>`
  )
}

export const encryptAssertion = (assertionXml, opts) => {
  if (!opts || !opts.encryptAssertion) {
    return assertionXml
  }

  const dataAlgoName =
    opts.dataEncryptionAlgo || DEFAULT_DATA_ENCRYPTION_ALGORITHM
  const dataAlgo = DATA_ENCRYPTION_ALGORITHMS[dataAlgoName]
  if (!dataAlgo) {
    throw new Error(`unsupported data encryption algorithm: ${dataAlgoName}`)
  }

  // Encrypt the assertion with a fresh key sized for the chosen algorithm.
  // Per xmlenc, the IV/nonce is prepended to the ciphertext, and for GCM the
  // 16-byte authentication tag is appended.
  const key = crypto.randomBytes(dataAlgo.keyLength)
  const iv = crypto.randomBytes(dataAlgo.ivLength)
  const cipher = crypto.createCipheriv(dataAlgo.cipher, key, iv)
  const ciphertext = Buffer.concat([
    cipher.update(assertionXml, 'utf8'),
    cipher.final(),
  ])
  const encryptedData = Buffer.concat([
    iv,
    ciphertext,
    dataAlgo.gcm ? cipher.getAuthTag() : Buffer.alloc(0),
  ]).toString('base64')

  // Build the EncryptionMethod first so an unsupported algorithm fails before
  // we spend the RSA operation.
  const keyEncryptionMethod = buildKeyEncryptionMethod(opts)

  // Wrap the AES key with the recipient's public key
  const encryptedKey = encryptSymmetricKey(key, opts).toString('base64')

  return (
    `<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">` +
    `<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Element">` +
    `<xenc:EncryptionMethod Algorithm="${dataAlgo.uri}"/>` +
    `<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">` +
    `<xenc:EncryptedKey>` +
    keyEncryptionMethod +
    `<xenc:CipherData><xenc:CipherValue>${encryptedKey}</xenc:CipherValue></xenc:CipherData>` +
    `</xenc:EncryptedKey>` +
    `</ds:KeyInfo>` +
    `<xenc:CipherData><xenc:CipherValue>${encryptedData}</xenc:CipherValue></xenc:CipherData>` +
    `</xenc:EncryptedData>` +
    `</saml:EncryptedAssertion>`
  )
}
