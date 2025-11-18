// lib.js (ES module for browser)

export const govEncryptionDataStr = 'AES-GENERATION'

// ArrayBuffer -> string
export function bufferToString(arr) {
  return new TextDecoder().decode(arr)
}

// Random IV
export function genRandomSalt(len = 16) {
  return crypto.getRandomValues(new Uint8Array(len))
}

// CryptoKey -> JWK JSON
export async function cryptoKeyToJSON(cryptoKey) {
  return await crypto.subtle.exportKey('jwk', cryptoKey)
}

// ECDH keypair
export async function generateEG() {
  const keypair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-384' },
    true,
    ['deriveKey']
  )
  return { pub: keypair.publicKey, sec: keypair.privateKey }
}

// Diffie-Hellman shared secret (returns HMAC key)
export async function computeDH(myPrivateKey, theirPublicKey) {
  return await crypto.subtle.deriveKey(
    { name: 'ECDH', public: theirPublicKey },
    myPrivateKey,
    { name: 'HMAC', hash: 'SHA-256', length: 256 },
    true,
    ['sign', 'verify']
  )
}

// ECDSA verify
export async function verifyWithECDSA(publicKey, message, signature) {
  return await crypto.subtle.verify(
    { name: 'ECDSA', hash: { name: 'SHA-384' } },
    publicKey,
    signature,
    new TextEncoder().encode(message)
  )
}

// HMAC -> AES-GCM key (optionally raw bytes)
export async function HMACtoAESKey(key, data, exportToArrayBuffer = false) {
  const hmacBuf = await crypto.subtle.sign({ name: 'HMAC' }, key, new TextEncoder().encode(data))
  const out = await crypto.subtle.importKey('raw', hmacBuf, 'AES-GCM', true, ['encrypt', 'decrypt'])
  if (exportToArrayBuffer) {
    return await crypto.subtle.exportKey('raw', out)
  }
  return out
}

// HMAC -> next HMAC key
export async function HMACtoHMACKey(key, data) {
  const hmacBuf = await crypto.subtle.sign({ name: 'HMAC' }, key, new TextEncoder().encode(data))
  return await crypto.subtle.importKey(
    'raw',
    hmacBuf,
    { name: 'HMAC', hash: 'SHA-256', length: 256 },
    true,
    ['sign']
  )
}

// HKDF deriving two outputs
export async function HKDF(inputKey, salt, infoStr) {
  const inputKeyBuf = await crypto.subtle.sign({ name: 'HMAC' }, inputKey, new TextEncoder().encode('0'))
  const inputKeyHKDF = await crypto.subtle.importKey('raw', inputKeyBuf, 'HKDF', false, ['deriveKey'])

  const salt1 = await crypto.subtle.sign({ name: 'HMAC' }, salt, new TextEncoder().encode('salt1'))
  const salt2 = await crypto.subtle.sign({ name: 'HMAC' }, salt, new TextEncoder().encode('salt2'))

  const hkdfOut1 = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: salt1, info: new TextEncoder().encode(infoStr) },
    inputKeyHKDF,
    { name: 'HMAC', hash: 'SHA-256', length: 256 },
    true,
    ['sign']
  )

  const hkdfOut2 = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: salt2, info: new TextEncoder().encode(infoStr) },
    inputKeyHKDF,
    { name: 'HMAC', hash: 'SHA-256', length: 256 },
    true,
    ['sign']
  )

  return [hkdfOut1, hkdfOut2]
}

// AES-GCM encrypt
export async function encryptWithGCM(key, plaintext, iv, authenticatedData = '') {
  const data = typeof plaintext === 'string' ? new TextEncoder().encode(plaintext) : plaintext
  return await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(authenticatedData) },
    key,
    data
  )
}

// AES-GCM decrypt
export async function decryptWithGCM(key, ciphertext, iv, authenticatedData = '') {
  return await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(authenticatedData) },
    key,
    ciphertext
  )
}

// ECDSA generate/sign (if needed for CA simulation)
export async function generateECDSA() {
  const keypair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-384' },
    true,
    ['sign', 'verify']
  )
  return { pub: keypair.publicKey, sec: keypair.privateKey }
}

export async function signWithECDSA(privateKey, message) {
  return await crypto.subtle.sign(
    { name: 'ECDSA', hash: { name: 'SHA-384' } },
    privateKey,
    new TextEncoder().encode(message)
  )
}


