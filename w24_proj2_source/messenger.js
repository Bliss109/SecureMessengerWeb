'use strict'

import {
  bufferToString,
  genRandomSalt,
  generateEG,
  computeDH,
  verifyWithECDSA,
  HMACtoAESKey,
  HMACtoHMACKey,
  HKDF,
  encryptWithGCM,
  decryptWithGCM,
  cryptoKeyToJSON,
  govEncryptionDataStr
} from './lib.js'

const INFO_ROOT = 'DR-root'
const INFO_CHAIN = 'DR-chain'
const INFO_MSG = 'DR-msg'
const INFO_NEXT = 'DR-next'

function arrayBufferToBase64(uint8Array) {
  let binary = ''
  const bytes = new Uint8Array(uint8Array)
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i])
  }
  return btoa(binary)
}

function base64ToUint8Array(b64) {
  const binary = atob(b64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

class MessengerClient {
  constructor(certAuthorityPublicKey, govPublicKey) {
    if (!certAuthorityPublicKey || !govPublicKey) {
      throw new Error('Missing CA or government public key.')
    }
    this.caPublicKey = certAuthorityPublicKey
    this.govPublicKey = govPublicKey
    this.certs = {}
    this.conns = {}
    this.EGKeyPair = null
    this.username = null
  }

  async generateCertificate(username) {
    this.EGKeyPair = await generateEG()
    this.username = username
    return {
      username,
      elgamalPubKey: this.EGKeyPair.pub,
      createdAt: Date.now()
    }
  }

  async receiveCertificate(certificate, signature) {
    const certString = JSON.stringify(certificate)
    const ok = await verifyWithECDSA(this.caPublicKey, certString, signature)
    if (!ok) throw new Error('Certificate signature invalid or tampered.')
    const { username, elgamalPubKey } = certificate
    if (!username || !elgamalPubKey) throw new Error('Malformed certificate.')
    this.certs[username] = certificate
    if (!this.conns[username]) this.conns[username] = this._newConnState()
  }

  async sendMessage(name, plaintext) {
    const peerCert = this.certs[name]
    if (!peerCert) throw new Error('Unknown recipient: missing certificate.')
    const state = this.conns[name]
    if (!state.initialized) {
      await this._initializeSession(state, peerCert.elgamalPubKey)
    }

    // Derive message key and advance send chain
    const { msgKey, msgKeyRaw, nextCK } = await this._deriveMessageKey(state.sendCK)
    state.sendCK = nextCK
    state.sendCount += 1

    // Wrap for government
    const { vGov, cGov, ivGov } = await this._wrapMsgKeyForGovernment(msgKeyRaw)
    // Unique IV for receiver (use base64 string to tag replays consistently)
    const receiverIV = genRandomSalt()
    const receiverIVb64 = arrayBufferToBase64(receiverIV)

    const header = {
      senderDHPub: await cryptoKeyToJSON(state.dhSelf.pub),
      vGov: await cryptoKeyToJSON(vGov),
      cGov: arrayBufferToBase64(cGov),
      ivGov: arrayBufferToBase64(ivGov),
      receiverIV: receiverIVb64,
      sendCount: state.sendCount,
      recvCount: state.recvCount
    }

    const aad = JSON.stringify(header)
    const ciphertext = await encryptWithGCM(msgKey, plaintext, receiverIV, aad)
    return [header, ciphertext]
  }

  async receiveMessage(name, [header, ciphertext]) {
    const peerCert = this.certs[name]
    if (!peerCert) throw new Error('Unknown sender: missing certificate.')
    const state = this.conns[name]
    if (!state.initialized) {
      await this._initializeSession(state, peerCert.elgamalPubKey)
    }

    // DH ratchet step if peer's DH changed
    const same = await this._dhPubJSONEquals(state.dhPeerJSON, header.senderDHPub)
    if (!same) {
      await this._dhRatchetOnReceive(state, header.senderDHPub, peerCert.elgamalPubKey)
      // Reset counters and skipped keys on DH ratchet to avoid stale decrypts
      state.skippedKeys = {}
      state.recvCount = 0
      state.sendCount = 0
    }

    // Replay protection by IV tag (base64 string)
    state.seenIVs = state.seenIVs || new Set()
    const ivTag = header.receiverIV
    if (state.seenIVs.has(ivTag)) throw new Error('Replay detected.')
    state.seenIVs.add(ivTag)

    // Prepare to decrypt target index
    const targetIndex = header.sendCount
    const aad = JSON.stringify(header)

    // If we previously skipped this exact index, use that key first
    state.skippedKeys = state.skippedKeys || {}
    if (state.skippedKeys[targetIndex]) {
      const{ key, iv } = state.skippedKeys[targetIndex]
      delete state.skippedKeys[targetIndex]
      const plaintextArr = await decryptWithGCM(key, ciphertext, base64ToUint8Array(header.receiverIV), aad)
      return bufferToString(plaintextArr)
    }

    // Advance receive chain until reaching target index, caching skipped keys
    while (state.recvCount < targetIndex) {
      const { msgKey: skippedKey, nextCK } = await this._deriveMessageKey(state.recvCK)
      state.recvCK = nextCK
      state.recvCount += 1
      // Cache the exact message key for this index
      state.skippedKeys[state.recvCount] = { key: skippedKey }
    }

    // Derive the key for targetIndex (or next in sequence)
    const { msgKey, nextCK } = await this._deriveMessageKey(state.recvCK)
    state.recvCK = nextCK
    state.recvCount += 1

    const plaintextArr = await decryptWithGCM(
      msgKey,
      ciphertext,
      base64ToUint8Array(header.receiverIV),
      aad
    )
    return bufferToString(plaintextArr)
  }

  _newConnState() {
    return {
      initialized: false,
      rootKey: null,
      sendCK: null,
      recvCK: null,
      sendCount: 0,
      recvCount: 0,
      dhSelf: null,
      dhPeerJSON: null,
      skippedKeys: {},
      seenIVs: new Set()
    }
  }

  async _initializeSession(state, peerLongTermPub) {
    state.dhSelf = await generateEG()
    const dhIdentity = await computeDH(this.EGKeyPair.sec, peerLongTermPub)
    const dhSession = await computeDH(state.dhSelf.sec, peerLongTermPub)
    const [rootKey, chainSeed] = await HKDF(dhIdentity, dhSession, INFO_ROOT)
    const [sendCK, recvCK] = await HKDF(chainSeed, dhSession, INFO_CHAIN)
    state.rootKey = rootKey
    state.sendCK = sendCK
    state.recvCK = recvCK
    state.dhPeerJSON = await cryptoKeyToJSON(peerLongTermPub)
    state.initialized = true
  }

  async _dhRatchetOnReceive(state, newPeerDHPubJSON, peerLongTermPub) {
    state.dhPeerJSON = newPeerDHPubJSON
    state.dhSelf = await generateEG()
    const dhMix = await computeDH(state.dhSelf.sec, peerLongTermPub)
    const [newRoot, newChainSeed] = await HKDF(state.rootKey, dhMix, INFO_ROOT)
    const [sendCK, recvCK] = await HKDF(newChainSeed, dhMix, INFO_CHAIN)
    state.rootKey = newRoot
    state.sendCK = sendCK
    state.recvCK = recvCK
  }

  async _deriveMessageKey(chainKey) {
    const msgKey = await HMACtoAESKey(chainKey, INFO_MSG)
    const msgKeyRaw = await HMACtoAESKey(chainKey, INFO_MSG, true)
    const nextCK = await HMACtoHMACKey(chainKey, INFO_NEXT)
    return { msgKey, msgKeyRaw, nextCK }
  }

  async _wrapMsgKeyForGovernment(msgKeyRaw) {
    if (!this.govPublicKey) throw new Error('Government public key not initialized.')
    const eph = await generateEG()
    const govDH = await computeDH(eph.sec, this.govPublicKey)
    const govAESKey = await HMACtoAESKey(govDH, govEncryptionDataStr)
    const ivGov = genRandomSalt()
    const cGov = await encryptWithGCM(govAESKey, msgKeyRaw, ivGov, '')
    return { vGov: eph.pub, cGov, ivGov }
  }

  async _dhPubJSONEquals(aJSON, bJSON) {
    if (!aJSON || !bJSON) return false
    return JSON.stringify(aJSON) === JSON.stringify(bJSON)
  }

  // -------- Persistence helpers (simple, JSON-safe) --------

  // Export minimal ratchet state needed to resume (does not export private keys)
  async exportState(name) {
    const s = this.conns[name]
    if (!s || !s.initialized) return null
    return {
      initialized: s.initialized,
      sendCount: s.sendCount,
      recvCount: s.recvCount,
      dhPeerJSON: s.dhPeerJSON,
      // IV replay cache as array
      seenIVs: Array.from(s.seenIVs || []),
      // Note: symmetric keys (rootKey, sendCK, recvCK) are CryptoKeys and
      // may not be JSON-exportable depending on implementation. If your lib
      // supports exporting them via cryptoKeyToJSON, uncomment below:
      // rootKey: await cryptoKeyToJSON(s.rootKey),
      // sendCK: await cryptoKeyToJSON(s.sendCK),
      // recvCK: await cryptoKeyToJSON(s.recvCK),
      // We do not persist skippedKeys; they rebuild as messages arrive.
    }
  }

  // Import minimal state; requires fresh re-derivation of keys via _initializeSession
  async importState(name, saved) {
    if (!saved) return
    const s = this.conns[name] || this._newConnState()
    s.initialized = saved.initialized
    s.sendCount = saved.sendCount || 0
    s.recvCount = saved.recvCount || 0
    s.dhPeerJSON = saved.dhPeerJSON || null
    s.seenIVs = new Set(saved.seenIVs || [])
    // Keys will be (re)derived on first use by _initializeSession if not set
    this.conns[name] = s
  }
}

export { MessengerClient }
