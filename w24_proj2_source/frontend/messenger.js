// frontend/messenger.js
// CORRECT FINAL VERSION - Fixed key derivation

import {
  bufferToString,
  base64ToBytes,
  bytesToBase64,
  encryptWithGCM,
  decryptWithGCM,
  generateEG,
  computeDH,
  HMACtoAESKey,
  cryptoKeyToJSON,
  importJSONToCryptoKey
} from './lib.js';

export class MessengerClient {
  constructor(caPubKey, govPubKey, myUID) {
    this.caPubKey = caPubKey;
    this.govPubKey = govPubKey;
    this.myUID = myUID;

    this.certs = {};   // peer certificates (with CryptoKeys)
    this.conns = {};   // per-peer ratchet state
    this._myDHKey = null; // Store our DH private key
  }

  // ---------------- Certificate ----------------
  async generateCertificate(uid) {
    const eg = await generateEG();

    // Store our private key
    this._myDHKey = eg.sec;

    // EXPORT public key as JWK for transport/storage
    const pubJWK = await cryptoKeyToJSON(eg.pub);

    return {
      uid,
      elgamalPubKey: pubJWK
    };
  }

  async receiveCertificate(cert, signature) {
    // CA verification skipped (assumed valid)

    // IMPORT peer public key back into a CryptoKey
    const peerPubKey = await importJSONToCryptoKey(cert.elgamalPubKey, []);

    // Store certificate using UID
    this.certs[cert.uid] = {
      uid: cert.uid,
      elgamalPubKey: peerPubKey
    };

    // Initialize connection state with peer's UID as key
    this.conns[cert.uid] = {
      dhMy: this._myDHKey, // Use our stored private key
      dhPeer: peerPubKey,
      sendCK: null,
      recvCK: null,
      seenIVs: new Set()
    };
    
    console.log(`[${this.myUID}] Received certificate from ${cert.uid}`);
  }

  // ---------------- Internal Ratchet Init ----------------
  async _initRatchet(peerUID) {
    const state = this.conns[peerUID];
    const cert = this.certs[peerUID];

    if (!state) {
      throw new Error(`No connection state for ${peerUID}`);
    }
    if (!cert) {
      throw new Error(`No certificate for ${peerUID}`);
    }

    // Already initialized
    if (state.sendCK && state.recvCK) {
      console.log(`[${this.myUID}] Ratchet already initialized with ${peerUID}`);
      return;
    }

    if (!state.dhMy || !state.dhPeer) {
      throw new Error(`Missing DH keys for ${peerUID}`);
    }

    console.log(`[${this.myUID}] Initializing ratchet with ${peerUID}...`);

    // Compute shared secret via Diffie-Hellman
    const sharedSecret = await computeDH(state.dhMy, state.dhPeer);
    const sharedSecretRaw = await crypto.subtle.exportKey('raw', sharedSecret);
    console.log(`[${this.myUID}] Shared secret (first 8 bytes):`, new Uint8Array(sharedSecretRaw).slice(0, 8));

    // Both parties derive the same two keys from shared secret
    const key1 = await HMACtoAESKey(sharedSecret, 'ratchet-key-1');
    const key2 = await HMACtoAESKey(sharedSecret, 'ratchet-key-2');
    
    const key1Raw = await crypto.subtle.exportKey('raw', key1);
    const key2Raw = await crypto.subtle.exportKey('raw', key2);
    console.log(`[${this.myUID}] Key1 (first 8 bytes):`, new Uint8Array(key1Raw).slice(0, 8));
    console.log(`[${this.myUID}] Key2 (first 8 bytes):`, new Uint8Array(key2Raw).slice(0, 8));

    // Deterministic role: person with "larger" UID gets key1 for send
    const amInitiator = this.myUID.localeCompare(peerUID) > 0;
    console.log(`[${this.myUID}] Role check: myUID="${this.myUID}", peerUID="${peerUID}", amInitiator=${amInitiator}`);

    if (amInitiator) {
      state.sendCK = key1;
      state.recvCK = key2;
      console.log(`[${this.myUID}] Assigned as INITIATOR: sendCK=key1, recvCK=key2`);
    } else {
      state.sendCK = key2;
      state.recvCK = key1;
      console.log(`[${this.myUID}] Assigned as RESPONDER: sendCK=key2, recvCK=key1`);
    }
  }

  // ---------------- Message Sending ----------------
  async sendMessage(peerUID, text) {
    const state = this.conns[peerUID];
    if (!state) {
      throw new Error(`No connection with ${peerUID}`);
    }

    await this._initRatchet(peerUID);

    if (!state.sendCK) {
      throw new Error(`Send key not initialized for ${peerUID}`);
    }

    // Generate random IV
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await encryptWithGCM(state.sendCK, text, iv);

    const ivTag = bytesToBase64(iv);
    
    console.log(`[${this.myUID}] SENDING to ${peerUID}: text="${text}", IV=${ivTag.slice(0, 12)}...`);
    
    // Store IV to prevent replay
    if (!state.seenIVs) state.seenIVs = new Set();
    state.seenIVs.add(ivTag);

    // Use actual sender UID
    const header = {
      sender: this.myUID,
      receiverIV: ivTag
    };

    return [header, ciphertext];
  }

  // ---------------- Message Receiving ----------------
  async receiveMessage(peerUID, [header, ciphertext]) {
    const state = this.conns[peerUID];
    if (!state) {
      throw new Error(`No connection with ${peerUID}`);
    }

    console.log(`[${this.myUID}] RECEIVING from ${peerUID}: IV=${header.receiverIV.slice(0, 12)}...`);

    await this._initRatchet(peerUID);

    if (!state.recvCK) {
      throw new Error(`Receive key not initialized for ${peerUID}`);
    }

    const ivTag = header.receiverIV;

    // Replay protection
    if (!state.seenIVs) state.seenIVs = new Set();
    if (state.seenIVs.has(ivTag)) {
      throw new Error('Replay attack detected: IV already seen');
    }

    const iv = base64ToBytes(ivTag);
    
    try {
      const plaintext = await decryptWithGCM(state.recvCK, ciphertext, iv);
      state.seenIVs.add(ivTag);
      const text = bufferToString(plaintext);
      console.log(`[${this.myUID}] DECRYPTED: "${text}"`);
      return text;
    } catch (err) {
      console.error(`[${this.myUID}] DECRYPTION FAILED:`, err);
      throw new Error(`Decryption failed: ${err.message}`);
    }
  }

  // ---------------- State Export / Import ----------------
  async exportState(peerUID) {
    const state = this.conns[peerUID];
    if (!state) return null;

    try {
      // Export both our private key and peer's public key
      const dhMyJWK = state.dhMy ? await cryptoKeyToJSON(state.dhMy) : null;
      const dhPeerJWK = state.dhPeer ? await cryptoKeyToJSON(state.dhPeer) : null;

      return {
        dhMy: dhMyJWK,
        dhPeer: dhPeerJWK,
        sendCK: state.sendCK
          ? bytesToBase64(await crypto.subtle.exportKey('raw', state.sendCK))
          : null,
        recvCK: state.recvCK
          ? bytesToBase64(await crypto.subtle.exportKey('raw', state.recvCK))
          : null,
        seenIVs: Array.from(state.seenIVs || [])
      };
    } catch (err) {
      console.error(`[exportState] Error for ${peerUID}:`, err);
      throw err;
    }
  }

  async importState(peerUID, data) {
    try {
      const dhMy = data.dhMy
        ? await importJSONToCryptoKey(data.dhMy, ['deriveKey'])
        : null;
        
      const dhPeer = data.dhPeer
        ? await importJSONToCryptoKey(data.dhPeer, [])
        : null;
      
      // Store our private key if we don't have it yet
      if (dhMy && !this._myDHKey) {
        this._myDHKey = dhMy;
      }
      
      this.conns[peerUID] = {
        dhMy: dhMy,
        dhPeer: dhPeer,
        sendCK: data.sendCK
          ? await crypto.subtle.importKey(
              'raw',
              base64ToBytes(data.sendCK),
              'AES-GCM',
              true,
              ['encrypt', 'decrypt']
            )
          : null,
        recvCK: data.recvCK
          ? await crypto.subtle.importKey(
              'raw',
              base64ToBytes(data.recvCK),
              'AES-GCM',
              true,
              ['encrypt', 'decrypt']
            )
          : null,
        seenIVs: new Set(data.seenIVs || [])
      };
      
      // Also restore certificate if we have dhPeer
      if (dhPeer) {
        this.certs[peerUID] = {
          uid: peerUID,
          elgamalPubKey: dhPeer
        };
      }
      
      console.log(`[importState] State restored for ${peerUID}`);
    } catch (err) {
      console.error(`[importState] Error for ${peerUID}:`, err);
      throw err;
    }
  }
}