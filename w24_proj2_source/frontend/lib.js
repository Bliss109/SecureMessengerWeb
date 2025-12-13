// lib.js — FULLY CORRECTED VERSION

// ArrayBuffer -> string
export function bufferToString(arr) {
  return new TextDecoder().decode(arr);
}

// Random IV
export function genRandomSalt(len = 16) {
  return crypto.getRandomValues(new Uint8Array(len));
}

// CryptoKey -> JWK JSON (with proper key_ops handling)
export async function cryptoKeyToJSON(cryptoKey) {
  try {
    const jwk = await crypto.subtle.exportKey('jwk', cryptoKey);
    const algInfo = cryptoKey.algorithm;
    
    // Handle ECDH/ECDSA keys
    if (algInfo && (algInfo.name === 'ECDH' || algInfo.name === 'ECDSA')) {
      jwk.alg = algInfo.name;
      
      // FIX: Set appropriate key_ops based on key type and algorithm
      if (cryptoKey.type === 'private') {
        if (algInfo.name === 'ECDH') {
          jwk.key_ops = ['deriveKey'];
        } else if (algInfo.name === 'ECDSA') {
          jwk.key_ops = ['sign'];
        }
      } else {
        // Public keys for ECDH don't need key_ops (used in deriveKey params)
        // Public keys for ECDSA need verify
        if (algInfo.name === 'ECDSA') {
          jwk.key_ops = ['verify'];
        } else {
          jwk.key_ops = [];
        }
      }
    } 
    // Handle HMAC keys
    else if (algInfo && algInfo.name === 'HMAC') {
      jwk.hash = algInfo.hash ? algInfo.hash.name : jwk.hash || 'SHA-256';
      jwk.key_ops = jwk.key_ops && jwk.key_ops.length ? jwk.key_ops : ['sign'];
    } 
    // Handle AES-GCM keys
    else if (algInfo && algInfo.name === 'AES-GCM') {
      jwk.alg = 'A256GCM';
      jwk.key_ops = jwk.key_ops && jwk.key_ops.length ? jwk.key_ops : ['encrypt', 'decrypt'];
    } 
    else {
      jwk.key_ops = jwk.key_ops || [];
    }
    
    return jwk;
  } catch (error) {
    console.error('[cryptoKeyToJSON] Failed to export key:', error);
    throw error;
  }
}

// JWK JSON -> CryptoKey (with robust usage handling)
export async function importJSONToCryptoKey(json, usage = []) {
  try {
    if (typeof json === 'string') json = JSON.parse(json);
    if (!json || typeof json !== 'object' || !json.kty) {
      throw new Error('Invalid JWK structure');
    }
    
    let algorithm;
    
    switch (json.kty) {
      case 'EC':
        algorithm = { name: json.alg || 'ECDH', namedCurve: json.crv };
        break;
      case 'oct':
        if (json.alg && json.alg.startsWith('A')) {
          const bits = parseInt(json.alg.substring(1, 4)) || 256;
          algorithm = { name: 'AES-GCM', length: bits };
        } else {
          algorithm = { name: 'HMAC', hash: json.hash || 'SHA-256', length: 256 };
        }
        break;
      default:
        throw new Error(`Unsupported key type: ${json.kty}`);
    }
    
    const jwkKeyOps = Array.isArray(json.key_ops) ? json.key_ops : [];
    let finalUsage = Array.isArray(usage) ? [...usage] : [];
    
    // If no usage provided, try to use JWK key_ops
    if (finalUsage.length === 0 && jwkKeyOps.length > 0) {
      finalUsage = [...jwkKeyOps];
    }
    
    // Default usage based on key type
    if (finalUsage.length === 0) {
      if (json.kty === 'oct') {
        finalUsage = json.alg && json.alg.startsWith('A') ? ['encrypt', 'decrypt'] : ['sign'];
      } else if (json.kty === 'EC') {
        if (json.d) {
          // Private key
          finalUsage = algorithm.name === 'ECDH' ? ['deriveKey'] : ['sign'];
        } else {
          // Public key - ECDH public keys don't need key_ops
          finalUsage = algorithm.name === 'ECDSA' ? ['verify'] : [];
        }
      }
    }
    
    // Validate usage against JWK key_ops if present
    if (jwkKeyOps.length > 0 && finalUsage.length > 0) {
      const intersection = finalUsage.filter(u => jwkKeyOps.includes(u));
      if (intersection.length > 0) {
        finalUsage = intersection;
      }
    }
    
    return await crypto.subtle.importKey('jwk', json, algorithm, true, finalUsage);
  } catch (error) {
    console.error('[importJSONToCryptoKey] Failed to import key:', error);
    throw error;
  }
}

// ECDH ephemeral keypair generator
export async function generateEG() {
  const keypair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-384' },
    true,
    ['deriveKey']
  );
  return { pub: keypair.publicKey, sec: keypair.privateKey };
}

// Diffie-Hellman shared secret -> HMAC CryptoKey
export async function computeDH(myPrivateKey, theirPublicKey) {
  try {
    return await crypto.subtle.deriveKey(
      { name: 'ECDH', public: theirPublicKey },
      myPrivateKey,
      { name: 'HMAC', hash: 'SHA-256', length: 256 },
      true,
      ['sign']
    );
  } catch (error) {
    console.error('[computeDH] Error:', error);
    throw error;
  }
}

// ECDSA verify
export async function verifyWithECDSA(publicKey, message, signature) {
  try {
    return await crypto.subtle.verify(
      { name: 'ECDSA', hash: { name: 'SHA-384' } },
      publicKey,
      signature,
      new TextEncoder().encode(message)
    );
  } catch (error) {
    console.error('[verifyWithECDSA] Error:', error);
    return false;
  }
}

// HMAC -> AES-GCM key
export async function HMACtoAESKey(key, data, exportToArrayBuffer = false) {
  try {
    const hmacBuf = await crypto.subtle.sign(
      { name: 'HMAC' },
      key,
      new TextEncoder().encode(data)
    );
    
    const out = await crypto.subtle.importKey(
      'raw',
      hmacBuf,
      'AES-GCM',
      true,
      ['encrypt', 'decrypt']
    );
    
    if (exportToArrayBuffer) {
      return await crypto.subtle.exportKey('raw', out);
    }
    return out;
  } catch (error) {
    console.error('[HMACtoAESKey] Error:', error);
    throw error;
  }
}

// HMAC -> HMAC key
export async function HMACtoHMACKey(key, data) {
  try {
    const hmacBuf = await crypto.subtle.sign(
      { name: 'HMAC' },
      key,
      new TextEncoder().encode(data)
    );
    
    return await crypto.subtle.importKey(
      'raw',
      hmacBuf,
      { name: 'HMAC', hash: 'SHA-256', length: 256 },
      true,
      ['sign']
    );
  } catch (error) {
    console.error('[HMACtoHMACKey] Error:', error);
    throw error;
  }
}

// HKDF deriving two outputs
export async function HKDF(inputKey, salt, infoStr) {
  try {
    const inputKeyBuf = await crypto.subtle.sign(
      { name: 'HMAC' },
      inputKey,
      new TextEncoder().encode('0')
    );
    
    const inputKeyHKDF = await crypto.subtle.importKey(
      'raw',
      inputKeyBuf,
      'HKDF',
      false,
      ['deriveKey']
    );
    
    const salt1 = await crypto.subtle.sign(
      { name: 'HMAC' },
      salt,
      new TextEncoder().encode('salt1')
    );
    
    const salt2 = await crypto.subtle.sign(
      { name: 'HMAC' },
      salt,
      new TextEncoder().encode('salt2')
    );
    
    const hkdfOut1 = await crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: salt1, info: new TextEncoder().encode(infoStr) },
      inputKeyHKDF,
      { name: 'HMAC', hash: 'SHA-256', length: 256 },
      true,
      ['sign']
    );
    
    const hkdfOut2 = await crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: salt2, info: new TextEncoder().encode(infoStr) },
      inputKeyHKDF,
      { name: 'HMAC', hash: 'SHA-256', length: 256 },
      true,
      ['sign']
    );
    
    return [hkdfOut1, hkdfOut2];
  } catch (error) {
    console.error('[HKDF] Error:', error);
    throw error;
  }
}

// AES-GCM encrypt/decrypt
export async function encryptWithGCM(key, plaintext, iv, authenticatedData = '') {
  try {
    const data = typeof plaintext === 'string' 
      ? new TextEncoder().encode(plaintext) 
      : plaintext;
    
    return await crypto.subtle.encrypt(
      { 
        name: 'AES-GCM', 
        iv, 
        additionalData: new TextEncoder().encode(authenticatedData) 
      },
      key,
      data
    );
  } catch (error) {
    console.error('[encryptWithGCM] Error:', error);
    throw error;
  }
}

export async function decryptWithGCM(key, ciphertext, iv, authenticatedData = '') {
  try {
    return await crypto.subtle.decrypt(
      { 
        name: 'AES-GCM', 
        iv, 
        additionalData: new TextEncoder().encode(authenticatedData) 
      },
      key,
      ciphertext
    );
  } catch (error) {
    console.error('[decryptWithGCM] Error:', error);
    throw error;
  }
}

// ECDSA generate/sign
export async function generateECDSA() {
  const keypair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-384' },
    true,
    ['sign', 'verify']
  );
  return { pub: keypair.publicKey, sec: keypair.privateKey };
}

export async function signWithECDSA(privateKey, message) {
  try {
    return await crypto.subtle.sign(
      { name: 'ECDSA', hash: { name: 'SHA-384' } },
      privateKey,
      new TextEncoder().encode(message)
    );
  } catch (error) {
    console.error('[signWithECDSA] Error:', error);
    throw error;
  }
}

// ----- Base64 helpers -----
export function bytesToBase64(uint8) {
  let binary = '';
  const bytes = new Uint8Array(uint8);
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function base64ToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    bytes[i] = bin.charCodeAt(i);
  }
  return bytes;
}