// frontend/app.js — FULLY CORRECTED VERSION

// ---------------- Global error handling ----------------
window.addEventListener('error', (e) => {
  console.error('Global error:', e.error);
});

window.addEventListener('unhandledrejection', (e) => {
  console.error('Unhandled promise rejection:', e.reason);
});

// ---------------- Imports ----------------
import { db } from "./firebase.js";
import {
  doc, collection, addDoc, setDoc, getDoc, updateDoc,
  onSnapshot, query, orderBy, serverTimestamp, arrayRemove
} from "https://www.gstatic.com/firebasejs/11.0.1/firebase-firestore.js";

import { MessengerClient } from "./messenger.js";
import { generateECDSA, generateEG, signWithECDSA } from "./lib.js";

// ---------------- Helpers ----------------
function bytesToBase64(uint8) {
  let binary = '';
  const bytes = new Uint8Array(uint8);
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function base64ToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function getChatId(a, b) {
  return [a, b].sort().join('__');
}

function nowTime() {
  return new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function appendMessage(container, text, who, msgId) {
  if (msgId && container.querySelector(`[data-msg-id="${msgId}"]`)) return;
  const div = document.createElement('div');
  div.className = `msg ${who}`;
  if (msgId) div.dataset.msgId = msgId;
  div.innerHTML = `${text}<span class="meta">${nowTime()}</span>`;
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
}

async function persistState() {
  try {
    const [aState, bState] = await Promise.all([
      aliceClient.exportState(bob.uid),
      bobClient.exportState(alice.uid)
    ]);
    
    if (aState) localStorage.setItem("ratchet-alice", JSON.stringify(aState));
    if (bState) localStorage.setItem("ratchet-bob", JSON.stringify(bState));
    console.log("[persistState] State saved");
  } catch (err) {
    console.error("[persistState] Error:", err);
  }
}

// ---------------- Demo identities ----------------
const alice = { uid: 'alice-uid', name: 'Alice' };
const bob   = { uid: 'bob-uid',   name: 'Bob' };

// ---------------- Crypto bootstrap ----------------
let caKeyPair, govKeyPair;
let aliceClient, bobClient;

async function bootCrypto() {
  console.log("[boot] Generating keys...");

  caKeyPair = await generateECDSA();
  govKeyPair = await generateEG();

  aliceClient = new MessengerClient(caKeyPair.pub, govKeyPair.pub, alice.uid);
  bobClient   = new MessengerClient(caKeyPair.pub, govKeyPair.pub, bob.uid);

  // Try to restore ratchet state FIRST
  let aliceRestored = false;
  let bobRestored = false;
  
  try {
    const aSaved = localStorage.getItem("ratchet-alice");
    const bSaved = localStorage.getItem("ratchet-bob");

    if (aSaved) {
      await aliceClient.importState(bob.uid, JSON.parse(aSaved));
      aliceRestored = true;
      console.log("[boot] Alice state restored");
    }
    if (bSaved) {
      await bobClient.importState(alice.uid, JSON.parse(bSaved));
      bobRestored = true;
      console.log("[boot] Bob state restored");
    }
  } catch (e) {
    console.warn("[boot] Failed to restore state:", e.message);
  }

  // Only generate NEW certificates if state wasn't restored
  if (!aliceRestored || !bobRestored) {
    console.log("[boot] Generating new certificates...");
    
    const aliceCert = await aliceClient.generateCertificate(alice.uid);
    const bobCert   = await bobClient.generateCertificate(bob.uid);

    const aliceSig = await signWithECDSA(caKeyPair.sec, JSON.stringify(aliceCert));
    const bobSig   = await signWithECDSA(caKeyPair.sec, JSON.stringify(bobCert));

    await aliceClient.receiveCertificate(bobCert, bobSig);
    await bobClient.receiveCertificate(aliceCert, aliceSig);
  } else {
    console.log("[boot] Using restored keys, skipping certificate exchange");
  }

  console.log("[boot] Crypto ready");
}

// ---------------- UI wiring ----------------
const aliceList = document.getElementById('alice-chat-list');
const bobList   = document.getElementById('bob-chat-list');
const alicePane = document.getElementById('alice-chat-pane');
const bobPane   = document.getElementById('bob-chat-pane');

// Track active listeners for cleanup
const activeListeners = new Map();

function renderContact(listEl, self, peer) {
  const li = document.createElement('li');
  li.className = 'chat-list-item';
  li.innerHTML = `
    <div class="peer-avatar">${peer.name[0]}</div>
    <div class="peer-details">
      <div class="peer-name">${peer.name}</div>
      <div class="peer-last">Tap to open secure chat</div>
    </div>`;
  li.onclick = () => openChat(self, peer);
  listEl.appendChild(li);
}

function openChat(self, peer) {
  const pane = self.uid === alice.uid ? alicePane : bobPane;
  const client = self.uid === alice.uid ? aliceClient : bobClient;

  // Cleanup previous listener
  const listenerKey = `${self.uid}-${peer.uid}`;
  if (activeListeners.has(listenerKey)) {
    activeListeners.get(listenerKey)();
    activeListeners.delete(listenerKey);
  }

  // CRITICAL FIX: Clear seenIVs when opening chat to allow re-processing old messages
  const state = client.conns[peer.uid];
  if (state && state.seenIVs) {
    console.log(`[${self.uid}] Clearing ${state.seenIVs.size} seen IVs for ${peer.uid}`);
    state.seenIVs.clear();
  }

  pane.innerHTML = `
    <header class="chat-header"><h3>${peer.name}</h3><small>secure</small></header>
    <section class="messages" id="msgs-${self.uid}"></section>
    <form class="composer" id="form-${self.uid}">
      <input id="input-${self.uid}" autocomplete="off" placeholder="Type a message..." />
      <button type="submit">Send</button>
    </form>`;

  const msgsEl = document.getElementById(`msgs-${self.uid}`);
  const form = document.getElementById(`form-${self.uid}`);
  const input = document.getElementById(`input-${self.uid}`);

  const chatId = getChatId(self.uid, peer.uid);
  const q = query(collection(db, 'chats', chatId, 'messages'), orderBy('createdAt'));

  const unsubscribe = onSnapshot(q, snapshot => {
    snapshot.docChanges().forEach(async change => {
      if (change.type !== 'added') return;

      const docSnap = change.doc;
      const data = docSnap.data();

      // Handle our own messages
      if (data.senderId === self.uid) {
        // Use stored plaintext for our own messages
        if (data.plaintextForSender) {
          appendMessage(msgsEl, data.plaintextForSender, 'me', docSnap.id);
        }
        return;
      }

      // For peer's messages, decrypt and display
      try {
        const header = JSON.parse(data.header);
        const ciphertext = base64ToBytes(data.ciphertext);

        const plaintext = await client.receiveMessage(peer.uid, [header, ciphertext]);
        
        appendMessage(msgsEl, plaintext, 'them', docSnap.id);

        // Mark as read
        if (Array.isArray(data.unreadBy) && data.unreadBy.includes(self.uid)) {
          await updateDoc(docSnap.ref, { unreadBy: arrayRemove(self.uid) });
        }

        // Save state after receiving message
        await persistState();
      } catch (e) {
        console.error("[receive] Error decrypting message:", e.message, e);
        appendMessage(msgsEl, '[Decryption failed]', 'them', docSnap.id);
      }
    });
  }, error => {
    console.error("[snapshot] Error:", error);
  });

  activeListeners.set(listenerKey, unsubscribe);

  form.onsubmit = async (e) => {
    e.preventDefault();
    const text = input.value.trim();
    if (!text) return;
    
    input.value = '';
    input.disabled = true;

    try {
      const [header, ciphertext] = await client.sendMessage(peer.uid, text);

      const chatRef = doc(db, 'chats', chatId);
      const chatDoc = await getDoc(chatRef);
      
      if (!chatDoc.exists()) {
        await setDoc(chatRef, { 
          users: [self.uid, peer.uid], 
          createdAt: serverTimestamp() 
        });
      }

      const msgRef = await addDoc(collection(chatRef, 'messages'), {
        header: JSON.stringify(header),
        ciphertext: bytesToBase64(ciphertext),
        senderId: self.uid,
        receiverId: peer.uid,
        createdAt: serverTimestamp(),
        unreadBy: [peer.uid],
        plaintextForSender: text // Store plaintext for sender to see after refresh
      });

      // Show the message immediately in our own chat
      appendMessage(msgsEl, text, 'me', msgRef.id);

      // Save state after sending
      await persistState();
      
    } catch (err) {
      console.error("[send] Error:", err);
      alert(`Failed to send message: ${err.message}`);
      input.value = text; // Restore message
    } finally {
      input.disabled = false;
      input.focus();
    }
  };

  input.focus();
}

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
  activeListeners.forEach(unsub => unsub());
  activeListeners.clear();
});

// ---------------- Boot ----------------
(async function main() {
  try {
    await bootCrypto();
    renderContact(aliceList, alice, bob);
    renderContact(bobList, bob, alice);
    openChat(alice, bob);
  } catch (err) {
    console.error("[main] Initialization failed:", err);
    alert("Failed to initialize application. Please refresh.");
  }
})();