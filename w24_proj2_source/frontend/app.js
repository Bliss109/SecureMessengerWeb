// frontend/app.js
import { db } from "./firebase.js";
import {
  doc, collection, addDoc, setDoc, getDoc, updateDoc,
  onSnapshot, query, orderBy, where, serverTimestamp, arrayRemove
} from "https://www.gstatic.com/firebasejs/11.0.1/firebase-firestore.js";

import { MessengerClient } from "../messenger.js";
import { generateECDSA, generateEG, signWithECDSA } from "../lib.js";

// ----- Helpers -----
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
function getChatId(a, b) { return [a, b].sort().join('__'); }
function nowTime() { return new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }); }
function appendMessage(container, text, who) {
  const div = document.createElement('div');
  div.className = `msg ${who}`;
  div.innerHTML = `${text}<span class="meta">${nowTime()}</span>`;
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
}
function persistState() {
  Promise.all([
    aliceClient.exportState?.(bob.name),
    bobClient.exportState?.(alice.name)
  ]).then(([aState, bState]) => {
    if (aState) localStorage.setItem("ratchet-alice", JSON.stringify(aState));
    if (bState) localStorage.setItem("ratchet-bob", JSON.stringify(bState));
  }).catch(() => {});
}

// ----- Demo identities -----
const alice = { uid: 'alice-uid', name: 'Alice' };
const bob   = { uid: 'bob-uid',   name: 'Bob' };

// ----- Crypto bootstrap -----
let caKeyPair, govKeyPair;
let aliceClient, bobClient;

async function bootCrypto() {
  console.log("[boot] generating keys...");
  caKeyPair = await generateECDSA();
  govKeyPair = await generateEG();

  aliceClient = new MessengerClient(caKeyPair.pub, govKeyPair.pub);
  bobClient   = new MessengerClient(caKeyPair.pub, govKeyPair.pub);

  // Restore saved ratchet state (optional)
  try {
    const aSaved = localStorage.getItem("ratchet-alice");
    const bSaved = localStorage.getItem("ratchet-bob");
    if (aSaved) await aliceClient.importState(alice.name, JSON.parse(aSaved));
    if (bSaved) await bobClient.importState(bob.name, JSON.parse(bSaved));
  } catch {}

  const aliceCert = await aliceClient.generateCertificate(alice.name);
  const bobCert   = await bobClient.generateCertificate(bob.name);
  const aliceSig  = await signWithECDSA(caKeyPair.sec, JSON.stringify(aliceCert));
  const bobSig    = await signWithECDSA(caKeyPair.sec, JSON.stringify(bobCert));

  await aliceClient.receiveCertificate(bobCert, bobSig);
  await bobClient.receiveCertificate(aliceCert, aliceSig);

  console.log("[boot] crypto ready");
}

// ----- UI wiring -----
const aliceList = document.getElementById('alice-chat-list');
const bobList   = document.getElementById('bob-chat-list');
const alicePane = document.getElementById('alice-chat-pane');
const bobPane   = document.getElementById('bob-chat-pane');

function renderContact(listEl, self, peer) {
  const li = document.createElement('li');
  li.className = 'chat-list-item';
  li.innerHTML = `
    <div class="peer-avatar">${peer.name.charAt(0).toUpperCase()}</div>
    <div class="peer-details">
      <div class="peer-name">${peer.name}</div>
      <div class="peer-last">Tap to open secure chat</div>
    </div>
    <span class="unread-badge" style="display:none"></span>
  `;
  li.addEventListener('click', () => openChat(self, peer));
  listEl.appendChild(li);
}

function openChat(self, peer) {
  const pane = self.uid === alice.uid ? alicePane : bobPane;
  const client = self.uid === alice.uid ? aliceClient : bobClient;

  pane.innerHTML = `
    <header class="chat-header"><h3>${peer.name}</h3><small>secure</small></header>
    <section class="messages" id="msgs-${self.uid}"></section>
    <form class="composer" id="form-${self.uid}">
      <input id="input-${self.uid}" placeholder="Type a message..." />
      <button type="submit">Send</button>
    </form>
  `;
  const msgsEl = document.getElementById(`msgs-${self.uid}`);
  const form = document.getElementById(`form-${self.uid}`);
  const input = document.getElementById(`input-${self.uid}`);
  const sendBtn = form.querySelector('button');

  const chatId = getChatId(self.uid, peer.uid);

  // Stream messages for this chat only (avoids collectionGroup index requirement)
  const q = query(collection(db, 'chats', chatId, 'messages'), orderBy('createdAt'));

  const unsub = onSnapshot(q, async snapshot => {
    msgsEl.innerHTML = '';
    for (const docSnap of snapshot.docs) {
      const data = docSnap.data();
      let textOut = '';
      try {
        if (data.header && data.ciphertext) {
          const header = JSON.parse(data.header);
          const ciphertext = base64ToBytes(data.ciphertext);
          textOut = await client.receiveMessage(peer.name, [header, ciphertext]);
          persistState(); // save ratchet after successful decrypt
        } else {
          textOut = data.text || '[no content]';
        }
      } catch (e) {
        if (e.message === 'Replay detected.') continue; // silently skip
        textOut = `Hello`;
      }
      const who = data.senderId === self.uid ? 'me' : 'them';
      appendMessage(msgsEl, textOut, who);

      // Mark as read
      if (Array.isArray(data.unreadBy) && data.unreadBy.includes(self.uid)) {
        await updateDoc(docSnap.ref, { unreadBy: arrayRemove(self.uid) }).catch(() => {});
      }
    }
    msgsEl.scrollTop = msgsEl.scrollHeight;
  }, err => {
    appendMessage(msgsEl, `[Stream error: ${err.message}]`, 'them');
  });

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const text = input.value.trim();
    if (!text) return;
    input.value = '';
    sendBtn.disabled = true;

    try {
      const [header, ciphertext] = await client.sendMessage(peer.name, text);
      const chatDocRef = doc(db, 'chats', chatId);
      const chatSnap = await getDoc(chatDocRef);
      if (!chatSnap.exists()) {
        await setDoc(chatDocRef, {
          users: [self.uid, peer.uid],
          createdAt: serverTimestamp(),
          updatedAt: serverTimestamp(),
          lastMessage: text
        });
      } else {
        await updateDoc(chatDocRef, {
          updatedAt: serverTimestamp(),
          lastMessage: text
        });
      }
      await addDoc(collection(chatDocRef, 'messages'), {
        header: JSON.stringify(header),
        ciphertext: bytesToBase64(ciphertext),
        senderId: self.uid,
        receiverId: peer.uid,
        createdAt: serverTimestamp(),
        unreadBy: [peer.uid]
      });
      persistState(); // save ratchet after send
    } catch (err) {
      appendMessage(msgsEl, `[Delivery error: ${err.message}]`, 'them');
    } finally {
      sendBtn.disabled = false;
    }
  });

  pane._unsub = unsub;
}

// ----- Boot sequence -----
;(async function main() {
  console.log("[main] boot start");
  await bootCrypto();
  renderContact(aliceList, alice, bob);
  renderContact(bobList, bob, alice);
  console.log("[main] UI ready — tap a contact to open chat");
})();
