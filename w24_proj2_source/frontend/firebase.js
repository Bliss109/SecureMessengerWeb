// frontend/firebase.js
import { initializeApp } from "https://www.gstatic.com/firebasejs/11.0.1/firebase-app.js";
import { getFirestore } from "https://www.gstatic.com/firebasejs/11.0.1/firebase-firestore.js";

const firebaseConfig = {
  apiKey: "AIzaSyBuR1JOaBCLT54-UXFrm3cLrcsCA1wKz3Y",
  authDomain: "messenger-38e0a.firebaseapp.com",
  projectId: "messenger-38e0a",
  storageBucket: "messenger-38e0a.appspot.com", // corrected suffix
  messagingSenderId: "23809580010",
  appId: "1:23809580010:web:c7762e9bef3a46470db093",
  measurementId: "G-BMML5KXCXJ"
};

const app = initializeApp(firebaseConfig);
export const db = getFirestore(app);

// Optional debug
console.log("[firebase] Initialized app and Firestore:", app.name);
