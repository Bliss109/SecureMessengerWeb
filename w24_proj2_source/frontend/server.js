// server.js
import { WebSocketServer } from 'ws';

const wss = new WebSocketServer({ port: 8080 });
const clients = new Map(); // username -> ws

wss.on('connection', (ws) => {
  ws.on('message', (data) => {
    let msg;
    try {
      msg = JSON.parse(data.toString());
    } catch {
      return;
    }

    // Client can register: { type: 'register', username }
    if (msg.type === 'register' && msg.username) {
      clients.set(msg.username, ws);
      ws.send(JSON.stringify({ type: 'registered', username: msg.username }));
      return;
    }

    // Relay encrypted messages: { type: 'message', to, from, header, ciphertext }
    if (msg.type === 'message' && msg.to && msg.from && msg.header && msg.ciphertext) {
      const dest = clients.get(msg.to);
      if (dest && dest.readyState === dest.OPEN) {
        dest.send(JSON.stringify(msg));
      } else {
        ws.send(JSON.stringify({ type: 'error', error: 'Recipient not connected' }));
      }
    }
  });

  ws.on('close', () => {
    for (const [name, socket] of clients.entries()) {
      if (socket === ws) clients.delete(name);
    }
  });
});

console.log('WebSocket relay listening on ws://localhost:8080');
