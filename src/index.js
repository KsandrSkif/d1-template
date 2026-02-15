export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    
    const headers = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Content-Type': 'application/json'
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers });
    }

    try {
      // HEALTH
      if (path === '/api/health') {
        return new Response(JSON.stringify({ success: true, status: 'ok' }), { headers });
      }

      // LOGIN
      if (path === '/api/login' && request.method === 'POST') {
        const { userId } = await request.json();
        
        await env.DB.prepare(
          'INSERT OR IGNORE INTO users (id) VALUES (?)'
        ).bind(userId).run();
        
        await env.DB.prepare(
          'UPDATE users SET is_online = 1 WHERE id = ?'
        ).bind(userId).run();

        return new Response(JSON.stringify({ success: true, user: { id: userId } }), { headers });
      }

      // GET CHATS
      if (path === '/api/chats' && request.method === 'GET') {
        const userId = url.searchParams.get('userId');
        const chats = await env.DB.prepare(
          'SELECT * FROM chats WHERE members LIKE ? ORDER BY updated_at DESC'
        ).bind(`%${userId}%`).all();
        
        return new Response(JSON.stringify({ success: true, chats: chats.results || [] }), { headers });
      }

      // CREATE CHAT
      if (path === '/api/chats' && request.method === 'POST') {
        const { type, name, members } = await request.json();
        const chatId = type === 'private' 
          ? `p_${members.sort().join('_')}` 
          : Date.now().toString(36) + Math.random().toString(36).substring(2);

        await env.DB.prepare(
          'INSERT INTO chats (id, type, name, members) VALUES (?, ?, ?, ?)'
        ).bind(chatId, type, name || 'Чат', JSON.stringify(members)).run();

        return new Response(JSON.stringify({ success: true, chat: { id: chatId, type, name, members } }), { headers });
      }

      // GET MESSAGES
      if (path === '/api/messages' && request.method === 'GET') {
        const chatId = url.searchParams.get('chatId');
        const messages = await env.DB.prepare(
          'SELECT * FROM messages WHERE chat_id = ? ORDER BY timestamp ASC'
        ).bind(chatId).all();
        
        return new Response(JSON.stringify({ success: true, messages: messages.results || [] }), { headers });
      }

      // SEND MESSAGE
      if (path === '/api/messages' && request.method === 'POST') {
        const { chatId, senderId, text } = await request.json();
        const messageId = Date.now().toString(36) + Math.random().toString(36).substring(2);

        await env.DB.batch([
          env.DB.prepare('INSERT INTO messages (id, chat_id, sender_id, text) VALUES (?, ?, ?, ?)').bind(messageId, chatId, senderId, text),
          env.DB.prepare('UPDATE chats SET updated_at = CURRENT_TIMESTAMP WHERE id = ?').bind(chatId)
        ]);

        return new Response(JSON.stringify({ success: true, message: { id: messageId, chat_id: chatId, sender_id: senderId, text, timestamp: new Date().toISOString() } }), { headers });
      }

      return new Response(JSON.stringify({ success: false, error: 'Not found' }), { status: 404, headers });

    } catch (error) {
      return new Response(JSON.stringify({ success: false, error: error.message }), { status: 500, headers });
    }
  }
};