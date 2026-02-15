export interface Env {
  DB: D1Database;
  CORS_ORIGIN?: string;
}

// Генерация ID
function generateId(): string {
  return Date.now().toString(36) + Math.random().toString(36).substring(2, 8);
}

// Валидация userId
function isValidUserId(id: string): boolean {
  return typeof id === 'string' && id.length >= 3 && id.length <= 32 && /^[a-zA-Z0-9_]+$/.test(id);
}

// Ответ с JSON
function jsonResponse(data: any, status: number = 200, headers?: Record<string, string>): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      ...headers
    }
  });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    // OPTIONS запросы
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type',
          'Access-Control-Max-Age': '86400',
        }
      });
    }

    try {
      // HEALTH CHECK
      if (path === '/api/health') {
        return jsonResponse({
          success: true,
          status: 'ok',
          time: Date.now(),
          message: 'Worker is running'
        });
      }

      // LOGIN
      if (path === '/api/login') {
        if (request.method !== 'POST') {
          return jsonResponse({ success: false, error: 'Method not allowed' }, 405);
        }

        const body = await request.json() as { userId?: string };
        const userId = body.userId;

        if (!userId || !isValidUserId(userId)) {
          return jsonResponse({ success: false, error: 'Invalid user ID' }, 400);
        }

        // Проверяем существование пользователя
        const user = await env.DB.prepare(
          'SELECT * FROM users WHERE id = ?'
        ).bind(userId).first();

        if (user) {
          await env.DB.prepare(
            'UPDATE users SET is_online = 1, last_seen = CURRENT_TIMESTAMP WHERE id = ?'
          ).bind(userId).run();
        } else {
          await env.DB.prepare(
            'INSERT INTO users (id, is_online) VALUES (?, 1)'
          ).bind(userId).run();
        }

        return jsonResponse({
          success: true,
          user: { id: userId }
        });
      }

      // GET CHATS
      if (path === '/api/chats' && request.method === 'GET') {
        const userId = url.searchParams.get('userId');
        
        if (!userId) {
          return jsonResponse({ success: false, error: 'Missing userId' }, 400);
        }

        const chats = await env.DB.prepare(`
          SELECT * FROM chats 
          WHERE members LIKE ? 
          ORDER BY updated_at DESC
        `).bind(`%${userId}%`).all();

        return jsonResponse({
          success: true,
          chats: chats.results || []
        });
      }

      // CREATE CHAT
      if (path === '/api/chats' && request.method === 'POST') {
        const body = await request.json() as { type: string; name?: string; members: string[] };
        const { type, name, members } = body;

        if (!type || !members || !Array.isArray(members) || members.length === 0) {
          return jsonResponse({ success: false, error: 'Invalid data' }, 400);
        }

        const chatId = type === 'private' && members.length === 2
          ? `p_${members.sort().join('_')}`
          : generateId();

        await env.DB.prepare(
          'INSERT INTO chats (id, type, name, members) VALUES (?, ?, ?, ?)'
        ).bind(chatId, type, name || 'Чат', JSON.stringify(members)).run();

        return jsonResponse({
          success: true,
          chat: { id: chatId, type, name, members }
        });
      }

      // GET MESSAGES
      if (path === '/api/messages' && request.method === 'GET') {
        const chatId = url.searchParams.get('chatId');
        
        if (!chatId) {
          return jsonResponse({ success: false, error: 'Missing chatId' }, 400);
        }

        const messages = await env.DB.prepare(`
          SELECT * FROM messages 
          WHERE chat_id = ? 
          ORDER BY timestamp ASC
        `).bind(chatId).all();

        return jsonResponse({
          success: true,
          messages: messages.results || []
        });
      }

      // SEND MESSAGE
      if (path === '/api/messages' && request.method === 'POST') {
        const body = await request.json() as { chatId: string; senderId: string; text: string };
        const { chatId, senderId, text } = body;

        if (!chatId || !senderId || !text) {
          return jsonResponse({ success: false, error: 'Missing data' }, 400);
        }

        const messageId = generateId();

        await env.DB.batch([
          env.DB.prepare(
            'INSERT INTO messages (id, chat_id, sender_id, text) VALUES (?, ?, ?, ?)'
          ).bind(messageId, chatId, senderId, text),
          env.DB.prepare(
            'UPDATE chats SET updated_at = CURRENT_TIMESTAMP WHERE id = ?'
          ).bind(chatId)
        ]);

        const message = await env.DB.prepare(
          'SELECT * FROM messages WHERE id = ?'
        ).bind(messageId).first();

        return jsonResponse({
          success: true,
          message
        });
      }

      // TYPING
      if (path === '/api/typing' && request.method === 'POST') {
        const body = await request.json() as { chatId: string; userId: string; isTyping: boolean };
        const { chatId, userId, isTyping } = body;

        if (isTyping) {
          await env.DB.prepare(
            'INSERT OR REPLACE INTO typing (chat_id, user_id, timestamp) VALUES (?, ?, ?)'
          ).bind(chatId, userId, Date.now()).run();
        } else {
          await env.DB.prepare(
            'DELETE FROM typing WHERE chat_id = ? AND user_id = ?'
          ).bind(chatId, userId).run();
        }

        return jsonResponse({ success: true });
      }

      // GET TYPING
      if (path === '/api/typing' && request.method === 'GET') {
        const chatId = url.searchParams.get('chatId');
        
        if (!chatId) {
          return jsonResponse({ success: false, error: 'Missing chatId' }, 400);
        }

        // Очищаем старые записи (старше 5 секунд)
        await env.DB.prepare(
          'DELETE FROM typing WHERE timestamp < ?'
        ).bind(Date.now() - 5000).run();

        const typing = await env.DB.prepare(
          'SELECT user_id FROM typing WHERE chat_id = ?'
        ).bind(chatId).all();

        return jsonResponse({
          success: true,
          typing: typing.results.map(t => t.user_id)
        });
      }

      // 404
      return jsonResponse({
        success: false,
        error: 'Not found',
        path
      }, 404);

    } catch (error: any) {
      console.error('Worker error:', error);
      return jsonResponse({
        success: false,
        error: error?.message || 'Internal server error'
      }, 500);
    }
  }
};