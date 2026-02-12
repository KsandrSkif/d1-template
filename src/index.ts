// src/index.ts - адаптированный worker.js для Cloudflare Workers

export interface Env {
	DB: D1Database;
}

// Константы
const RATE_LIMIT_WINDOW = 60000;
const RATE_LIMIT_MAX = 60;
const RATE_LIMIT_MESSAGE = 10;
const RATE_LIMIT_CREATE = 5;

// Валидация ID
const isValidId = (id: string): boolean => 
	typeof id === 'string' && /^[a-zA-Z0-9_]{3,32}$/.test(id);

// Генерация ID
const generateId = (): string => {
	const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
	let result = '_';
	for (let i = 0; i < 12; i++) {
		result += chars.charAt(Math.floor(Math.random() * chars.length));
	}
	return result;
};

// Экранирование для LIKE
const escapeLike = (str: string): string => {
	if (typeof str !== 'string') return '';
	return str.replace(/[%_\\]/g, '\\$&');
};

// Безопасный JSON parse
const safeJsonParse = (str: string | null, defaultVal: any[] = []): any[] => {
	try {
		return str ? JSON.parse(str) : defaultVal;
	} catch {
		return defaultVal;
	}
};

// Rate limiting через D1
async function checkRateLimit(db: D1Database, key: string, limit: number, windowMs: number = RATE_LIMIT_WINDOW): Promise<boolean> {
	const now = Date.now();
	const windowStart = now - windowMs;
	
	try {
		await db.prepare('DELETE FROM rate_limits WHERE timestamp < ?').bind(windowStart).run();
		const count = await db.prepare('SELECT COUNT(*) as count FROM rate_limits WHERE key = ? AND timestamp > ?')
			.bind(key, windowStart).first();
		
		if ((count?.count as number) >= limit) return false;
		
		await db.prepare('INSERT INTO rate_limits (key, timestamp) VALUES (?, ?)').bind(key, now).run();
		return true;
	} catch (error) {
		console.error('Rate limit error:', error);
		return true;
	}
}

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		const corsHeaders = {
			'Access-Control-Allow-Origin': '*',
			'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
			'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Client-Version',
			'X-Content-Type-Options': 'nosniff',
			'X-Frame-Options': 'DENY',
		};
		
		if (path === '/') {
  return new Response(JSON.stringify({ 
    status: 'ok',
    name: 'DarkChat Worker',
    version: '2.1'
  }), {
    status: 200,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' }
  });
}
		
		if (request.method === 'OPTIONS') {
			return new Response(null, { headers: corsHeaders });
		}
		
		const url = new URL(request.url);
		const path = url.pathname;
		const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
		
		const allowed = await checkRateLimit(env.DB, `global:${clientIP}`, RATE_LIMIT_MAX);
		if (!allowed) {
			return new Response(JSON.stringify({ success: false, error: 'Rate limit exceeded' }), {
				status: 429,
				headers: { ...corsHeaders, 'Content-Type': 'application/json' }
			});
		}
		
		try {
			if (path === '/api/login' && request.method === 'POST') {
				return await handleLogin(request, env.DB, corsHeaders);
			}
			else if (path === '/api/chats' && request.method === 'GET') {
				return await handleGetChats(request, env.DB, corsHeaders);
			}
			else if (path === '/api/chats' && request.method === 'POST') {
				return await handleCreateChat(request, env.DB, corsHeaders, clientIP);
			}
			else if (path === '/api/messages' && request.method === 'GET') {
				return await handleGetMessages(request, env.DB, corsHeaders);
			}
			else if (path === '/api/messages' && request.method === 'POST') {
				return await handleSendMessage(request, env.DB, corsHeaders, clientIP);
			}
			else if (path.startsWith('/api/messages/') && request.method === 'PUT') {
				return await handleUpdateMessage(request, env.DB, corsHeaders);
			}
			else if (path.startsWith('/api/messages/') && request.method === 'DELETE') {
				return await handleDeleteMessage(request, env.DB, corsHeaders);
			}
			else if (path === '/api/typing' && request.method === 'POST') {
				return await handleTyping(request, env.DB, corsHeaders);
			}
			else if (path === '/api/typing' && request.method === 'GET') {
				return await handleGetTyping(request, env.DB, corsHeaders);
			}
			else if (path === '/api/user/status' && request.method === 'POST') {
				return await handleUserStatus(request, env.DB, corsHeaders);
			}
			else if (path === '/api/contacts' && request.method === 'POST') {
				return await handleContacts(request, env.DB, corsHeaders);
			}
			else if (path === '/api/search' && request.method === 'GET') {
				return await handleSearch(request, env.DB, corsHeaders);
			}
			else if (path === '/api/query' && request.method === 'POST') {
				return await handleQuery(request, env.DB, corsHeaders);
			}
			else if (path === '/api/clear-chat' && request.method === 'POST') {
				return await handleClearChat(request, env.DB, corsHeaders);
			}
			else if (path === '/api/user/rename' && request.method === 'POST') {
				return await handleUserRename(request, env.DB, corsHeaders);
			}
			else if (path === '/api/group/rename' && request.method === 'POST') {
				return await handleGroupRename(request, env.DB, corsHeaders);
			}
			else if (path === '/api/group/member' && request.method === 'POST') {
				return await handleGroupAddMember(request, env.DB, corsHeaders);
			}
			else if (path === '/api/group/member' && request.method === 'DELETE') {
				return await handleGroupRemoveMember(request, env.DB, corsHeaders);
			}
			else if (path === '/api/group' && request.method === 'DELETE') {
				return await handleGroupDelete(request, env.DB, corsHeaders);
			}
			else {
				return new Response(JSON.stringify({ success: false, error: 'Not Found' }), {
					status: 404,
					headers: { ...corsHeaders, 'Content-Type': 'application/json' }
				});
			}
		} catch (error) {
			console.error('Worker error:', error);
			return new Response(JSON.stringify({ success: false, error: 'Internal server error' }), {
				status: 500,
				headers: { ...corsHeaders, 'Content-Type': 'application/json' }
			});
		}
	}
};

// ============ HANDLERS ============

async function handleLogin(request: Request, db: D1Database, corsHeaders: Record<string, string>): Promise<Response> {
	let body: any;
	try {
		body = await request.json();
	} catch {
		return jsonResponse({ success: false, error: 'Invalid JSON' }, 400, corsHeaders);
	}
	
	const { userId } = body;
	if (!isValidId(userId)) {
		return jsonResponse({ success: false, error: 'ID должен быть 3-32 символа' }, 400, corsHeaders);
	}
	
	try {
		const user = await db.prepare('SELECT * FROM users WHERE id = ?').bind(userId).first();
		
		if (user) {
			await db.prepare('UPDATE users SET is_online = 1, last_seen = CURRENT_TIMESTAMP WHERE id = ?').bind(userId).run();
			return jsonResponse({ 
				success: true, 
				user: { ...user, is_online: 1, contacts: safeJsonParse(user.contacts as string) }
			}, 200, corsHeaders);
		} else {
			const newUser = {
				id: userId,
				avatar: userId.charAt(0).toUpperCase(),
				contacts: [],
				is_online: 1,
				created_at: new Date().toISOString()
			};
			
			await db.prepare('INSERT INTO users (id, avatar, contacts, is_online, created_at) VALUES (?, ?, ?, ?, ?)')
				.bind(newUser.id, newUser.avatar, JSON.stringify(newUser.contacts), 1, newUser.created_at).run();
			
			return jsonResponse({ success: true, user: newUser }, 200, corsHeaders);
		}
	} catch (error) {
		return jsonResponse({ success: false, error: 'Database error' }, 500, corsHeaders);
	}
}

async function handleGetChats(request: Request, db: D1Database, corsHeaders: Record<string, string>): Promise<Response> {
	const url = new URL(request.url);
	const userId = url.searchParams.get('userId');
	const offset = parseInt(url.searchParams.get('offset') || '0');
	const limit = Math.min(parseInt(url.searchParams.get('limit') || '50'), 100);
	
	if (!userId || !isValidId(userId)) {
		return jsonResponse({ success: false, error: 'Invalid userId' }, 400, corsHeaders);
	}
	
	try {
		const chats = await db.prepare(
			`SELECT c.* FROM chats c
			 JOIN chat_members cm ON c.id = cm.chat_id
			 WHERE cm.user_id = ?
			 ORDER BY c.updated_at DESC 
			 LIMIT ? OFFSET ?`
		).bind(userId, limit, offset).all();
		
		const userChats = [];
		for (const chat of chats.results) {
			const members = safeJsonParse(chat.members as string, []);
			
			const stats = await db.prepare(
				`SELECT 
					(SELECT COUNT(*) FROM messages 
					 WHERE chat_id = ? AND sender_id != ? 
					 AND (read_by IS NULL OR read_by NOT LIKE ?)
					 AND (deleted_for IS NULL OR deleted_for NOT LIKE ?)
					 AND is_system = 0) as unread_count,
					(SELECT text FROM messages 
					 WHERE chat_id = ? AND (deleted_for IS NULL OR deleted_for NOT LIKE ?)
					 AND is_system = 0 ORDER BY timestamp DESC LIMIT 1) as last_message,
					(SELECT timestamp FROM messages 
					 WHERE chat_id = ? AND (deleted_for IS NULL OR deleted_for NOT LIKE ?)
					 AND is_system = 0 ORDER BY timestamp DESC LIMIT 1) as last_time`
			).bind(
				chat.id, userId, `%"${userId}"%`, `%"${userId}"%`,
				chat.id, `%"${userId}"%`,
				chat.id, `%"${userId}"%`
			).first();
			
			userChats.push({
				...chat,
				members,
				unreadCount: (stats?.unread_count as number) || 0,
				lastMessage: (stats?.last_message as string) || '',
				lastTime: stats?.last_time ? new Date(stats.last_time as string).toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' }) : ''
			});
		}
		
		return jsonResponse({ success: true, chats: userChats }, 200, corsHeaders);
	} catch (error) {
		return jsonResponse({ success: false, error: 'Database error' }, 500, corsHeaders);
	}
}

async function handleCreateChat(request: Request, db: D1Database, corsHeaders: Record<string, string>, clientIP: string): Promise<Response> {
	const allowed = await checkRateLimit(db, `create:${clientIP}`, RATE_LIMIT_CREATE);
	if (!allowed) {
		return jsonResponse({ success: false, error: 'Too many chats created' }, 429, corsHeaders);
	}
	
	let body: any;
	try {
		body = await request.json();
	} catch {
		return jsonResponse({ success: false, error: 'Invalid JSON' }, 400, corsHeaders);
	}
	
	const { type, name, members } = body;
	
	if (!['private', 'group', 'notes'].includes(type)) {
		return jsonResponse({ success: false, error: 'Invalid chat type' }, 400, corsHeaders);
	}
	
	if (!Array.isArray(members) || members.length === 0 || !members.every(isValidId)) {
		return jsonResponse({ success: false, error: 'Invalid members' }, 400, corsHeaders);
	}
	
	try {
		let chatId: string;
		if (type === 'private') {
			const sortedMembers = [...members].sort();
			chatId = `private_${sortedMembers.join('_')}`;
			
			const existing = await db.prepare('SELECT * FROM chats WHERE id = ?').bind(chatId).first();
			if (existing) {
				return jsonResponse({ 
					success: true, 
					chat: { ...existing, members: safeJsonParse(existing.members as string) }
				}, 200, corsHeaders);
			}
		} else {
			chatId = generateId();
		}
		
		const chatName = name?.slice(0, 100) || (type === 'private' ? members.join(', ') : 'Новая группа');
		
		const statements: D1PreparedStatement[] = [];
		
		statements.push(db.prepare(
			`INSERT INTO chats (id, type, name, members, created_at, updated_at) 
			 VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`
		).bind(chatId, type, chatName, JSON.stringify(members)));
		
		for (const memberId of members) {
			statements.push(db.prepare(
				`INSERT INTO chat_members (chat_id, user_id, is_admin) VALUES (?, ?, ?)`
			).bind(chatId, memberId, memberId === members[0] ? 1 : 0));
		}
		
		let systemText = '';
		if (type === 'group') systemText = `👥 Группа "${chatName}" создана`;
		else if (type === 'notes') systemText = '📝 Чат для заметок создан';
		else systemText = '💬 Приватный чат создан';
		
		statements.push(db.prepare(
			`INSERT INTO messages (id, chat_id, sender_id, text, timestamp, is_system) 
			 VALUES (?, ?, 'system', ?, CURRENT_TIMESTAMP, 1)`
		).bind(generateId(), chatId, systemText));
		
		await db.batch(statements);
		
		return jsonResponse({
			success: true,
			chat: {
				id: chatId,
				type,
				name: chatName,
				members,
				created_at: new Date().toISOString(),
				updated_at: new Date().toISOString()
			}
		}, 200, corsHeaders);
	} catch (error) {
		return jsonResponse({ success: false, error: 'Database error' }, 500, corsHeaders);
	}
}

async function handleGetMessages(request: Request, db: D1Database, corsHeaders: Record<string, string>): Promise<Response> {
	const url = new URL(request.url);
	const chatId = url.searchParams.get('chatId');
	const userId = url.searchParams.get('userId');
	const limit = Math.min(parseInt(url.searchParams.get('limit') || '50'), 100);
	const offset = parseInt(url.searchParams.get('offset') || '0');
	
	if (!chatId || !userId || !isValidId(userId)) {
		return jsonResponse({ success: false, error: 'Invalid parameters' }, 400, corsHeaders);
	}
	
	try {
		const membership = await db.prepare(
			'SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?'
		).bind(chatId, userId).first();
		
		if (!membership) {
			return jsonResponse({ success: false, error: 'Access denied' }, 403, corsHeaders);
		}
		
		const escapedUserId = escapeLike(userId);
		const pattern = `%"${escapedUserId}"%`;
		
		const messages = await db.prepare(
			`SELECT id, chat_id, sender_id, text, timestamp, read_by, edited_at, is_system 
			 FROM messages 
			 WHERE chat_id = ? AND (deleted_for IS NULL OR deleted_for NOT LIKE ?)
			 ORDER BY timestamp ASC LIMIT ? OFFSET ?`
		).bind(chatId, pattern, limit, offset).all();
		
		const parsedMessages = messages.results.map(msg => ({
			...msg,
			read_by: safeJsonParse(msg.read_by as string, [])
		}));
		
		const updatePromises = parsedMessages
			.filter(m => !m.is_system && m.sender_id !== userId && !m.read_by.includes(userId))
			.map(m => {
				const newReadBy = [...m.read_by, userId];
				return db.prepare('UPDATE messages SET read_by = ? WHERE id = ?')
					.bind(JSON.stringify(newReadBy), m.id).run();
			});
		
		Promise.all(updatePromises).catch(console.error);
		
		return jsonResponse({ success: true, messages: parsedMessages }, 200, corsHeaders);
	} catch (error) {
		return jsonResponse({ success: false, error: 'Database error' }, 500, corsHeaders);
	}
}

async function handleSendMessage(request: Request, db: D1Database, corsHeaders: Record<string, string>, clientIP: string): Promise<Response> {
	const allowed = await checkRateLimit(db, `msg:${clientIP}`, RATE_LIMIT_MESSAGE);
	if (!allowed) {
		return jsonResponse({ success: false, error: 'Too many messages' }, 429, corsHeaders);
	}
	
	let body: any;
	try {
		body = await request.json();
	} catch {
		return jsonResponse({ success: false, error: 'Invalid JSON' }, 400, corsHeaders);
	}
	
	const { chatId, senderId, text } = body;
	
	if (!chatId || !isValidId(senderId) || !text || typeof text !== 'string' || text.length > 4000) {
		return jsonResponse({ success: false, error: 'Invalid parameters' }, 400, corsHeaders);
	}
	
	const trimmedText = text.trim();
	if (!trimmedText) {
		return jsonResponse({ success: false, error: 'Empty message' }, 400, corsHeaders);
	}
	
	try {
		const membership = await db.prepare(
			'SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?'
		).bind(chatId, senderId).first();
		
		if (!membership) {
			return jsonResponse({ success: false, error: 'Access denied' }, 403, corsHeaders);
		}
		
		const messageId = generateId();
		
		await db.batch([
			db.prepare(
				`INSERT INTO messages (id, chat_id, sender_id, text, timestamp, read_by, is_system) 
				 VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, ?, 0)`
			).bind(messageId, chatId, senderId, trimmedText.slice(0, 4000), JSON.stringify([senderId])),
			
			db.prepare('UPDATE chats SET updated_at = CURRENT_TIMESTAMP WHERE id = ?').bind(chatId)
		]);
		
		return jsonResponse({
			success: true,
			message: {
				id: messageId,
				chat_id: chatId,
				sender_id: senderId,
				text: trimmedText.slice(0, 4000),
				timestamp: new Date().toISOString(),
				read_by: [senderId],
				is_system: 0
			}
		}, 200, corsHeaders);
	} catch (error) {
		return jsonResponse({ success: false, error: 'Database error' }, 500, corsHeaders);
	}
}

async function handleUpdateMessage(request: Request, db: D1Database, corsHeaders: Record<string, string>): Promise<Response> {
	const url = new URL(request.url);
	const messageId = url.pathname.split('/').pop();
	
	let body: any;
	try {
		body = await request.json();
	} catch {
		return jsonResponse({ success: false, error: 'Invalid JSON' }, 400, corsHeaders);
	}
	
	const { text } = body;
	
	if (!messageId || !text || typeof text !== 'string' || text.length > 4000) {
		return jsonResponse({ success: false, error: 'Invalid parameters' }, 400, corsHeaders);
	}
	
	const trimmedText = text.trim();
	if (!trimmedText) {
		return jsonResponse({ success: false, error: 'Empty message' }, 400, corsHeaders);
	}
	
	try {
		const result = await db.prepare(
			'UPDATE messages SET text = ?, edited_at = CURRENT_TIMESTAMP WHERE id = ? AND is_system = 0'
		).bind(trimmedText.slice(0, 4000), messageId).run();
		
		return jsonResponse({ success: true }, 200, corsHeaders);
	} catch (error) {
		return jsonResponse({ success: false, error: 'Database error' }, 500, corsHeaders);
	}
}

async function handleDeleteMessage(request: Request, db: D1Database, corsHeaders: Record<string, string>): Promise<Response> {
	const url = new URL(request.url);
	const messageId = url.pathname.split('/').pop();
	
	let body: any;
	try {
		body = await request.json();
	} catch {
		return jsonResponse({ success: false, error: 'Invalid JSON' }, 400, corsHeaders);
	}
	
	const { userId, isMyMessage } = body;
	
	if (!messageId || !isValidId(userId)) {
		return jsonResponse({ success: false, error: 'Invalid parameters' }, 400, corsHeaders);
	}
	
	try {
		if (isMyMessage) {
			const msg = await db.prepare('SELECT sender_id FROM messages WHERE id = ?').bind(messageId).first();
			if (!msg || msg.sender_id !== userId) {
				return jsonResponse({ success: false, error: 'Not authorized' }, 403, corsHeaders);
			}
			await db.prepare('DELETE FROM messages WHERE id = ?').bind(messageId).run();
		} else {
			const message = await db.prepare('SELECT deleted_for FROM messages WHERE id = ?').bind(messageId).first();
			if (message) {
				let deletedFor = safeJsonParse(message.deleted_for as string, []);
				if (!deletedFor.includes(userId)) {
					deletedFor.push(userId);
					await db.prepare('UPDATE messages SET deleted_for = ? WHERE id = ?')
						.bind(JSON.stringify(deletedFor), messageId).run();
				}
			}
		}
		
		return jsonResponse({ success: true }, 200, corsHeaders);
	} catch (error) {
		return jsonResponse({ success: false, error: 'Database error' }, 500, corsHeaders);
	}
}

async function handleTyping(request: Request, db: D1Database, corsHeaders: Record<string, string>): Promise<Response> {
	let body: any;
	try {
		body = await request.json();
	} catch {
		return jsonResponse({ success: false, error: 'Invalid JSON' }, 400, corsHeaders);
	}
	
	const { chatId, userId, isTyping } = body;
	
	if (!chatId || !isValidId(userId)) {
		return jsonResponse({ success: false, error: 'Invalid parameters' }, 400, corsHeaders);
	}
	
	try {
		const membership = await db.prepare(
			'SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?'
		).bind(chatId, userId).first();
		
		if (!membership) {
			return jsonResponse({ success: false, error: 'Access denied' }, 403, corsHeaders);
		}
		
		if (isTyping) {
			await db.prepare('DELETE FROM typing WHERE typing_time < ?').bind(Date.now() - 10000).run();
			await db.prepare(
				'INSERT OR REPLACE INTO typing (chat_id, user_id, typing_time) VALUES (?, ?, ?)'
			).bind(chatId, userId, Date.now()).run();
		} else {
			await db.prepare('DELETE FROM typing WHERE chat_id = ? AND user_id = ?').bind(chatId, userId).run();
		}
		
		return jsonResponse({ success: true }, 200, corsHeaders);
	} catch (error) {
		return jsonResponse({ success: false, error: 'Database error' }, 500, corsHeaders);
	}
}

async function handleGetTyping(request: Request, db: D1Database, corsHeaders: Record<string, string>): Promise<Response> {
	const url = new URL(request.url);
	const chatId = url.searchParams.get('chatId');
	
	if (!chatId) {
		return jsonResponse({ success: false, error: 'Missing chatId' }, 400, corsHeaders);
	}
	
	try {
		await db.prepare('DELETE FROM typing WHERE typing_time < ?').bind(Date.now() - 10000).run();
		const typing = await db.prepare('SELECT user_id FROM typing WHERE chat_id = ?').bind(chatId).all();
		
		return jsonResponse({ success: true, typing: typing.results.map(t => t.user_id) }, 200, corsHeaders);
	} catch (error) {
		return jsonResponse({ success: false, error: 'Database error' }, 500, corsHeaders);
	}
}

async function handleUserStatus(request: Request, db: D1Database, corsHeaders: Record<string, string>): Promise<Response> {
	let body: any;
	try {
		body = await request.json();
	} catch {
		return jsonResponse({ success: false, error: 'Invalid JSON' }, 400, corsHeaders);
	}
	
	const { userId, isOnline } = body;
	
	if (!isValidId(userId)) {
		return jsonResponse({ success: false, error: 'Invalid userId' }, 400, corsHeaders);
	}
	
	try {
		await db.prepare(
			'UPDATE users SET is_online = ?, last_seen = CURRENT_TIMESTAMP WHERE id = ?'
		).bind(isOnline ? 1 : 0, userId).run();
		
		return jsonResponse({ success: true }, 200, corsHeaders);
	} catch (error) {
		return jsonResponse({ success: false, error: 'Database error' }, 500, corsHeaders);
	}
}

async function handleContacts(request: Request, db: D1Database, corsHeaders: Record<string, string>): Promise<Response> {
	let body: any;
	try {
		body = await request.json();
	} catch {
		return jsonResponse({ success: false, error: 'Invalid JSON' }, 400, corsHeaders);
	}
	
	const { userId, contactId, action } = body;
	
	if (!isValidId(userId) || !isValidId(contactId) || !['add', 'remove'].includes(action)) {
		return jsonResponse({ success: false, error: 'Invalid parameters' }, 400, corsHeaders);
	}
	
	try {
		const user = await db.prepare('SELECT contacts FROM users WHERE id = ?').bind(userId).first();
		if (!user) {
			return jsonResponse({ success: false, error: 'User not found' }, 404, corsHeaders);
		}
		
		let contacts = safeJsonParse(user.contacts as string, []);
		
		if (action === 'add') {
			if (!contacts.includes(contactId)) contacts.push(contactId);
		} else {
			contacts = contacts.filter((id: string) => id !== contactId);
		}
		
		await db.prepare('UPDATE users SET contacts = ? WHERE id = ?').bind(JSON.stringify(contacts), userId).run();
		
		return jsonResponse({ success: true, contacts }, 200, corsHeaders);
	} catch (error) {
		return jsonResponse({ success: false, error: 'Database error' }, 500, corsHeaders);
	}
}

async function handleSearch(request: Request, db: D1Database, corsHeaders: Record<string, string>): Promise<Response> {
	const url = new URL(request.url);
	const query = url.searchParams.get('q')?.trim();
	const userId = url.searchParams.get('userId');
	
	if (!query || query.length > 100 || !userId || !isValidId(userId)) {
		return jsonResponse({ success: false, error: 'Invalid parameters' }, 400, corsHeaders);
	}
	
	try {
		const userChats = await db.prepare(
			`SELECT c.id FROM chats c
			 JOIN chat_members cm ON c.id = cm.chat_id
			 WHERE cm.user_id = ?`
		).bind(userId).all();
		
		const chatIds = userChats.results.map(c => c.id);
		
		if (chatIds.length === 0) {
			return jsonResponse({ success: true, results: [] }, 200, corsHeaders);
		}
		
		const placeholders = chatIds.map(() => '?').join(',');
		const escapedUserId = escapeLike(userId);
		const pattern = `%"${escapedUserId}"%`;
		const searchPattern = `%${escapeLike(query)}%`;
		
		const messages = await db.prepare(
			`SELECT m.id, m.chat_id, m.sender_id, m.text, m.timestamp, c.name as chat_name
			 FROM messages m
			 JOIN chats c ON m.chat_id = c.id
			 WHERE m.text LIKE ? AND m.chat_id IN (${placeholders})
			 AND m.is_system = 0 AND (m.deleted_for IS NULL OR m.deleted_for NOT LIKE ?)
			 ORDER BY m.timestamp DESC LIMIT 50`
		).bind(searchPattern, ...chatIds, pattern).all();
		
		return jsonResponse({ success: true, results: messages.results }, 200, corsHeaders);
	} catch (error) {
		return jsonResponse({ success: false, error: 'Database error' }, 500, corsHeaders);
	}
}

async function handleQuery(request: Request, db: D1Database, corsHeaders: Record<string, string>): Promise<Response> {
	let body: any;
	try {
		body = await request.json();
	} catch {
		return jsonResponse({ success: false, error: 'Invalid JSON' }, 400, corsHeaders);
	}
	
	const { sql, params } = body;
	
	if (typeof sql !== 'string') {
		return jsonResponse({ success: false, error: 'SQL must be string' }, 400, corsHeaders);
	}
	
	const normalizedSql = sql.trim().toLowerCase();
	if (!normalizedSql.startsWith('select')) {
		return jsonResponse({ success: false, error: 'Only SELECT queries allowed' }, 403, corsHeaders);
	}
	
	const forbidden = ['insert', 'update', 'delete', 'drop', 'create', 'alter', 'pragma', 'attach', 'detach'];
	if (forbidden.some(f => normalizedSql.includes(f))) {
		return jsonResponse({ success: false, error: 'Query contains forbidden keywords' }, 403, corsHeaders);
	}
	
	try {
		const stmt = db.prepare(sql);
		const result = Array.isArray(params) && params.length > 0 
			? await stmt.bind(...params).all() 
			: await stmt.all();
		
		return jsonResponse({ success: true, result: result.results }, 200, corsHeaders);
	} catch (error) {
		return jsonResponse({ success: false, error: 'Query execution failed' }, 500, corsHeaders);
	}
}

async function handleClearChat(request: Request, db: D1Database, corsHeaders: Record<string, string>): Promise<Response> {
	let body: any;
	try {
		body = await request.json();
	} catch {
		return jsonResponse({ success: false, error: 'Invalid JSON' }, 400, corsHeaders);
	}
	
	const { chatId, userId } = body;
	
	if (!chatId || !isValidId(userId)) {
		return jsonResponse({ success: false, error: 'Invalid parameters' }, 400, corsHeaders);
	}
	
	try {
		const membership = await db.prepare(
			'SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?'
		).bind(chatId, userId).first();
		
		if (!membership) {
			return jsonResponse({ success: false, error: 'Access denied' }, 403, corsHeaders);
		}
		
		const messages = await db.prepare('SELECT id, deleted_for FROM messages WHERE chat_id = ?').bind(chatId).all();
		
		const statements: D1PreparedStatement[] = [];
		
		for (const msg of messages.results) {
			let deletedFor = safeJsonParse(msg.deleted_for as string, []);
			if (!deletedFor.includes(userId)) {
				deletedFor.push(userId);
				statements.push(db.prepare('UPDATE messages SET deleted_for = ? WHERE id = ?')
					.bind(JSON.stringify(deletedFor), msg.id));
			}
		}
		
		statements.push(db.prepare(
			`INSERT INTO messages (id, chat_id, sender_id, text, timestamp, is_system) 
			 VALUES (?, ?, 'system', ?, CURRENT_TIMESTAMP, 1)`
		).bind(generateId(), chatId, `🧹 История очищена`));
		
		if (statements.length > 0) {
			await db.batch(statements);
		}
		
		return jsonResponse({ success: true }, 200, corsHeaders);
	} catch (error) {
		return jsonResponse({ success: false, error: 'Database error' }, 500, corsHeaders);
	}
}

async function handleUserRename(request: Request, db: D1Database, corsHeaders: Record<string, string>): Promise<Response> {
	let body: any;
	try {
		body = await request.json();
	} catch {
		return jsonResponse({ success: false, error: 'Invalid JSON' }, 400, corsHeaders);
	}
	
	const { oldUserId, newUserId } = body;
	
	if (!isValidId(oldUserId) || !isValidId(newUserId)) {
		return jsonResponse({ success: false, error: 'Invalid user IDs' }, 400, corsHeaders);
	}
	
	if (oldUserId === newUserId) {
		return jsonResponse({ success: false, error: 'New ID must be different' }, 400, corsHeaders);
	}
	
	try {
		const oldUser = await db.prepare('SELECT 1 FROM users WHERE id = ?').bind(oldUserId).first();
		if (!oldUser) {
			return jsonResponse({ success: false, error: 'Old user ID not found' }, 404, corsHeaders);
		}
		
		const existingNew = await db.prepare('SELECT 1 FROM users WHERE id = ?').bind(newUserId).first();
		if (existingNew) {
			return jsonResponse({ success: false, error: 'New user ID already exists' }, 409, corsHeaders);
		}
		
		await db.batch([
			db.prepare('UPDATE users SET id = ?, avatar = ? WHERE id = ?').bind(newUserId, newUserId.charAt(0).toUpperCase(), oldUserId),
			db.prepare('UPDATE messages SET sender_id = ? WHERE sender_id = ?').bind(newUserId, oldUserId),
			db.prepare('UPDATE chat_members SET user_id = ? WHERE user_id = ?').bind(newUserId, oldUserId),
			db.prepare('UPDATE typing SET user_id = ? WHERE user_id = ?').bind(newUserId, oldUserId),
		]);
		
		return jsonResponse({ success: true, newUserId }, 200, corsHeaders);
	} catch (error) {
		return jsonResponse({ success: false, error: 'Database error' }, 500, corsHeaders);
	}
}

async function handleGroupRename(request: Request, db: D1Database, corsHeaders: Record<string, string>): Promise<Response> {
	let body: any;
	try {
		body = await request.json();
	} catch {
		return jsonResponse({ success: false, error: 'Invalid JSON' }, 400, corsHeaders);
	}
	
	const { chatId, userId, newName } = body;
	
	if (!chatId || !isValidId(userId) || !newName || typeof newName !== 'string') {
		return jsonResponse({ success: false, error: 'Invalid parameters' }, 400, corsHeaders);
	}
	
	const trimmedName = newName.trim().slice(0, 100);
	if (!trimmedName) {
		return jsonResponse({ success: false, error: 'Empty name' }, 400, corsHeaders);
	}
	
	try {
		const membership = await db.prepare(
			'SELECT is_admin FROM chat_members WHERE chat_id = ? AND user_id = ?'
		).bind(chatId, userId).first();
		
		if (!membership) {
			return jsonResponse({ success: false, error: 'Access denied' }, 403, corsHeaders);
		}
		
		await db.prepare('UPDATE chats SET name = ? WHERE id = ?').bind(trimmedName, chatId).run();
		
		await db.prepare(
			`INSERT INTO messages (id, chat_id, sender_id, text, timestamp, is_system) 
			 VALUES (?, ?, 'system', ?, CURRENT_TIMESTAMP, 1)`
		).bind(generateId(), chatId, `✏️ Группа переименована в "${trimmedName}"`).run();
		
		return jsonResponse({ success: true }, 200, corsHeaders);
	} catch (error) {
		return jsonResponse({ success: false, error: 'Database error' }, 500, corsHeaders);
	}
}

async function handleGroupAddMember(request: Request, db: D1Database, corsHeaders: Record<string, string>): Promise<Response> {
	let body: any;
	try {
		body = await request.json();
	} catch {
		return jsonResponse({ success: false, error: 'Invalid JSON' }, 400, corsHeaders);
	}
	
	const { chatId, userId, newMemberId } = body;
	
	if (!chatId || !isValidId(userId) || !isValidId(newMemberId)) {
		return jsonResponse({ success: false, error: 'Invalid parameters' }, 400, corsHeaders);
	}
	
	try {
		const membership = await db.prepare(
			'SELECT is_admin FROM chat_members WHERE chat_id = ? AND user_id = ?'
		).bind(chatId, userId).first();
		
		if (!membership) {
			return jsonResponse({ success: false, error: 'Access denied' }, 403, corsHeaders);
		}
		
		const newUser = await db.prepare('SELECT 1 FROM users WHERE id = ?').bind(newMemberId).first();
		if (!newUser) {
			return jsonResponse({ success: false, error: 'User not found' }, 404, corsHeaders);
		}
		
		await db.prepare('INSERT OR IGNORE INTO chat_members (chat_id, user_id) VALUES (?, ?)')
			.bind(chatId, newMemberId).run();
		
		const chat = await db.prepare('SELECT members FROM chats WHERE id = ?').bind(chatId).first();
		const members = safeJsonParse(chat?.members as string, []);
		if (!members.includes(newMemberId)) {
			members.push(newMemberId);
			await db.prepare('UPDATE chats SET members = ? WHERE id = ?').bind(JSON.stringify(members), chatId).run();
		}
		
		await db.prepare(
			`INSERT INTO messages (id, chat_id, sender_id, text, timestamp, is_system) 
			 VALUES (?, ?, 'system', ?, CURRENT_TIMESTAMP, 1)`
		).bind(generateId(), chatId, `➕ ${newMemberId} добавлен в группу`).run();
		
		return jsonResponse({ success: true }, 200, corsHeaders);
	} catch (error) {
		return jsonResponse({ success: false, error: 'Database error' }, 500, corsHeaders);
	}
}

async function handleGroupRemoveMember(request: Request, db: D1Database, corsHeaders: Record<string, string>): Promise<Response> {
	let body: any;
	try {
		body = await request.json();
	} catch {
		return jsonResponse({ success: false, error: 'Invalid JSON' }, 400, corsHeaders);
	}
	
	const { chatId, userId, memberIdToRemove } = body;
	
	if (!chatId || !isValidId(userId) || !isValidId(memberIdToRemove)) {
		return jsonResponse({ success: false, error: 'Invalid parameters' }, 400, corsHeaders);
	}
	
	try {
		const membership = await db.prepare(
			'SELECT is_admin FROM chat_members WHERE chat_id = ? AND user_id = ?'
		).bind(chatId, userId).first();
		
		const isSelfRemoval = userId === memberIdToRemove;
		
		if (!membership && !isSelfRemoval) {
			return jsonResponse({ success: false, error: 'Access denied' }, 403, corsHeaders);
		}
		
		await db.prepare('DELETE FROM chat_members WHERE chat_id = ? AND user_id = ?')
			.bind(chatId, memberIdToRemove).run();
		
		const chat = await db.prepare('SELECT members FROM chats WHERE id = ?').bind(chatId).first();
		const members = safeJsonParse(chat?.members as string, []).filter((id: string) => id !== memberIdToRemove);
		await db.prepare('UPDATE chats SET members = ? WHERE id = ?').bind(JSON.stringify(members), chatId).run();
		
		await db.prepare(
			`INSERT INTO messages (id, chat_id, sender_id, text, timestamp, is_system) 
			 VALUES (?, ?, 'system', ?, CURRENT_TIMESTAMP, 1)`
		).bind(generateId(), chatId, `➖ ${memberIdToRemove} покинул группу`).run();
		
		return jsonResponse({ success: true }, 200, corsHeaders);
	} catch (error) {
		return jsonResponse({ success: false, error: 'Database error' }, 500, corsHeaders);
	}
}

async function handleGroupDelete(request: Request, db: D1Database, corsHeaders: Record<string, string>): Promise<Response> {
	let body: any;
	try {
		body = await request.json();
	} catch {
		return jsonResponse({ success: false, error: 'Invalid JSON' }, 400, corsHeaders);
	}
	
	const { chatId, userId } = body;
	
	if (!chatId || !isValidId(userId)) {
		return jsonResponse({ success: false, error: 'Invalid parameters' }, 400, corsHeaders);
	}
	
	try {
		const membership = await db.prepare(
			'SELECT is_admin FROM chat_members WHERE chat_id = ? AND user_id = ?'
		).bind(chatId, userId).first();
		
		if (!(membership?.is_admin as number)) {
			return jsonResponse({ success: false, error: 'Only admin can delete group' }, 403, corsHeaders);
		}
		
		await db.prepare('DELETE FROM chats WHERE id = ?').bind(chatId).run();
		
		return jsonResponse({ success: true }, 200, corsHeaders);
	} catch (error) {
		return jsonResponse({ success: false, error: 'Database error' }, 500, corsHeaders);
	}
}

// Helper function
function jsonResponse(data: any, status: number, corsHeaders: Record<string, string>): Response {
	return new Response(JSON.stringify(data), {
		status,
		headers: { ...corsHeaders, 'Content-Type': 'application/json' }
	});
}
