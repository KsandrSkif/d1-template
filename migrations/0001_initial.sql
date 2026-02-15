-- Создание таблиц
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS chats;
DROP TABLE IF EXISTS messages;
DROP TABLE IF EXISTS typing;

-- Пользователи
CREATE TABLE users (
    id TEXT PRIMARY KEY,
    last_seen TEXT DEFAULT CURRENT_TIMESTAMP,
    is_online INTEGER DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Чаты
CREATE TABLE chats (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT 'Чат',
    members TEXT NOT NULL DEFAULT '[]',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Сообщения
CREATE TABLE messages (
    id TEXT PRIMARY KEY,
    chat_id TEXT NOT NULL,
    sender_id TEXT NOT NULL,
    text TEXT NOT NULL,
    timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
    is_system INTEGER DEFAULT 0
);

-- Печатающие пользователи
CREATE TABLE typing (
    chat_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    PRIMARY KEY (chat_id, user_id)
);

-- Индексы
CREATE INDEX idx_messages_chat ON messages(chat_id, timestamp);
CREATE INDEX idx_chats_updated ON chats(updated_at DESC);
CREATE INDEX idx_typing_cleanup ON typing(timestamp);