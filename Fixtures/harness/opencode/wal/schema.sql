PRAGMA journal_mode=WAL;
PRAGMA wal_autocheckpoint=0;
CREATE TABLE session (
    id TEXT PRIMARY KEY,
    parent_id TEXT,
    directory TEXT,
    title TEXT,
    time_created INTEGER
);
CREATE TABLE message (
    id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    time_created INTEGER,
    data BLOB NOT NULL,
    PRIMARY KEY (id, session_id)
);
CREATE TABLE part (
    id TEXT NOT NULL,
    message_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    time_created INTEGER,
    data BLOB NOT NULL,
    PRIMARY KEY (id, message_id)
);
CREATE INDEX part_message_id_id_idx ON part(message_id, id);
CREATE TABLE session_v2 (
    id TEXT PRIMARY KEY,
    parent_id TEXT,
    directory TEXT,
    title TEXT,
    time_created INTEGER
);
CREATE TABLE session_message (
    id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    type TEXT NOT NULL,
    seq INTEGER NOT NULL,
    time_created INTEGER,
    data BLOB NOT NULL,
    PRIMARY KEY (id, session_id)
);
