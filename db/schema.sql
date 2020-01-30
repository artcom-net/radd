-- noinspection SqlNoDataSourceInspectionForFile

CREATE TABLE users (
  id INTEGER PRIMARY KEY,
  login TEXT NOT NULL,
  password TEXT,
  ip TEXT,
  mac TEXT
);

CREATE TABLE nas (
  id INTEGER PRIMARY KEY,
  ip TEXT NOT NULL,
  secret TEXT NOT NULL,
  auth_type INTEGER DEFAULT 0
);

CREATE TABLE sessions (
  id INTEGER PRIMARY KEY,
  -- UNIQUE??
  session_id TEXT NOT NULL,
  time_start TEXT NOT NULL,
  time_stop TEXT,
  input_octets INTEGER,
  output_octets INTEGER,
  -- ON UPDATE NO ACTION - it's need?
  FOREIGN KEY (id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE TABLE dictionary (
  id INTEGER PRIMARY KEY,
  code INTEGER NOT NULL UNIQUE,
  type INTEGER NOT NULL,
  name TEXT NOT NULL UNIQUE
);

CREATE TABLE reply_attrs (
  id INTEGER PRIMARY KEY,
  user_id INTEGER,
  reply_code INTEGER NOT NULL,
  attr_id INTEGER,
  attr_value TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
  FOREIGN KEY (attr_id) REFERENCES dictionary (id) ON DELETE CASCADE
);