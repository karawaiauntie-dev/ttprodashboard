const Database = require("better-sqlite3");
const path = require("path");
const fs = require("fs");

// Railway persistent volume, otherwise project directory
const dataDir =
    process.env.RAILWAY_VOLUME_MOUNT_PATH || __dirname;

if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
}

const db = new Database(
    path.join(dataDir, "database.sqlite")
);

db.pragma("foreign_keys = ON");

/* ========================================
   HELPERS
======================================== */

function getColumns(table) {
    return db
        .prepare(`PRAGMA table_info(${table})`)
        .all()
        .map(row => row.name);
}

/* ========================================
   USERS
======================================== */

db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        name TEXT NOT NULL,
        phone TEXT,
        password_hash TEXT,
        verified INTEGER NOT NULL DEFAULT 1,
        status TEXT NOT NULL DEFAULT 'active',
        last_ip TEXT,
        last_device TEXT,
        last_login TEXT,
        balance REAL NOT NULL DEFAULT 0,
        invitation_code TEXT UNIQUE,
        referred_by INTEGER,
        total_referrals INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,

        FOREIGN KEY (referred_by)
            REFERENCES users(id)
            ON DELETE SET NULL
    )
`);

/* ========================================
   USERNAME MIGRATION
======================================== */

let userColumns = getColumns("users");

if (!userColumns.includes("username")) {
    db.exec(`
        ALTER TABLE users
        ADD COLUMN username TEXT
    `);

    console.log("Added users.username");
}

/*
 * Old accounts may have no username.
 * Generate a temporary unique username from their ID.
 */
const usersWithoutUsername = db
    .prepare(`
        SELECT id, name
        FROM users
        WHERE username IS NULL OR TRIM(username) = ''
    `)
    .all();

for (const user of usersWithoutUsername) {
    const base = String(user.name || "user")
        .toLowerCase()
        .replace(/[^a-z0-9]/g, "")
        .substring(0, 20) || "user";

    let username = `${base}${user.id}`;

    while (
        db
            .prepare("SELECT id FROM users WHERE username = ?")
            .get(username)
    ) {
        username = `${base}${user.id}${Math.floor(Math.random() * 1000)}`;
    }

    db.prepare(`
        UPDATE users
        SET username = ?
        WHERE id = ?
    `).run(username, user.id);
}

/* ========================================
   ADMINS
======================================== */

db.exec(`
    CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
`);

/* ========================================
   LOGIN HISTORY
======================================== */

db.exec(`
    CREATE TABLE IF NOT EXISTS login_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        success INTEGER NOT NULL DEFAULT 0,
        ip_address TEXT,
        user_agent TEXT,
        created_at TEXT NOT NULL,

        FOREIGN KEY (user_id)
            REFERENCES users(id)
            ON DELETE CASCADE
    )
`);

/* ========================================
   SETTLEMENTS
======================================== */

db.exec(`
    CREATE TABLE IF NOT EXISTS settlements (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        reference TEXT,
        amount REAL NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'Pending',
        created_at TEXT NOT NULL,

        FOREIGN KEY (user_id)
            REFERENCES users(id)
            ON DELETE CASCADE
    )
`);

/* ========================================
   NOTIFICATIONS
======================================== */

db.exec(`
    CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        message TEXT NOT NULL,
        is_read INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,

        FOREIGN KEY (user_id)
            REFERENCES users(id)
            ON DELETE CASCADE
    )
`);

/* ========================================
   WITHDRAWALS
======================================== */

db.exec(`
    CREATE TABLE IF NOT EXISTS withdrawals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        amount REAL NOT NULL,
        account_name TEXT NOT NULL,
        account_number TEXT NOT NULL,
        bank_name TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'Pending',
        note TEXT,
        created_at TEXT NOT NULL,
        processed_at TEXT,

        FOREIGN KEY (user_id)
            REFERENCES users(id)
            ON DELETE CASCADE
    )
`);

/* ========================================
   INVITATION CODES
======================================== */

db.exec(`
    CREATE TABLE IF NOT EXISTS invitation_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        code TEXT NOT NULL UNIQUE,
        owner_id INTEGER NOT NULL,
        used_by INTEGER,
        used_at TEXT,
        created_at TEXT NOT NULL,

        FOREIGN KEY (owner_id)
            REFERENCES users(id)
            ON DELETE CASCADE,

        FOREIGN KEY (used_by)
            REFERENCES users(id)
            ON DELETE SET NULL
    )
`);

/* ========================================
   TASKS
======================================== */

db.exec(`
    CREATE TABLE IF NOT EXISTS tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT,
        reward REAL NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'active',
        created_at TEXT NOT NULL
    )
`);

/* ========================================
   TASK COMPLETIONS
======================================== */

db.exec(`
    CREATE TABLE IF NOT EXISTS task_completions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        task_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        proof TEXT,
        status TEXT NOT NULL DEFAULT 'Pending',
        reviewed_at TEXT,
        created_at TEXT NOT NULL,

        FOREIGN KEY (task_id)
            REFERENCES tasks(id)
            ON DELETE CASCADE,

        FOREIGN KEY (user_id)
            REFERENCES users(id)
            ON DELETE CASCADE
    )
`);

/* ========================================
   GLOBAL CHAT
======================================== */

db.exec(`
    CREATE TABLE IF NOT EXISTS chat_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        message TEXT NOT NULL,
        created_at TEXT NOT NULL,

        FOREIGN KEY (user_id)
            REFERENCES users(id)
            ON DELETE CASCADE
    )
`);

db.exec(`
    CREATE INDEX IF NOT EXISTS idx_chat_created
    ON chat_messages (created_at DESC)
`);

/* ========================================
   USERS MIGRATIONS
======================================== */

userColumns = getColumns("users");

const migrations = [
    {
        column: "password_hash",
        sql: `
            ALTER TABLE users
            ADD COLUMN password_hash TEXT
        `
    },
    {
        column: "verified",
        sql: `
            ALTER TABLE users
            ADD COLUMN verified INTEGER NOT NULL DEFAULT 1
        `
    },
    {
        column: "status",
        sql: `
            ALTER TABLE users
            ADD COLUMN status TEXT NOT NULL DEFAULT 'active'
        `
    },
    {
        column: "last_ip",
        sql: `
            ALTER TABLE users
            ADD COLUMN last_ip TEXT
        `
    },
    {
        column: "last_device",
        sql: `
            ALTER TABLE users
            ADD COLUMN last_device TEXT
        `
    },
    {
        column: "last_login",
        sql: `
            ALTER TABLE users
            ADD COLUMN last_login TEXT
        `
    },
    {
        column: "balance",
        sql: `
            ALTER TABLE users
            ADD COLUMN balance REAL NOT NULL DEFAULT 0
        `
    },
    {
        column: "phone",
        sql: `
            ALTER TABLE users
            ADD COLUMN phone TEXT
        `
    },
    {
        column: "invitation_code",
        sql: `
            ALTER TABLE users
            ADD COLUMN invitation_code TEXT
        `
    },
    {
        column: "referred_by",
        sql: `
            ALTER TABLE users
            ADD COLUMN referred_by INTEGER
        `
    },
    {
        column: "total_referrals",
        sql: `
            ALTER TABLE users
            ADD COLUMN total_referrals INTEGER NOT NULL DEFAULT 0
        `
    },
    {
        column: "avatar",
        sql: `
            ALTER TABLE users
            ADD COLUMN avatar TEXT
        `
    }
];

for (const migration of migrations) {
    if (!userColumns.includes(migration.column)) {
        db.exec(migration.sql);
        console.log(`Added users.${migration.column}`);
        userColumns = getColumns("users");
    }
}

/* ========================================
   OLD PASSWORD MIGRATION
======================================== */

userColumns = getColumns("users");

if (
    userColumns.includes("password") &&
    userColumns.includes("password_hash")
) {
    db.exec(`
        UPDATE users
        SET password_hash = password
        WHERE
            (password_hash IS NULL OR password_hash = '')
            AND password IS NOT NULL
    `);

    console.log("Migrated old passwords.");
}

/* ========================================
   FINAL CHECK
======================================== */

console.log("");
console.log("=================================");
console.log("TTPRO DATABASE READY");
console.log("=================================");

console.log(
    "Users:",
    db.prepare(
        "SELECT COUNT(*) AS count FROM users"
    ).get().count
);

console.log(
    "Admins:",
    db.prepare(
        "SELECT COUNT(*) AS count FROM admins"
    ).get().count
);

console.log(
    "Login History:",
    db.prepare(
        "SELECT COUNT(*) AS count FROM login_history"
    ).get().count
);

console.log("=================================");
console.log("");

module.exports = db;
