const crypto = require("node:crypto");
const db = require("./database");

const username = String(process.env.TTPRO_ADMIN_USERNAME || "").trim().toLowerCase();
const password = process.env.TTPRO_ADMIN_SECRET || "";

if (!username || !password) {
    console.error("Set TTPRO_ADMIN_USERNAME and TTPRO_ADMIN_SECRET before provisioning an admin.");
    process.exitCode = 1;
} else {
    const passwordHash = crypto
        .createHash("sha256")
        .update(password)
        .digest("hex");

    const existing = db
        .prepare("SELECT id FROM admins WHERE username = ?")
        .get(username);

    if (existing) {
        db.prepare(`
            UPDATE admins
            SET password_hash = ?
            WHERE username = ?
        `).run(passwordHash, username);
        console.log("Admin password updated.");
    } else {
        db.prepare(`
            INSERT INTO admins (username, password_hash, created_at)
            VALUES (?, ?, ?)
        `).run(username, passwordHash, new Date().toISOString());
        console.log("Admin account created.");
    }
}
