require("dotenv").config();

const express = require("express");
const session = require("express-session");
const path = require("path");
const crypto = require("node:crypto");

const db = require("./database");

const app = express();
const PORT = process.env.PORT || 3000;
const sessionSecret = process.env.SESSION_SECRET;

if (!sessionSecret) {
    throw new Error("SESSION_SECRET must be configured.");
}

app.set("trust proxy", 1);

/* ========================================
   MIDDLEWARE
======================================== */

app.use(express.json({ limit: "10mb" }));

app.use(
    session({
        secret: sessionSecret,
        resave: false,
        saveUninitialized: false,

        cookie: {
            httpOnly: true,
            secure: "auto",
            maxAge: 30 * 60 * 1000
        }
    })
);

/* ========================================
   STATIC / PAGES
======================================== */

app.get("/admin", (req, res) => {
    res.sendFile(
        path.join(__dirname, "admin.html")
    );
});

app.use(
    express.static(
        path.join(__dirname, "public")
    )
);

app.get("/", (req, res) => {
    res.sendFile(
        path.join(__dirname, "public", "index.html")
    );
});

/* ========================================
   HELPERS
======================================== */

function hashPassword(password) {
    return crypto
        .createHash("sha256")
        .update(String(password))
        .digest("hex");
}

function getClientIP(req) {
    return (
        req.headers["x-forwarded-for"]
            ?.split(",")[0]
            ?.trim() ||
        req.socket.remoteAddress ||
        ""
    );
}

function generateInvitationCode() {
    let code;

    do {
        code =
            "TT" +
            Math.random()
                .toString(36)
                .substring(2, 8)
                .toUpperCase();
    } while (
        db
            .prepare(
                "SELECT id FROM users WHERE invitation_code = ?"
            )
            .get(code)
    );

    return code;
}

function requireUser(req, res, next) {
    if (!req.session.user) {
        return res.status(401).json({
            success: false,
            message: "Login required."
        });
    }

    next();
}

function requireAdmin(req, res, next) {
    if (!req.session.admin) {
        return res.status(401).json({
            success: false,
            message: "Admin authentication required."
        });
    }

    next();
}

/* ========================================
   REAL-TIME / LIVE CONNECTIONS
======================================== */

const liveClients = new Set();

const ACTIVE_WINDOW_MS = 2 * 60 * 1000;

function isRecentlyActive(lastSeen) {
    return Boolean(
        lastSeen &&
        Date.now() - Date.parse(lastSeen) <= ACTIVE_WINDOW_MS
    );
}

function getActiveUserCount() {
    const cutoff = new Date(
        Date.now() - ACTIVE_WINDOW_MS
    ).toISOString();

    return db
        .prepare(`
            SELECT COUNT(*) AS count
            FROM users
            WHERE last_seen IS NOT NULL
              AND last_seen >= ?
              AND status != 'frozen'
        `)
        .get(cutoff).count;
}

function broadcastLive(event, payload = {}) {
    const message =
        `event: ${event}\n` +
        `data: ${JSON.stringify(payload)}\n\n`;

    for (const client of liveClients) {
        try {
            client.res.write(message);
        } catch {
            liveClients.delete(client);
        }
    }
}

/* ========================================
   REGISTER
======================================== */

app.post("/api/register", (req, res) => {
    try {
        const {
            username,
            name,
            password,
            invite_code
        } = req.body;

        const cleanUsername = String(
            username || ""
        )
            .trim()
            .toLowerCase();

        const cleanName = String(
            name || ""
        ).trim();

        const cleanInviteCode = String(
            invite_code || ""
        )
            .trim()
            .toUpperCase();

        if (
            !cleanUsername ||
            !cleanName ||
            !password
        ) {
            return res.status(400).json({
                success: false,
                message:
                    "Username, name and password are required."
            });
        }

        if (!/^[a-z0-9_]{3,30}$/.test(cleanUsername)) {
            return res.status(400).json({
                success: false,
                message:
                    "Username must be 3-30 characters and may contain only letters, numbers and underscore."
            });
        }

        if (String(password).length < 6) {
            return res.status(400).json({
                success: false,
                message:
                    "Password must be at least 6 characters."
            });
        }

        const existingUser = db
            .prepare(`
                SELECT id
                FROM users
                WHERE username = ?
            `)
            .get(cleanUsername);

        if (existingUser) {
            return res.status(409).json({
                success: false,
                message:
                    "Username is already taken."
            });
        }

        /* ========================================
           REFERRAL
        ======================================== */

        let inviteOwnerId = null;

        if (cleanInviteCode) {
            const inviteOwner = db
                .prepare(`
                    SELECT id
                    FROM users
                    WHERE invitation_code = ?
                `)
                .get(cleanInviteCode);

            if (inviteOwner) {
                inviteOwnerId = inviteOwner.id;
            }
        }

        const now = new Date().toISOString();

        const registrationIP = getClientIP(req);

        /* ========================================
           CREATE USER
        ======================================== */

        const createUser = db.transaction(() => {
            const result = db
                .prepare(`
                    INSERT INTO users
                    (
                        username,
                        name,
                        password_hash,
                        verified,
                        status,
                        registration_ip,
                        referred_by,
                        invitation_code,
                        created_at
                    )
                    VALUES (?, ?, ?, 1, 'active', ?, ?, ?, ?)
                `)
                .run(
                    cleanUsername,
                    cleanName,
                    hashPassword(password),
                    registrationIP,
                    inviteOwnerId,
                    null,
                    now
                );

            const userId =
                Number(result.lastInsertRowid);

            const invitationCode =
                generateInvitationCode();

            db.prepare(`
                UPDATE users
                SET invitation_code = ?
                WHERE id = ?
            `).run(
                invitationCode,
                userId
            );

            /* Referral reward */

            if (inviteOwnerId) {
                const REWARD = 2;

                db.prepare(`
                    UPDATE users
                    SET balance = balance + ?
                    WHERE id = ?
                `).run(
                    REWARD,
                    userId
                );

                db.prepare(`
                    UPDATE users
                    SET
                        balance = balance + ?,
                        total_referrals =
                            total_referrals + 1
                    WHERE id = ?
                `).run(
                    REWARD,
                    inviteOwnerId
                );

                db.prepare(`
                    INSERT INTO notifications
                    (
                        user_id,
                        title,
                        message,
                        is_read,
                        created_at
                    )
                    VALUES (?, ?, ?, 0, ?)
                `).run(
                    userId,
                    "🎁 Welcome Bonus!",
                    `You used an invitation code and received ₱${REWARD}.00.`,
                    now
                );

                db.prepare(`
                    INSERT INTO notifications
                    (
                        user_id,
                        title,
                        message,
                        is_read,
                        created_at
                    )
                    VALUES (?, ?, ?, 0, ?)
                `).run(
                    inviteOwnerId,
                    "🎉 Referral Bonus!",
                    `${cleanUsername} joined using your invitation code. You received ₱${REWARD}.00.`,
                    now
                );
            }

            return {
                userId,
                invitationCode
            };
        });

        const createdUser = createUser();

        const user = {
            id: createdUser.userId,
            username: cleanUsername,
            name: cleanName
        };

        req.session.user = user;

        db.prepare(`
            UPDATE users
            SET last_seen = ?
            WHERE id = ?
        `).run(
            new Date().toISOString(),
            user.id
        );

        broadcastLive("refresh", {
            reason: "user-register",
            activeNow: getActiveUserCount(),
            userId: user.id
        });

        res.json({
            success: true,
            message:
                "Account created successfully.",
            user
        });

    } catch (error) {
        console.error(
            "REGISTER ERROR:",
            error
        );

        res.status(500).json({
            success: false,
            message:
                "Unable to create account."
        });
    }
});

/* ========================================
   LOGIN
======================================== */

app.post("/api/login", (req, res) => {
    try {
        const {
            username,
            password
        } = req.body;

        const cleanUsername = String(
            username || ""
        )
            .trim()
            .toLowerCase();

        if (
            !cleanUsername ||
            !password
        ) {
            return res.status(400).json({
                success: false,
                message:
                    "Username and password are required."
            });
        }

        const user = db
            .prepare(`
                SELECT *
                FROM users
                WHERE username = ?
            `)
            .get(cleanUsername);

        if (!user) {
            return res.status(401).json({
                success: false,
                message:
                    "Account not found."
            });
        }

        if (user.status === "frozen") {
            return res.status(403).json({
                success: false,
                message:
                    "This account is frozen."
            });
        }

        const passwordHash =
            hashPassword(password);

        if (
            user.password_hash !==
            passwordHash
        ) {
            saveLoginHistory(
                user.id,
                false,
                req
            );

            return res.status(401).json({
                success: false,
                message:
                    "Incorrect password."
            });
        }

        const ip =
            getClientIP(req);

        const device =
            req.headers["user-agent"] ||
            "Unknown";

        const loginTime =
            new Date().toISOString();

        db.prepare(`
            UPDATE users
            SET
                last_ip = ?,
                last_device = ?,
                last_login = ?,
                last_seen = ?
            WHERE id = ?
        `).run(
            ip,
            device,
            loginTime,
            loginTime,
            user.id
        );

        saveLoginHistory(
            user.id,
            true,
            req
        );

        req.session.user = {
            id: user.id,
            username: user.username,
            name: user.name
        };

        broadcastLive("refresh", {
            reason: "user-login",
            activeNow: getActiveUserCount(),
            userId: user.id
        });

        res.json({
            success: true,
            message:
                "Login successful.",
            user: req.session.user
        });

    } catch (error) {
        console.error(
            "LOGIN ERROR:",
            error
        );

        res.status(500).json({
            success: false,
            message:
                "Login failed."
        });
    }
});

/* ========================================
   LOGIN HISTORY
======================================== */

function saveLoginHistory(
    userId,
    success,
    req
) {
    try {
        db.prepare(`
            INSERT INTO login_history
            (
                user_id,
                success,
                ip_address,
                user_agent,
                created_at
            )
            VALUES (?, ?, ?, ?, ?)
        `).run(
            userId,
            success ? 1 : 0,
            getClientIP(req),
            req.headers["user-agent"] || "",
            new Date().toISOString()
        );
    } catch (error) {
        console.error(
            "LOGIN HISTORY ERROR:",
            error
        );
    }
}

/* ========================================
   CURRENT USER
======================================== */

app.get("/api/me", (req, res) => {
    if (!req.session.user) {
        return res.json({
            loggedIn: false
        });
    }

    res.json({
        loggedIn: true,
        user: req.session.user
    });
});

/* ========================================
   LIVE HEARTBEAT / SERVER-SENT EVENTS
======================================== */

app.post(
    "/api/heartbeat",
    requireUser,
    (req, res) => {
        const lastSeen =
            new Date().toISOString();

        db.prepare(`
            UPDATE users
            SET last_seen = ?
            WHERE id = ?
        `).run(
            lastSeen,
            req.session.user.id
        );

        broadcastLive("refresh", {
            reason: "heartbeat",
            activeNow: getActiveUserCount(),
            at: lastSeen
        });

        res.json({
            success: true,
            last_seen: lastSeen
        });
    }
);

app.get("/api/live", (req, res) => {
    if (
        !req.session.user &&
        !req.session.admin
    ) {
        return res.status(401).end();
    }

    res.setHeader(
        "Content-Type",
        "text/event-stream"
    );

    res.setHeader(
        "Cache-Control",
        "no-cache, no-transform"
    );

    res.setHeader(
        "Connection",
        "keep-alive"
    );

    res.flushHeaders?.();

    const client = {
        res,
        userId:
            req.session.user?.id || null,
        admin:
            Boolean(req.session.admin)
    };

    liveClients.add(client);

    res.write(
        `event: connected\n` +
        `data: ${JSON.stringify({
            connected: true,
            activeNow: getActiveUserCount()
        })}\n\n`
    );

    req.on("close", () => {
        liveClients.delete(client);
    });
});

setInterval(() => {
    broadcastLive("refresh", {
        reason: "heartbeat-window",
        activeNow: getActiveUserCount(),
        at: new Date().toISOString()
    });
}, 3000).unref();

/* ========================================
   LOGOUT
======================================== */

app.post("/api/logout", (req, res) => {
    req.session.destroy(error => {
        if (error) {
            return res.status(500).json({
                success: false,
                message:
                    "Logout failed."
            });
        }

        res.json({
            success: true
        });
    });
});

/* ========================================
   DASHBOARD
======================================== */

app.get(
    "/api/dashboard",
    requireUser,
    (req, res) => {
        try {
            const userId =
                req.session.user.id;

            const user = db
                .prepare(`
                    SELECT
                        id,
                        username,
                        name,
                        phone,
                        balance,
                        verified,
                        status,
                        created_at,
                        invitation_code,
                        total_referrals,
                        avatar
                    FROM users
                    WHERE id = ?
                `)
                .get(userId);

            if (!user) {
                return res.status(404).json({
                    success: false,
                    message:
                        "User not found."
                });
            }

            if (!user.invitation_code) {
                const code =
                    generateInvitationCode();

                db.prepare(`
                    UPDATE users
                    SET invitation_code = ?
                    WHERE id = ?
                `).run(
                    code,
                    userId
                );

                user.invitation_code =
                    code;
            }

            const history = db
                .prepare(`
                    SELECT
                        id,
                        reference,
                        amount,
                        status,
                        created_at
                    FROM settlements
                    WHERE user_id = ?
                    ORDER BY id DESC
                    LIMIT 20
                `)
                .all(userId);

            const notifications = db
                .prepare(`
                    SELECT
                        id,
                        title,
                        message,
                        is_read,
                        created_at
                    FROM notifications
                    WHERE user_id = ?
                    ORDER BY id DESC
                    LIMIT 20
                `)
                .all(userId);

            const recentWithdrawals = db
                .prepare(`
                    SELECT
                        id,
                        amount,
                        account_name,
                        bank_name,
                        status,
                        created_at
                    FROM withdrawals
                    WHERE user_id = ?
                    ORDER BY id DESC
                    LIMIT 5
                `)
                .all(userId);

            const totalSettlements = db
                .prepare(`
                    SELECT COUNT(*) AS count
                    FROM settlements
                    WHERE user_id = ?
                `)
                .get(userId).count;

            const unreadNotifications = db
                .prepare(`
                    SELECT COUNT(*) AS count
                    FROM notifications
                    WHERE user_id = ?
                      AND is_read = 0
                `)
                .get(userId).count;

            const totalWithdrawals = db
                .prepare(`
                    SELECT
                        COALESCE(
                            SUM(amount),
                            0
                        ) AS total
                    FROM withdrawals
                    WHERE user_id = ?
                      AND status != 'Rejected'
                `)
                .get(userId).total;

            res.json({
                success: true,
                user,
                balance: user.balance || 0,
                totalSettlements,
                unreadNotifications,
                totalWithdrawals,
                invitation_code:
                    user.invitation_code,
                total_referrals:
                    user.total_referrals || 0,
                history,
                notifications,
                recentWithdrawals
            });

        } catch (error) {
            console.error(
                "DASHBOARD ERROR:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to load dashboard."
            });
        }
    }
);

/* ========================================
   HISTORY
======================================== */

app.get(
    "/api/history",
    requireUser,
    (req, res) => {
        try {
            const history = db
                .prepare(`
                    SELECT
                        id,
                        reference,
                        amount,
                        status,
                        created_at
                    FROM settlements
                    WHERE user_id = ?
                    ORDER BY id DESC
                `)
                .all(
                    req.session.user.id
                );

            res.json({
                success: true,
                history
            });

        } catch (error) {
            console.error(
                "HISTORY ERROR:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to load settlement history."
            });
        }
    }
);

/* ========================================
   NOTIFICATIONS
======================================== */

app.get(
    "/api/notifications",
    requireUser,
    (req, res) => {
        try {
            const userId =
                req.session.user.id;

            const notifications = db
                .prepare(`
                    SELECT
                        id,
                        title,
                        message,
                        is_read,
                        created_at
                    FROM notifications
                    WHERE user_id = ?
                    ORDER BY id DESC
                `)
                .all(userId);

            db.prepare(`
                UPDATE notifications
                SET is_read = 1
                WHERE user_id = ?
            `).run(userId);

            res.json({
                success: true,
                notifications
            });

        } catch (error) {
            console.error(
                "NOTIFICATIONS ERROR:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to load notifications."
            });
        }
    }
);

/* ========================================
   PROFILE
======================================== */

app.get(
    "/api/profile",
    requireUser,
    (req, res) => {
        try {
            const user = db
                .prepare(`
                    SELECT
                        id,
                        username,
                        name,
                        phone,
                        balance,
                        verified,
                        status,
                        registration_ip,
                        last_ip,
                        last_device,
                        last_login,
                        created_at,
                        invitation_code,
                        total_referrals,
                        avatar
                    FROM users
                    WHERE id = ?
                `)
                .get(
                    req.session.user.id
                );

            if (!user) {
                return res.status(404).json({
                    success: false,
                    message:
                        "User not found."
                });
            }

            res.json({
                success: true,
                user
            });

        } catch (error) {
            console.error(
                "PROFILE ERROR:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to load profile."
            });
        }
    }
);

/* ========================================
   INVITATION
======================================== */

app.get(
    "/api/invite",
    requireUser,
    (req, res) => {
        try {
            const userId =
                req.session.user.id;

            let user = db
                .prepare(`
                    SELECT
                        id,
                        username,
                        name,
                        invitation_code,
                        total_referrals
                    FROM users
                    WHERE id = ?
                `)
                .get(userId);

            if (!user) {
                return res.status(404).json({
                    success: false,
                    message:
                        "User not found."
                });
            }

            if (!user.invitation_code) {
                const code =
                    generateInvitationCode();

                db.prepare(`
                    UPDATE users
                    SET invitation_code = ?
                    WHERE id = ?
                `).run(
                    code,
                    userId
                );

                user.invitation_code =
                    code;
            }

            const referrals = db
                .prepare(`
                    SELECT
                        username,
                        name,
                        phone,
                        created_at
                    FROM users
                    WHERE referred_by = ?
                    ORDER BY id DESC
                    LIMIT 20
                `)
                .all(userId);

            res.json({
                success: true,
                invitation_code:
                    user.invitation_code,
                total_referrals:
                    user.total_referrals ||
                    referrals.length,
                referrals
            });

        } catch (error) {
            console.error(
                "INVITE ERROR:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to load invitation info."
            });
        }
    }
);

/* ========================================
   WITHDRAW
======================================== */

app.post(
    "/api/withdraw",
    requireUser,
    (req, res) => {
        try {
            const userId =
                req.session.user.id;

            const {
                amount,
                account_name,
                account_number,
                bank_name
            } = req.body;

            if (
                !amount ||
                !account_name ||
                !account_number ||
                !bank_name
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "All fields are required."
                });
            }

            const parsedAmount =
                parseFloat(amount);

            if (
                isNaN(parsedAmount) ||
                parsedAmount <= 0
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Enter a valid amount."
                });
            }

            if (parsedAmount < 100) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Minimum withdrawal is ₱100."
                });
            }

            const user = db
                .prepare(`
                    SELECT balance
                    FROM users
                    WHERE id = ?
                `)
                .get(userId);

            if (
                !user ||
                user.balance < parsedAmount
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Insufficient balance."
                });
            }

            const now =
                new Date().toISOString();

            const withdrawal =
                db.transaction(() => {

                    db.prepare(`
                        UPDATE users
                        SET balance =
                            balance - ?
                        WHERE id = ?
                    `).run(
                        parsedAmount,
                        userId
                    );

                    return db
                        .prepare(`
                            INSERT INTO withdrawals
                            (
                                user_id,
                                amount,
                                account_name,
                                account_number,
                                bank_name,
                                status,
                                created_at
                            )
                            VALUES
                            (?, ?, ?, ?, ?, 'Pending', ?)
                        `)
                        .run(
                            userId,
                            parsedAmount,
                            account_name,
                            account_number,
                            bank_name,
                            now
                        );
                })();

            broadcastLive("refresh", {
                reason: "new-withdrawal",
                withdrawalId:
                    Number(withdrawal.lastInsertRowid),
                userId
            });

            res.json({
                success: true,
                message:
                    "Withdrawal request submitted.",
                withdrawal_id:
                    withdrawal.lastInsertRowid
            });

        } catch (error) {
            console.error(
                "WITHDRAW ERROR:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to process withdrawal."
            });
        }
    }
);

/* ========================================
   USER WITHDRAWALS
======================================== */

app.get(
    "/api/withdrawals",
    requireUser,
    (req, res) => {
        try {
            const withdrawals = db
                .prepare(`
                    SELECT
                        id,
                        amount,
                        account_name,
                        account_number,
                        bank_name,
                        status,
                        note,
                        created_at
                    FROM withdrawals
                    WHERE user_id = ?
                    ORDER BY id DESC
                    LIMIT 50
                `)
                .all(
                    req.session.user.id
                );

            res.json({
                success: true,
                withdrawals
            });

        } catch (error) {
            console.error(
                "WITHDRAWALS ERROR:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to load withdrawals."
            });
        }
    }
);

/* ========================================
   ADMIN AUTH
======================================== */

app.post(
    "/api/admin/login",
    (req, res) => {
        try {
            const {
                username,
                password
            } = req.body;

            if (
                !username ||
                !password
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Username and password are required."
                });
            }

            const admin = db
                .prepare(`
                    SELECT *
                    FROM admins
                    WHERE username = ?
                `)
                .get(
                    String(username)
                        .trim()
                        .toLowerCase()
                );

            if (!admin) {
                return res.status(401).json({
                    success: false,
                    message:
                        "Invalid admin credentials."
                });
            }

            if (
                hashPassword(password) !==
                admin.password_hash
            ) {
                return res.status(401).json({
                    success: false,
                    message:
                        "Invalid admin credentials."
                });
            }

            req.session.admin = {
                id: admin.id,
                username: admin.username
            };

            res.json({
                success: true,
                message:
                    "Admin login successful."
            });

        } catch (error) {
            console.error(
                "ADMIN LOGIN ERROR:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Admin login failed."
            });
        }
    }
);

/* ========================================
   ADMIN LOGOUT
======================================== */

app.post(
    "/api/admin/logout",
    requireAdmin,
    (req, res) => {
        delete req.session.admin;

        res.json({
            success: true
        });
    }
);

/* ========================================
   ADMIN ME
======================================== */

app.get(
    "/api/admin/me",
    (req, res) => {
        if (!req.session.admin) {
            return res.json({
                loggedIn: false
            });
        }

        res.json({
            loggedIn: true,
            admin: req.session.admin
        });
    }
);

/* ========================================
   ADMIN USERS
======================================== */

app.get(
    "/api/admin/users",
    requireAdmin,
    (req, res) => {
        try {
            const users = db
                .prepare(`
                    SELECT
                        id,
                        username,
                        name,
                        phone,
                        balance,
                        verified,
                        status,
                        registration_ip,
                        last_ip,
                        last_device,
                        last_login,
                        last_seen,
                        invitation_code,
                        total_referrals,
                        created_at
                    FROM users
                    ORDER BY id DESC
                `)
                .all()
                .map(user => ({
                    ...user,
                    is_active:
                        isRecentlyActive(
                            user.last_seen
                        )
                }));

            res.json({
                success: true,
                users,
                activeNow:
                    users.filter(
                        user =>
                            user.is_active
                    ).length
            });

        } catch (error) {
            console.error(
                "ADMIN USERS ERROR:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to load users."
            });
        }
    }
);

/* ========================================
   ADMIN USER DETAILS
======================================== */

app.get(
    "/api/admin/users/:id",
    requireAdmin,
    (req, res) => {
        try {
            const user = db
                .prepare(`
                    SELECT
                        id,
                        username,
                        name,
                        phone,
                        balance,
                        verified,
                        status,
                        registration_ip,
                        last_ip,
                        last_device,
                        last_login,
                        last_seen,
                        invitation_code,
                        total_referrals,
                        created_at,
                        avatar
                    FROM users
                    WHERE id = ?
                `)
                .get(req.params.id);

            if (!user) {
                return res.status(404).json({
                    success: false,
                    message:
                        "User not found."
                });
            }

            const loginHistory = db
                .prepare(`
                    SELECT
                        id,
                        success,
                        ip_address,
                        user_agent,
                        created_at
                    FROM login_history
                    WHERE user_id = ?
                    ORDER BY id DESC
                    LIMIT 50
                `)
                .all(req.params.id);

            const withdrawals = db
                .prepare(`
                    SELECT
                        id,
                        amount,
                        account_name,
                        account_number,
                        bank_name,
                        status,
                        note,
                        created_at
                    FROM withdrawals
                    WHERE user_id = ?
                    ORDER BY id DESC
                    LIMIT 50
                `)
                .all(req.params.id);

            res.json({
                success: true,
                user,
                loginHistory,
                withdrawals
            });

        } catch (error) {
            console.error(
                "USER DETAILS ERROR:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to load user details. Please refresh and try again."
            });
        }
    }
);

/* ========================================
   FREEZE USER
======================================== */

app.post(
    "/api/admin/users/:id/freeze",
    requireAdmin,
    (req, res) => {
        try {
            const result = db
                .prepare(`
                    UPDATE users
                    SET status = 'frozen'
                    WHERE id = ?
                `)
                .run(req.params.id);

            if (!result.changes) {
                return res.status(404).json({
                    success: false,
                    message:
                        "User not found."
                });
            }

            broadcastLive("refresh", {
                reason: "user-freeze",
                userId:
                    Number(req.params.id),
                activeNow:
                    getActiveUserCount()
            });

            res.json({
                success: true,
                message:
                    "Account frozen."
            });

        } catch (error) {
            console.error(
                "FREEZE ERROR:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to freeze account."
            });
        }
    }
);

/* ========================================
   UNFREEZE USER
======================================== */

app.post(
    "/api/admin/users/:id/unfreeze",
    requireAdmin,
    (req, res) => {
        try {
            const result = db
                .prepare(`
                    UPDATE users
                    SET status = 'active'
                    WHERE id = ?
                `)
                .run(req.params.id);

            if (!result.changes) {
                return res.status(404).json({
                    success: false,
                    message:
                        "User not found."
                });
            }

            broadcastLive("refresh", {
                reason: "user-unfreeze",
                userId:
                    Number(req.params.id),
                activeNow:
                    getActiveUserCount()
            });

            res.json({
                success: true,
                message:
                    "Account unfrozen."
            });

        } catch (error) {
            console.error(
                "UNFREEZE ERROR:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to unfreeze account."
            });
        }
    }
);

/* ========================================
   ADMIN ADD CASH
======================================== */

app.post(
    "/api/admin/users/:id/add-cash",
    requireAdmin,
    (req, res) => {
        try {
            const userId =
                req.params.id;

            const {
                amount,
                note
            } = req.body;

            const parsed =
                parseFloat(amount);

            if (
                isNaN(parsed) ||
                parsed <= 0
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Enter a valid amount."
                });
            }

            const user = db
                .prepare(`
                    SELECT
                        id,
                        username,
                        name,
                        balance
                    FROM users
                    WHERE id = ?
                `)
                .get(userId);

            if (!user) {
                return res.status(404).json({
                    success: false,
                    message:
                        "User not found."
                });
            }

            db.prepare(`
                UPDATE users
                SET balance =
                    balance + ?
                WHERE id = ?
            `).run(
                parsed,
                userId
            );

            const newBalance =
                (user.balance || 0) +
                parsed;

            const now =
                new Date().toISOString();

            db.prepare(`
                INSERT INTO notifications
                (
                    user_id,
                    title,
                    message,
                    is_read,
                    created_at
                )
                VALUES (?, ?, ?, 0, ?)
            `).run(
                userId,
                "Cash Added",
                `₱${parsed.toLocaleString(
                    "en-PH",
                    {
                        minimumFractionDigits: 2
                    }
                )} has been added to your account${
                    note
                        ? `: ${note}`
                        : "."
                }`,
                now
            );

            broadcastLive("refresh", {
                reason: "cash-added",
                userId:
                    Number(userId),
                amount: parsed,
                newBalance
            });

            res.json({
                success: true,
                message:
                    `Successfully added ₱${parsed} to ${user.username}.`,
                newBalance
            });

        } catch (error) {
            console.error(
                "ADD CASH ERROR:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to add cash."
            });
        }
    }
);

/* ========================================
   ADMIN ALL WITHDRAWALS
======================================== */

app.get(
    "/api/admin/withdrawals",
    requireAdmin,
    (req, res) => {
        try {
            const search =
                String(
                    req.query.search || ""
                ).trim();

            const status =
                String(
                    req.query.status || "all"
                )
                    .trim()
                    .toLowerCase();

            const where = [];
            const params = [];

            if (search) {
                where.push(`
                    (
                        u.username LIKE ?
                        OR u.name LIKE ?
                        OR u.phone LIKE ?
                        OR w.account_name LIKE ?
                        OR w.account_number LIKE ?
                        OR w.bank_name LIKE ?
                    )
                `);

                const keyword =
                    `%${search}%`;

                params.push(
                    keyword,
                    keyword,
                    keyword,
                    keyword,
                    keyword,
                    keyword
                );
            }

            if (
                [
                    "pending",
                    "approved",
                    "rejected"
                ].includes(status)
            ) {
                where.push(
                    "LOWER(w.status) = ?"
                );

                params.push(status);
            }

            const whereSql =
                where.length
                    ? `WHERE ${where.join(" AND ")}`
                    : "";

            const withdrawals = db
                .prepare(`
                    SELECT
                        w.*,
                        u.username AS username,
                        u.name AS user_name,
                        u.phone AS phone_number,
                        u.balance AS current_balance
                    FROM withdrawals w
                    LEFT JOIN users u
                        ON u.id = w.user_id
                    ${whereSql}
                    ORDER BY w.id DESC
                `)
                .all(...params);

            const summary = db
                .prepare(`
                    SELECT
                        COUNT(*) AS total,

                        SUM(
                            CASE
                                WHEN LOWER(status) =
                                    'pending'
                                THEN 1
                                ELSE 0
                            END
                        ) AS pending,

                        SUM(
                            CASE
                                WHEN LOWER(status) =
                                    'approved'
                                THEN 1
                                ELSE 0
                            END
                        ) AS approved,

                        SUM(
                            CASE
                                WHEN LOWER(status) =
                                    'rejected'
                                THEN 1
                                ELSE 0
                            END
                        ) AS rejected,

                        COALESCE(
                            SUM(
                                CASE
                                    WHEN LOWER(status) =
                                        'pending'
                                    THEN amount
                                    ELSE 0
                                END
                            ),
                            0
                        ) AS pending_amount,

                        COALESCE(
                            SUM(
                                CASE
                                    WHEN LOWER(status) =
                                        'approved'
                                    THEN amount
                                    ELSE 0
                                END
                            ),
                            0
                        ) AS approved_amount,

                        COALESCE(
                            SUM(
                                CASE
                                    WHEN LOWER(status) =
                                        'rejected'
                                    THEN amount
                                    ELSE 0
                                END
                            ),
                            0
                        ) AS rejected_amount

                    FROM withdrawals
                `)
                .get();

            res.json({
                success: true,
                withdrawals,
                summary: {
                    total:
                        Number(
                            summary.total || 0
                        ),
                    pending:
                        Number(
                            summary.pending || 0
                        ),
                    approved:
                        Number(
                            summary.approved || 0
                        ),
                    rejected:
                        Number(
                            summary.rejected || 0
                        ),
                    pending_amount:
                        Number(
                            summary.pending_amount ||
                            0
                        ),
                    approved_amount:
                        Number(
                            summary.approved_amount ||
                            0
                        ),
                    rejected_amount:
                        Number(
                            summary.rejected_amount ||
                            0
                        )
                }
            });

        } catch (error) {
            console.error(
                "ADMIN WITHDRAWALS ERROR:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to load withdrawals."
            });
        }
    }
);

/* ========================================
   ADMIN WITHDRAWAL DETAILS
======================================== */

app.get(
    "/api/admin/withdrawals/:id",
    requireAdmin,
    (req, res) => {
        try {
            const withdrawal = db
                .prepare(`
                    SELECT
                        w.*,
                        u.username AS username,
                        u.name AS user_name,
                        u.phone AS phone_number,
                        u.balance AS current_balance
                    FROM withdrawals w
                    LEFT JOIN users u
                        ON u.id = w.user_id
                    WHERE w.id = ?
                `)
                .get(req.params.id);

            if (!withdrawal) {
                return res.status(404).json({
                    success: false,
                    message:
                        "Withdrawal not found."
                });
            }

            res.json({
                success: true,
                withdrawal
            });

        } catch (error) {
            console.error(
                "WITHDRAWAL DETAILS ERROR:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to load withdrawal."
            });
        }
    }
);

/* ========================================
   ADMIN APPROVE WITHDRAWAL
======================================== */

app.post(
    "/api/admin/withdrawals/:id/approve",
    requireAdmin,
    (req, res) => {
        try {
            const withdrawal = db
                .prepare(`
                    SELECT *
                    FROM withdrawals
                    WHERE id = ?
                `)
                .get(req.params.id);

            if (!withdrawal) {
                return res.status(404).json({
                    success: false,
                    message:
                        "Withdrawal not found."
                });
            }

            if (
                String(
                    withdrawal.status
                ).toLowerCase() !==
                "pending"
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "This withdrawal has already been processed."
                });
            }

            const now =
                new Date().toISOString();

            const result = db
                .prepare(`
                    UPDATE withdrawals
                    SET status = 'Approved'
                    WHERE id = ?
                      AND LOWER(status) =
                          'pending'
                `)
                .run(req.params.id);

            if (!result.changes) {
                return res.status(409).json({
                    success: false,
                    message:
                        "Withdrawal was already processed."
                });
            }

            db.prepare(`
                INSERT INTO notifications
                (
                    user_id,
                    title,
                    message,
                    is_read,
                    created_at
                )
                VALUES (?, ?, ?, 0, ?)
            `).run(
                withdrawal.user_id,
                "Withdrawal Approved",
                `Your withdrawal of ₱${Number(
                    withdrawal.amount
                ).toLocaleString(
                    "en-PH",
                    {
                        minimumFractionDigits: 2
                    }
                )} to ${
                    withdrawal.bank_name ||
                    "your account"
                } has been approved.`,
                now
            );

            broadcastLive("refresh", {
                reason: "withdrawal-approved",
                withdrawalId:
                    Number(req.params.id),
                userId:
                    withdrawal.user_id
            });

            res.json({
                success: true,
                message:
                    "Withdrawal approved."
            });

        } catch (error) {
            console.error(
                "APPROVE WITHDRAWAL ERROR:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to approve withdrawal."
            });
        }
    }
);

/* ========================================
   ADMIN REJECT WITHDRAWAL
======================================== */

app.post(
    "/api/admin/withdrawals/:id/reject",
    requireAdmin,
    (req, res) => {
        try {
            const withdrawal = db
                .prepare(`
                    SELECT *
                    FROM withdrawals
                    WHERE id = ?
                `)
                .get(req.params.id);

            if (!withdrawal) {
                return res.status(404).json({
                    success: false,
                    message:
                        "Withdrawal not found."
                });
            }

            if (
                String(
                    withdrawal.status
                ).toLowerCase() !==
                "pending"
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "This withdrawal has already been processed."
                });
            }

            const now =
                new Date().toISOString();

            const transaction =
                db.transaction(() => {

                    const result =
                        db.prepare(`
                            UPDATE withdrawals
                            SET status = 'Rejected'
                            WHERE id = ?
                              AND LOWER(status) =
                                  'pending'
                        `).run(
                            req.params.id
                        );

                    if (!result.changes) {
                        throw new Error(
                            "Withdrawal was already processed."
                        );
                    }

                    db.prepare(`
                        UPDATE users
                        SET balance =
                            balance + ?
                        WHERE id = ?
                    `).run(
                        withdrawal.amount,
                        withdrawal.user_id
                    );

                    db.prepare(`
                        INSERT INTO notifications
                        (
                            user_id,
                            title,
                            message,
                            is_read,
                            created_at
                        )
                        VALUES (?, ?, ?, 0, ?)
                    `).run(
                        withdrawal.user_id,
                        "Withdrawal Rejected",
                        `Your withdrawal of ₱${Number(
                            withdrawal.amount
                        ).toLocaleString(
                            "en-PH",
                            {
                                minimumFractionDigits: 2
                            }
                        )} has been rejected. The amount has been refunded to your balance.`,
                        now
                    );
                });

            transaction();

            broadcastLive("refresh", {
                reason: "withdrawal-rejected",
                withdrawalId:
                    Number(req.params.id),
                userId:
                    withdrawal.user_id
            });

            res.json({
                success: true,
                message:
                    "Withdrawal rejected and balance refunded."
            });

        } catch (error) {
            console.error(
                "REJECT WITHDRAWAL ERROR:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    error.message ||
                    "Unable to reject withdrawal."
            });
        }
    }
);

/* ========================================
   ADMIN SEND NOTIFICATION
======================================== */

app.post(
    "/api/admin/notify",
    requireAdmin,
    (req, res) => {
        try {
            const {
                userId,
                title,
                message
            } = req.body;

            if (
                !title ||
                !message
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Title and message are required."
                });
            }

            const now =
                new Date().toISOString();

            if (userId === "all") {
                const users = db
                    .prepare(`
                        SELECT id
                        FROM users
                        WHERE status = 'active'
                    `)
                    .all();

                const insert =
                    db.prepare(`
                        INSERT INTO notifications
                        (
                            user_id,
                            title,
                            message,
                            is_read,
                            created_at
                        )
                        VALUES (?, ?, ?, 0, ?)
                    `);

                const bulk =
                    db.transaction(rows => {
                        for (const user of rows) {
                            insert.run(
                                user.id,
                                title,
                                message,
                                now
                            );
                        }
                    });

                bulk(users);

                broadcastLive("refresh", {
                    reason:
                        "notification-all"
                });

                return res.json({
                    success: true,
                    message:
                        `Notification sent to ${users.length} users.`
                });
            }

            const user = db
                .prepare(`
                    SELECT id
                    FROM users
                    WHERE id = ?
                `)
                .get(userId);

            if (!user) {
                return res.status(404).json({
                    success: false,
                    message:
                        "User not found."
                });
            }

            db.prepare(`
                INSERT INTO notifications
                (
                    user_id,
                    title,
                    message,
                    is_read,
                    created_at
                )
                VALUES (?, ?, ?, 0, ?)
            `).run(
                userId,
                title,
                message,
                now
            );

            broadcastLive("refresh", {
                reason:
                    "notification-user",
                userId:
                    Number(userId)
            });

            res.json({
                success: true,
                message:
                    "Notification sent."
            });

        } catch (error) {
            console.error(
                "NOTIFY ERROR:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to send notification."
            });
        }
    }
);

/* ========================================
   USER + ADMIN TASKS
======================================== */

app.get(
    "/api/tasks",
    requireUser,
    (req, res) => {
        try {
            const tasks = db
                .prepare(`
                    SELECT
                        t.*,
                        (
                            SELECT status
                            FROM task_completions tc
                            WHERE tc.task_id = t.id
                              AND tc.user_id = ?
                            ORDER BY tc.id DESC
                            LIMIT 1
                        ) AS my_status
                    FROM tasks t
                    WHERE t.status = 'active'
                    ORDER BY t.id DESC
                `)
                .all(
                    req.session.user.id
                );

            const completions = db
                .prepare(`
                    SELECT
                        tc.*,
                        t.title,
                        t.reward
                    FROM task_completions tc
                    JOIN tasks t
                        ON t.id = tc.task_id
                    WHERE tc.user_id = ?
                    ORDER BY tc.id DESC
                    LIMIT 50
                `)
                .all(
                    req.session.user.id
                );

            res.json({
                success: true,
                tasks,
                completions
            });

        } catch (error) {
            console.error(
                "TASKS ERROR:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to load tasks."
            });
        }
    }
);

app.post(
    "/api/tasks/:id/complete",
    requireUser,
    (req, res) => {
        try {
            const task = db
                .prepare(`
                    SELECT *
                    FROM tasks
                    WHERE id = ?
                      AND status = 'active'
                `)
                .get(req.params.id);

            if (!task) {
                return res.status(404).json({
                    success: false,
                    message:
                        "Task not found or inactive."
                });
            }

            const proof =
                String(
                    req.body.proof || ""
                ).trim();

            if (!proof) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Proof is required."
                });
            }

            const existing = db
                .prepare(`
                    SELECT
                        id,
                        status
                    FROM task_completions
                    WHERE task_id = ?
                      AND user_id = ?
                      AND status IN
                          ('Pending', 'Approved')
                `)
                .get(
                    task.id,
                    req.session.user.id
                );

            if (existing) {
                return res.status(409).json({
                    success: false,
                    message:
                        existing.status === "Approved"
                            ? "You already completed this task."
                            : "This task is still pending review."
                });
            }

            db.prepare(`
                INSERT INTO task_completions
                (
                    task_id,
                    user_id,
                    proof,
                    status,
                    created_at
                )
                VALUES (?, ?, ?, 'Pending', ?)
            `).run(
                task.id,
                req.session.user.id,
                proof,
                new Date().toISOString()
            );

            broadcastLive("refresh", {
                reason:
                    "task-submitted",
                userId:
                    req.session.user.id,
                taskId:
                    task.id
            });

            res.json({
                success: true,
                message:
                    "Task submitted for review."
            });

        } catch (error) {
            console.error(
                "TASK SUBMIT ERROR:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to submit task."
            });
        }
    }
);

/* ========================================
   ADMIN TASKS
======================================== */

app.get(
    "/api/admin/tasks",
    requireAdmin,
    (req, res) => {
        try {
            const tasks = db
                .prepare(`
                    SELECT
                        t.*,
                        (
                            SELECT COUNT(*)
                            FROM task_completions tc
                            WHERE tc.task_id = t.id
                        ) AS submissions,
                        (
                            SELECT COUNT(*)
                            FROM task_completions tc
                            WHERE tc.task_id = t.id
                              AND tc.status = 'Pending'
                        ) AS pending_submissions
                    FROM tasks t
                    ORDER BY t.id DESC
                `)
                .all();

            res.json({
                success: true,
                tasks
            });

        } catch (error) {
            console.error(
                "ADMIN TASKS ERROR:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to load tasks."
            });
        }
    }
);

app.post(
    "/api/admin/tasks",
    requireAdmin,
    (req, res) => {
        try {
            const title =
                String(
                    req.body.title || ""
                ).trim();

            const description =
                String(
                    req.body.description || ""
                ).trim();

            const reward =
                Number(req.body.reward);

            if (
                !title ||
                !Number.isFinite(reward) ||
                reward <= 0
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Title and positive reward are required."
                });
            }

            db.prepare(`
                INSERT INTO tasks
                (
                    title,
                    description,
                    reward,
                    status,
                    created_at
                )
                VALUES (?, ?, ?, 'active', ?)
            `).run(
                title,
                description,
                reward,
                new Date().toISOString()
            );

            broadcastLive("refresh", {
                reason:
                    "task-created"
            });

            res.json({
                success: true,
                message:
                    "Task created."
            });

        } catch (error) {
            console.error(
                "CREATE TASK ERROR:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to create task."
            });
        }
    }
);

app.post(
    "/api/admin/tasks/:id/status",
    requireAdmin,
    (req, res) => {
        try {
            const status =
                req.body.status;

            if (
                ![
                    "active",
                    "inactive"
                ].includes(status)
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Invalid task status."
                });
            }

            const result = db
                .prepare(`
                    UPDATE tasks
                    SET status = ?
                    WHERE id = ?
                `)
                .run(
                    status,
                    req.params.id
                );

            broadcastLive("refresh", {
                reason:
                    "task-status",
                taskId:
                    Number(req.params.id)
            });

            res.json({
                success:
                    result.changes > 0,
                message:
                    result.changes
                        ? "Task status updated."
                        : "Task not found."
            });

        } catch (error) {
            console.error(
                "TASK STATUS ERROR:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to update task status."
            });
        }
    }
);

app.get(
    "/api/admin/task-completions",
    requireAdmin,
    (req, res) => {
        try {
            const completions =
                db.prepare(`
                    SELECT
                        tc.*,
                        u.name AS user_name,
                        u.username AS user_username,
                        t.title AS task_title,
                        t.reward AS task_reward
                    FROM task_completions tc
                    JOIN users u
                        ON u.id = tc.user_id
                    JOIN tasks t
                        ON t.id = tc.task_id
                    ORDER BY tc.id DESC
                `).all();

            res.json({
                success: true,
                completions
            });

        } catch (error) {
            console.error(
                "ADMIN TASK COMPLETIONS ERROR:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to load task submissions."
            });
        }
    }
);

app.post(
    "/api/admin/task-completions/:id/review",
    requireAdmin,
    (req, res) => {
        try {
            const status =
                req.body.status;

            if (
                ![
                    "Approved",
                    "Rejected"
                ].includes(status)
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Invalid review status."
                });
            }

            const row = db
                .prepare(`
                    SELECT
                        tc.*,
                        t.title AS task_title,
                        t.reward AS task_reward
                    FROM task_completions tc
                    JOIN tasks t
                        ON t.id = tc.task_id
                    WHERE tc.id = ?
                `)
                .get(req.params.id);

            if (!row) {
                return res.status(404).json({
                    success: false,
                    message:
                        "Submission not found."
                });
            }

            if (row.status !== "Pending") {
                return res.status(409).json({
                    success: false,
                    message:
                        "Submission already reviewed."
                });
            }

            const now =
                new Date().toISOString();

            const tx = db.transaction(() => {

                db.prepare(`
                    UPDATE task_completions
                    SET
                        status = ?,
                        reviewed_at = ?
                    WHERE id = ?
                `).run(
                    status,
                    now,
                    row.id
                );

                if (status === "Approved") {
                    db.prepare(`
                        UPDATE users
                        SET balance =
                            balance + ?
                        WHERE id = ?
                    `).run(
                        row.task_reward,
                        row.user_id
                    );
                }

                db.prepare(`
                    INSERT INTO notifications
                    (
                        user_id,
                        title,
                        message,
                        is_read,
                        created_at
                    )
                    VALUES (?, ?, ?, 0, ?)
                `).run(
                    row.user_id,
                    status === "Approved"
                        ? "Task Approved"
                        : "Task Rejected",
                    status === "Approved"
                        ? `Your task "${row.task_title}" was approved and ₱${Number(
                            row.task_reward
                        ).toFixed(2)} was added.`
                        : `Your task "${row.task_title}" was rejected.`,
                    now
                );
            });

            tx();

            broadcastLive("refresh", {
                reason:
                    "task-reviewed",
                completionId:
                    Number(req.params.id),
                userId:
                    row.user_id,
                status
            });

            res.json({
                success: true,
                message:
                    `Submission ${status.toLowerCase()}.`
            });

        } catch (error) {
            console.error(
                "REVIEW TASK ERROR:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to review submission."
            });
        }
    }
);

/* ========================================
   GLOBAL CHAT
   PERMANENT REACTIONS
======================================== */

const ALLOWED_REACTIONS = new Set([
    "like",
    "love",
    "laugh",
    "wow",
    "sad",
    "angry"
]);

function getChatReactions(
    messageId,
    userId
) {
    const counts = db
        .prepare(`
            SELECT
                reaction,
                COUNT(*) AS count
            FROM chat_reactions
            WHERE chat_message_id = ?
            GROUP BY reaction
        `)
        .all(messageId)
        .reduce(
            (result, row) => {
                result[row.reaction] =
                    Number(row.count);

                return result;
            },
            {}
        );

    const mine = db
        .prepare(`
            SELECT reaction
            FROM chat_reactions
            WHERE chat_message_id = ?
              AND user_id = ?
        `)
        .get(
            messageId,
            userId
        );

    return {
        counts,
        mine:
            mine?.reaction || null
    };
}

/* ========================================
   GET CHAT
======================================== */

app.get(
    "/api/chat",
    requireUser,
    (req, res) => {
        try {
            const messages = db
                .prepare(`
                    SELECT
                        cm.id,
                        cm.user_id,
                        cm.message,
                        cm.created_at,
                        u.username,
                        u.name,
                        u.avatar
                    FROM chat_messages cm
                    JOIN users u
                        ON u.id = cm.user_id
                    ORDER BY cm.id DESC
                    LIMIT 100
                `)
                .all();

            const enrichedMessages =
                messages.map(message => ({
                    ...message,

                    reactions:
                        getChatReactions(
                            message.id,
                            req.session.user.id
                        )
                }));

            res.json({
                success: true,

                messages:
                    enrichedMessages.reverse()
            });

        } catch (error) {
            console.error(
                "CHAT ERROR:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to load chat."
            });
        }
    }
);

/* ========================================
   SEND CHAT MESSAGE
======================================== */

app.post(
    "/api/chat",
    requireUser,
    (req, res) => {
        try {
            const message =
                String(
                    req.body.message || ""
                ).trim();

            if (!message) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Message is required."
                });
            }

            if (message.length > 500) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Message is too long (max 500 characters)."
                });
            }

            const now =
                new Date().toISOString();

            const result = db
                .prepare(`
                    INSERT INTO chat_messages
                    (
                        user_id,
                        message,
                        created_at
                    )
                    VALUES (?, ?, ?)
                `)
                .run(
                    req.session.user.id,
                    message,
                    now
                );

            const messageId =
                Number(result.lastInsertRowid);

            /*
                Notify every connected
                user/admin immediately.
            */

            broadcastLive("refresh", {
                reason:
                    "chat-message",
                messageId,
                userId:
                    req.session.user.id,
                at: now
            });

            res.json({
                success: true,
                message:
                    "Message sent.",
                message_id:
                    messageId
            });

        } catch (error) {
            console.error(
                "CHAT SEND ERROR:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to send message."
            });
        }
    }
);

/* ========================================
   CHAT REACTION
   PERMANENT / NO TIMER
======================================== */

app.post(
    "/api/chat/:messageId/reaction",
    requireUser,
    (req, res) => {
        try {
            const messageId =
                Number(req.params.messageId);

            const reaction =
                String(
                    req.body.reaction || ""
                )
                    .trim()
                    .toLowerCase();

            if (
                !Number.isInteger(messageId) ||
                messageId <= 0
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Invalid message."
                });
            }

            if (
                !ALLOWED_REACTIONS.has(
                    reaction
                )
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Invalid reaction."
                });
            }

            const chatMessage = db
                .prepare(`
                    SELECT id
                    FROM chat_messages
                    WHERE id = ?
                `)
                .get(messageId);

            if (!chatMessage) {
                return res.status(404).json({
                    success: false,
                    message:
                        "Message not found."
                });
            }

            const userId =
                req.session.user.id;

            const existing = db
                .prepare(`
                    SELECT reaction
                    FROM chat_reactions
                    WHERE chat_message_id = ?
                      AND user_id = ?
                `)
                .get(
                    messageId,
                    userId
                );

            const now =
                new Date().toISOString();

            /*
                SAME REACTION
                = REMOVE IT
            */

            if (
                existing?.reaction ===
                reaction
            ) {
                db.prepare(`
                    DELETE FROM chat_reactions
                    WHERE chat_message_id = ?
                      AND user_id = ?
                `).run(
                    messageId,
                    userId
                );
            }

            /*
                DIFFERENT REACTION
                = CHANGE IT
            */

            else {
                db.prepare(`
                    INSERT INTO chat_reactions
                    (
                        chat_message_id,
                        user_id,
                        reaction,
                        created_at,
                        updated_at
                    )
                    VALUES (?, ?, ?, ?, ?)

                    ON CONFLICT(
                        chat_message_id,
                        user_id
                    )

                    DO UPDATE SET
                        reaction =
                            excluded.reaction,
                        updated_at =
                            excluded.updated_at
                `).run(
                    messageId,
                    userId,
                    reaction,
                    now,
                    now
                );
            }

            const reactions =
                getChatReactions(
                    messageId,
                    userId
                );

            broadcastLive("refresh", {
                reason:
                    "chat-reaction",
                messageId,
                userId,
                at: now
            });

            res.json({
                success: true,
                reactions
            });

        } catch (error) {
            console.error(
                "CHAT REACTION ERROR:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to save reaction."
            });
        }
    }
);

/* ========================================
   ADMIN CHAT
   GET ALL CHAT MESSAGES
======================================== */

app.get(
    "/api/admin/chat",
    requireAdmin,
    (req, res) => {
        try {
            const messages = db
                .prepare(`
                    SELECT
                        cm.id,
                        cm.user_id,
                        cm.message,
                        cm.created_at,
                        u.username,
                        u.name,
                        u.avatar
                    FROM chat_messages cm
                    JOIN users u
                        ON u.id = cm.user_id
                    ORDER BY cm.id DESC
                    LIMIT 200
                `)
                .all();

            const enrichedMessages =
                messages.map(message => ({
                    ...message,

                    reactions:
                        getChatReactions(
                            message.id,
                            null
                        )
                }));

            res.json({
                success: true,
                messages:
                    enrichedMessages.reverse()
            });

        } catch (error) {
            console.error(
                "ADMIN CHAT ERROR:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to load admin chat."
            });
        }
    }
);

/* ========================================
   ADMIN DELETE CHAT MESSAGE
======================================== */

app.delete(
    "/api/admin/chat/:messageId",
    requireAdmin,
    (req, res) => {
        try {
            const messageId =
                Number(req.params.messageId);

            if (
                !Number.isInteger(messageId) ||
                messageId <= 0
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Invalid message ID."
                });
            }

            const message = db
                .prepare(`
                    SELECT
                        id,
                        user_id,
                        message
                    FROM chat_messages
                    WHERE id = ?
                `)
                .get(messageId);

            if (!message) {
                return res.status(404).json({
                    success: false,
                    message:
                        "Chat message not found."
                });
            }

            /*
                Because chat_reactions should
                use ON DELETE CASCADE,
                deleting the message also
                deletes its reactions.
            */

            const result = db
                .prepare(`
                    DELETE FROM chat_messages
                    WHERE id = ?
                `)
                .run(messageId);

            if (!result.changes) {
                return res.status(404).json({
                    success: false,
                    message:
                        "Chat message not found."
                });
            }

            /*
                Tell every connected
                browser to refresh chat.
            */

            broadcastLive("refresh", {
                reason:
                    "chat-message-deleted",
                messageId,
                at:
                    new Date().toISOString()
            });

            res.json({
                success: true,
                message:
                    "Chat message deleted."
            });

        } catch (error) {
            console.error(
                "ADMIN DELETE CHAT ERROR:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to delete chat message."
            });
        }
    }
);

/* ========================================
   AVATAR UPLOAD
======================================== */

app.post(
    "/api/avatar",
    requireUser,
    (req, res) => {
        try {
            const avatar =
                String(
                    req.body.avatar || ""
                ).trim();

            if (!avatar) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Avatar is required."
                });
            }

            if (
                !avatar.startsWith(
                    "data:image/"
                )
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Invalid image format."
                });
            }

            /*
                Rough size guard
                ~4MB maximum after base64.
            */

            if (avatar.length > 5_500_000) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Image is too large (max ~4MB)."
                });
            }

            db.prepare(`
                UPDATE users
                SET avatar = ?
                WHERE id = ?
            `).run(
                avatar,
                req.session.user.id
            );

            broadcastLive("refresh", {
                reason:
                    "avatar-updated",
                userId:
                    req.session.user.id
            });

            res.json({
                success: true,
                message:
                    "Avatar updated.",
                avatar
            });

        } catch (error) {
            console.error(
                "AVATAR ERROR:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to update avatar."
            });
        }
    }
);

/* ========================================
   START SERVER
======================================== */

app.listen(
    PORT,
    "0.0.0.0",
    () => {
        console.log("");

        console.log(
            "================================="
        );

        console.log(
            `TTPRO running on http://localhost:${PORT}`
        );

        console.log(
            "AUTH MODE: USERNAME + PASSWORD"
        );

        console.log(
            "EMAIL OTP: DISABLED"
        );

        console.log(
            "REAL-TIME: SSE ENABLED"
        );

        console.log(
            "GLOBAL CHAT: ENABLED"
        );

        console.log(
            "CHAT REACTIONS: PERMANENT"
        );

        console.log(
            "================================="
        );

        console.log("");
    }
);