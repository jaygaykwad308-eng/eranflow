
const encoder = new TextEncoder();

async function hash(value) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    encoder.encode(value)
  );
  return [...new Uint8Array(digest)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

function randomToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

async function passwordHash(password, salt) {
  const key = await crypto.subtle.importKey(
    "raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits({
    name: "PBKDF2",
    salt: encoder.encode(salt),
    iterations: 310000,
    hash: "SHA-256"
  }, key, 256);

  return [...new Uint8Array(bits)]
    .map(b => b.toString(16).padStart(2, "0")).join("");
}

function cookie(token, maxAge) {
  return `ef_session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
}

function getToken(request) {
  const cookies = request.headers.get("Cookie") || "";
  const item = cookies.split(";").map(x => x.trim())
    .find(x => x.startsWith("ef_session="));
  return item ? item.slice("ef_session=".length) : null;
}

async function createSession(userId, env) {
  const token = randomToken();
  const tokenHash = await hash(token);
  const expiry = new Date(Date.now() + 7 * 86400000).toISOString();

  await env.DB.prepare(
    "INSERT INTO sessions (user_id, token_hash, expires_at) VALUES (?, ?, ?)"
  ).bind(userId, tokenHash, expiry).run();

  return token;
}

export async function onRequestPost({ request, env }) {
  try {
    const data = await request.json();
    const action = data.action;

    if (action === "register") {
      const name = String(data.name || "").trim();
      const email = String(data.email || "").trim().toLowerCase();
      const phone = String(data.phone || "").trim();
      const password = String(data.password || "");

      if (!name || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
          password.length < 8 || password.length > 128) {
        return Response.json({
          success: false,
          message: "Enter valid details. Password must be at least 8 characters."
        }, { status: 400 });
      }

      const salt = randomToken();
      const derived = await passwordHash(password, salt);
      const storedHash = `${salt}:${derived}`;

      const result = await env.DB.prepare(
        "INSERT INTO users (name, email, phone, password_hash) VALUES (?, ?, ?, ?)"
      ).bind(name, email, phone, storedHash).run();

      const userId = result.meta.last_row_id;
      const token = await createSession(userId, env);

      return Response.json({
        success: true,
        message: "Account created",
        user: { id: userId, name, email }
      }, {
        headers: { "Set-Cookie": cookie(token, 604800) }
      });
    }

    if (action === "login") {
      const email = String(data.email || "").trim().toLowerCase();
      const password = String(data.password || "");

      const user = await env.DB.prepare(
        "SELECT id, name, email, password_hash FROM users WHERE email = ?"
      ).bind(email).first();

      if (!user || !user.password_hash) {
        return Response.json({
          success: false, message: "Invalid email or password"
        }, { status: 401 });
      }

      const [salt, savedHash] = user.password_hash.split(":");
      const enteredHash = await passwordHash(password, salt);

      if (enteredHash !== savedHash) {
        return Response.json({
          success: false, message: "Invalid email or password"
        }, { status: 401 });
      }

      const token = await createSession(user.id, env);

      return Response.json({
        success: true,
        user: { id: user.id, name: user.name, email: user.email }
      }, {
        headers: { "Set-Cookie": cookie(token, 604800) }
      });
    }

    if (action === "logout") {
      const token = getToken(request);
      if (token) {
        await env.DB.prepare(
          "DELETE FROM sessions WHERE token_hash = ?"
        ).bind(await hash(token)).run();
      }

      return Response.json({ success: true }, {
        headers: { "Set-Cookie": cookie("", 0) }
      });
    }

    return Response.json({
      success: false, message: "Unknown action"
    }, { status: 400 });

  } catch (error) {
    return Response.json({
      success: false, message: "Request failed"
    }, { status: 400 });
  }
}

export async function onRequestGet({ request, env }) {
  const token = getToken(request);

  if (!token) {
    return Response.json({ success: false, message: "Not logged in" }, { status: 401 });
  }

  const user = await env.DB.prepare(`
    SELECT users.id, users.name, users.email, users.role
    FROM sessions
    JOIN users ON users.id = sessions.user_id
    WHERE sessions.token_hash = ? AND sessions.expires_at > CURRENT_TIMESTAMP
  `).bind(await hash(token)).first();

  if (!user) {
    return Response.json({ success: false, message: "Session expired" }, { status: 401 });
  }

  return Response.json({ success: true, user });
                                 }
