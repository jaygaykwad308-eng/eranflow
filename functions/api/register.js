
export async function onRequestPost({ request, env }) {
  try {
    const { name, email, password } = await request.json();

    const cleanName = String(name || "").trim();
    const cleanEmail = String(email || "").trim().toLowerCase();

    if (!cleanName || !cleanEmail || !password) {
      return Response.json({ success: false, message: "All fields required" }, { status: 400 });
    }

    if (String(password).length < 8) {
      return Response.json({ success: false, message: "Password must be at least 8 characters" }, { status: 400 });
    }

    const existing = await env.DB.prepare(
      "SELECT id FROM users WHERE email = ?"
    ).bind(cleanEmail).first();

    if (existing) {
      return Response.json({ success: false, message: "Email already registered" }, { status: 409 });
    }

    const salt = crypto.getRandomValues(new Uint8Array(16));

    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );

    const bits = await crypto.subtle.deriveBits({
      name: "PBKDF2",
      salt,
      iterations: 100000,
      hash: "SHA-256"
    }, key, 256);

    const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");

    const passwordHash = `pbkdf2$100000$${hex(salt)}$${hex(new Uint8Array(bits))}`;

    await env.DB.prepare(
      `INSERT INTO users (mobile, name, email, password_hash, balance)
       VALUES (?, ?, ?, ?, 0)`
    ).bind(`email:${cleanEmail}`, cleanName, cleanEmail, passwordHash).run();

    return Response.json({ success: true, message: "Registration successful" }, { status: 201 });

  } catch (error) {
    return Response.json({ success: false, message: error.message }, { status: 500 });
  }
}
