
export async function onRequestPost({ request, env }) {
  try {
    // Check database connection
    if (!env.DB) {
      throw new Error("DB binding not connected");
    }

    const data = await request.json();

    const name = String(data.name || "").trim();
    const email = String(data.email || "").trim().toLowerCase();
    const password = String(data.password || "");

    if (!name || !email || !password) {
      return Response.json({
        success: false,
        message: "All fields are required"
      }, { status: 400 });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return Response.json({
        success: false,
        message: "Enter a valid email"
      }, { status: 400 });
    }

    if (password.length < 8) {
      return Response.json({
        success: false,
        message: "Password must be at least 8 characters"
      }, { status: 400 });
    }

    const existing = await env.DB.prepare(
      "SELECT id FROM users WHERE email = ?"
    ).bind(email).first();

    if (existing) {
      return Response.json({
        success: false,
        message: "Email already registered"
      }, { status: 409 });
    }

    // Generate secure password hash
    const salt = crypto.getRandomValues(
      new Uint8Array(16)
    );

    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );

    const bits = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt,
        iterations: 100000,
        hash: "SHA-256"
      },
      key,
      256
    );

    const toHex = bytes =>
      Array.from(bytes, b =>
        b.toString(16).padStart(2, "0")
      ).join("");

    const passwordHash =
      `pbkdf2$100000$${toHex(salt)}$${toHex(new Uint8Array(bits))}`;

    // Save user
    const result = await env.DB.prepare(
      `INSERT INTO users
       (name, email, password_hash, balance)
       VALUES (?, ?, ?, 0)`
    ).bind(name, email, passwordHash).run();

    if (!result.success) {
      throw new Error("Database could not save user");
    }

    return Response.json({
      success: true,
      message: "Registration successful"
    }, { status: 201 });

  } catch (error) {
    return Response.json({
      success: false,
      message: error.message || "Unknown registration error"
    }, { status: 500 });
  }
}
