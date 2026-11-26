
export async function onRequestPost({ request, env }) {
  try {
    const { name, email, password } = await request.json();

    if (!name || !email || !password) {
      return Response.json(
        { success: false, message: "All fields are required" },
        { status: 400 }
      );
    }

    if (password.length < 8) {
      return Response.json(
        { success: false, message: "Password must be at least 8 characters" },
        { status: 400 }
      );
    }

    const normalizedEmail = email.trim().toLowerCase();

    const existing = await env.DB.prepare(
      "SELECT id FROM users WHERE email = ?"
    ).bind(normalizedEmail).first();

    if (existing) {
      return Response.json(
        { success: false, message: "Email already registered" },
        { status: 409 }
      );
    }

    const salt = crypto.getRandomValues(new Uint8Array(16));

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
        iterations: 310000,
        hash: "SHA-256"
      },
      key,
      256
    );

    const toHex = bytes =>
      Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");

    const passwordHash =
      `pbkdf2$310000$${toHex(salt)}$${toHex(new Uint8Array(bits))}`;

    await env.DB.prepare(
      "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)"
    ).bind(name.trim(), normalizedEmail, passwordHash).run();

    return Response.json(
      { success: true, message: "Registration successful" },
      { status: 201 }
    );

  } catch (error) {
    return Response.json(
      { success: false, message: "Registration failed" },
      { status: 500 }
    );
  }
}
