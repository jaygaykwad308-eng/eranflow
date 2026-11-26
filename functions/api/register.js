
export async function onRequestPost({ request, env }) {
  try {
    const { email, password } = await request.json();

    if (!email || !password) {
      return Response.json({
        success: false,
        message: "Email and password required"
      }, { status: 400 });
    }

    const user = await env.DB.prepare(
      "SELECT * FROM users WHERE email = ?"
    ).bind(email.trim().toLowerCase()).first();

    if (!user) {
      return Response.json({
        success: false,
        message: "Invalid email or password"
      }, { status: 401 });
    }

    const parts = user.password_hash.split("$");

    if (parts.length !== 4 || parts[0] !== "pbkdf2") {
      return Response.json({
        success: false,
        message: "Invalid password format"
      }, { status: 500 });
    }

    const iterations = Number(parts[1]);

    if (!Number.isInteger(iterations) ||
        iterations < 1 || iterations > 100000) {
      return Response.json({
        success: false,
        message: "Unsupported password format"
      }, { status: 500 });
    }

    const fromHex = hex =>
      new Uint8Array(hex.match(/.{2}/g).map(x => parseInt(x, 16)));

    const salt = fromHex(parts[2]);
    const expectedHash = fromHex(parts[3]);

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
      iterations,
      hash: "SHA-256"
    }, key, 256);

    const actualHash = new Uint8Array(bits);

    if (actualHash.length !== expectedHash.length ||
        !actualHash.every((b, i) => b === expectedHash[i])) {
      return Response.json({
        success: false,
        message: "Invalid email or password"
      }, { status: 401 });
    }

    const tokenBytes = crypto.getRandomValues(new Uint8Array(32));
    const token = Array.from(tokenBytes, b =>
      b.toString(16).padStart(2, "0")
    ).join("");

    const digest = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(token)
    );

    const tokenHash = Array.from(new Uint8Array(digest), b =>
      b.toString(16).padStart(2, "0")
    ).join("");

    const expires = Math.floor(Date.now() / 1000) + 604800;

    await env.DB.prepare(
      "INSERT INTO sessions (user_id, token_hash, expires_at) VALUES (?, ?, ?)"
    ).bind(user.id, tokenHash, expires).run();

    return Response.json({
      success: true,
      message: "Login successful",
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        balance: user.balance
      }
    }, {
      headers: {
        "Set-Cookie": `session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800`
      }
    });

  } catch (error) {
    return Response.json({
      success: false,
      message: error.message || "Login failed"
    }, { status: 500 });
  }
}
