
export async function onRequestPost({ request, env }) {
  try {
    const { email, password } = await request.json();

    if (!email || !password) {
      return Response.json(
        { success: false, message: "Required fields missing" },
        { status: 400 }
      );
    }

    const user = await env.DB.prepare(
      "SELECT * FROM users WHERE email = ?"
    ).bind(email.trim().toLowerCase()).first();

    if (!user) {
      return Response.json(
        { success: false, message: "Invalid email or password" },
        { status: 401 }
      );
    }

    const [algorithm, iterations, saltHex, hashHex] =
      user.password_hash.split("$");

    if (algorithm !== "pbkdf2" || iterations !== "310000") {
      return Response.json(
        { success: false, message: "Invalid credentials" },
        { status: 401 }
      );
    }

    const fromHex = hex =>
      new Uint8Array(hex.match(/.{2}/g).map(x => parseInt(x, 16)));

    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );

    const bits = await crypto.subtle.deriveBits({
      name: "PBKDF2",
      salt: fromHex(saltHex),
      iterations: 310000,
      hash: "SHA-256"
    }, key, 256);

    const actualHash = Array.from(new Uint8Array(bits))
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");

    if (actualHash !== hashHex) {
      return Response.json(
        { success: false, message: "Invalid email or password" },
        { status: 401 }
      );
    }

    const tokenBytes = crypto.getRandomValues(new Uint8Array(32));
    const token = Array.from(tokenBytes)
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");

    const digest = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(token)
    );

    const tokenHash = Array.from(new Uint8Array(digest))
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");

    const expiresAt = Math.floor(Date.now() / 1000) + 604800;

    await env.DB.prepare(
      "INSERT INTO sessions (user_id, token_hash, expires_at) VALUES (?, ?, ?)"
    ).bind(user.id, tokenHash, expiresAt).run();

    return new Response(JSON.stringify({
      success: true,
      message: "Login successful",
      user: {
        id: user.id,
        name: user.name,
        email: user.email
      }
    }), {
      headers: {
        "Content-Type": "application/json",
        "Set-Cookie": `session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800`
      }
    });

  } catch (error) {
    return Response.json(
      { success: false, message: "Login failed" },
      { status: 500 }
    );
  }
}
