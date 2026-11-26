export async function onRequestPost({ request, env }) {
  try {
    const { email, password } = await request.json();

    if (!email || !password) {
      return Response.json(
        { success: false, message: "Email and password required" },
        { status: 400 }
      );
    }

    const user = await env.DB.prepare(
      "SELECT id, name, email, password_hash FROM users WHERE email = ?"
    ).bind(email.trim().toLowerCase()).first();

    if (!user) {
      return Response.json(
        { success: false, message: "Invalid email or password" },
        { status: 401 }
      );
    }

    const [algorithm, iterations, saltHex, hashHex] =
      user.password_hash.split("$");

    if (algorithm !== "pbkdf2" || Number(iterations) !== 310000) {
      return Response.json(
        { success: false, message: "Invalid account credentials" },
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

    const bits = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: fromHex(saltHex),
        iterations: 310000,
        hash: "SHA-256"
      },
      key,
      256
    );

    const actualHash = Array.from(new Uint8Array(bits))
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");

    if (actualHash !== hashHex) {
      return Response.json(
        { success: false, message: "Invalid email or password" },
        { status: 401 }
      );
    }

    return Response.json({
      success: true,
      message: "Login successful",
      user: {
        id: user.id,
        name: user.name,
        email: user.email
      }
    });

  } catch {
    return Response.json(
      { success: false, message: "Login failed" },
      { status: 500 }
    );
  }
}
