
export async function onRequestGet({ request, env }) {
  try {
    const cookie = request.headers.get("Cookie") || "";
    const token = cookie.match(/(?:^|;\s*)session=([^;]+)/)?.[1];

    if (!token) {
      return Response.json(
        { success: false, message: "Not logged in" },
        { status: 401 }
      );
    }

    const digest = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(token)
    );

    const tokenHash = Array.from(new Uint8Array(digest))
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");

    const result = await env.DB.prepare(`
      SELECT users.id, users.name, users.email, users.balance
      FROM sessions
      JOIN users ON users.id = sessions.user_id
      WHERE sessions.token_hash = ?
      AND sessions.expires_at > ?
    `).bind(tokenHash, Math.floor(Date.now() / 1000)).first();

    if (!result) {
      return Response.json(
        { success: false, message: "Session expired" },
        { status: 401 }
      );
    }

    return Response.json({
      success: true,
      user: result
    });

  } catch {
    return Response.json(
      { success: false, message: "Authentication failed" },
      { status: 500 }
    );
  }
}
