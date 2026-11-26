export async function onRequestGet({ request, env }) {
  try {
    const cookie = request.headers.get("Cookie") || "";
    const match = cookie.match(/(?:^|;\s*)session=([^;]+)/);

    if (!match) {
      return Response.json({ success: false, message: "Not logged in" }, { status: 401 });
    }

    const token = match[1];
    const digest = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(token)
    );

    const tokenHash = Array.from(new Uint8Array(digest), b =>
      b.toString(16).padStart(2, "0")
    ).join("");

    const user = await env.DB.prepare(`
      SELECT users.id, users.name, users.email, users.balance
      FROM sessions
      JOIN users ON users.id = sessions.user_id
      WHERE sessions.token_hash = ?
      AND sessions.expires_at > ?
    `).bind(tokenHash, Math.floor(Date.now() / 1000)).first();

    if (!user) {
      return Response.json({ success: false, message: "Session expired" }, { status: 401 });
    }

    return Response.json({ success: true, user });

  } catch (error) {
    return Response.json({ success: false, message: error.message }, { status: 500 });
  }
}
