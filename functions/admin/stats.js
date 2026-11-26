export async function onRequestGet({ request, env }) {
  try {
    const cookie = request.headers.get("Cookie") || "";
    const match = cookie.match(/(?:^|;\s*)session=([^;]+)/);

    if (!match) {
      return Response.json({ success: false, message: "Unauthorized" }, { status: 401 });
    }

    const token = match[1];
    const digest = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(token)
    );

    const hash = Array.from(new Uint8Array(digest), b =>
      b.toString(16).padStart(2, "0")
    ).join("");

    const admin = await env.DB.prepare(`
      SELECT users.id, users.role
      FROM sessions
      JOIN users ON users.id = sessions.user_id
      WHERE sessions.token_hash = ? AND sessions.expires_at > ?
    `).bind(hash, Math.floor(Date.now() / 1000)).first();

    if (!admin || admin.role !== "admin") {
      return Response.json({ success: false, message: "Admin access denied" }, { status: 403 });
    }

    const users = await env.DB.prepare("SELECT COUNT(*) AS total FROM users").first();
    const offers = await env.DB.prepare("SELECT COUNT(*) AS total FROM offers").first().catch(() => ({ total: 0 }));

    return Response.json({
      success: true,
      stats: {
        totalUsers: users.total,
        totalOffers: offers.total
      }
    });

  } catch (error) {
    return Response.json({ success: false, message: error.message }, { status: 500 });
  }
}
