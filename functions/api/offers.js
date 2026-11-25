
async function getAdmin(request, env) {
  const cookies = request.headers.get("Cookie") || "";
  const item = cookies.split(";").map(x => x.trim())
    .find(x => x.startsWith("ef_session="));

  if (!item) return false;

  const token = item.slice("ef_session=".length);
  const bytes = await crypto.subtle.digest(
    "SHA-256", new TextEncoder().encode(token)
  );
  const tokenHash = [...new Uint8Array(bytes)]
    .map(b => b.toString(16).padStart(2, "0")).join("");

  const user = await env.DB.prepare(`
    SELECT users.id
    FROM sessions
    JOIN users ON users.id = sessions.user_id
    WHERE sessions.token_hash = ?
      AND sessions.expires_at > CURRENT_TIMESTAMP
      AND users.role = 'admin'
  `).bind(tokenHash).first();

  return !!user;
}

export async function onRequestGet({ env }) {
  try {
    const result = await env.DB.prepare(
      "SELECT id, title, description, payout, status FROM offers WHERE status = 'active' ORDER BY id DESC"
    ).all();

    return Response.json({ success: true, offers: result.results });
  } catch {
    return Response.json({ success: false }, { status: 500 });
  }
}

export async function onRequestPost({ request, env }) {
  try {
    if (!await getAdmin(request, env)) {
      return Response.json(
        { success: false, message: "Admin access required" },
        { status: 403 }
      );
    }

    const data = await request.json();
    const title = String(data.title || "").trim();
    const payout = Number(data.payout);

    if (!title || title.length > 150 ||
        !Number.isFinite(payout) || payout < 0 || payout > 100000) {
      return Response.json({ success: false, message: "Invalid details" }, { status: 400 });
    }

    await env.DB.prepare(
      "INSERT INTO offers (title, description, payout, tracking_url) VALUES (?, ?, ?, ?)"
    ).bind(
      title,
      String(data.description || "").slice(0, 1000),
      payout,
      String(data.tracking_url || "").slice(0, 2000)
    ).run();

    return Response.json({ success: true, message: "Offer added" });
  } catch {
    return Response.json({ success: false }, { status: 500 });
  }
}
