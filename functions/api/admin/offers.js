
async function verifyAdmin(request, env) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(/(?:^|;\s*)session=([^;]+)/);

  if (!match) return null;

  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(match[1])
  );

  const hash = Array.from(new Uint8Array(digest), b =>
    b.toString(16).padStart(2, "0")
  ).join("");

  return await env.DB.prepare(`
    SELECT users.id, users.role
    FROM sessions
    JOIN users ON users.id = sessions.user_id
    WHERE sessions.token_hash = ?
    AND sessions.expires_at > ?
  `).bind(hash, Math.floor(Date.now() / 1000)).first();
}

function json(data, status = 200) {
  return Response.json(data, { status });
}

export async function onRequestGet({ request, env }) {
  try {
    const admin = await verifyAdmin(request, env);
    if (!admin || admin.role !== "admin") {
      return json({ success: false, message: "Admin access denied" }, 403);
    }

    const result = await env.DB.prepare(`
      SELECT id, name, description, payout, tracking_url, status, created_at
      FROM offers ORDER BY id DESC
    `).all();

    return json({ success: true, offers: result.results || [] });
  } catch (error) {
    return json({ success: false, message: error.message }, 500);
  }
}

export async function onRequestPost({ request, env }) {
  try {
    const admin = await verifyAdmin(request, env);
    if (!admin || admin.role !== "admin") {
      return json({ success: false, message: "Admin access denied" }, 403);
    }

    const body = await request.json();
    const name = String(body.name || "").trim();
    const description = String(body.description || "").trim();
    const payout = Number(body.payout);
    const trackingUrl = String(body.tracking_url || "").trim();

    if (!name || !Number.isFinite(payout) || payout < 0) {
      return json({ success: false, message: "Valid name and payout required" }, 400);
    }

    if (trackingUrl && !/^https:\/\/\S+$/i.test(trackingUrl)) {
      return json({ success: false, message: "Tracking URL must use HTTPS" }, 400);
    }

    const result = await env.DB.prepare(`
      INSERT INTO offers (name, description, payout, tracking_url, status)
      VALUES (?, ?, ?, ?, 'active')
    `).bind(name, description, payout, trackingUrl || null).run();

    return json({
      success: true,
      message: "Offer added",
      id: result.meta.last_row_id
    }, 201);

  } catch (error) {
    return json({ success: false, message: error.message }, 500);
  }
}

export async function onRequestPut({ request, env }) {
  try {
    const admin = await verifyAdmin(request, env);
    if (!admin || admin.role !== "admin") {
      return json({ success: false, message: "Admin access denied" }, 403);
    }

    const body = await request.json();
    const id = Number(body.id);
    const name = String(body.name || "").trim();
    const description = String(body.description || "").trim();
    const payout = Number(body.payout);
    const trackingUrl = String(body.tracking_url || "").trim();
    const status = String(body.status || "");

    if (!Number.isInteger(id) || id < 1 || !name ||
        !Number.isFinite(payout) || payout < 0 ||
        !["active", "inactive"].includes(status)) {
      return json({ success: false, message: "Invalid offer details" }, 400);
    }

    if (trackingUrl && !/^https:\/\/\S+$/i.test(trackingUrl)) {
      return json({ success: false, message: "Tracking URL must use HTTPS" }, 400);
    }

    const result = await env.DB.prepare(`
      UPDATE offers
      SET name = ?, description = ?, payout = ?, tracking_url = ?, status = ?
      WHERE id = ?
    `).bind(name, description, payout, trackingUrl || null, status, id).run();

    if (!result.meta.changes) {
      return json({ success: false, message: "Offer not found" }, 404);
    }

    return json({ success: true, message: "Offer updated" });
  } catch (error) {
    return json({ success: false, message: error.message }, 500);
  }
}

export async function onRequestDelete({ request, env }) {
  try {
    const admin = await verifyAdmin(request, env);
    if (!admin || admin.role !== "admin") {
      return json({ success: false, message: "Admin access denied" }, 403);
    }

    const body = await request.json();
    const id = Number(body.id);

    if (!Number.isInteger(id) || id < 1) {
      return json({ success: false, message: "Valid offer ID required" }, 400);
    }

    const result = await env.DB.prepare(
      "DELETE FROM offers WHERE id = ?"
    ).bind(id).run();

    if (!result.meta.changes) {
      return json({ success: false, message: "Offer not found" }, 404);
    }

    return json({ success: true, message: "Offer deleted" });
  } catch (error) {
    return json({ success: false, message: error.message }, 500);
  }
                   }
