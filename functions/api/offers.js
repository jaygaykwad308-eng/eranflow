
export async function onRequestGet({ env }) {
  try {
    const result = await env.DB.prepare(
      "SELECT id, title, description, payout, status FROM offers WHERE status = 'active' ORDER BY id DESC"
    ).all();

    return Response.json({
      success: true,
      offers: result.results
    });
  } catch (error) {
    return Response.json({
      success: false,
      message: "Unable to load offers"
    }, { status: 500 });
  }
}

export async function onRequestPost({ request, env }) {
  try {
    const data = await request.json();

    if (!data.title || !Number.isFinite(Number(data.payout)) || Number(data.payout) < 0) {
      return Response.json({ success: false, message: "Invalid offer details" }, { status: 400 });
    }

    await env.DB.prepare(
      "INSERT INTO offers (title, description, payout, tracking_url) VALUES (?, ?, ?, ?)"
    ).bind(
      data.title,
      data.description || "",
      Number(data.payout),
      data.tracking_url || ""
    ).run();

    return Response.json({ success: true, message: "Offer created" });
  } catch (error) {
    return Response.json({ success: false, message: "Unable to create offer" }, { status: 500 });
  }
}
