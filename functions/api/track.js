
export async function onRequestPost({ request, env }) {
  try {
    const data = await request.json();

    const userId = Number(data.user_id);
    const offerId = Number(data.offer_id);

    if (!Number.isSafeInteger(userId) || userId <= 0 ||
        !Number.isSafeInteger(offerId) || offerId <= 0) {
      return Response.json({
        success: false,
        message: "Invalid tracking details"
      }, { status: 400 });
    }

    const offer = await env.DB.prepare(
      "SELECT id FROM offers WHERE id = ? AND status = 'active'"
    ).bind(offerId).first();

    if (!offer) {
      return Response.json({
        success: false,
        message: "Offer not found"
      }, { status: 404 });
    }

    const trackingId = "EF-" + crypto.randomUUID();

    await env.DB.prepare(
      "INSERT INTO clicks (user_id, offer_id, tracking_id) VALUES (?, ?, ?)"
    ).bind(userId, offerId, trackingId).run();

    return Response.json({
      success: true,
      tracking_id: trackingId
    });
  } catch (error) {
    return Response.json({
      success: false,
      message: "Tracking failed"
    }, { status: 500 });
  }
}
