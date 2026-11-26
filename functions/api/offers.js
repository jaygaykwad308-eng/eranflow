
export async function onRequestGet({ env }) {
  try {
    const result = await env.DB.prepare(`
      SELECT id, name, description, payout, tracking_url, status
      FROM offers
      WHERE status = 'active'
      ORDER BY id DESC
    `).all();

    return Response.json({
      success: true,
      offers: result.results || []
    });

  } catch (error) {
    return Response.json({
      success: false,
      message: error.message
    }, { status: 500 });
  }
}
