export async function onRequestGet({ env }) {
  try {
    const result = await env.DB.prepare(
      "SELECT id, name, description, payout, tracking_url, status FROM offers WHERE status = 'active' ORDER BY id DESC"
    ).all();

    return new Response(JSON.stringify({
      success: true,
      offers: result.results || []
    }), {
      headers: { "Content-Type": "application/json" }
    });
  } catch (error) {
    return new Response(JSON.stringify({
      success: false,
      message: error.message
    }), {
      status: 500,
      headers: { "Content-Type": "application/json" }
    });
  }
}
