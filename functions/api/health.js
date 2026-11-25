export async function onRequestGet({ env }) {
  try {
    await env.DB.prepare("SELECT 1").first();

    return Response.json({
      success: true,
      message: "EarnFlow backend is connected!",
      database: "Connected"
    });
  } catch (error) {
    return Response.json({
      success: false,
      message: "Database connection failed"
    }, { status: 500 });
  }
}
