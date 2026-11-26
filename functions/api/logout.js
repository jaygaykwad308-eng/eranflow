
export async function onRequestPost({ request, env }) {
  try {
    const cookie = request.headers.get("Cookie") || "";
    const match = cookie.match(/(?:^|;\s*)session=([^;]+)/);

    if (match) {
      const token = match[1];

      const digest = await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(token)
      );

      const tokenHash = Array.from(
        new Uint8Array(digest),
        b => b.toString(16).padStart(2, "0")
      ).join("");

      await env.DB.prepare(
        "DELETE FROM sessions WHERE token_hash = ?"
      ).bind(tokenHash).run();
    }

    return Response.json(
      { success: true, message: "Logged out successfully" },
      {
        headers: {
          "Set-Cookie": "session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"
        }
      }
    );

  } catch (error) {
    return Response.json(
      { success: false, message: "Logout failed" },
      { status: 500 }
    );
  }
}
