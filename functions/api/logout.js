export async function onRequestPost({ request, env }) {
  try {
    const cookie = request.headers.get("Cookie") || "";
    const token = cookie.match(/(?:^|;\s*)session=([^;]+)/)?.[1];

    if (token) {
      const digest = await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(token)
      );

      const tokenHash = Array.from(new Uint8Array(digest))
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");

      await env.DB.prepare(
        "DELETE FROM sessions WHERE token_hash = ?"
      ).bind(tokenHash).run();
    }

    return new Response(JSON.stringify({
      success: true,
      message: "Logged out successfully"
    }), {
      headers: {
        "Content-Type": "application/json",
        "Set-Cookie": "session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"
      }
    });

  } catch {
    return Response.json(
      { success: false, message: "Logout failed" },
      { status: 500 }
    );
  }
    }
