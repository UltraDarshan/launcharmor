/**
 * VibeShield Edge Proxy (Cloudflare Worker)
 * Zero-cost API shield, rate-limiting, and secret masker for vibe-coded apps.
 * Deploy for free on Cloudflare Workers (100,000 req/day free).
 */

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // 1. Block common bot and exploit probes (PHP exploits, path traversal)
    const dangerousPaths = [
      /\.php$/i,
      /\/wp-admin/i,
      /\/eval-stdin/i,
      /\/\.env/i,
      /\/\.git/i,
      /\.\.\//, // Directory traversal
    ];

    for (const pattern of dangerousPaths) {
      if (pattern.test(url.pathname)) {
        return new Response(
          JSON.stringify({ error: "Blocked by VibeShield Edge Firewall: Malicious pattern detected." }),
          { status: 403, headers: { "Content-Type": "application/json" } }
        );
      }
    }

    // 2. Strict Rate Limiting Header Check (Stub for Cloudflare Rate Limiting Binding)
    const clientIP = request.headers.get("CF-Connecting-IP") || "unknown";

    // 3. Forward request to origin app
    // Replace with your real origin (e.g. your Vercel / VPS endpoint)
    const originUrl = new URL(request.url);
    originUrl.hostname = env.ORIGIN_HOSTNAME || "wintershogun.com";

    const modifiedRequest = new Request(originUrl.toString(), {
      method: request.method,
      headers: request.headers,
      body: request.body,
      redirect: "follow",
    });

    const response = await fetch(modifiedRequest);

    // 4. Secret Masking on Outgoing Responses (Prevent accidental API key leaks in API responses)
    const contentType = response.headers.get("content-type") || "";
    if (contentType.includes("application/json") || contentType.includes("text/")) {
      let bodyText = await response.text();

      // Mask OpenAI and Stripe secret keys if leaked in JSON responses
      bodyText = bodyText.replace(/sk-[a-zA-Z0-9]{20,}/g, "[MASKED_BY_VIBESHIELD]");
      bodyText = bodyText.replace(/sk_live_[0-9a-zA-Z]{24,}/g, "[MASKED_BY_VIBESHIELD]");

      const newHeaders = new Headers(response.headers);
      newHeaders.set("X-Protected-By", "VibeShield-Edge");
      newHeaders.set("X-Content-Type-Options", "nosniff");
      newHeaders.set("X-Frame-Options", "DENY");

      return new Response(bodyText, {
        status: response.status,
        statusText: response.statusText,
        headers: newHeaders,
      });
    }

    return response;
  },
};
