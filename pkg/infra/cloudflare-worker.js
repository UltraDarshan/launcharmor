/**
 * VibeShield Edge Proxy (Cloudflare Worker)
 * Zero-cost API shield, rate-limiting, and secret masker for vibe-coded apps.
 * Deploy for free on Cloudflare Workers (100,000 req/day free).
 *
 * Required: ORIGIN_HOSTNAME var (your real app host, e.g. myapp.vercel.app).
 * Optional: RATE_LIMITER binding (Workers Rate Limiting API), see wrangler.toml.
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

    // 2. Per-IP rate limiting (stops bots draining paid AI API credits)
    if (env.RATE_LIMITER) {
      const clientIP = request.headers.get("CF-Connecting-IP") || "unknown";
      const { success } = await env.RATE_LIMITER.limit({ key: clientIP });
      if (!success) {
        return new Response(JSON.stringify({ error: "Rate limit exceeded. Slow down." }), {
          status: 429,
          headers: { "Content-Type": "application/json", "Retry-After": "60" },
        });
      }
    }

    // 3. Forward request to origin app
    if (!env.ORIGIN_HOSTNAME) {
      return new Response("VibeShield Edge misconfigured: set the ORIGIN_HOSTNAME variable.", { status: 500 });
    }
    const originUrl = new URL(request.url);
    originUrl.hostname = env.ORIGIN_HOSTNAME;

    // redirect: "manual" passes origin redirects (e.g. to /login) back to the browser untouched
    const modifiedRequest = new Request(originUrl.toString(), {
      method: request.method,
      headers: request.headers,
      body: request.body,
      redirect: "manual",
    });

    const response = await fetch(modifiedRequest);

    // 4. Secret Masking on Outgoing Responses (Prevent accidental API key leaks in API responses)
    const contentType = response.headers.get("content-type") || "";
    // Never buffer streams (SSE is how AI chat apps stream tokens)
    const isStream = contentType.includes("text/event-stream");
    if (!isStream && (contentType.includes("application/json") || contentType.includes("text/"))) {
      let bodyText = await response.text();

      // Mask OpenAI and Stripe secret keys if leaked in JSON responses
      bodyText = bodyText.replace(/sk-(?:proj-|svcacct-|admin-)?[a-zA-Z0-9_-]{20,}/g, "[MASKED_BY_VIBESHIELD]");
      bodyText = bodyText.replace(/sk_live_[0-9a-zA-Z]{24,}/g, "[MASKED_BY_VIBESHIELD]");

      const newHeaders = new Headers(response.headers);
      newHeaders.delete("Content-Length"); // body length changes after masking
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
