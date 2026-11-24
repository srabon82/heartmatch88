export default async (request, context) => {
  const headers = {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store, no-cache, must-revalidate",
    "x-content-type-options": "nosniff"
  };

  if (request.method !== "GET") {
    return new Response(JSON.stringify({ checked: false, error: "Method not allowed" }), {
      status: 405, headers: { ...headers, "allow": "GET" }
    });
  }

  const apiKey = Netlify.env.get("IPQS_API_KEY");
  if (!apiKey) {
    return new Response(JSON.stringify({ checked: false, error: "IP risk service is not configured" }), {
      status: 503, headers
    });
  }

  // Netlify supplies the visitor IP in the function request context.
  // Do not trust client-submitted X-Forwarded-For or query-string IP values.
  const ip = context.ip;
  if (!ip) {
    return new Response(JSON.stringify({ checked: false, error: "Visitor IP unavailable" }), {
      status: 503, headers
    });
  }

  const userAgent = request.headers.get("user-agent") || "";
  const endpoint = new URL(
    `https://ipqualityscore.com/api/json/ip/${encodeURIComponent(apiKey)}/${encodeURIComponent(ip)}`
  );
  endpoint.searchParams.set("strictness", "1");
  endpoint.searchParams.set("allow_public_access_points", "true");
  if (userAgent) endpoint.searchParams.set("user_agent", userAgent);

  try {
    const upstream = await fetch(endpoint, {
      method: "GET",
      headers: { "accept": "application/json" },
      signal: AbortSignal.timeout(9000)
    });

    if (!upstream.ok) {
      return new Response(JSON.stringify({ checked: false, error: "Risk provider unavailable" }), {
        status: 503, headers
      });
    }

    const data = await upstream.json();
    if (data?.success !== true) {
      return new Response(JSON.stringify({ checked: false, error: "Risk check could not be completed" }), {
        status: 503, headers
      });
    }

    const proxy = data.proxy === true;
    const vpn = data.vpn === true;
    const tor = data.tor === true;
    const recentAbuse = data.recent_abuse === true;
    const blocked = proxy || vpn || tor || recentAbuse;
    const country = String(data.country_code || "").toUpperCase();
    const allowedCountries = new Set(["US", "CA", "AU", "GB"]);

    return new Response(JSON.stringify({
      checked: true,
      blocked,
      reason: blocked
        ? "A proxy, VPN, Tor or recently abusive connection was detected. Please disable anonymizing services and try again."
        : "",
      proxy,
      vpn,
      tor,
      recent_abuse: recentAbuse,
      country_code: country,
      allowed_country: allowedCountries.has(country)
    }), { status: 200, headers });
  } catch (error) {
    return new Response(JSON.stringify({ checked: false, error: "Risk check timed out or failed" }), {
      status: 503, headers
    });
  }
};
