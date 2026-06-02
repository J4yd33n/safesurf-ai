// FRONTEND? No — BACKEND edge function. Looks up domain registration
// data via RDAP (free, no API key needed) and returns domain age in days.
import { corsHeaders } from "npm:@supabase/supabase-js@2/cors";

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const { domain } = await req.json();
    if (!domain || typeof domain !== "string") {
      return new Response(JSON.stringify({ error: "Missing domain" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // Strip protocol/path
    const clean = domain.replace(/^https?:\/\//, "").split("/")[0].split(":")[0];
    // Use registration domain (last 2 labels)
    const parts = clean.split(".");
    const registration = parts.slice(-2).join(".");

    const rdapResp = await fetch(`https://rdap.org/domain/${registration}`, {
      headers: { Accept: "application/rdap+json" },
    });

    if (!rdapResp.ok) {
      return new Response(
        JSON.stringify({
          domain: registration,
          found: false,
          message: `RDAP lookup failed (${rdapResp.status})`,
        }),
        { headers: { ...corsHeaders, "Content-Type": "application/json" } },
      );
    }

    const data = await rdapResp.json();
    const events = (data.events || []) as Array<{ eventAction: string; eventDate: string }>;
    const registration_event = events.find((e) => e.eventAction === "registration");
    const expiration_event = events.find((e) => e.eventAction === "expiration");
    const last_changed = events.find((e) => e.eventAction === "last changed");

    let ageDays: number | null = null;
    if (registration_event) {
      const created = new Date(registration_event.eventDate).getTime();
      ageDays = Math.floor((Date.now() - created) / (1000 * 60 * 60 * 24));
    }

    const registrar = (data.entities || [])
      .find((e: any) => (e.roles || []).includes("registrar"))?.vcardArray?.[1]
      ?.find((v: any) => v[0] === "fn")?.[3] ?? null;

    return new Response(
      JSON.stringify({
        domain: registration,
        found: true,
        registered_at: registration_event?.eventDate ?? null,
        expires_at: expiration_event?.eventDate ?? null,
        last_changed_at: last_changed?.eventDate ?? null,
        age_days: ageDays,
        registrar,
        nameservers: (data.nameservers || []).map((n: any) => n.ldhName).filter(Boolean),
        status: data.status || [],
      }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } },
    );
  } catch (err) {
    return new Response(JSON.stringify({ error: (err as Error).message }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});