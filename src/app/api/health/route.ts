export const dynamic = "force-dynamic";

/** Liveness only. Deliberately reports nothing about configuration or secrets. */
export function GET() {
  return Response.json({ status: "ok" });
}
