import type { APIRoute } from "astro";
import { getCveIndex, getRecordById } from "../../lib/data";

export function getStaticPaths() {
  const index = getCveIndex();
  return Object.keys(index).map((id) => ({ params: { id } }));
}

export const GET: APIRoute = ({ params }) => {
  const id = params.id ?? "";
  const record = getRecordById(id);

  if (!record) {
    return new Response(JSON.stringify({ error: "not_found", message: `${id} was not found in the database.` }), {
      status: 404,
      headers: { "Content-Type": "application/json" },
    });
  }

  return new Response(JSON.stringify(record, null, 2), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "public, max-age=3600",
    },
  });
};
