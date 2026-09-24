import { mkdirSync, writeFileSync } from "node:fs"

const OUT = process.env.OUT ?? "/tmp/anth-e2e/captures"
const EXPIRES_IN = Number(process.env.EXPIRES_IN ?? 28800)
mkdirSync(OUT, { recursive: true })
let n = 0
let tokenN = 0
const used = new Set<string>()
const record = (req: Request, body: string) => {
  n++
  writeFileSync(`${OUT}/req-${String(n).padStart(3, "0")}.json`, JSON.stringify({ method: req.method, url: req.url, headers: Object.fromEntries(req.headers), body }, null, 1))
}
const sse = (events: any[]) =>
  new Response(events.map((e) => `event: ${e.type}\ndata: ${JSON.stringify(e)}\n\n`).join(""), {
    headers: { "content-type": "text/event-stream" },
  })
const usage = { input_tokens: 10, output_tokens: 5, cache_read_input_tokens: 0, cache_creation_input_tokens: 0 }
const message = (content: any[], stop: string) => [
  { type: "message_start", message: { id: `msg_${n}`, type: "message", role: "assistant", model: "claude-sonnet-5", content: [], stop_reason: null, usage } },
  ...content.flatMap((block, index) =>
    block.type === "text"
      ? [
          { type: "content_block_start", index, content_block: { type: "text", text: "" } },
          { type: "content_block_delta", index, delta: { type: "text_delta", text: block.text } },
          { type: "content_block_stop", index },
        ]
      : [
          { type: "content_block_start", index, content_block: { type: "tool_use", id: block.id, name: block.name, input: {} } },
          { type: "content_block_delta", index, delta: { type: "input_json_delta", partial_json: JSON.stringify(block.input) } },
          { type: "content_block_stop", index },
        ],
  ),
  { type: "message_delta", delta: { stop_reason: stop, stop_sequence: null }, usage: { output_tokens: 5 } },
  { type: "message_stop" },
]

const server = Bun.serve({
  port: Number(process.env.PORT ?? 4800),
  hostname: "127.0.0.1",
  async fetch(req) {
    const url = new URL(req.url)
    const body = await req.text()
    record(req, body)
    if (url.pathname === "/v1/oauth/token") {
      const b = JSON.parse(body)
      if (b.grant_type === "refresh_token") {
        if (used.has(b.refresh_token)) return Response.json({ error: "invalid_grant", error_description: "reused" }, { status: 400 })
        used.add(b.refresh_token)
      } else if (b.code !== "goodcode") return Response.json({ error: "invalid_grant" }, { status: 400 })
      tokenN++
      return Response.json({ access_token: `sk-ant-oat01-fake${tokenN}`, refresh_token: `sk-ant-ort01-fake${tokenN}`, expires_in: EXPIRES_IN, token_type: "Bearer" })
    }
    if (url.pathname === "/api/oauth/profile") return Response.json({ account: { uuid: "acc-11111111-2222-3333-4444-555555555555" } })
    if (url.pathname.endsWith("/v1/messages")) {
      const auth = req.headers.get("authorization") ?? ""
      if (!auth.startsWith("Bearer sk-ant-oat01-fake")) return Response.json({ type: "error", error: { type: "authentication_error", message: "bad auth" } }, { status: 401 })
      const parsed = JSON.parse(body)
      const tools: string[] = (parsed.tools ?? []).map((t: any) => t.name)
      const hasResult = JSON.stringify(parsed.messages).includes('"tool_result"')
      if (!tools.includes("Read") || hasResult) return sse(message([{ type: "text", text: "E2E-OK" }], "end_turn"))
      return sse(message([{ type: "tool_use", id: `toolu_${n}`, name: "Read", input: { path: "hello.txt" } }], "tool_use"))
    }
    return new Response("not found", { status: 404 })
  },
})
console.log(`fake anthropic on ${server.url}`)
