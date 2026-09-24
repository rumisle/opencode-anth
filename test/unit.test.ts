import { afterAll, beforeAll, describe, expect, test } from "bun:test"
import { mkdtempSync } from "node:fs"
import { tmpdir } from "node:os"
import path from "node:path"

const stateHome = mkdtempSync(path.join(tmpdir(), "anth-state-"))
process.env.XDG_STATE_HOME = stateHome

let refreshCalls = 0
const used = new Set<string>()
let counter = 0
const server = Bun.serve({
  port: 0,
  async fetch(req) {
    const body: any = await req.json()
    if (body.grant_type !== "refresh_token") return new Response("bad", { status: 400 })
    refreshCalls++
    await Bun.sleep(150)
    if (used.has(body.refresh_token)) return Response.json({ error: "invalid_grant" }, { status: 400 })
    used.add(body.refresh_token)
    counter++
    return Response.json({ access_token: `sk-ant-oat01-a${counter}`, refresh_token: `sk-ant-ort01-r${counter}`, expires_in: 28800 })
  },
})
process.env.OPENCODE_ANTH_TOKEN_URL = `http://127.0.0.1:${server.port}/v1/oauth/token`

const { __test: t } = await import("../index.ts")

afterAll(() => server.stop(true))

describe("billing header", () => {
  test("version suffix", () => {
    expect(t.versionSuffix("hello there, this is a capture test message")).toBe("403")
  })
  test("first prompt skips <system-reminder> meta blocks", () => {
    const messages = [
      { role: "user", content: [{ type: "text", text: "<system-reminder>\nstuff" }, { type: "text", text: "real prompt" }] },
    ]
    expect(t.firstPromptText(messages)).toBe("real prompt")
  })
  test("body layout: billing, identity, sanitized system; metadata; cch filled", () => {
    const body = {
      model: "claude-sonnet-5",
      system: [
        { type: "text", text: "You are OpenCode, the best agent.\nKeep going." },
        { type: "text", text: "Para one.\n\nSee opencode.ai/docs for help.\n\nHere is some useful information about the environment you are running in:\nlinux", cache_control: { type: "ephemeral" } },
      ],
      messages: [{ role: "user", content: "hello there, this is a capture test message" }],
      tools: [{ name: "read" }, { name: "shell" }, { name: "octopi_spawn" }],
    }
    const out = JSON.parse(t.rewriteBody(body, { device: "d".repeat(64), account: "acc", session: "sess" }, t.buildToolMap(body.tools)))
    expect(out.system[0].text).toMatch(/^x-anthropic-billing-header: cc_version=2\.1\.281\.403; cc_entrypoint=sdk-cli; cch=[0-9a-f]{5};$/)
    expect(out.system[0].text).not.toContain("cch=00000")
    expect(out.system[1].text).toBe("You are a Claude agent, built on Anthropic's Claude Agent SDK.")
    expect(out.system[2].text).toBe("Keep going.")
    expect(out.system[3].text).toBe("Para one.\n\nEnvironment context you are running in:\nlinux")
    expect(out.system[3].cache_control).toEqual({ type: "ephemeral" })
    expect(JSON.parse(out.metadata.user_id)).toEqual({ device_id: "d".repeat(64), account_uuid: "acc", session_id: "sess" })
    expect(out.tools.map((x: any) => x.name)).toEqual(["Read", "Bash", "octopi_spawn"])
  })
  test("idempotent on an already-rewritten body (retries)", () => {
    const body: any = { system: "sys", messages: [{ role: "user", content: "hi there friend" }] }
    const once = JSON.parse(t.rewriteBody(body, { device: "d", account: "", session: "s" }, t.buildToolMap([])))
    const twice = JSON.parse(t.rewriteBody(once, { device: "d", account: "", session: "s" }, t.buildToolMap([])))
    expect(twice.system.length).toBe(3)
    expect(twice.system.filter((b: any) => b.text.startsWith("x-anthropic-billing-header")).length).toBe(1)
  })
})

describe("tool names", () => {
  test("maps CC names, aliases shell→Bash, never collides", () => {
    const m = t.buildToolMap([{ name: "read" }, { name: "shell" }, { name: "Grep" }, { name: "bash" }])
    expect(m.forward.get("read")).toBe("Read")
    expect(m.forward.get("bash")).toBe("Bash")
    expect(m.forward.has("shell")).toBe(false)
    expect(m.forward.has("Grep")).toBe(false)
  })
  test("history tool_use blocks renamed", () => {
    const body: any = {
      tools: [{ name: "shell" }],
      messages: [
        { role: "user", content: "run it please ok" },
        { role: "assistant", content: [{ type: "tool_use", id: "1", name: "shell", input: {} }] },
      ],
    }
    const out = JSON.parse(t.rewriteBody(body, { device: "d", account: "", session: "s" }, t.buildToolMap(body.tools)))
    expect(out.messages[1].content[0].name).toBe("Bash")
  })
  test("SSE stream unmapped across awkward chunk boundaries", async () => {
    const sse =
      'event: message_start\ndata: {"type":"message_start"}\n\n' +
      'event: content_block_start\ndata: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"t","name":"Bash","input":{}}}\n\n' +
      'event: content_block_delta\ndata: {"type":"content_block_delta","delta":{"type":"input_json_delta","partial_json":"{\\"name\\":\\"Bash\\"}"}}\n\n'
    const bytes = new TextEncoder().encode(sse)
    const stream = new ReadableStream({
      start(c) {
        for (let i = 0; i < bytes.length; i += 7) c.enqueue(bytes.slice(i, i + 7))
        c.close()
      },
    })
    const res = t.unmapToolNames(new Response(stream, { headers: { "content-type": "text/event-stream" } }), new Map([["Bash", "shell"]]))
    const text = await res.text()
    expect(text).toContain('"name":"shell"')
    expect(text).toContain('partial_json":"{\\"name\\":\\"Bash\\"}')
    expect(text.split("\n").length).toBe(sse.split("\n").length)
  })
  test("JSON response unmapped", async () => {
    const res = t.unmapToolNames(
      Response.json({ content: [{ type: "tool_use", name: "Read" }] }),
      new Map([["Read", "read"]]),
    )
    expect((await res.json()).content[0].name).toBe("read")
  })
})

describe("oauth", () => {
  test("pasted code formats", () => {
    expect(t.parsePastedCode("abc#xyz")).toEqual({ code: "abc", state: "xyz" })
    expect(t.parsePastedCode("https://platform.claude.com/oauth/code/callback?code=abc&state=xyz")).toEqual({ code: "abc", state: "xyz" })
    expect(t.parsePastedCode("  abc  ")).toEqual({ code: "abc" })
  })
  test("concurrent refreshes in one process hit the endpoint once", async () => {
    const cred = { type: "oauth" as const, methodID: "claude-pro-max", access: "x", refresh: "sk-ant-ort01-start", expires: 0 }
    const before = refreshCalls
    const results = await Promise.all(Array.from({ length: 8 }, () => t.refreshCredential(cred)))
    expect(refreshCalls - before).toBe(1)
    expect(new Set(results.map((r) => r.refresh)).size).toBe(1)
  })
  test("concurrent refreshes across processes hit the endpoint once", async () => {
    const script = path.join(import.meta.dir, "refresh-child.ts")
    await Bun.write(
      script,
      `const { __test } = await import(${JSON.stringify(path.join(import.meta.dir, "..", "index.ts"))});
       const r = await __test.refreshCredential({ type: "oauth", methodID: "claude-pro-max", access: "x", refresh: "sk-ant-ort01-xproc", expires: 0 });
       console.log(r.refresh);`,
    )
    const before = refreshCalls
    const procs = Array.from({ length: 4 }, () =>
      Bun.spawn(["bun", script], { env: { ...process.env }, stdout: "pipe", stderr: "pipe" }),
    )
    const outs = await Promise.all(procs.map(async (p) => ({ out: (await new Response(p.stdout).text()).trim(), err: await new Response(p.stderr).text(), code: await p.exited })))
    for (const o of outs) expect(o.code, o.err).toBe(0)
    expect(refreshCalls - before).toBe(1)
    expect(new Set(outs.map((o) => o.out)).size).toBe(1)
  })
  test("revoked refresh token gives an actionable error", async () => {
    used.add("sk-ant-ort01-dead")
    const cred = { type: "oauth" as const, methodID: "claude-pro-max", access: "x", refresh: "sk-ant-ort01-dead", expires: 0 }
    await expect(t.refreshCredential(cred)).rejects.toThrow(/run \/connect/)
  })
})
