import { createHash, randomBytes, randomUUID } from "node:crypto"
import { chmodSync, mkdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs"
import { homedir } from "node:os"
import path from "node:path"

const PLUGIN_ID = "opencode-anth"
const INTEGRATION_ID = "anthropic"
const METHOD_ID = "claude-pro-max"

const CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
const AUTHORIZE_URL = "https://claude.ai/oauth/authorize"
const MANUAL_REDIRECT_URL = "https://platform.claude.com/oauth/code/callback"
const DEFAULT_TOKEN_URL = "https://platform.claude.com/v1/oauth/token"
const SCOPES = [
  "org:create_api_key",
  "user:profile",
  "user:inference",
  "user:sessions:claude_code",
  "user:mcp_servers",
  "user:file_upload",
].join(" ")

const DEFAULT_CC_VERSION = "2.1.281"
const CC_ENTRYPOINT = "sdk-cli"
const IDENTITY = "You are a Claude agent, built on Anthropic's Claude Agent SDK."
const BILLING_PREFIX = "x-anthropic-billing-header:"
const BILLING_SALT = "59cf53e54c78"
const CCH_SEED = 0x6e52736ac806831en
const CCH_MASK = 0xfffffn

const REQUIRED_BETAS = ["claude-code-20250219", "oauth-2025-04-20", "interleaved-thinking-2025-05-14"]

const CC_TOOLS = [
  "Read", "Write", "Edit", "Bash", "Grep", "Glob", "AskUserQuestion", "EnterPlanMode", "ExitPlanMode",
  "KillShell", "NotebookEdit", "Skill", "Task", "TaskOutput", "TodoWrite", "WebFetch", "WebSearch",
  "Agent", "ToolSearch",
]
const CC_TOOL_BY_LOWER = new Map(CC_TOOLS.map((name) => [name.toLowerCase(), name]))
const TOOL_ALIASES: Record<string, string> = { shell: "Bash", subagent: "Agent", question: "AskUserQuestion" }

const STRIP_HEADER = /^(x-opencode-.*|x-session-affinity|x-session-id|b3|traceparent|tracestate|x-b3-.*)$/i

const PARAGRAPH_ANCHORS = ["github.com/anomalyco/opencode", "opencode.ai/docs"]
const TEXT_REPLACEMENTS: Array<[string | RegExp, string]> = [
  [/^You are OpenCode[^\n]*\n?/m, ""],
  ["if OpenCode honestly", "if the assistant honestly"],
  ["Here is some useful information about the environment you are running in:", "Environment context you are running in:"],
]

const TOKEN_TIMEOUT_MS = 30_000
const ROTATION_TTL_MS = 60 * 60_000
const LOCK_STALE_MS = 60_000
const REFRESH_FAILURE_BACKOFF_MS = 30_000

const sha256 = (input: string | Uint8Array) => createHash("sha256").update(input).digest("hex")
const b64url = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url")
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))
const log = (...args: unknown[]) => {
  if (process.env.OPENCODE_ANTH_DEBUG) console.error(`[${PLUGIN_ID}]`, ...args)
}

function uuidFromHash(input: string) {
  const h = sha256(input)
  const variant = ((parseInt(h[16]!, 16) & 0x3) | 0x8).toString(16)
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-${variant}${h.slice(17, 20)}-${h.slice(20, 32)}`
}

function isLoopback(url: URL) {
  return ["127.0.0.1", "localhost", "[::1]"].includes(url.hostname)
}

function overrideUrl(env: string | undefined, fallback: string) {
  if (!env) return fallback
  try {
    const url = new URL(env)
    if (url.protocol === "https:" || (url.protocol === "http:" && isLoopback(url))) return url.toString()
  } catch {}
  console.error(`[${PLUGIN_ID}] ignoring invalid override URL: ${env}`)
  return fallback
}

const tokenUrl = () => overrideUrl(process.env.OPENCODE_ANTH_TOKEN_URL, DEFAULT_TOKEN_URL)

function stateDir() {
  const base = process.env.XDG_STATE_HOME || path.join(homedir(), ".local", "state")
  const dir = path.join(base, "opencode-anth")
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  return dir
}

function writePrivate(file: string, data: string) {
  const tmp = `${file}.${process.pid}.${Date.now()}.tmp`
  writeFileSync(tmp, data, { mode: 0o600 })
  chmodSync(tmp, 0o600)
  renameSync(tmp, file)
}

function readJson<T>(file: string, fallback: T): T {
  try {
    return JSON.parse(readFileSync(file, "utf8")) as T
  } catch {
    return fallback
  }
}

type OAuthCredential = {
  type: "oauth"
  methodID: string
  refresh: string
  access: string
  expires: number
  metadata?: Record<string, unknown>
}

class RefreshError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message)
  }
}

function toCredential(data: any): OAuthCredential {
  if (
    typeof data?.access_token !== "string" ||
    typeof data?.refresh_token !== "string" ||
    typeof data?.expires_in !== "number"
  )
    throw new Error("Anthropic token endpoint returned an unexpected response")
  return {
    type: "oauth",
    methodID: METHOD_ID,
    access: data.access_token,
    refresh: data.refresh_token,
    expires: Date.now() + data.expires_in * 1000,
  }
}

async function postToken(body: Record<string, string>) {
  return fetch(tokenUrl(), {
    method: "POST",
    redirect: "error",
    signal: AbortSignal.timeout(TOKEN_TIMEOUT_MS),
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/plain, */*",
      "user-agent": "axios/1.13.6",
    },
    body: JSON.stringify(body),
  })
}

function parsePastedCode(input: string): { code: string; state?: string } | undefined {
  const text = input.trim()
  if (!text) return undefined
  try {
    const url = new URL(text)
    const code = url.searchParams.get("code")
    if (code) return { code, state: url.searchParams.get("state") ?? undefined }
  } catch {}
  if (text.includes("#")) {
    const [code, state] = text.split("#", 2)
    if (code) return { code, state: state || undefined }
  }
  const params = new URLSearchParams(text)
  if (params.get("code")) return { code: params.get("code")!, state: params.get("state") ?? undefined }
  return { code: text }
}

async function startAuthorization() {
  const verifier = b64url(randomBytes(64))
  const challenge = createHash("sha256").update(verifier).digest("base64url")
  const state = randomBytes(16).toString("hex")
  const url = new URL(AUTHORIZE_URL)
  url.searchParams.set("code", "true")
  url.searchParams.set("client_id", CLIENT_ID)
  url.searchParams.set("response_type", "code")
  url.searchParams.set("redirect_uri", MANUAL_REDIRECT_URL)
  url.searchParams.set("scope", SCOPES)
  url.searchParams.set("code_challenge", challenge)
  url.searchParams.set("code_challenge_method", "S256")
  url.searchParams.set("state", state)

  const callback = async (pasted: string): Promise<OAuthCredential> => {
    const parsed = parsePastedCode(pasted)
    if (!parsed) throw new Error("Paste the code shown after approving (it looks like `abc…#xyz…`).")
    if (parsed.state && parsed.state !== state)
      throw new Error("That code belongs to a different login attempt. Start /connect again and paste the new code.")
    const res = await postToken({
      grant_type: "authorization_code",
      client_id: CLIENT_ID,
      code: parsed.code,
      state,
      redirect_uri: MANUAL_REDIRECT_URL,
      code_verifier: verifier,
    })
    if (!res.ok) {
      const detail = await res.text().catch(() => "")
      throw new Error(`Claude login failed (${res.status}). ${detail.slice(0, 300)}`)
    }
    return toCredential(await res.json())
  }
  return { url: url.toString(), callback }
}

const inflight = new Map<string, Promise<OAuthCredential>>()
const recentFailures = new Map<string, { at: number; error: Error }>()

type Journal = Record<string, { at: number; credential: OAuthCredential }>

function journalFile() {
  return path.join(stateDir(), "rotations.json")
}

function readJournal(): Journal {
  const journal = readJson<Journal>(journalFile(), {})
  const now = Date.now()
  for (const [key, entry] of Object.entries(journal)) if (now - entry.at > ROTATION_TTL_MS) delete journal[key]
  return journal
}

async function withLock<T>(fn: () => Promise<T>): Promise<T> {
  const lock = path.join(stateDir(), "refresh.lock")
  const deadline = Date.now() + TOKEN_TIMEOUT_MS + 15_000
  for (;;) {
    try {
      mkdirSync(lock, { mode: 0o700 })
      break
    } catch (error: any) {
      if (error?.code !== "EEXIST") throw error
      try {
        if (Date.now() - statSync(lock).mtimeMs > LOCK_STALE_MS) rmSync(lock, { recursive: true, force: true })
      } catch {}
      if (Date.now() > deadline) throw new Error("Timed out waiting for another OpenCode process to refresh the Claude token")
      await sleep(100 + Math.random() * 150)
    }
  }
  try {
    return await fn()
  } finally {
    rmSync(lock, { recursive: true, force: true })
  }
}

async function refreshOnce(credential: OAuthCredential): Promise<OAuthCredential> {
  const key = sha256(`refresh:${credential.refresh}`)
  return withLock(async () => {
    const journal = readJournal()
    const rotated = journal[key]
    if (rotated) {
      log("adopting credential rotated by another process")
      return rotated.credential
    }
    const res = await postToken({ grant_type: "refresh_token", refresh_token: credential.refresh, client_id: CLIENT_ID })
    if (!res.ok) {
      const detail = await res.text().catch(() => "")
      const hint =
        res.status === 400 || res.status === 401
          ? " The Claude login was revoked or already rotated elsewhere: run /connect → Anthropic → Claude Pro/Max again."
          : ""
      throw new RefreshError(`Claude token refresh failed (${res.status}).${hint} ${detail.slice(0, 200)}`, res.status)
    }
    const next = toCredential(await res.json())
    journal[key] = { at: Date.now(), credential: next }
    writePrivate(journalFile(), JSON.stringify(journal))
    return next
  })
}

async function refreshCredential(credential: OAuthCredential): Promise<OAuthCredential> {
  const key = sha256(`refresh:${credential.refresh}`)
  const failed = recentFailures.get(key)
  if (failed && Date.now() - failed.at < REFRESH_FAILURE_BACKOFF_MS) throw failed.error
  let pending = inflight.get(key)
  if (!pending) {
    pending = refreshOnce(credential)
      .then((next) => ({ ...next, metadata: credential.metadata }))
      .catch((error) => {
        recentFailures.set(key, { at: Date.now(), error })
        throw error
      })
      .finally(() => setTimeout(() => inflight.delete(key), 30_000).unref?.())
    inflight.set(key, pending)
  }
  return pending
}

let deviceIdCache: string | undefined
function deviceId() {
  if (deviceIdCache) return deviceIdCache
  const file = path.join(stateDir(), "device-id")
  try {
    const existing = readFileSync(file, "utf8").trim()
    if (/^[0-9a-f]{64}$/.test(existing)) return (deviceIdCache = existing)
  } catch {}
  deviceIdCache = randomBytes(32).toString("hex")
  writePrivate(file, deviceIdCache)
  return deviceIdCache
}

const accountByToken = new Map<string, Promise<string>>()
function accountUuid(origin: string, token: string): Promise<string> {
  const key = sha256(`access:${token}`)
  let pending = accountByToken.get(key)
  if (!pending) {
    pending = fetch(`${origin}/api/oauth/profile`, {
      headers: {
        accept: "application/json",
        authorization: `Bearer ${token}`,
        "user-agent": userAgent(),
        "x-app": "cli",
      },
      signal: AbortSignal.timeout(5000),
    })
      .then(async (res) => {
        if (!res.ok) return ""
        const uuid = ((await res.json()) as any)?.account?.uuid
        return typeof uuid === "string" ? uuid : ""
      })
      .catch(() => "")
    accountByToken.set(key, pending)
    if (accountByToken.size > 32) accountByToken.delete(accountByToken.keys().next().value!)
  }
  return pending
}

let ccVersion = (() => {
  const env = process.env.OPENCODE_ANTH_CC_VERSION
  if (env && /^\d+\.\d+\.\d+$/.test(env)) return env
  if (env) console.error(`[${PLUGIN_ID}] ignoring malformed OPENCODE_ANTH_CC_VERSION`)
  return DEFAULT_CC_VERSION
})()
const userAgent = () => `claude-cli/${ccVersion} (external, ${CC_ENTRYPOINT})`

function newerVersion(a: string, b: string) {
  const pa = a.split(".").map(Number)
  const pb = b.split(".").map(Number)
  for (let i = 0; i < 3; i++) if (pa[i]! !== pb[i]!) return pa[i]! > pb[i]!
  return false
}

type Block = { type: string; text?: string; [key: string]: unknown }

function sanitizeSystemText(text: string) {
  let out = text
    .split(/\n\n+/)
    .filter((para) => !PARAGRAPH_ANCHORS.some((anchor) => para.includes(anchor)))
    .join("\n\n")
  for (const [match, replacement] of TEXT_REPLACEMENTS) out = out.replace(match as any, replacement)
  return out.trim()
}

function normalizeSystem(system: unknown): Block[] {
  if (system == null) return []
  if (typeof system === "string") return system ? [{ type: "text", text: system }] : []
  if (Array.isArray(system)) return system.filter((b) => b && typeof b === "object") as Block[]
  return []
}

function rewriteSystem(system: unknown): Block[] {
  const out: Block[] = []
  for (const block of normalizeSystem(system)) {
    if (block.type !== "text" || typeof block.text !== "string") {
      out.push(block)
      continue
    }
    if (block.text.startsWith(BILLING_PREFIX)) continue
    if (block.text === IDENTITY || block.text.startsWith("You are Claude Code, Anthropic's official CLI")) continue
    const text = sanitizeSystemText(block.text)
    if (text) out.push({ ...block, text })
  }
  return [{ type: "text", text: IDENTITY }, ...out]
}

function firstPromptText(messages: any[]): string {
  for (const message of messages) {
    if (message?.role !== "user") continue
    if (typeof message.content === "string") return message.content
    if (!Array.isArray(message.content)) continue
    const texts = message.content.filter((b: any) => b?.type === "text" && typeof b.text === "string")
    const real = texts.find((b: any) => !b.text.trimStart().startsWith("<system-reminder>"))
    return (real ?? texts[0])?.text ?? ""
  }
  return ""
}

function versionSuffix(prompt: string) {
  const sampled = [4, 7, 20].map((i) => prompt[i] || "0").join("")
  return sha256(`${BILLING_SALT}${sampled}${ccVersion}`).slice(0, 3)
}

function xxh64(input: string): bigint | undefined {
  const bun = (globalThis as any).Bun
  if (typeof bun?.hash?.xxHash64 === "function") return BigInt(bun.hash.xxHash64(input, CCH_SEED))
  return undefined
}

type ToolMap = { forward: Map<string, string>; reverse: Map<string, string> }

function buildToolMap(tools: unknown): ToolMap {
  const forward = new Map<string, string>()
  const reverse = new Map<string, string>()
  if (!Array.isArray(tools)) return { forward, reverse }
  const names = tools.map((t: any) => t?.name).filter((n: unknown): n is string => typeof n === "string")
  const taken = new Set(names)
  for (const name of names) {
    const lower = name.toLowerCase()
    const target = CC_TOOL_BY_LOWER.get(lower) ?? TOOL_ALIASES[lower]
    if (!target || target === name) continue
    if (taken.has(target) || reverse.has(target)) continue
    if (TOOL_ALIASES[lower] && names.some((n) => n.toLowerCase() === target.toLowerCase())) continue
    forward.set(name, target)
    reverse.set(target, name)
  }
  return { forward, reverse }
}

function applyToolMap(body: any, map: ToolMap) {
  if (map.forward.size === 0) return
  const rename = (name: unknown) => (typeof name === "string" ? (map.forward.get(name) ?? name) : name)
  if (Array.isArray(body.tools)) body.tools = body.tools.map((t: any) => (t?.name ? { ...t, name: rename(t.name) } : t))
  if (body.tool_choice?.type === "tool") body.tool_choice = { ...body.tool_choice, name: rename(body.tool_choice.name) }
  if (!Array.isArray(body.messages)) return
  for (const message of body.messages) {
    if (!Array.isArray(message?.content)) continue
    message.content = message.content.map((block: any) => {
      if (block?.type === "tool_use" && typeof block.name === "string") return { ...block, name: rename(block.name) }
      if (block?.type === "tool_reference" && typeof block.tool?.name === "string")
        return { ...block, tool: { ...block.tool, name: rename(block.tool.name) } }
      return block
    })
  }
}

function rewriteBody(body: any, ids: { device: string; account: string; session: string }, map: ToolMap): string {
  applyToolMap(body, map)
  body.metadata = {
    ...(body.metadata && typeof body.metadata === "object" ? body.metadata : {}),
    user_id: JSON.stringify({ device_id: ids.device, account_uuid: ids.account, session_id: ids.session }),
  }
  const system = rewriteSystem(body.system)
  const messages = Array.isArray(body.messages) ? body.messages : []
  const hasUser = messages.some((m: any) => m?.role === "user")
  if (!hasUser) {
    body.system = system
    return JSON.stringify(body)
  }
  const header = `${BILLING_PREFIX} cc_version=${ccVersion}.${versionSuffix(firstPromptText(messages))}; cc_entrypoint=${CC_ENTRYPOINT}; cch=00000;`
  body.system = [{ type: "text", text: header }, ...system]
  const serialized = JSON.stringify(body)
  const hash = xxh64(serialized)
  const cch = hash !== undefined ? (hash & CCH_MASK).toString(16).padStart(5, "0") : sha256(serialized).slice(0, 5)
  return serialized.replace("cch=00000;", `cch=${cch};`)
}

function unmapToolNames(response: Response, reverse: Map<string, string>): Response {
  if (reverse.size === 0 || !response.body) return response
  const type = response.headers.get("content-type")?.split(";")[0]?.trim().toLowerCase()
  const headers = new Headers(response.headers)
  headers.delete("content-length")
  const init = { status: response.status, statusText: response.statusText, headers }
  const fix = (value: any) => {
    if (value && typeof value === "object" && typeof value.name === "string" && reverse.has(value.name))
      value.name = reverse.get(value.name)
  }

  if (type === "application/json") {
    const source = response
    const stream = new ReadableStream<Uint8Array>({
      async start(controller) {
        let text = await source.text()
        try {
          const json = JSON.parse(text)
          if (Array.isArray(json?.content)) json.content.forEach(fix)
          text = JSON.stringify(json)
        } catch {}
        controller.enqueue(new TextEncoder().encode(text))
        controller.close()
      },
    })
    return new Response(stream, init)
  }
  if (type !== "text/event-stream") return response

  const decoder = new TextDecoder()
  const encoder = new TextEncoder()
  let buffer = ""
  const rewriteLine = (line: string) => {
    if (!line.startsWith("data:") || !line.includes('"content_block_start"')) return line
    try {
      const json = JSON.parse(line.slice(5).trimStart())
      if (json?.type !== "content_block_start") return line
      const before = json.content_block?.name
      fix(json.content_block)
      return json.content_block?.name === before ? line : `data: ${JSON.stringify(json)}`
    } catch {
      return line
    }
  }
  const stream = response.body.pipeThrough(
    new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, controller) {
        buffer += decoder.decode(chunk, { stream: true })
        const lines = buffer.split("\n")
        buffer = lines.pop() ?? ""
        if (lines.length) controller.enqueue(encoder.encode(lines.map(rewriteLine).join("\n") + "\n"))
      },
      flush(controller) {
        buffer += decoder.decode()
        if (buffer) controller.enqueue(encoder.encode(rewriteLine(buffer)))
      },
    }),
  )
  return new Response(stream, init)
}

const STAINLESS_DEFAULTS: Record<string, string> = {
  "x-stainless-arch": process.arch,
  "x-stainless-lang": "js",
  "x-stainless-os": process.platform === "darwin" ? "MacOS" : process.platform === "linux" ? "Linux" : process.platform,
  "x-stainless-package-version": "0.112.1",
  "x-stainless-retry-count": "0",
  "x-stainless-runtime": "node",
  "x-stainless-runtime-version": process.version,
  "x-stainless-timeout": "600",
}

function subscriptionToken(headers: Headers): string | undefined {
  const auth = headers.get("authorization")
  if (auth?.startsWith("Bearer sk-ant-oat")) return auth.slice("Bearer ".length)
  const key = headers.get("x-api-key")
  if (key?.startsWith("sk-ant-oat")) return key
  return undefined
}

export default {
  id: PLUGIN_ID,
  setup: async (ctx: any) => {
    const toolMaps = new WeakMap<Request, Map<string, string>>()
    const versionRequests = new WeakSet<Request>()

    await ctx.integration.transform((draft: any) => {
      draft.method.update({
        integrationID: INTEGRATION_ID,
        method: { id: METHOD_ID, type: "oauth", label: "Claude Pro/Max (subscription)" },
        authorize: async () => {
          const { url, callback } = await startAuthorization()
          return {
            url,
            mode: "code",
            instructions: "Open the link, approve, then paste the code shown (looks like `abc…#xyz…`):",
            callback,
          }
        },
        refresh: refreshCredential,
        label: () => "Claude Pro/Max",
      })
    })

    await ctx.session.hook("http.request", async (event: any) => {
      const request: Request = event.request
      const token = subscriptionToken(request.headers)
      if (!token) return

      const url = new URL(request.url)
      const isMessages = request.method === "POST" && url.pathname.endsWith("/v1/messages")
      if (isMessages && !url.searchParams.has("beta")) url.searchParams.set("beta", "true")

      const headers = new Headers(request.headers)
      for (const name of [...headers.keys()]) if (STRIP_HEADER.test(name)) headers.delete(name)
      headers.delete("x-api-key")
      headers.delete("content-length")
      headers.set("accept", "application/json")
      headers.set("authorization", `Bearer ${token}`)
      const betas = (headers.get("anthropic-beta") ?? "").split(",").map((b) => b.trim()).filter(Boolean)
      headers.set("anthropic-beta", [...new Set([...REQUIRED_BETAS, ...betas])].join(","))
      headers.set("user-agent", userAgent())
      headers.set("x-app", "cli")
      headers.set("anthropic-dangerous-direct-browser-access", "true")
      headers.set("x-claude-code-session-id", uuidFromHash(`session:${event.sessionID}`))
      headers.set("x-client-request-id", randomUUID())
      if (!headers.has("anthropic-version")) headers.set("anthropic-version", "2023-06-01")
      for (const [key, value] of Object.entries(STAINLESS_DEFAULTS)) if (!headers.has(key)) headers.set(key, value)
      if (isMessages) headers.set("x-claude-code-request-class", "main")

      let body: string | undefined
      let reverse: Map<string, string> | undefined
      if (request.body) {
        const text = await request.clone().text()
        body = text
        if (isMessages) {
          try {
            const parsed = JSON.parse(text)
            const map = buildToolMap(parsed.tools)
            const account = await accountUuid(url.origin, token)
            body = rewriteBody(
              parsed,
              { device: deviceId(), account, session: uuidFromHash(`session:${event.sessionID}`) },
              map,
            )
            reverse = map.reverse
          } catch (error) {
            log("body rewrite skipped:", error)
          }
        }
      }

      const next = new Request(url.toString(), {
        method: request.method,
        headers,
        body,
        signal: request.signal,
        redirect: "error",
      })
      if (reverse?.size) toolMaps.set(next, reverse)
      if (isMessages) versionRequests.add(next)
      event.request = next
    })

    await ctx.session.hook("http.response", async (event: any) => {
      const request: Request = event.request
      if (!versionRequests.has(request)) return
      const response: Response = event.response

      if (response.status === 400) {
        const text = await response.clone().text().catch(() => "")
        if (text.includes("claude_code_version_too_old") || /version \d+\.\d+\.\d+ or newer/.test(text)) {
          const required = text.match(/(\d+\.\d+\.\d+) or newer/)?.[1]
          if (required && newerVersion(required, ccVersion)) {
            console.error(`[${PLUGIN_ID}] cc_version -> ${required}`)
            ccVersion = required
          }
        }
        return
      }
      const reverse = toolMaps.get(request)
      if (response.ok && reverse) event.response = unmapToolNames(response, reverse)
    })
  },
}

export const __test = {
  rewriteBody,
  rewriteSystem,
  buildToolMap,
  versionSuffix,
  firstPromptText,
  parsePastedCode,
  unmapToolNames,
  refreshCredential,
  uuidFromHash,
}
