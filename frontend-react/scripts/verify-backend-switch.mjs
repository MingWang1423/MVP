/**
 * 后端切换（本地 / 云端）验证脚本 —— Day19 任务 6 的可复现实现。
 *
 * 做三件事，全部基于 CDP（Node 22+ 内置 WebSocket，无需第三方依赖）：
 *   1. 打开前端页面，录制第一段 ``/api/v1/`` 请求的**实际地址**（默认模式应连本地后端）；
 *   2. 点击顶部导航里的后端切换按钮（``aria-label`` 以「切换后端」开头）；
 *   3. 刷新后录制第二段请求地址，并读取 ``localStorage`` 里的模式值，
 *      断言请求确实改走**云端**地址。
 *
 * 用法（需先启动 API 与 `npm run dev`）：
 *
 *   node scripts/verify-backend-switch.mjs \
 *     --url http://localhost:5173/ \
 *     --local-origin http://localhost:8000 \
 *     --cloud-origin http://127.0.0.1:8000
 *
 * 省略 `--cloud-origin` 时改为验证**云端未配置**的分支：点击按钮应拒绝切换
 * （localStorage 不写入）并弹出「云端后端未配置」提示。
 *
 * 退出码：0 通过；1 失败（打印失败原因）。
 */

import { spawn } from "node:child_process";
import { existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";

/** Edge / Chrome 可执行文件候选路径（与 capture-screenshot.mjs 保持一致）。 */
const BROWSER_CANDIDATES = [
  "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
  "C:/Program Files/Microsoft/Edge/Application/msedge.exe",
  "C:/Program Files/Google/Chrome/Application/chrome.exe",
];

/** API 请求路径前缀（与 src/lib/api.ts 的 API_PREFIX 一致）。 */
const API_PREFIX = "/api/v1/";

/** localStorage 键名（与 src/lib/api.ts 的 API_MODE_STORAGE_KEY 一致）。 */
const MODE_STORAGE_KEY = "aisec-intel-api-mode";

/**
 * 解析命令行参数。
 *
 * @returns {{url: string, localOrigin: string, cloudOrigin: string, port: number, settleMs: number, timeoutMs: number}} 参数对象。
 */
function parseArgs() {
  const argv = process.argv.slice(2);
  const options = {
    url: "http://localhost:5173/",
    localOrigin: "http://localhost:8000",
    cloudOrigin: "",
    port: 9444,
    settleMs: 2500,
    timeoutMs: 30_000,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const key = argv[index];
    const value = argv[index + 1];
    if (key === "--url") options.url = value;
    else if (key === "--local-origin") options.localOrigin = value;
    else if (key === "--cloud-origin") options.cloudOrigin = value;
    else if (key === "--port") options.port = Number(value);
    else if (key === "--settle-ms") options.settleMs = Number(value);
    else if (key === "--timeout-ms") options.timeoutMs = Number(value);
    else continue;
    index += 1;
  }
  return options;
}

/**
 * 轻微等待。
 *
 * @param {number} ms 毫秒。
 * @returns {Promise<void>} Promise。
 */
const sleep = (ms) => new Promise((done) => setTimeout(done, ms));

/** 极简 CDP 客户端（实现与 capture-screenshot.mjs 相同，保持零依赖）。 */
class CdpClient {
  /** @param {WebSocket} socket 已连接的 WebSocket。 */
  constructor(socket) {
    this.socket = socket;
    this.nextId = 1;
    this.pending = new Map();
    this.listeners = new Map();
    socket.addEventListener("message", (event) => this.#onMessage(event.data));
  }

  /**
   * 连接 CDP。
   *
   * @param {string} url 目标页面的 webSocketDebuggerUrl。
   * @returns {Promise<CdpClient>} 客户端实例。
   */
  static async connect(url) {
    const socket = new WebSocket(url);
    await new Promise((done, fail) => {
      socket.addEventListener("open", () => done());
      socket.addEventListener("error", () => fail(new Error(`CDP 连接失败：${url}`)));
    });
    return new CdpClient(socket);
  }

  /**
   * 处理 CDP 消息（响应分派 + 事件分派）。
   *
   * @param {string} raw 原始 JSON 文本。
   * @returns {void} 无返回值。
   */
  #onMessage(raw) {
    const message = JSON.parse(raw);
    if (message.id && this.pending.has(message.id)) {
      const { resolve, reject } = this.pending.get(message.id);
      this.pending.delete(message.id);
      if (message.error) reject(new Error(`${message.error.message}（${message.method ?? ""}）`));
      else resolve(message.result);
      return;
    }
    if (message.method && this.listeners.has(message.method)) {
      for (const handler of this.listeners.get(message.method)) handler(message.params);
    }
  }

  /**
   * 发送 CDP 命令。
   *
   * @param {string} method 方法名，如 ``Page.navigate``。
   * @param {object} [params] 参数。
   * @returns {Promise<object>} 命令结果。
   */
  send(method, params = {}) {
    const id = this.nextId;
    this.nextId += 1;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.socket.send(JSON.stringify({ id, method, params }));
    });
  }

  /**
   * 注册一次性事件监听。
   *
   * @param {string} method 事件名，如 ``Page.loadEventFired``。
   * @returns {Promise<void>} 事件触发后 resolve。
   */
  once(method) {
    return new Promise((done) => {
      const handlers = this.listeners.get(method) ?? [];
      const wrapper = () => {
        this.listeners.set(
          method,
          handlers.filter((item) => item !== wrapper),
        );
        done();
      };
      handlers.push(wrapper);
      this.listeners.set(method, handlers);
    });
  }

  /**
   * 注册常驻事件监听。
   *
   * @param {string} method 事件名。
   * @param {(params: object) => void} handler 回调。
   * @returns {void} 无返回值。
   */
  on(method, handler) {
    const handlers = this.listeners.get(method) ?? [];
    handlers.push(handler);
    this.listeners.set(method, handlers);
  }

  /**
   * 求值表达式并返回结果。
   *
   * @param {string} expression JS 表达式。
   * @returns {Promise<unknown>} 表达式返回值。
   */
  async evaluate(expression) {
    const result = await this.send("Runtime.evaluate", {
      expression,
      returnByValue: true,
      awaitPromise: true,
    });
    return result.result?.value;
  }

  /** 关闭连接。 */
  close() {
    try {
      this.socket.close();
    } catch {
      /* 忽略关闭异常 */
    }
  }
}



/**
 * 找到可用的浏览器可执行文件。
 *
 * @returns {string} 可执行文件路径。
 */
function findBrowser() {
  const found = BROWSER_CANDIDATES.find((candidate) => existsSync(candidate));
  if (!found) {
    throw new Error("未找到 Edge/Chrome 可执行文件，请安装其中之一");
  }
  return found;
}

/**
 * 等待 DevTools 调试端点就绪。
 *
 * @param {number} port 调试端口。
 * @param {number} timeoutMs 超时（毫秒）。
 * @returns {Promise<object>} 页面目标信息（含 webSocketDebuggerUrl）。
 */
async function waitForPageTarget(port, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`http://127.0.0.1:${port}/json/list`);
      const targets = await response.json();
      const page = targets.find((item) => item.type === "page" && item.webSocketDebuggerUrl);
      if (page) return page;
    } catch {
      /* 浏览器尚未起来，继续轮询 */
    }
    await sleep(300);
  }
  throw new Error(`等待浏览器调试端点超时（port=${port}）`);
}

/**
 * 从录制的请求里挑出 API 请求地址（去重，保持出现顺序）。
 *
 * @param {string[]} recorded 录制的全部请求地址。
 * @returns {string[]} 命中 ``/api/v1/`` 的地址。
 */
function apiRequests(recorded) {
  return [...new Set(recorded.filter((item) => item.includes(API_PREFIX)))];
}


/**
 * 主流程：录本地请求 → 点按钮 → 录云端请求 → 断言。
 *
 * @returns {Promise<void>} 通过则正常结束，失败置退出码 1。
 */
async function main() {
  const options = parseArgs();
  const browser = findBrowser();
  const profile = resolve(tmpdir(), "aisec-switch-profile");
  // 每次重跑都从干净的浏览器 profile 开始，避免上一轮的 localStorage 污染断言
  rmSync(profile, { recursive: true, force: true });
  const failures = [];

  const child = spawn(
    browser,
    [
      "--headless=new",
      "--disable-gpu",
      "--no-first-run",
      "--no-default-browser-check",
      `--user-data-dir=${profile}`,
      `--remote-debugging-port=${options.port}`,
      "--window-size=1440,900",
      "about:blank",
    ],
    { stdio: "ignore" },
  );

  /** 当前录制阶段：``local`` 切换前 / ``cloud`` 切换后。 */
  let phase = "local";
  const buckets = { local: [], cloud: [] };

  try {
    const target = await waitForPageTarget(options.port, options.timeoutMs);
    const client = await CdpClient.connect(target.webSocketDebuggerUrl);
    try {
      await client.send("Page.enable");
      await client.send("Runtime.enable");
      await client.send("Network.enable");
      client.on("Network.requestWillBeSent", (params) => {
        if (params.request?.url) buckets[phase].push(params.request.url);
      });

      // ① 默认模式：应连本地后端
      const loaded = client.once("Page.loadEventFired");
      await client.send("Page.navigate", { url: options.url });
      await Promise.race([loaded, sleep(options.timeoutMs)]);
      await sleep(options.settleMs);

      const modeBefore = await client.evaluate(
        `window.localStorage.getItem('${MODE_STORAGE_KEY}')`,
      );
      const buttonFound = await client.evaluate(
        'document.querySelector(\'[aria-label^="切换后端"]\') !== null',
      );
      if (!buttonFound) {
        failures.push("页面上未找到后端切换按钮（aria-label 前缀「切换后端」）");
      }
      if (modeBefore !== null) {
        failures.push(
          `首次加载模式由 VITE_API_DEFAULT 决定（localStorage 应为空），实际为 ${String(modeBefore)}`,
        );
      }

      if (!options.cloudOrigin) {
        // 云端地址未配置：点击必须**不切换**，只弹配置提示
        await client.evaluate('document.querySelector(\'[aria-label^="切换后端"]\').click(); true');
        await sleep(1500);
        const modeAfter = await client.evaluate(
          `window.localStorage.getItem('${MODE_STORAGE_KEY}')`,
        );
        const hinted = await client.evaluate('document.body.innerText.includes("云端后端未配置")');
        if (modeAfter !== null) {
          failures.push(`云端未配置时不应写入模式，实际写入 ${String(modeAfter)}`);
        }
        if (!hinted) {
          failures.push("云端未配置时未弹出「云端后端未配置」提示");
        }
        console.log(`[1] 切换前模式=local（localStorage=${String(modeBefore)}）`);
        console.log(`[2] 云端未配置时点击 → localStorage=${String(modeAfter)}，提示已出现=${String(hinted)}`);
      } else {
        // ② 点击切换：写 localStorage + 刷新页面
        phase = "cloud";
        const reloaded = client.once("Page.loadEventFired");
        await client.evaluate('document.querySelector(\'[aria-label^="切换后端"]\').click(); true');
        await Promise.race([reloaded, sleep(options.timeoutMs)]);
        await sleep(options.settleMs);

        const modeAfter = await client.evaluate(
          `window.localStorage.getItem('${MODE_STORAGE_KEY}')`,
        );

        const localHits = apiRequests(buckets.local);
        const cloudHits = apiRequests(buckets.cloud);
        const localPrefix = `${options.localOrigin}${API_PREFIX}`;
        const cloudPrefix = `${options.cloudOrigin}${API_PREFIX}`;
        const strayLocal = localHits.filter((item) => !item.startsWith(localPrefix));
        const strayCloud = cloudHits.filter((item) => !item.startsWith(cloudPrefix));

        if (modeAfter !== "cloud") {
          failures.push(
            `切换后 localStorage['${MODE_STORAGE_KEY}'] 应为 cloud，实际为 ${String(modeAfter)}`,
          );
        }
        if (localHits.length === 0) {
          failures.push(`切换前未录到 ${API_PREFIX} 请求（预期前缀 ${localPrefix}）`);
        }
        if (strayLocal.length > 0) {
          failures.push(`切换前存在非本地地址请求：${strayLocal.join(", ")}`);
        }
        if (cloudHits.length === 0) {
          failures.push(`切换后未录到 ${API_PREFIX} 请求（预期前缀 ${cloudPrefix}）`);
        }
        if (strayCloud.length > 0) {
          failures.push(`切换后仍存在非云端地址请求：${strayCloud.join(", ")}`);
        }

        console.log(`[1] 切换前模式=local（localStorage=${String(modeBefore)}）`);
        console.log(`    请求（${localHits.length} 条）：${localHits.slice(0, 3).join(" | ")}`);
        console.log(`[2] 点击切换按钮 → localStorage['${MODE_STORAGE_KEY}']=${String(modeAfter)}`);
        console.log(`    请求（${cloudHits.length} 条）：${cloudHits.slice(0, 3).join(" | ")}`);
      }
    } finally {
      client.close();
    }
  } finally {
    child.kill();
  }

  if (failures.length > 0) {
    for (const item of failures) console.error(`FAIL: ${item}`);
    process.exitCode = 1;
    return;
  }
  console.log(
    options.cloudOrigin
      ? "PASS: 默认连本地，切换后请求改走云端地址"
      : "PASS: 默认连本地，云端未配置时拒绝切换并给出提示",
  );
}

main().catch((error) => {
  console.error(`ERROR: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
});
