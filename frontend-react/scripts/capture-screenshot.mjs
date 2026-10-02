/**
 * 前端页面截图脚本（Day14 任务 9 的可复现实现）。
 *
 * 为什么不直接用 `msedge --headless --screenshot`：
 *  1. Chromium/Edge **没有** `--screenshot-delay` 参数（实测被忽略，会抓到 Skeleton 加载态）；
 *  2. 用 `--virtual-time-budget` 强制推进虚拟时间，会让 ECharts / Framer Motion 的
 *     入场动画停在 0 帧，图表与 KPI 卡片抓出来是空白或半透明。
 *
 * 因此改用 **CDP（Chrome DevTools Protocol）**：真实时间等待「页面数据就绪 + 动画播完」，
 * 再用 `Page.captureScreenshot(captureBeyondViewport=true)` 抓整页，结果稳定可复现。
 * 这样前端可以放心保留动画（不牺牲真实用户体验）。
 *
 * 用法（需先启动 `npm run dev`）：
 *
 *   node scripts/capture-screenshot.mjs \
 *     --url http://localhost:5173/ \
 *     --out ../reports/frontend_dashboard.png \
 *     --settle-ms 1500 --width 1600
 *
 * 退出码：0 成功；1 失败（打印原因）。
 */

import { spawn } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));

/** Edge 可执行文件候选路径（Windows）。 */
const EDGE_CANDIDATES = [
  "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
  "C:/Program Files/Microsoft/Edge/Application/msedge.exe",
  "C:/Program Files/Google/Chrome/Application/chrome.exe",
];

/**
 * 解析命令行参数。
 *
 * @returns 截图参数对象。
 */
function parseArgs() {
  const argv = process.argv.slice(2);
  const options = {
    url: "http://localhost:5173/",
    out: resolve(HERE, "..", "..", "reports", "frontend_dashboard.png"),
    width: 1600,
    height: 1000,
    settleMs: 1500,
    timeoutMs: 30_000,
    port: 9333,
    mode: "dashboard",
    waitSelector: null,
    ask: null,
    answerWaitMs: 25_000,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const key = argv[index];
    const value = argv[index + 1];
    if (key === "--url") options.url = value;
    else if (key === "--out") options.out = resolve(process.cwd(), value);
    else if (key === "--width") options.width = Number(value);
    else if (key === "--height") options.height = Number(value);
    else if (key === "--settle-ms") options.settleMs = Number(value);
    else if (key === "--timeout-ms") options.timeoutMs = Number(value);
    else if (key === "--port") options.port = Number(value);
    else if (key === "--mode") options.mode = value === "page" ? "page" : "dashboard";
    else if (key === "--wait-selector") options.waitSelector = value;
    else if (key === "--ask") options.ask = value;
    else if (key === "--answer-wait-ms") options.answerWaitMs = Number(value);
    else continue;
    index += 1;
  }
  return options;
}

/**
 * 轻微等待。
 *
 * @param ms 毫秒。
 * @returns Promise。
 */
const sleep = (ms) => new Promise((done) => setTimeout(done, ms));

/**
 * 构造「页面就绪」判定表达式。
 *
 * 判定口径：
 * - ``skeleton``：页面无 ``[aria-busy]``（本项目所有骨架屏都带该属性）；
 * - ``hit``：``--wait-selector`` 指定的元素已出现（未指定时恒为 true）；
 * - ``canvases`` / ``opaque``：首页专用（3 张 ECharts 画布 + 4 张 KPI 卡片不透明度已达 1）。
 *
 * @param {string | null} selector 额外等待的 CSS 选择器。
 * @returns {string} 可直接交给 ``Runtime.evaluate`` 的 IIFE 表达式。
 */
function buildReadyExpr(selector) {
  return `(() => {
  const canvases = document.querySelectorAll("canvas").length;
  const skeleton = document.querySelector("[aria-busy]") !== null;
  const cards = Array.from(document.querySelectorAll('main section[aria-label="核心指标"] > div'));
  const opaque = cards.length >= 4 && cards.every((el) => Number(getComputedStyle(el).opacity) > 0.99);
  const wanted = ${selector ? JSON.stringify(selector) : "null"};
  const hit = wanted ? document.querySelector(wanted) !== null : true;
  return { canvases, skeleton, opaque, hit };
})()`;
}

/**
 * 构造「自动提问」表达式（问答页截图用）。
 *
 * 通过原生 value setter + ``input`` 事件触发 React 的受控更新，
 * 再派发 ``Enter`` keydown 触发发送（与人工操作等价）。
 *
 * @param {string} question 要发送的问题。
 * @returns {string} ``Runtime.evaluate`` 表达式。
 */
function buildAskExpr(question) {
  return `(() => {
  const box = document.querySelector('textarea[aria-label="问题输入框"]');
  if (!box) return false;
  const setter = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, "value").set;
  setter.call(box, ${JSON.stringify(question)});
  box.dispatchEvent(new Event("input", { bubbles: true }));
  box.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
  return true;
})()`;
}


/** 极简 CDP 客户端（Node 22+ 内置 WebSocket，无需第三方依赖）。 */
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
   * 注册事件监听（仅需一次性的等待场景）。
   *
   * @param {string} method 事件名，如 ``Page.loadEventFired``。
   * @returns {Promise<void>} 事件触发后 resolve。
   */
  once(method) {
    return new Promise((resolve) => {
      const handlers = this.listeners.get(method) ?? [];
      const wrapper = () => {
        this.listeners.set(method, handlers.filter((item) => item !== wrapper));
        resolve();
      };
      handlers.push(wrapper);
      this.listeners.set(method, handlers);
    });
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
  const found = EDGE_CANDIDATES.find((candidate) => existsSync(candidate));
  if (!found) {
    throw new Error("未找到 Edge/Chrome 可执行文件，请安装其中之一");
  }
  return found;
}

/**
 * 轮询等待 DevTools 端点就绪。
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
 * 主流程：启动浏览器 → 导航 → 等待就绪 → 等待动画 → 抓整页截图。
 *
 * @returns {Promise<void>} 完成后结束。
 */
async function main() {
  const options = parseArgs();
  const browser = findBrowser();
  const profile = resolve(tmpdir(), "aisec-shot-profile");

  const child = spawn(
    browser,
    [
      "--headless=new",
      "--disable-gpu",
      "--hide-scrollbars",
      "--no-first-run",
      "--no-default-browser-check",
      `--user-data-dir=${profile}`,
      `--remote-debugging-port=${options.port}`,
      `--window-size=${options.width},${options.height}`,
      "about:blank",
    ],
    { stdio: "ignore" },
  );

  try {
    const target = await waitForPageTarget(options.port, options.timeoutMs);
    const client = await CdpClient.connect(target.webSocketDebuggerUrl);
    try {
      await client.send("Page.enable");
      await client.send("Runtime.enable");
      await client.send("Emulation.setDeviceMetricsOverride", {
        width: options.width,
        height: options.height,
        deviceScaleFactor: 1,
        mobile: false,
      });

      const loaded = client.once("Page.loadEventFired");
      await client.send("Page.navigate", { url: options.url });
      await Promise.race([loaded, sleep(options.timeoutMs)]);

      // 轮询「数据就绪 + 动画播完」，而不是用固定 sleep 赌时间。
      // mode=page 且未指定 wait-selector / ask 时，退化为「等 load + settle」。
      const readyExpr = buildReadyExpr(options.waitSelector);
      let state = null;
      let ready = options.mode === "page" && !options.waitSelector && !options.ask;
      if (!ready) {
        const deadline = Date.now() + options.timeoutMs;
        while (Date.now() < deadline) {
          const result = await client.send("Runtime.evaluate", {
            expression: readyExpr,
            returnByValue: true,
          });
          state = result.result?.value ?? null;
          const satisfied =
            state !== null &&
            !state.skeleton &&
            state.hit &&
            (options.mode === "dashboard" ? state.canvases >= 3 && state.opaque : true);
          if (satisfied) {
            ready = true;
            break;
          }
          await sleep(250);
        }
        console.log(`[capture] 页面状态=${JSON.stringify(state)} ready=${ready}`);
        if (!ready) {
          console.warn("[capture] 警告：未在超时内确认就绪，截图可能不完整（可调大 --timeout-ms）");
        }
      } else {
        console.log("[capture] 模式=page：仅等待 loadEventFired + settle");
      }

      // 可选：自动提问（问答页截图），提交后等待 LLM 回答产出
      if (options.ask) {
        const asked = await client.send("Runtime.evaluate", {
          expression: buildAskExpr(options.ask),
          returnByValue: true,
        });
        console.log(
          `[capture] 已提交问题「${options.ask}」ok=${Boolean(asked.result?.value)}，` +
            `等待回答 ${options.answerWaitMs}ms`,
        );
        await sleep(options.answerWaitMs);
      }

      // 动画收尾（ECharts 默认 1s 入场 + Framer Motion 0.35s），再抓帧
      await sleep(options.settleMs);

      const shot = await client.send("Page.captureScreenshot", {
        format: "png",
        captureBeyondViewport: true,
      });
      const buffer = Buffer.from(shot.data, "base64");
      mkdirSync(dirname(options.out), { recursive: true });
      writeFileSync(options.out, buffer);
      console.log(`[capture] 已写入 ${options.out}（${buffer.length} 字节）`);
    } finally {
      client.close();
    }
  } finally {
    child.kill();
  }
}

main().catch((error) => {
  console.error(`[capture] 失败：${error.message}`);
  process.exit(1);
});
