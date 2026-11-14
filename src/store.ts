import { createEffect, createSignal, on, untrack } from "solid-js";
import { listen } from "@tauri-apps/api/event";
import { api, type Json, type SpeedResult } from "./api";

export type StatusKey = "server" | "proxy" | "node" | "git" | "pip" | "remoteConfig" | "upgrade";
export type StatusValue = "starting" | "success" | "fail" | "stopped" | "error" | "idle";

export const [config, setConfig] = createSignal<Json>({});
export const [status, setStatus] = createSignal<Record<string, StatusValue>>({});
export const [speedResults, setSpeedResults] = createSignal<SpeedResult[]>([]);
export const [speedTesting, setSpeedTesting] = createSignal(false);
export const [traffic, setTraffic] = createSignal({ upload: 0, download: 0, uploadSpeed: 0, downloadSpeed: 0 });
export const [toasts, setToasts] = createSignal<{ id: number; type: string; msg: string }[]>([]);
export const [theme, setTheme] = createSignal<string>("dark");
export const [ready, setReady] = createSignal(false);

let toastId = 0;

export function toast(msg: string, type: "info" | "success" | "error" | "warn" = "info") {
  const id = ++toastId;
  setToasts((list) => [...list, { id, type, msg }]);
  setTimeout(() => {
    setToasts((list) => list.filter((t) => t.id !== id));
  }, 4000);
}

function applyTheme(value: string) {
  setTheme(value);
  document.documentElement.setAttribute("data-theme", value);
}

export async function reloadConfig() {
  const cfg = await api.getConfig();
  setConfig(cfg);
  applyTheme((cfg?.app?.theme as string) ?? "dark");
  return cfg;
}

export async function saveConfig(next: Json) {
  const cfg = await api.saveConfig(next);
  setConfig(cfg);
  applyTheme((cfg?.app?.theme as string) ?? "dark");
  return cfg;
}

export async function patchConfig(part: Json) {
  return saveConfig(deepMerge(config(), part));
}

export function deepMerge(base: Json, patch: Json): Json {
  const out: Json = { ...base };
  for (const [k, v] of Object.entries(patch)) {
    if (v && typeof v === "object" && !Array.isArray(v) && typeof out[k] === "object" && out[k] !== null) {
      out[k] = deepMerge(out[k], v);
    } else {
      out[k] = v;
    }
  }
  return out;
}

/// 整段替换保存：将 path 指向的配置段整体替换为 value。
/// 与 patchConfig 的合并语义不同：子树不再与旧值合并，编辑器里删除的键能真正删除。
export async function replaceConfig(path: string[], value: any) {
  const next = structuredClone(config() ?? {}) as Json;
  let cur: any = next;
  for (const key of path.slice(0, -1)) {
    if (typeof cur[key] !== "object" || cur[key] === null) cur[key] = {};
    cur = cur[key];
  }
  cur[path[path.length - 1]] = value;
  return saveConfig(next);
}

/**
 * 页面级配置草稿：编辑只改草稿不落盘，出现「保存并应用」按钮后统一保存。
 * excludeKeys：由开关即时保存、不参与草稿的键（如 enabled），保存时保持当前配置值。
 */
export function useDraft(section: () => Json, excludeKeys: string[] = []) {
  const strip = (v: any): Json => {
    const out: Json = { ...(v ?? {}) };
    for (const k of excludeKeys) delete out[k];
    return out;
  };
  const snap = () => strip(section());
  const [draft, setDraft] = createSignal<Json>(snap());

  const dirty = () => JSON.stringify(draft()) !== JSON.stringify(snap());

  // 草稿干净时跟随外部配置变化（自身保存 / 开关即时保存 / 远程配置更新）
  createEffect(
    on(snap, (v) => {
      if (!untrack(dirty)) setDraft({ ...v });
    }),
  );

  /// 合并方式修改草稿（适合零散字段：只动到 patch 里的键）
  const patch = (part: Json) => setDraft((d) => deepMerge(d, part) as Json);

  /// 整键替换草稿（适合 JSON 编辑器 / 多行文本整树提交，删除的键不会复活）
  const set = (key: string, value: any) => setDraft((d) => ({ ...d, [key]: value }));

  /// 放弃修改，回到当前配置
  const reset = () => setDraft(snap());

  /// 保存用的整段值：当前配置为底 + 草稿覆盖（排除的即时键保持当前值）
  const saveValue = () => ({ ...section(), ...draft() }) as Json;

  return { draft, patch, set, dirty, reset, saveValue };
}

const STATUS_KEYS = ["server", "proxy", "node", "git", "pip"] as const;

const PLUGIN_KEYS = ["node", "git", "pip"] as const;
export type PluginKey = (typeof PLUGIN_KEYS)[number];

/// 勾选了「随应用启动」的插件（是否真正启用由后端统一编排）
export function linkedPlugins(): PluginKey[] {
  return PLUGIN_KEYS.filter((k) => !!config().plugin?.[k]?.startWithApp);
}

/// 主动拉取后端真实状态：前端可能在后端初始化之后才加载，会错过那批 status 事件
export async function refreshStatus() {
  try {
    const s = await api.appStatus();
    setStatus((st) => {
      const next = { ...st };
      for (const key of STATUS_KEYS) {
        // 启动中 / 启动失败等过渡态以事件为准，避免轮询把中间状态冲掉
        if (st[key] === "starting" || st[key] === "fail") continue;
        next[key] = s[key] ? "success" : "stopped";
      }
      return next;
    });
  } catch {
    // 后端尚未就绪时静默忽略，等待下一次轮询
  }
}

export function initStore() {
  void (async () => {
    try {
      await reloadConfig();
      await refreshStatus();
    } catch (e) {
      toast(`初始化失败: ${e}`, "error");
    } finally {
      setReady(true);
    }
  })();

  // 后端初始化是异步的，首帧状态可能还没就绪，定时对齐真实状态
  setInterval(() => void refreshStatus(), 5000);
  window.addEventListener("focus", () => void refreshStatus());

  void listen<{ key: string; status: string }>("status", (e) => {
    setStatus((st) => ({ ...st, [e.payload.key]: e.payload.status as StatusValue }));
  });

  void listen<{ resultList: SpeedResult[] }>("speed", (e) => {
    setSpeedResults(e.payload.resultList ?? []);
    setSpeedTesting(false);
  });

  void listen<boolean>("speedTesting", (e) => setSpeedTesting(e.payload as boolean));

  void listen<{ upload: number; download: number; uploadSpeed: number; downloadSpeed: number }>(
    "traffic",
    (e) => setTraffic(e.payload),
  );

  void listen<{ title: string; msg: string }>("error", (e) => {
    toast(`${e.payload.title}: ${e.payload.msg}`, "error");
  });
}

export function humanBytes(bytes: number): string {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let size = bytes;
  let idx = 0;
  while (size >= 1024 && idx < units.length - 1) {
    size /= 1024;
    idx++;
  }
  return `${idx === 0 ? size : size.toFixed(2)} ${units[idx]}`;
}
