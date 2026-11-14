import { invoke } from "@tauri-apps/api/core";

export type Json = Record<string, any>;

export const api = {
  getConfig: () => invoke<Json>("get_config"),
  getConfigByPath: (path: string) => invoke<Json>("get_config_by_path", { path }),
  saveConfig: (config: Json) => invoke<Json>("save_config", { config }),
  resetDefault: (key?: string) => invoke<Json>("reset_default", { key: key ?? null }),
  removeUserConfig: () => invoke<boolean>("remove_user_config"),
  downloadRemoteConfig: () => invoke<Json>("download_remote_config"),

  startServer: () => invoke<void>("start_server"),
  stopServer: () => invoke<void>("stop_server"),
  startAcceleration: () => invoke<void>("start_acceleration"),
  stopAcceleration: () => invoke<void>("stop_acceleration"),
  repairResidualConfig: () => invoke<{ repaired: boolean; residual: string[] }>("repair_residual_config"),
  restartServer: () => invoke<void>("restart_server"),
  serverStatus: () => invoke<{ running: boolean }>("server_status"),
  appStatus: () => invoke<AppStatus>("app_status"),

  startProxy: () => invoke<void>("start_proxy"),
  stopProxy: () => invoke<void>("stop_proxy"),

  isCaExists: () => invoke<boolean>("is_ca_exists"),
  canTrustCa: () => invoke<boolean>("can_trust_ca"),
  getCaCertPath: () => invoke<string>("get_ca_cert_path"),
  getUserBasePath: () => invoke<string>("get_user_base_path"),
  setupCa: () => invoke<string>("setup_ca"),

  enablePlugin: (name: string) => invoke<void>("enable_plugin", { name }),
  disablePlugin: (name: string) => invoke<void>("disable_plugin", { name }),
  pluginStatus: () => invoke<Record<string, boolean>>("plugin_status"),

  speedTest: () => invoke<{ resultList: SpeedResult[] }>("speed_test"),
  trafficStats: () => invoke<{ upload: number; download: number }>("traffic_stats"),
  resetTraffic: () => invoke<void>("reset_traffic"),
  dnsProviders: () => invoke<Json>("dns_providers"),
  networkCheck: (hostname: string) => invoke<Json>("network_check", { hostname }),

  appVersion: () => invoke<string>("app_version"),
  npmGetRegistry: () => invoke<Json>("npm_get_registry"),
  getLogDir: () => invoke<string>("get_log_dir"),

  // 打开路径 / 链接走应用自带命令，避免 opener 插件 IPC scope 拦截
  openPath: (path: string) => invoke<void>("open_path", { path }),
  openUrl: (url: string) => invoke<void>("open_url", { url }),
  getLogStatus: () => invoke<{ disabled: boolean; dir: string }>("get_log_status"),
  setLogDisabled: (disabled: boolean) => invoke<{ disabled: boolean; config: Json }>("set_log_disabled", { disabled }),
  shutdown: () => invoke<void>("shutdown"),
  executeClose: (action: "exit" | "hide") => invoke<void>("execute_close", { action }),
  applyWindowSize: () => invoke<void>("apply_window_size"),
};

export interface AppStatus {
  server: boolean;
  proxy: boolean;
  node: boolean;
  git: boolean;
  pip: boolean;
}

export interface SpeedResult {
  hostname: string;
  name: string;
  ip: string;
  delay: number;
  ok: boolean;
}

export async function openExternal(url: string) {
  // 仅放行 http(s) 外链：链接可能来自远程配置，防止 javascript: 等协议被用于钓鱼/执行；
  // 打开统一交给后端 opener，不再回退 window.open
  if (!/^https?:\/\//i.test(url)) {
    console.warn("openExternal: 拒绝非 http(s) 链接", url);
    return;
  }
  try {
    await api.openUrl(url);
  } catch (e) {
    console.warn("openExternal: 打开链接失败", url, e);
  }
}

/// 打开文件或目录；失败时返回错误信息，由调用方提示
export async function openPath(path: string): Promise<void> {
  if (!path) throw new Error("路径为空");
  await api.openPath(path);
}
