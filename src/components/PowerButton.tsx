import { For, Show, createSignal, onMount } from "solid-js";
import { api } from "../api";
import { config, linkedPlugins, patchConfig, refreshStatus, reloadConfig, setStatus, status, toast } from "../store";
import { navigate } from "../router";
import { StatusDot, Tag } from "./ui";

const PLUGIN_META: Record<string, { label: string; icon: string }> = {
  node: { label: "NPM 加速", icon: "📦" },
  git: { label: "Git 代理", icon: "🔧" },
  pip: { label: "PIP 加速", icon: "🐍" },
};

/// 首页的一键启停按钮：编排「加速服务」+「系统代理」，并联动设置了「随应用启动」的插件
export default function PowerButton() {
  const [busy, setBusy] = createSignal(false);
  const [caMissing, setCaMissing] = createSignal(false);

  const serverOn = () => status().server === "success";
  const proxyOn = () => status().proxy === "success";
  // 任一项在跑即为「已开启」，此时点击表示全部停止
  const on = () => serverOn() || proxyOn();
  const partial = () => serverOn() !== proxyOn();
  const accent = () => (on() ? "var(--ds-danger)" : "var(--ds-primary)");

  const pluginOn = (key: string) => status()[key] === "success";
  /// 勾选了「随应用启动」的插件
  const linked = () => linkedPlugins();

  const syncStatus = (server: boolean, proxy: boolean) => {
    setStatus((st) => ({
      ...st,
      server: server ? "success" : "stopped",
      proxy: proxy ? "success" : "stopped",
    }));
  };

  const checkCa = async () => {
    try {
      const exists = await api.isCaExists();
      // 证书文件存在不等于已安装，需确认已加入系统信任区
      const trusted = exists ? await api.canTrustCa() : false;
      setCaMissing(!trusted);
      return trusted;
    } catch {
      return true;
    }
  };

  const toggle = async () => {
    if (busy()) return;
    setBusy(true);
    try {
      if (on()) {
        // 后端统一按「插件 → 系统代理 → 服务」停用，前端不再自行决定顺序。
        await api.stopAcceleration();
        // 后端已撤销活动插件并回写 enabled，先重新拉配置再写自己的开关，
        // 避免用旧快照把插件 enabled 又改回 true。
        await reloadConfig();
        await patchConfig({ server: { enabled: false }, proxy: { enabled: false } });
        syncStatus(false, false);
        await refreshStatus();
        toast("已停止加速，插件外部配置与系统代理均已恢复", "success");
      } else {
        // 后端完成服务连通性检查、代理接管和随应用启动插件；任一步失败会整体回滚。
        await api.startAcceleration();
        await reloadConfig();
        await patchConfig({ server: { enabled: true }, proxy: { enabled: true } });
        syncStatus(true, true);
        await refreshStatus();
        const caOk = await checkCa();
        toast(caOk ? "加速已开启" : "加速已开启，但根证书未安装", caOk ? "success" : "warn");
      }
    } catch (e: any) {
      // 失败时向后端对账，不能只依赖本地猜测的状态
      await refreshStatus().catch(() => {});
      toast(String(e), "error");
    } finally {
      setBusy(false);
    }
  };

  onMount(() => {
    void checkCa();
  });

  return (
    <div class="flex flex-col gap-4 sm:flex-row sm:items-center">
      <div class="flex shrink-0 justify-center">
        <button
          type="button"
          disabled={busy()}
          aria-pressed={on()}
          title={on() ? "停止加速服务与系统代理" : "启动加速服务并接管系统代理"}
          class="flex h-32 w-32 flex-col items-center justify-center rounded-full transition-transform duration-150 active:scale-95 disabled:opacity-60 sm:h-36 sm:w-36"
          style={{
            background: accent(),
            border: "1px solid var(--ds-border)",
            "box-shadow": `0 0 28px -6px ${accent()}, 0 8px 20px rgba(0,0,0,.25)`,
            cursor: busy() ? "progress" : "pointer",
          }}
          onClick={toggle}
        >
          <svg
            width="40"
            height="40"
            viewBox="0 0 24 24"
            fill="none"
            stroke="#fff"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
          >
            <path d="M12 3v8" />
            <path d="M18.36 6.64a9 9 0 1 1-12.73 0" />
          </svg>
          <span class="mt-2 text-sm font-medium text-white">{busy() ? "处理中…" : on() ? "停止加速" : "一键加速"}</span>
        </button>
      </div>

      <div class="min-w-0 flex-1">
        <div class="flex flex-wrap items-center gap-2">
          <Tag type={on() ? (partial() ? "warn" : "success") : "default"}>
            {on() ? (partial() ? "部分开启" : "加速中") : "已停止"}
          </Tag>
          <span class="text-xs" style={{ color: "var(--ds-text-soft)" }}>
            {on() ? "点击按钮可停止加速服务与系统代理" : "点击按钮启动加速服务，并自动接管系统代理"}
          </span>
        </div>

        <div class="mt-3 grid grid-cols-1 gap-2 text-sm sm:grid-cols-2" style={{ color: "var(--ds-text)" }}>
          <div class="flex items-center gap-2">
            <StatusDot status={serverOn() ? "success" : "stopped"} />
            <span>加速服务</span>
            <span class="ml-auto text-xs" style={{ color: "var(--ds-text-soft)" }}>
              {serverOn() ? "运行中" : "已停止"}
            </span>
          </div>
          <div class="flex items-center gap-2">
            <StatusDot status={proxyOn() ? "success" : "stopped"} />
            <span>系统代理</span>
            <span class="ml-auto text-xs" style={{ color: "var(--ds-text-soft)" }}>
              {proxyOn() ? "已接管" : "未接管"}
            </span>
          </div>
        </div>

        <div class="mt-2 flex flex-wrap items-center gap-2 text-xs" style={{ color: "var(--ds-text-soft)" }}>
          <span>联动插件</span>
          <Show
            when={linked().length > 0}
            fallback={<span>未选择，可到插件页开启「随应用启动」后随一键加速同步</span>}
          >
            <For each={linked()}>
              {(key) => (
                <span
                  class="inline-flex items-center gap-1 rounded px-2 py-0.5"
                  style={{ border: "1px solid var(--ds-border)", color: "var(--ds-text)" }}
                >
                  <StatusDot status={pluginOn(key) ? "success" : "stopped"} />
                  <span class="mr-0.5">{PLUGIN_META[key].icon}</span>
                  <span>{PLUGIN_META[key].label}</span>
                </span>
              )}
            </For>
          </Show>
        </div>

        <div class="mt-2 text-xs" style={{ color: "var(--ds-text-soft)" }}>
          监听地址 {config().server?.host ?? "127.0.0.1"}:{config().server?.port ?? 31181}
        </div>

        <Show when={caMissing()}>
          <div class="mt-2 text-xs" style={{ color: "var(--ds-warn)" }}>
            根证书未安装，HTTPS 加速可能不可用。
            <button
              class="ml-1 underline"
              style={{ color: "var(--ds-primary)", background: "transparent", border: "none" }}
              onClick={() => navigate("ca")}
            >
              前往安装
            </button>
          </div>
        </Show>
      </div>
    </div>
  );
}
