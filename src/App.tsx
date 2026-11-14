import { For, Show, createEffect, createSignal, onMount } from "solid-js";
import { StatusDot, Tag, Toasts } from "./components/ui";
import CloseDialog from "./components/CloseDialog";
import { humanBytes, patchConfig, status, theme, toast, traffic } from "./store";
import { api, openExternal } from "./api";
import { MENUS, type MenuItem, parseHash, route, setRoute } from "./router";

import IndexPage from "./pages/Index";
import ServerPage from "./pages/Server";
import ProxyPage from "./pages/Proxy";
import SettingPage from "./pages/Setting";
import HelpPage from "./pages/Help";
import TrafficPage from "./pages/Traffic";
import GithubStatusPage from "./pages/GithubStatus";
import CheckPage from "./pages/Check";
import CaPage from "./pages/Ca";
import PluginNodePage from "./pages/PluginNode";
import PluginGitPage from "./pages/PluginGit";
import PluginPipPage from "./pages/PluginPip";

export default function App() {
  const toggleTheme = async () => {
    const next = theme() === "dark" ? "light" : "dark";
    try {
      await patchConfig({ app: { theme: next } });
    } catch (e: any) {
      toast(String(e), "error");
    }
  };

  // 版本号以后端 Cargo 包版本为唯一来源，避免界面写死后与安装包版本不一致
  const [version, setVersion] = createSignal("1.0.0");

  onMount(() => {
    setRoute(parseHash());
    window.addEventListener("hashchange", () => setRoute(parseHash()));
    api
      .appVersion()
      .then((v: string) => {
        if (v) setVersion(v);
      })
      .catch(() => {});
  });

  createEffect(() => {
    document.title = `DevSidecar - ${MENUS.find((m) => m.key === route())?.title ?? ""}`;
  });

  const groups = () => {
    const map = new Map<string, MenuItem[]>();
    for (const item of MENUS) {
      const list = map.get(item.group) ?? [];
      list.push(item);
      map.set(item.group, list);
    }
    return [...map.entries()];
  };

  const renderPage = () => {
    switch (route()) {
      case "index":
        return <IndexPage />;
      case "server":
        return <ServerPage />;
      case "proxy":
        return <ProxyPage />;
      case "plugin/node":
        return <PluginNodePage />;
      case "plugin/git":
        return <PluginGitPage />;
      case "plugin/pip":
        return <PluginPipPage />;
      case "traffic":
        return <TrafficPage />;
      case "github":
        return <GithubStatusPage />;
      case "check":
        return <CheckPage />;
      case "ca":
        return <CaPage />;
      case "setting":
        return <SettingPage />;
      case "help":
        return <HelpPage />;
      default:
        return <IndexPage />;
    }
  };

  return (
    <div class="flex h-screen w-screen overflow-hidden" style={{ background: "var(--ds-bg)" }}>
      <aside
        class="flex w-52 shrink-0 flex-col border-r"
        style={{ background: "var(--ds-bg-soft)", "border-color": "var(--ds-border)" }}
      >
        <div class="flex items-center gap-2 px-4 py-4">
          <span class="text-lg">🚗</span>
          <div class="min-w-0 flex-1">
            <div class="text-sm font-semibold" style={{ color: "var(--ds-text)" }}>
              DevSidecar
            </div>
            <div class="text-xs" style={{ color: "var(--ds-text-soft)" }}>
              Tauri 重构版
            </div>
          </div>
          <button
            type="button"
            title={theme() === "dark" ? "切换到亮色模式" : "切换到暗色模式"}
            aria-label={theme() === "dark" ? "切换到亮色模式" : "切换到暗色模式"}
            class="shrink-0 rounded px-1.5 py-1 text-sm leading-none"
            // style={{ background: "var(--ds-bg)", color: "var(--ds-text)", border: "1px solid var(--ds-border)" }}
            onClick={toggleTheme}
          >
            {theme() === "dark" ? "🌙" : "☀️"}
          </button>
        </div>

        <nav class="flex-1 overflow-y-auto px-2 pb-4">
          <For each={groups()}>
            {([group, items]) => (
              <div class="mb-3">
                <div class="px-2 py-1 text-xs" style={{ color: "var(--ds-text-soft)" }}>
                  {group}
                </div>
                <For each={items}>
                  {(item) => (
                    <a
                      href={`#/${item.key}`}
                      class="mb-0.5 flex items-center gap-2 rounded px-2 py-1.5 text-sm no-underline transition-colors"
                      style={{
                        color: route() === item.key ? "#fff" : "var(--ds-text)",
                        background: route() === item.key ? "var(--ds-primary)" : "transparent",
                      }}
                    >
                      <span>{item.icon}</span>
                      <span class="flex-1">{item.title}</span>
                      <Show when={["server", "proxy", "plugin/node", "plugin/git", "plugin/pip"].includes(item.key)}>
                        <StatusDot status={status()[item.key.replace("plugin/", "")] ?? "stopped"} />
                      </Show>
                    </a>
                  )}
                </For>
              </div>
            )}
          </For>
        </nav>

        <div class="border-t px-4 py-3 text-xs" style={{ "border-color": "var(--ds-border)", color: "var(--ds-text-soft)" }}>
          <div class="flex justify-between">
            <span>上传</span>
            <span>{humanBytes(traffic().upload)}</span>
          </div>
          <div class="flex justify-between">
            <span>下载</span>
            <span>{humanBytes(traffic().download)}</span>
          </div>
        </div>
      </aside>

      <main class="flex min-w-0 flex-1 flex-col">
        <header
          class="flex h-12 shrink-0 items-center justify-between border-b px-6"
          style={{ "border-color": "var(--ds-border)", background: "var(--ds-bg-soft)" }}
        >
          <div class="text-sm font-medium" style={{ color: "var(--ds-text)" }}>
            {MENUS.find((m) => m.key === route())?.title}
          </div>
          <div class="flex items-center gap-2">
            <Tag type="info">v{version()}</Tag>
            <button
              class="rounded px-2 py-1 text-xs"
              style={{ background: "var(--ds-bg)", color: "var(--ds-text-soft)", border: "1px solid var(--ds-border)" }}
              onClick={() => openExternal("https://github.com/docmirror/dev-sidecar")}
            >
              Wiki
            </button>
          </div>
        </header>
        <div class="flex-1 overflow-y-auto p-6">{renderPage()}</div>
      </main>

      <Toasts />
      <CloseDialog />
    </div>
  );
}
