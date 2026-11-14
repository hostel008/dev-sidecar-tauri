import { For, Show, createSignal } from "solid-js";
import { Button, Card, Container, StatusDot, Tag } from "../components/ui";
import PowerButton from "../components/PowerButton";
import { api } from "../api";
import { config, humanBytes, patchConfig, refreshStatus, reloadConfig, setStatus, speedResults, status, toast, traffic } from "../store";
import { navigate } from "../router";

export default function IndexPage() {
  const [busy, setBusy] = createSignal("");

  const toggleServer = async () => {
    setBusy("server");
    try {
      if (status().server === "success") {
        // 后端会先撤销活动插件、恢复系统代理，再停止监听；不会留下指向死端口的配置。
        // 插件 enabled 也由后端回写，前端不再自己推断。
        await api.stopServer();
        await reloadConfig();
        await patchConfig({
          server: { enabled: false },
          ...(status().proxy === "success" ? { proxy: { enabled: false } } : {}),
        });
        setStatus((st) => ({ ...st, server: "stopped", proxy: "stopped" }));
        await refreshStatus();
        toast("加速服务与系统代理已停止，活动插件配置已恢复", "success");
      } else {
        await api.startServer();
        await patchConfig({ server: { enabled: true } });
        setStatus((st) => ({ ...st, server: "success" }));
      }
    } catch (e: any) {
      await refreshStatus().catch(() => {});
      toast(String(e), "error");
    } finally {
      setBusy("");
    }
  };

  const toggleProxy = async () => {
    setBusy("proxy");
    try {
      if (status().proxy === "success") {
        await api.stopProxy();
        await patchConfig({ proxy: { enabled: false } });
        setStatus((st) => ({ ...st, proxy: "stopped" }));
      } else {
        // 后端会再次检查服务端口是否真实可连；服务未运行会直接报错且不改注册表。
        await api.startProxy();
        await patchConfig({ proxy: { enabled: true } });
        setStatus((st) => ({ ...st, proxy: "success" }));
      }
    } catch (e: any) {
      await refreshStatus().catch(() => {});
      toast(String(e), "error");
    } finally {
      setBusy("");
    }
  };

  /// 插件（npm / git / pip）直接开关，不跳转页面
  const togglePlugin = async (name: string) => {
    setBusy(name);
    try {
      // 动作与显示都以运行时状态为准；enabled 由后端回写，前端只做对账
      if (status()[name] === "success") {
        await api.disablePlugin(name);
      } else {
        // 服务未运行时后端拒绝启用，且不会写入 npm/git/pip 外部配置。
        await api.enablePlugin(name);
      }
      await reloadConfig();
      await refreshStatus();
    } catch (e: any) {
      await refreshStatus().catch(() => {});
      toast(String(e), "error");
    } finally {
      setBusy("");
    }
  };

  const toggleRemote = async () => {
    const app = config().app ?? {};
    const enabled = !(app.remoteConfig ?? {}).enabled;
    await patchConfig({ app: { remoteConfig: { enabled } } });
    if (enabled) {
      try {
        await api.downloadRemoteConfig();
        await reloadConfig();
        toast("远程配置已更新", "success");
      } catch (e: any) {
        toast(String(e), "error");
      }
    }
  };

  const cards = () => [
    { key: "server", title: "加速服务", desc: "本地 MITM 代理服务" },
    { key: "proxy", title: "系统代理", desc: "接管系统网络请求" },
    { key: "node", title: "NPM 加速", desc: "npm / yarn 镜像" },
    { key: "git", title: "Git 代理", desc: "git 命令行代理" },
    { key: "pip", title: "PIP 加速", desc: "pip 镜像源" },
  ];

  return (
    <Container title="首页概览" desc="DevSidecar（Tauri 重构版）：本地开发者加速工具">
      <Card title="一键加速" desc="同时管理本地加速服务与系统代理，点一下即可开始 / 停止">
        <PowerButton />
      </Card>

      <div class="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-5">
        <For each={cards()}>
          {(c) => {
            const running = () => status()[c.key] === "success";
            return (
            <Card>
              <div class="flex items-start justify-between">
                <div>
                  <div class="flex items-center gap-2">
                    {/* 与一键加速面板一致：状态点，运行中变绿，未运行保持灰黑 */}
                    <StatusDot status={running() ? "success" : "stopped"} />
                    <span class="text-sm font-medium" style={{ color: "var(--ds-text)" }}>
                      {c.title}
                    </span>
                  </div>
                  <div class="mt-1 text-xs" style={{ color: "var(--ds-text-soft)" }}>
                    {c.desc}
                  </div>
                </div>
                <Tag type={running() ? "success" : "default"}>{running() ? "已启用" : "未启用"}</Tag>
              </div>
              <div class="mt-3 flex gap-2">
                <Button
                  size="sm"
                  type={running() ? "danger" : "primary"}
                  loading={busy() === c.key}
                  onClick={() => {
                    if (c.key === "server") return void toggleServer();
                    if (c.key === "proxy") return void toggleProxy();
                    void togglePlugin(c.key);
                  }}
                >
                  {running() ? "关闭" : "开启"}
                </Button>
                <Button size="sm" onClick={() => navigate(c.key === "server" ? "server" : c.key === "proxy" ? "proxy" : `plugin/${c.key}`)}>
                  配置
                </Button>
              </div>
            </Card>
            );
          }}
        </For>
      </div>

      <div class="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card title="流量统计">
          <div class="flex flex-col gap-2 text-sm" style={{ color: "var(--ds-text)" }}>
            <div class="flex justify-between">
              <span>上传</span>
              <span>{humanBytes(traffic().upload)}</span>
            </div>
            <div class="flex justify-between">
              <span>下载</span>
              <span>{humanBytes(traffic().download)}</span>
            </div>
            <div class="flex justify-between">
              <span>上传速率</span>
              <span>{humanBytes(traffic().uploadSpeed)}/s</span>
            </div>
            <div class="flex justify-between">
              <span>下载速率</span>
              <span>{humanBytes(traffic().downloadSpeed)}/s</span>
            </div>
          </div>
        </Card>

        <Card title="服务信息">
          <div class="flex flex-col gap-2 text-sm" style={{ color: "var(--ds-text)" }}>
            <div class="flex justify-between">
              <span>监听地址</span>
              <span>
                {config().server?.host}:{config().server?.port}
              </span>
            </div>
            <div class="flex justify-between">
              <span>HTTP 端口</span>
              <span>{(config().server?.port ?? 1) - 1}</span>
            </div>
            <div class="flex justify-between">
              <span>拦截功能</span>
              <span>{config().server?.intercept?.enabled ? "已开启" : "已关闭"}</span>
            </div>
            <div class="flex justify-between">
              <span>远程配置</span>
              <span>{config().app?.remoteConfig?.enabled ? "已开启" : "已关闭"}</span>
            </div>
          </div>
          <div class="mt-3">
            <Button size="sm" onClick={toggleRemote}>
              {config().app?.remoteConfig?.enabled ? "关闭远程配置" : "开启远程配置"}
            </Button>
          </div>
        </Card>

        <Card title="测速结果">
          <Show when={speedResults().length > 0} fallback={<div class="text-xs" style={{ color: "var(--ds-text-soft)" }}>暂无测速数据，可在「加速服务」页面手动测速</div>}>
            <div class="flex flex-col gap-1 text-xs">
              <For each={speedResults().slice(0, 6)}>
                {(r) => (
                  <div class="flex justify-between" style={{ color: "var(--ds-text)" }}>
                    <span class="truncate">
                      {r.hostname} → {r.ip}
                    </span>
                    <span style={{ color: r.ok ? "var(--ds-success)" : "var(--ds-danger)" }}>
                      {r.ok ? `${r.delay} ms` : "失败"}
                    </span>
                  </div>
                )}
              </For>
            </div>
          </Show>
          <div class="mt-3">
            <Button size="sm" onClick={() => navigate("server")}>
              前往测速
            </Button>
          </div>
        </Card>
      </div>
    </Container>
  );
}
