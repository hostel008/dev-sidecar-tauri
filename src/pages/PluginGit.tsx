import { createSignal } from "solid-js";
import { Button, Card, Container, Field, JsonEditor, SaveBar, Switch, Tag } from "../components/ui";
import { api } from "../api";
import { config, refreshStatus, reloadConfig, replaceConfig, status, toast, useDraft } from "../store";

export default function PluginGitPage() {
  const [busy, setBusy] = createSignal("");
  const git = () => config().plugin?.git ?? {};
  /// 唯一事实来源：后端运行时状态（外部配置是否真的写入）。配置里的 enabled
  /// 由后端回写，只用于持久化，不再单独驱动开关，避免两者不一致。
  const running = () => status().git === "success";
  const serverOn = () => status().server === "success";

  /// 编辑走草稿：修改后出现「保存并应用」，保存前不落盘；enabled 开关即时生效，不进草稿
  const { draft, patch, set, dirty, reset, saveValue } = useDraft(git, ["enabled"]);

  const toggle = async () => {
    if (busy()) return;
    setBusy("toggle");
    try {
      // 动作与显示都基于后端运行时状态，避免“开关看着是开、点击却在开启”的错位
      if (running()) {
        await api.disablePlugin("git");
      } else {
        await api.enablePlugin("git");
      }
      // 后端已把真实结果写回 plugin.git.enabled，这里只做对账
      await reloadConfig();
      await refreshStatus();
    } catch (e: any) {
      await refreshStatus().catch(() => {});
      toast(String(e), "error");
    } finally {
      setBusy("");
    }
  };

  /// 保存草稿并应用：插件启用中则重新应用，使 sslVerify/noProxyUrls 等设置立即写入 git config
  const save = async () => {
    setBusy("save");
    try {
      await replaceConfig(["plugin", "git"], saveValue());
      if (running()) {
        await api.enablePlugin("git");
        toast("配置已保存，Git 代理已重新应用", "success");
      } else {
        toast("配置已保存", "success");
      }
    } catch (e: any) {
      toast(String(e), "error");
    } finally {
      setBusy("");
    }
  };

  return (
    <Container title="Git 代理" desc={git().tip ?? "为 git 命令行设置 http/https 代理"}>
      <Card title="插件开关" extra={<Tag type={running() ? "success" : "default"}>{running() ? "已启用" : "未启用"}</Tag>}>
        <Field
          label="启用 Git 代理"
          desc={serverOn() ? undefined : "加速服务未运行，请先在首页启动加速服务"}
        >
          <Switch checked={running()} onChange={toggle} disabled={busy() === "toggle"} />
        </Field>
        <Field label="随应用启动" desc="跟随加速服务：服务启动时自动拉起（服务未运行则不启动），并随首页「一键加速」同步开关">
          <Switch checked={!!draft().startWithApp} onChange={(v) => patch({ startWithApp: v })} />
        </Field>
        <Field label="校验 SSL" desc="设置 http.sslVerify">
          <Switch
            checked={!!draft().setting?.sslVerify}
            onChange={(v) => patch({ setting: { sslVerify: v } })}
          />
        </Field>
        <div class="mt-3">
          <Button type={running() ? "danger" : "primary"} loading={busy() === "toggle"} onClick={toggle}>
            {running() ? "关闭代理" : "开启代理"}
          </Button>
        </div>
      </Card>

      <Card title="不走代理的站点" desc="这些站点将不经过 DevSidecar 代理">
        <JsonEditor
          height="260px"
          value={draft().setting?.noProxyUrls ?? {}}
          onChange={(v) => set("setting", { ...(draft().setting ?? {}), noProxyUrls: v })}
        />
      </Card>

      <SaveBar dirty={dirty()} saving={busy() === "save"} onSave={save} onReset={reset} text="插件配置已修改，尚未保存" />
    </Container>
  );
}
