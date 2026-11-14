import { For, createSignal } from "solid-js";
import { Button, Card, Container, Field, Input, SaveBar, Switch, Tag } from "../components/ui";
import { api } from "../api";
import { config, refreshStatus, reloadConfig, replaceConfig, status, toast, useDraft } from "../store";

export default function PluginPipPage() {
  const [busy, setBusy] = createSignal("");
  const pip = () => config().plugin?.pip ?? {};
  /// 唯一事实来源：后端运行时状态（外部配置是否真的写入）。配置里的 enabled
  /// 由后端回写，只用于持久化，不再单独驱动开关，避免两者不一致。
  const running = () => status().pip === "success";
  const serverOn = () => status().server === "success";

  /// 编辑走草稿：修改后出现「保存并应用」，保存前不落盘；enabled 开关即时生效，不进草稿
  const { draft, patch, dirty, reset, saveValue } = useDraft(pip, ["enabled"]);
  const dsetting = () => draft().setting ?? {};

  const registryList = () => {
    const list = (dsetting().registryList ?? {}) as Record<string, { name?: string; value?: string }>;
    return Object.entries(list).map(([k, v]) => ({ key: k, name: v.name ?? k, value: v.value }));
  };

  const toggle = async () => {
    if (busy()) return;
    setBusy("toggle");
    try {
      // 动作与显示都基于后端运行时状态，避免“开关看着是开、点击却在开启”的错位
      if (running()) {
        await api.disablePlugin("pip");
      } else {
        await api.enablePlugin("pip");
      }
      // 后端已把真实结果写回 plugin.pip.enabled，这里只做对账
      await reloadConfig();
      await refreshStatus();
    } catch (e: any) {
      await refreshStatus().catch(() => {});
      toast(String(e), "error");
    } finally {
      setBusy("");
    }
  };

  /// 保存草稿并应用：插件启用中则重新应用，使 mirror/trustedHost 等设置立即写入 pip
  const save = async () => {
    setBusy("save");
    try {
      await replaceConfig(["plugin", "pip"], saveValue());
      if (running()) {
        await api.enablePlugin("pip");
        toast("配置已保存，PIP 加速已重新应用", "success");
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
    <Container title="PIP 加速" desc={pip().tip ?? "为 pip 设置镜像源"}>
      <Card title="插件开关" extra={<Tag type={running() ? "success" : "default"}>{running() ? "已启用" : "未启用"}</Tag>}>
        <Field
          label="启用 PIP 加速"
          desc={serverOn() ? undefined : "加速服务未运行，请先在首页启动加速服务"}
        >
          <Switch checked={running()} onChange={toggle} disabled={busy() === "toggle"} />
        </Field>
        <Field label="随应用启动" desc="跟随加速服务：服务启动时自动拉起（服务未运行则不启动），并随首页「一键加速」同步开关">
          <Switch checked={!!draft().startWithApp} onChange={(v) => patch({ startWithApp: v })} />
        </Field>
        <Field label="命令">
          <Input value={dsetting().command ?? "pip"} onInput={(v) => patch({ setting: { command: v } })} />
        </Field>
        <Field label="镜像地址">
          <Input
            class="w-96"
            value={dsetting().registry ?? ""}
            onInput={(v) => patch({ setting: { registry: v } })}
          />
        </Field>
        <Field label="信任的主机">
          <Input
            class="w-64"
            value={dsetting().trustedHost ?? ""}
            onInput={(v) => patch({ setting: { trustedHost: v } })}
          />
        </Field>
        <div class="mt-2 flex flex-wrap gap-2">
          <For each={registryList()}>
            {(r) => (
              <Button size="sm" onClick={() => patch({ setting: { registry: r.value } })}>
                {r.name}
              </Button>
            )}
          </For>
        </div>
        <div class="mt-3">
          <Button type={running() ? "danger" : "primary"} loading={busy() === "toggle"} onClick={toggle}>
            {running() ? "关闭加速" : "开启加速"}
          </Button>
        </div>
      </Card>

      <SaveBar dirty={dirty()} saving={busy() === "save"} onSave={save} onReset={reset} text="插件配置已修改，尚未保存" />
    </Container>
  );
}
