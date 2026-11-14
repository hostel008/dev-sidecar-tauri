import { createSignal } from "solid-js";
import { Button, Card, Container, Field, Input, SaveBar, Select, Switch } from "../components/ui";
import { api } from "../api";
import { config, patchConfig, refreshStatus, reloadConfig, replaceConfig, setConfig, setStatus, toast, useDraft } from "../store";
import { openPath } from "../api";

export default function SettingPage() {
  const [busy, setBusy] = createSignal("");
  const app = () => config().app ?? {};

  const update = async (part: any) => {
    try {
      await patchConfig(part);
    } catch (e: any) {
      toast(String(e), "error");
    }
  };

  /// 数字输入：空串/非数字不写入配置
  const num = (v: string): number | undefined => {
    if (v === "") return undefined;
    const n = Number(v);
    return Number.isFinite(n) ? n : undefined;
  };

  /// 界面设置走草稿：修改后出现「保存 / 保存并应用」，保存前不落盘。
  /// 主题等界面项随保存生效（保存即保存至配置）；窗口大小需「保存并应用」立即调整当前窗口。
  const { draft, patch, dirty, reset, saveValue } = useDraft(app);
  const dwin = () => draft().windowSize ?? {};

  const save = async () => {
    setBusy("save");
    try {
      await replaceConfig(["app"], saveValue());
      toast("设置已保存", "success");
    } catch (e: any) {
      toast(String(e), "error");
    } finally {
      setBusy("");
    }
  };

  const apply = async () => {
    setBusy("apply");
    try {
      await replaceConfig(["app"], saveValue());
      await api.applyWindowSize();
      toast("设置已保存，新窗口大小已应用", "success");
    } catch (e: any) {
      toast(String(e), "error");
    } finally {
      setBusy("");
    }
  };

  const resetAll = async () => {
    setBusy("reset");
    try {
      await api.removeUserConfig();
      await reloadConfig();
      // 恢复出厂后重启服务，使运行中的服务立即使用默认配置
      try {
        await api.restartServer();
      } catch {
        /* 服务未运行时忽略 */
      }
      const p = await api.pluginStatus().catch(() => ({ node: false, git: false, pip: false }));
      setStatus((st) => ({
        ...st,
        node: p.node ? "success" : "stopped",
        git: p.git ? "success" : "stopped",
        pip: p.pip ? "success" : "stopped",
      }));
      toast("已恢复出厂设置", "success");
    } catch (e: any) {
      toast(String(e), "error");
    } finally {
      setBusy("");
    }
  };

  return (
    <Container title="应用设置" desc="界面、日志、远程配置等全局设置">
      <Card title="界面">
        <Field label="主题">
          <Select
            value={(draft().theme as string) ?? "dark"}
            options={[
              { label: "暗色", value: "dark" },
              { label: "亮色", value: "light" },
            ]}
            onChange={(v) => patch({ theme: v })}
          />
        </Field>
        <Field label="启动时显示窗口">
          <Switch checked={!!draft().startShowWindow} onChange={(v) => patch({ startShowWindow: v })} />
        </Field>
        <Field label="关闭窗口时" desc="选择“每次询问”时点击关闭会弹窗供选择；直接退出会同时恢复系统代理、回滚插件配置并停止加速服务">
          <Select
            value={(draft().closeAction as string) ?? "ask"}
            options={[
              { label: "每次询问", value: "ask" },
              { label: "最小化到托盘", value: "hide" },
              { label: "直接退出", value: "exit" },
            ]}
            onChange={(v) => patch({ closeAction: v })}
          />
        </Field>
        <Field label="窗口宽度" desc="保存后下次启动生效；「保存并应用」可立即调整当前窗口">
          <Input
            type="number"
            value={dwin().width ?? 900}
            onInput={(v) => {
              const n = num(v);
              if (n !== undefined) patch({ windowSize: { width: n } });
            }}
          />
        </Field>
        <Field label="窗口高度" desc="保存后下次启动生效；「保存并应用」可立即调整当前窗口">
          <Input
            type="number"
            value={dwin().height ?? 750}
            onInput={(v) => {
              const n = num(v);
              if (n !== undefined) patch({ windowSize: { height: n } });
            }}
          />
        </Field>
      </Card>

      <Card title="远程配置">
        <Field label="启用远程配置" desc="从远端拉取拦截规则与帮助信息">
          <Switch
            checked={!!app().remoteConfig?.enabled}
            onChange={(v) => update({ app: { remoteConfig: { enabled: v } } })}
          />
        </Field>
        <Field label="远程配置地址">
          <Input
            class="w-96"
            value={(app().remoteConfig?.url as string) ?? ""}
            onInput={(v) => update({ app: { remoteConfig: { url: v } } })}
          />
        </Field>
        <Field label="个人远程配置地址">
          <Input
            class="w-96"
            value={(app().remoteConfig?.personalUrl as string) ?? ""}
            onInput={(v) => update({ app: { remoteConfig: { personalUrl: v } } })}
          />
        </Field>
        <div class="mt-2 flex gap-2">
          <Button
            loading={busy() === "download"}
            onClick={async () => {
              setBusy("download");
              try {
                await api.downloadRemoteConfig();
                await reloadConfig();
                toast("远程配置已更新", "success");
              } catch (e: any) {
                toast(String(e), "error");
              } finally {
                setBusy("");
              }
            }}
          >
            立即更新
          </Button>
        </div>
      </Card>

      <Card title="日志">
        <Field label="禁用日志">
          <Switch
            checked={!!app().logDisabled}
            onChange={async (v) => {
              try {
                const res = await api.setLogDisabled(v);
                if (typeof res?.config === "object") setConfig(res.config);
                toast(`日志已${res?.disabled ? "禁用" : "启用"}`, "success");
              } catch (e: any) {
                toast(String(e), "error");
              }
            }}
          />
        </Field>
        <Field label="日志目录">
          <Input
            class="w-96"
            value={(app().logFileSavePath as string) ?? ""}
            onInput={(v) => update({ app: { logFileSavePath: v } })}
          />
        </Field>
        <Field label="单文件最大体积（GB）">
          <Input
            type="number"
            value={app().maxLogFileSize ?? 1}
            onInput={(v) => {
              const n = num(v);
              if (n !== undefined) update({ app: { maxLogFileSize: n } });
            }}
          />
        </Field>
        <div class="mt-2">
          <Button
            onClick={async () => {
              try {
                await openPath(await api.getLogDir());
              } catch (e: any) {
                toast(`打开日志目录失败: ${e}`, "error");
              }
            }}
          >
            打开日志目录
          </Button>
        </div>
      </Card>

      <Card title="维护">
        <Field label="恢复出厂设置" desc="备份并清空用户自定义配置">
          <Button type="danger" loading={busy() === "reset"} onClick={resetAll}>
            恢复出厂设置
          </Button>
        </Field>
        <Field
          label="修复残留配置"
          desc="服务已停止但系统代理或插件配置仍指向本应用时，用此功能重新对账并恢复"
        >
          <Button
            loading={busy() === "repair"}
            onClick={async () => {
              setBusy("repair");
              try {
                const r = await api.repairResidualConfig();
                if (r.repaired && r.residual.length === 0) {
                  toast("残留配置已恢复", "success");
                } else {
                  toast(`仍有残留未恢复: ${r.residual.join("; ")}`, "error");
                }
                await refreshStatus();
              } catch (e: any) {
                toast(String(e), "error");
              } finally {
                setBusy("");
              }
            }}
          >
            检查并修复
          </Button>
        </Field>
        <Field label="打开用户目录">
          <Button
            onClick={async () => {
              try {
                await openPath(await api.getUserBasePath());
              } catch (e: any) {
                toast(`打开目录失败: ${e}`, "error");
              }
            }}
          >
            打开
          </Button>
        </Field>
      </Card>

      <SaveBar
        dirty={dirty()}
        saving={busy() === "save" || busy() === "apply" ? busy() : false}
        onSave={save}
        onApply={apply}
        onReset={reset}
        text="界面设置已修改，尚未保存"
      />
    </Container>
  );
}
