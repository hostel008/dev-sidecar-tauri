import { Show, createSignal, onMount } from "solid-js";
import { listen } from "@tauri-apps/api/event";
import { api } from "../api";
import { patchConfig, toast } from "../store";
import { Button } from "./ui";

type CloseAction = "exit" | "hide";

/**
 * 关闭询问弹窗：点击窗口关闭按钮时由后端触发（app.closeAction === "ask"），
 * 让用户选择「退出应用」或「最小化到托盘」，可记住选择写入配置。
 */
export default function CloseDialog() {
  const [visible, setVisible] = createSignal(false);
  const [remember, setRemember] = createSignal(false);
  const [busy, setBusy] = createSignal(false);

  onMount(() => {
    void listen<string>("close-requested", () => {
      // 每次弹窗都重置为不勾选，避免沿用上一次的选择
      setRemember(false);
      setVisible(true);
    });
  });

  const choose = async (action: CloseAction) => {
    if (busy()) return;
    setBusy(true);
    try {
      // 记住选择：写入配置，下次点击关闭直接执行，不再弹窗
      if (remember()) {
        await patchConfig({ app: { closeAction: action } }).catch((e) => {
          toast(`保存选择失败: ${e}`, "warn");
        });
      }
      await api.executeClose(action);
    } catch (e: any) {
      toast(String(e), "error");
    } finally {
      setBusy(false);
      setVisible(false);
    }
  };

  const cancel = () => {
    if (!busy()) setVisible(false);
  };

  return (
    <Show when={visible()}>
      <div
        class="fixed inset-0 z-50 flex items-center justify-center"
        style={{ background: "rgba(0, 0, 0, 0.45)" }}
        onClick={cancel}
      >
        <div
          class="w-96 rounded-lg border p-5 shadow-2xl"
          style={{ background: "var(--ds-panel)", "border-color": "var(--ds-border)" }}
          onClick={(e) => e.stopPropagation()}
        >
          <div class="text-base font-semibold" style={{ color: "var(--ds-text)" }}>
            关闭 DevSidecar
          </div>
          <div class="mt-2 text-sm leading-relaxed" style={{ color: "var(--ds-text-soft)" }}>
            关闭后是否保留在后台运行？选择「最小化到托盘」后，加速服务将继续在后台运行。
          </div>

          <label class="mt-3 flex cursor-pointer items-center gap-2 select-none">
            <input
              type="checkbox"
              class="h-3.5 w-3.5"
              style={{ "accent-color": "var(--ds-primary)" }}
              checked={remember()}
              onChange={(e) => setRemember(e.currentTarget.checked)}
            />
            <span class="text-xs" style={{ color: "var(--ds-text-soft)" }}>
              记住我的选择（可在 设置 → 界面 中修改）
            </span>
          </label>

          <div class="mt-4 flex items-center justify-between">
            <button
              type="button"
              class="rounded px-2 py-1 text-xs transition-opacity hover:opacity-70"
              style={{ color: "var(--ds-text-soft)" }}
              onClick={cancel}
            >
              取消
            </button>
            <div class="flex gap-2">
              <Button type="danger" loading={busy()} onClick={() => choose("exit")}>
                退出应用
              </Button>
              <Button type="primary" loading={busy()} onClick={() => choose("hide")}>
                最小化到托盘
              </Button>
            </div>
          </div>
        </div>
      </div>
    </Show>
  );
}
