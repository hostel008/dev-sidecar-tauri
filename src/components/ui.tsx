import type { JSX } from "solid-js";
import { For, Show, createEffect, createSignal, on, splitProps } from "solid-js";
import { toasts } from "../store";

export function Container(props: { children: JSX.Element; title?: string; desc?: string }) {
  return (
    <div class="flex flex-col gap-4">
      <Show when={props.title}>
        <div>
          <h2 class="text-base font-semibold" style={{ color: "var(--ds-text)" }}>
            {props.title}
          </h2>
          <Show when={props.desc}>
            <p class="mt-1 text-xs" style={{ color: "var(--ds-text-soft)" }}>
              {props.desc}
            </p>
          </Show>
        </div>
      </Show>
      {props.children}
    </div>
  );
}

export function Card(props: {
  children: JSX.Element;
  title?: string;
  desc?: string;
  extra?: JSX.Element;
  class?: string;
}) {
  return (
    <div
      class={`rounded-lg border p-4 ${props.class ?? ""}`}
      style={{ background: "var(--ds-panel)", "border-color": "var(--ds-border)" }}
    >
      <Show when={props.title || props.desc}>
        <div class="mb-3 flex items-start justify-between gap-4">
          <div>
            <Show when={props.title}>
              <div class="text-sm font-medium" style={{ color: "var(--ds-text)" }}>
                {props.title}
              </div>
            </Show>
            <Show when={props.desc}>
              <div class="mt-0.5 text-xs" style={{ color: "var(--ds-text-soft)" }}>
                {props.desc}
              </div>
            </Show>
          </div>
          {props.extra}
        </div>
      </Show>
      {props.children}
    </div>
  );
}

export function Switch(props: { checked: boolean; onChange: (v: boolean) => void; label?: string; disabled?: boolean }) {
  return (
    <label class="inline-flex cursor-pointer items-center gap-2 select-none">
      <span
        class="relative inline-block h-5 w-9 rounded-full transition-colors"
        style={{
          background: props.checked ? "var(--ds-primary)" : "var(--ds-border)",
          opacity: props.disabled ? 0.5 : 1,
        }}
        onClick={() => !props.disabled && props.onChange(!props.checked)}
      >
        <span
          class="absolute top-0.5 h-4 w-4 rounded-full bg-white transition-all"
          style={{ left: props.checked ? "18px" : "2px" }}
        />
      </span>
      <Show when={props.label}>
        <span class="text-sm" style={{ color: "var(--ds-text)" }}>
          {props.label}
        </span>
      </Show>
    </label>
  );
}

export function Button(
  props: {
    children: JSX.Element;
    onClick?: () => void;
    type?: "primary" | "default" | "danger" | "success";
    disabled?: boolean;
    size?: "sm" | "md";
    loading?: boolean;
  } & Omit<JSX.ButtonHTMLAttributes<HTMLButtonElement>, "type">,
) {
  const [local, rest] = splitProps(props, ["children", "onClick", "type", "disabled", "size", "loading"]);
  const colors: Record<string, string> = {
    primary: "var(--ds-primary)",
    default: "var(--ds-bg-soft)",
    danger: "var(--ds-danger)",
    success: "var(--ds-success)",
  };
  return (
    <button
      {...rest}
      disabled={local.disabled || local.loading}
      class={`rounded transition-opacity disabled:opacity-50 ${local.size === "sm" ? "px-2 py-1 text-xs" : "px-3 py-1.5 text-sm"}`}
      style={{
        background: colors[local.type ?? "default"],
        color: (local.type ?? "default") === "default" ? "var(--ds-text)" : "#fff",
        border: `1px solid var(--ds-border)`,
      }}
      onClick={() => local.onClick?.()}
    >
      {local.loading ? "处理中…" : local.children}
    </button>
  );
}

export function Input(props: {
  value: string | number;
  onInput?: (v: string) => void;
  placeholder?: string;
  type?: string;
  class?: string;
}) {
  return (
    <input
      type={props.type ?? "text"}
      value={String(props.value ?? "")}
      placeholder={props.placeholder}
      class={`rounded border px-2 py-1 text-sm outline-none ${props.class ?? ""}`}
      style={{ background: "var(--ds-bg-soft)", color: "var(--ds-text)", "border-color": "var(--ds-border)" }}
      onInput={(e) => props.onInput?.(e.currentTarget.value)}
    />
  );
}

/// 多行文本输入：去掉浏览器默认的右下角缩放角标，
/// 改为鼠标移到下边框（光标变为上下箭头）按住拖动调整高度
export function TextArea(props: {
  value: string;
  onInput?: (v: string) => void;
  onBlur?: (v: string) => void;
  placeholder?: string;
  class?: string;
  style?: JSX.CSSProperties;
  height?: string;
}) {
  let ref: HTMLTextAreaElement | undefined;
  const [hover, setHover] = createSignal(false);
  const [dragging, setDragging] = createSignal(false);
  // 拖动后的高度（px）；未拖动时用 props.height 作为初始高度
  const [dragHeight, setDragHeight] = createSignal(0);
  let startY = 0;
  let startH = 0;

  const style = () => ({
    ...props.style,
    height: dragHeight() ? `${dragHeight()}px` : (props.height ?? "120px"),
  });

  const startDrag = (e: PointerEvent) => {
    e.preventDefault();
    startY = e.clientY;
    startH = ref?.offsetHeight ?? 0;
    setDragging(true);
    // 捕获指针，拖出把手范围也能持续收到 move/up 事件；全程保持上下箭头光标
    document.body.style.cursor = "row-resize";
    (e.currentTarget as HTMLElement).setPointerCapture(e.pointerId);
  };

  const moveDrag = (e: PointerEvent) => {
    if (!dragging() || !e.buttons) return;
    const max = Math.max(240, window.innerHeight - 120);
    const next = Math.min(Math.max(startH + e.clientY - startY, 80), max);
    setDragHeight(Math.round(next));
  };

  const endDrag = (e: PointerEvent) => {
    if (!dragging()) return;
    setDragging(false);
    document.body.style.cursor = "";
    const el = e.currentTarget as HTMLElement;
    if (el.hasPointerCapture(e.pointerId)) el.releasePointerCapture(e.pointerId);
  };

  return (
    <div class="relative w-full">
      <textarea
        ref={ref}
        value={props.value}
        placeholder={props.placeholder}
        spellcheck={false}
        class={`w-full resize-none rounded border p-2 text-xs outline-none ${props.class ?? ""}`}
        style={style()}
        onInput={(e) => props.onInput?.(e.currentTarget.value)}
        onBlur={(e) => props.onBlur?.(e.currentTarget.value)}
      />
      {/* 底边拖拽把手：盖住下边框，悬停/拖动时高亮提示可拉高 */}
      <div
        class="absolute inset-x-0 bottom-0 h-1.5 cursor-row-resize"
        style={{
          background: hover() || dragging() ? "var(--ds-primary)" : "transparent",
          opacity: 0.6,
        }}
        onPointerEnter={() => setHover(true)}
        onPointerLeave={() => setHover(false)}
        onPointerDown={startDrag}
        onPointerMove={moveDrag}
        onPointerUp={endDrag}
        onPointerCancel={endDrag}
      />
    </div>
  );
}

export function Select(props: {
  value: string;
  options: { label: string; value: string }[];
  onChange: (v: string) => void;
  class?: string;
}) {
  return (
    <select
      value={props.value}
      class={`rounded border px-2 py-1 text-sm outline-none ${props.class ?? ""}`}
      style={{ background: "var(--ds-bg-soft)", color: "var(--ds-text)", "border-color": "var(--ds-border)" }}
      onChange={(e) => props.onChange(e.currentTarget.value)}
    >
      {props.options.map((o) => (
        <option value={o.value}>{o.label}</option>
      ))}
    </select>
  );
}

export function Field(props: { label: string; children: JSX.Element; desc?: string }) {
  return (
    <div class="flex items-start justify-between gap-4 py-2">
      <div class="min-w-0">
        <div class="text-sm" style={{ color: "var(--ds-text)" }}>
          {props.label}
        </div>
        <Show when={props.desc}>
          <div class="mt-0.5 text-xs break-all" style={{ color: "var(--ds-text-soft)" }}>
            {props.desc}
          </div>
        </Show>
      </div>
      <div class="shrink-0">{props.children}</div>
    </div>
  );
}

export function Tag(props: { children: JSX.Element; type?: "success" | "warn" | "danger" | "info" | "default" }) {
  const colors: Record<string, string> = {
    success: "var(--ds-success)",
    warn: "var(--ds-warn)",
    danger: "var(--ds-danger)",
    info: "var(--ds-primary)",
    default: "var(--ds-text-soft)",
  };
  return (
    <span
      class="inline-flex items-center gap-1 rounded px-2 py-0.5 text-xs"
      style={{ color: colors[props.type ?? "default"], border: `1px solid ${colors[props.type ?? "default"]}` }}
    >
      {props.children}
    </span>
  );
}

export function StatusDot(props: { status?: string }) {
  // 注意：颜色必须在 JSX 内通过函数读取，写在组件体常量里会丢失响应性（状态变化后点不更新）
  const color = () =>
    props.status === "success" || props.status === "enabled"
      ? "var(--ds-success)"
      : props.status === "fail" || props.status === "error"
        ? "var(--ds-danger)"
        : props.status === "starting"
          ? "var(--ds-warn)"
          : "var(--ds-text-soft)";
  return (
    <span
      class="inline-block h-2 w-2 rounded-full"
      style={{ background: color(), "box-shadow": `0 0 6px ${color()}` }}
    />
  );
}

export function JsonEditor(props: { value: Json; onChange?: (v: Json) => void; height?: string }) {
  const [text, setText] = createSignal(JSON.stringify(props.value ?? {}, null, 2));
  const [error, setError] = createSignal("");
  // 上次播种 / 提交的值，用于判断外部 value 变化是否需要重新同步编辑器
  let committed: Json = props.value ?? {};

  // 外部值变化（保存后草稿重置、恢复出厂、远程配置更新）时重新播种；
  // 内容未变时（如其他字段触发的草稿刷新）不打断正在编辑的内容
  createEffect(
    on(
      () => props.value,
      (v) => {
        const next = v ?? {};
        if (JSON.stringify(next) !== JSON.stringify(committed)) {
          committed = next;
          setText(JSON.stringify(next, null, 2));
          setError("");
        }
      },
    ),
  );

  // 输入时只做解析校验，失焦后才提交，避免每次按键都触发全量保存
  const validate = (raw: string) => {
    setText(raw);
    try {
      JSON.parse(raw);
      setError("");
    } catch (e: any) {
      setError(e?.message ?? "JSON 解析失败");
    }
  };

  const commit = () => {
    try {
      const parsed = JSON.parse(text());
      setError("");
      committed = parsed;
      props.onChange?.(parsed);
    } catch {
      // 保留错误提示，不提交
    }
  };

  return (
    <div class="flex flex-col gap-1">
      <TextArea
        class="font-mono"
        height={props.height ?? "320px"}
        style={{
          background: "var(--ds-bg-soft)",
          color: "var(--ds-text)",
          "border-color": error() ? "var(--ds-danger)" : "var(--ds-border)",
        }}
        value={text()}
        onInput={(v) => validate(v)}
        onBlur={() => commit()}
      />
      <Show when={error()}>
        <div class="text-xs" style={{ color: "var(--ds-danger)" }}>
          {error()}
        </div>
      </Show>
    </div>
  );
}

type Json = Record<string, unknown>;

/// 底部悬浮保存条：页面配置被修改后出现，保存前不落盘
export function SaveBar(props: {
  dirty: boolean;
  /** true/"apply" → 「保存并应用」加载中；"save" → 「保存」加载中；truthy 时禁用全部按钮 */
  saving: string | boolean;
  /** 保存：仅写入配置，不立即应用运行态；提供 onApply 时显示为独立的「保存」按钮 */
  onSave: () => void;
  /** 保存并应用：写入配置并立即生效；未提供时不显示单独的「保存」按钮 */
  onApply?: () => void;
  onReset: () => void;
  text?: string;
}) {
  const busy = () => !!props.saving;
  return (
    <Show when={props.dirty}>
      <div
        class="fixed bottom-6 left-1/2 z-40 flex -translate-x-1/2 items-center gap-3 rounded-lg border px-4 py-3 shadow-2xl"
        style={{ background: "var(--ds-panel)", "border-color": "var(--ds-primary)" }}
      >
        <span class="text-sm whitespace-nowrap" style={{ color: "var(--ds-text)" }}>
          {props.text ?? "配置已修改，尚未保存"}
        </span>
        <Button onClick={props.onReset} disabled={busy()}>
          放弃修改
        </Button>
        <Show
          when={props.onApply}
          fallback={
            <Button type="primary" loading={busy()} onClick={props.onSave}>
              保存并应用
            </Button>
          }
        >
          <Button loading={props.saving === "save"} onClick={props.onSave} disabled={busy()}>
            保存
          </Button>
          <Button
            type="primary"
            loading={props.saving === true || props.saving === "apply"}
            onClick={props.onApply}
          >
            保存并应用
          </Button>
        </Show>
      </div>
    </Show>
  );
}

export function Toasts() {
  return (
    <div class="pointer-events-none fixed right-4 bottom-4 z-50 flex flex-col gap-2">
      <For each={toasts()}>
        {(t) => (
          <div
            class="rounded border px-3 py-2 text-sm shadow-lg"
            style={{
              background: "var(--ds-panel)",
              "border-color":
                t.type === "error"
                  ? "var(--ds-danger)"
                  : t.type === "success"
                    ? "var(--ds-success)"
                    : t.type === "warn"
                      ? "var(--ds-warn)"
                      : "var(--ds-border)",
              color: "var(--ds-text)",
            }}
          >
            {t.msg}
          </div>
        )}
      </For>
    </div>
  );
}
