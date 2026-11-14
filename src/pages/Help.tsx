import { For, Show } from "solid-js";
import { Card, Container, Tag } from "../components/ui";
import { config } from "../store";
import { openExternal } from "../api";

export default function HelpPage() {
  const list = () => (config().help?.dataList ?? []) as { title: string; url?: string }[];

  return (
    <Container title="帮助" desc="使用说明与常用链接">
      <Card title="帮助列表">
        <div class="flex flex-col gap-1">
          <For each={list()}>
            {(item) => (
              <div class="flex items-center justify-between gap-4 py-1">
                <span class="text-sm" style={{ color: "var(--ds-text)" }}>
                  {item.title}
                </span>
                <Show when={item.url}>
                  <button
                    class="rounded px-2 py-1 text-xs"
                    style={{ background: "var(--ds-bg)", color: "var(--ds-primary)", border: "1px solid var(--ds-border)" }}
                    onClick={() => openExternal(item.url!)}
                  >
                    打开
                  </button>
                </Show>
              </div>
            )}
          </For>
        </div>
      </Card>

      <Card title="常用操作">
        <div class="flex flex-col gap-2 text-sm" style={{ color: "var(--ds-text)" }}>
          <div>1. 开启「加速服务」后，会自动生成根证书文件。</div>
          <div>2. 在「安装证书」页面将根证书加入系统信任区，避免浏览器提示不安全。</div>
          <div>3. 在「系统代理」页面开启系统代理，即可接管系统网络请求。</div>
          <div>4. 若只需要为某工具加速，可使用对应的 NPM / Git / PIP 插件。</div>
          <div class="mt-2" style={{ color: "var(--ds-text-soft)" }}>
            <Tag type="info">提示</Tag> 修改配置后需重启加速服务才能生效。
          </div>
        </div>
      </Card>
    </Container>
  );
}
