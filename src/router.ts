import { createSignal } from "solid-js";

export interface MenuItem {
  key: string;
  title: string;
  icon: string;
  group: string;
}

export const MENUS: MenuItem[] = [
  { key: "index", title: "首页概览", icon: "🏠", group: "主菜单" },
  { key: "server", title: "加速服务", icon: "🚀", group: "主菜单" },
  { key: "proxy", title: "系统代理", icon: "🌐", group: "主菜单" },
  { key: "plugin/node", title: "NPM 加速", icon: "📦", group: "插件" },
  { key: "plugin/git", title: "Git 代理", icon: "🔧", group: "插件" },
  { key: "plugin/pip", title: "PIP 加速", icon: "🐍", group: "插件" },
  { key: "traffic", title: "流量统计", icon: "📊", group: "工具" },
  { key: "github", title: "GitHub 状态", icon: "🐙", group: "工具" },
  { key: "check", title: "网络检测", icon: "🔍", group: "工具" },
  { key: "ca", title: "安装证书", icon: "🔐", group: "工具" },
  { key: "setting", title: "应用设置", icon: "⚙️", group: "其他" },
  { key: "help", title: "帮助", icon: "❓", group: "其他" },
];

export const [route, setRoute] = createSignal<string>("index");

export function navigate(key: string) {
  if (window.location.hash !== `#/${key}`) {
    window.location.hash = `#/${key}`;
  }
  setRoute(key);
}

export function parseHash(): string {
  const h = window.location.hash.replace(/^#\/?/, "");
  return h || "index";
}
