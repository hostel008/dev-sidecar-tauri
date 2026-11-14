/* @refresh reload */
import { render } from "solid-js/web";
import App from "./App";
import "./styles.css";
import { initStore } from "./store";

const root = document.getElementById("root")!;

initStore();

render(() => <App />, root);
