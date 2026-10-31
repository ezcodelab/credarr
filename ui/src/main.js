import { mount } from "svelte";
import App from "./App.svelte";
import DesignSystem from "./views/DesignSystem.svelte";
import "./app.css";

// The gallery is a development aid, not a product route. It uses the real
// tokens and components so an agent can see a pattern before adding it.
const showDesign =
  import.meta.env.DEV && new URLSearchParams(globalThis.location.search).has("design");

mount(showDesign ? DesignSystem : App, { target: document.getElementById("app") });
