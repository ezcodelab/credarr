// One dull toast store for the whole console. Success confirmations are
// always the word "Saved."; anything with content stays an inline banner
// where the failure happened. Toasts clear on navigation (the shell calls
// clearToasts on every route change) so a save on one entity never greets the
// next one.
import { writable } from "svelte/store";

let nextId = 0;

export const toasts = writable([]);

export function toast(message = "Saved.") {
  const id = ++nextId;
  toasts.update((list) => [...list, { id, message }]);
  setTimeout(() => {
    toasts.update((list) => list.filter((item) => item.id !== id));
  }, 4000);
}

export function clearToasts() {
  toasts.set([]);
}
