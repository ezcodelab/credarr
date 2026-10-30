// The count of requests in flight, for the console's thin progress line.
//
// A store rather than a rune module: `api.js` is plain JavaScript loaded by the
// Node tests too, so it cannot import a `.svelte.js` file.
import { writable } from "svelte/store";

let pending = 0;
export const activity = writable(0);

export function beginActivity() {
  pending += 1;
  activity.set(pending);
}

export function endActivity() {
  pending = Math.max(0, pending - 1);
  activity.set(pending);
}
