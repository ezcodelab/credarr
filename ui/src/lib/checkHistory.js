// Last successful check history per app, kept for the session.
//
// The pane is the one part of an app page that arrives after the rest, so a
// revisit paints the rows it already knows while the fresh read lands. Every
// mount still reads; this is a head start, not a cache of record.
const history = new Map();

export function readHistory(name) {
  return history.get(name) ?? null;
}

export function writeHistory(name, checks) {
  // Store a plain copy: the caller's array is a reactive proxy, and a cache
  // outlives the component that made it.
  history.set(name, Array.isArray(checks) ? [...checks] : []);
}
