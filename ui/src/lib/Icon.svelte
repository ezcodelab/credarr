<script>
  // Inline line icons keep the bundle free of an icon dependency and render the
  // same in every browser. Decorative: the label beside an icon carries meaning.
  let { name, size = 18, stroke = 1.7 } = $props();

  const PATHS = {
    overview: [
      "M3 3h7v7H3z",
      "M14 3h7v7h-7z",
      "M14 14h7v7h-7z",
      "M3 14h7v7H3z",
    ],
    apps: [
      "M12 2l9 5-9 5-9-5 9-5z",
      "M3 12l9 5 9-5",
      "M3 17l9 5 9-5",
    ],
    activity: [
      "M22 12h-4l-3 9L9 3l-3 9H2",
    ],
    key: [
      "M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4",
    ],
    services: [
      "M3 4h18v6H3z",
      "M3 14h18v6H3z",
      "M7 7h.01",
      "M7 17h.01",
    ],
    events: [
      "M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9",
      "M13.7 21a2 2 0 0 1-3.4 0",
    ],
    settings: [
      "M4 21v-7",
      "M4 10V3",
      "M12 21v-9",
      "M12 8V3",
      "M20 21v-5",
      "M20 12V3",
      "M1 14h6",
      "M9 8h6",
      "M17 16h6",
    ],
    menu: ["M3 6h18", "M3 12h18", "M3 18h18"],
    close: ["M18 6 6 18", "M6 6l12 12"],
    search: ["M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16", "m21 21-4.35-4.35"],
    shield: [
      "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z",
      "M12 8v4",
      "M12 16h.01",
    ],
    alert: [
      "M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z",
      "M12 9v4",
      "M12 17h.01",
    ],
    info: [
      "M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20",
      "M12 16v-4",
      "M12 8h.01",
    ],
    check: ["M20 6 9 17l-5-5"],
    import: [
      "M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4",
      "M17 8l-5-5-5 5",
      "M12 3v12",
    ],
  };

  const paths = $derived(PATHS[name] ?? PATHS.info);
</script>

<svg
  width={size}
  height={size}
  viewBox="0 0 24 24"
  fill="none"
  stroke="currentColor"
  stroke-width={stroke}
  stroke-linecap="round"
  stroke-linejoin="round"
  aria-hidden="true"
  focusable="false"
>
  {#each paths as d (d)}
    <path {d} />
  {/each}
</svg>
