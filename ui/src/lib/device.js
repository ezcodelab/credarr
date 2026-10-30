// A session row names the browser and operating system. The raw user agent is
// a developer string that changes with every patch release and says nothing an
// operator can use to tell two sessions apart.
export function deviceLabel(device) {
  const ua = String(device ?? "").trim();
  if (!ua) return "Unknown browser";
  // A label the server already wrote: keep it rather than parsing a string
  // that is not a user agent. Anything with a version slash that is not a
  // browser (curl, python-requests) is not meaningful to the operator.
  if (!/Mozilla\/|Chrome\/|Firefox\/|Safari\/|Edg\//.test(ua)) {
    return /\s/.test(ua) && !ua.includes("/") ? ua.slice(0, 60) : "Unknown browser";
  }

  const version = (pattern) => {
    const match = pattern.exec(ua);
    return match ? match[1] : "";
  };
  const browserName = (pattern, name) => {
    const number = version(pattern);
    return number ? `${name} ${number}` : "";
  };
  const browser =
    browserName(/Edg\/(\d+)/, "Edge") ||
    browserName(/OPR\/(\d+)/, "Opera") ||
    browserName(/CriOS\/(\d+)/, "Chrome") ||
    browserName(/Chrome\/(\d+)/, "Chrome") ||
    browserName(/FxiOS\/(\d+)/, "Firefox") ||
    browserName(/Firefox\/(\d+)/, "Firefox") ||
    browserName(/Version\/(\d+).*Safari/, "Safari") ||
    "Browser";

  const os = /Windows NT/.test(ua)
    ? "Windows"
    : /Android/.test(ua)
      ? "Android"
      : /(iPhone|iPad|iPod)/.test(ua)
        ? "iOS"
        : /Mac OS X/.test(ua)
          ? "macOS"
          : /Linux/.test(ua)
            ? "Linux"
            : "";

  return os ? `${browser} on ${os}` : browser;
}
