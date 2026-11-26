export function deliveryConfigured(sync) {
  return Boolean(sync?.tree_configured);
}

export function agentServerUrl(plane) {
  return plane?.url || `https://<credarr-host>:${plane?.port || 8443}`;
}

export function listenerCopy(plane) {
  if (!plane) return { off: false, text: "" };
  if (!plane.enabled) {
    return {
      off: true,
      text:
        plane.failure ||
        "Agents cannot connect. Set CREDARR_AGENT_PORT (default 8443) and restart the server.",
    };
  }
  if (plane.url) {
    return { off: false, text: `Agents connect to ${plane.url}. TLS 1.3.` };
  }
  return {
    off: false,
    text: `Listening on port ${plane.port}. Set CREDARR_AGENT_HOSTNAME to the address agents use.`,
  };
}
