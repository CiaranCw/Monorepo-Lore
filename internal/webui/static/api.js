const TOKEN_KEY = "lore_mono_console_token";

export function getToken() {
  try {
    return sessionStorage.getItem(TOKEN_KEY) || "";
  } catch (_e) {
    return "";
  }
}

export function setToken(token) {
  try {
    if (token) {
      sessionStorage.setItem(TOKEN_KEY, token);
    } else {
      sessionStorage.removeItem(TOKEN_KEY);
    }
  } catch (_e) {
    // sessionStorage unavailable
  }
}

export class APIError extends Error {
  constructor(status, message) {
    super(message || `HTTP ${status}`);
    this.status = status;
  }
}

let onUnauthorized = null;
export function setUnauthorizedHandler(fn) {
  onUnauthorized = fn;
}

export async function request(method, path, body) {
  const headers = { Accept: "application/json" };
  const token = getToken();
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  const init = { method, headers };
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(body);
  }
  const res = await fetch(path, init);
  let data = null;
  const text = await res.text();
  if (text) {
    try {
      data = JSON.parse(text);
    } catch (_e) {
      data = { error: text };
    }
  }
  if (!res.ok) {
    const errMsg = (data && data.error) ? data.error : `请求失败 (${res.status})`;
    if (res.status === 401 && path !== "/api/v1/auth/login") {
      setToken("");
      if (onUnauthorized) onUnauthorized(errMsg);
    }
    throw new APIError(res.status, errMsg);
  }
  return data;
}

export const api = {
  clientInfo: () => request("GET", "/api/v1/client/info"),
  version: () => request("GET", "/version"),
  login: (username, password) => request("POST", "/api/v1/auth/login", { username, password }),
  me: () => request("GET", "/api/v1/auth/me"),
  changeOwnPassword: (password) => request("POST", "/api/v1/auth/password", { password }),

  projects: () => request("GET", "/api/v1/projects"),
  overview: (project) => request("GET", `/api/v1/projects/${encodeURIComponent(project)}/overview`),
  patchModule: (moduleId, payload) => request("PATCH", `/api/v1/modules/${moduleId}`, payload),
  bulkModuleMetadata: (project, items) =>
    request("POST", `/api/v1/projects/${encodeURIComponent(project)}/modules/metadata`, { items }),

  moduleRefs: (moduleId) => request("GET", `/api/v1/modules/${moduleId}/refs`),
  moduleHistory: (moduleId, cursor = "", limit = 30) => {
    const qs = new URLSearchParams({ limit: String(limit) });
    if (cursor) qs.set("cursor", cursor);
    return request("GET", `/api/v1/modules/${moduleId}/history?${qs.toString()}`);
  },

  members: (project) => request("GET", `/api/v1/projects/${encodeURIComponent(project)}/members`),
  createProjectUser: (project, payload) =>
    request("POST", `/api/v1/projects/${encodeURIComponent(project)}/users`, payload),
  addExistingMember: (project, username, role) =>
    request("POST", `/api/v1/projects/${encodeURIComponent(project)}/members`, { username, role }),
  updateMemberRole: (project, userId, role) =>
    request("PATCH", `/api/v1/projects/${encodeURIComponent(project)}/members/${userId}`, { role }),
  removeMember: (project, userId) =>
    request("DELETE", `/api/v1/projects/${encodeURIComponent(project)}/members/${userId}`),

  setUserStatus: (username, projectId, status) =>
    request("POST", `/api/v1/users/${encodeURIComponent(username)}/status`, { project_id: projectId, status }),
  resetUserPassword: (username, projectId, password) =>
    request("POST", `/api/v1/users/${encodeURIComponent(username)}/password`, { project_id: projectId, password }),

  permissions: (project) => request("GET", `/api/v1/projects/${encodeURIComponent(project)}/permissions`),
  batchPermissions: (project, changes) =>
    request("POST", `/api/v1/projects/${encodeURIComponent(project)}/permissions/batch`, { changes }),

  snapshots: (project) => request("GET", `/api/v1/projects/${encodeURIComponent(project)}/snapshots`),
  imports: (project) => request("GET", `/api/v1/projects/${encodeURIComponent(project)}/imports`),
  audit: (project, limit = 150) =>
    request("GET", `/api/v1/projects/${encodeURIComponent(project)}/audit?limit=${limit}`),
};
