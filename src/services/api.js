const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000/api/v1";

function getHeaders() {
  const token = localStorage.getItem("access_token");
  const headers = {
    "Content-Type": "application/json",
    "ngrok-skip-browser-warning": "69420",
  };
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}

async function request(path, options = {}) {
  const url = `${API_BASE}${path}`;
  const res = await fetch(url, {
    ...options,
    headers: { ...getHeaders(), ...options.headers },
  });

  if (res.status === 401) {
    localStorage.removeItem("access_token");
    localStorage.removeItem("refresh_token");
    window.location.href = "/login";
    throw new Error("Unauthorized");
  }

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || "Request failed");
  }

  if (res.status === 204) return null;
  return res.json();
}

export const api = {
  auth: {
    login: (email, password) =>
      request("/auth/login", {
        method: "POST",
        body: JSON.stringify({ email, password }),
      }),
    register: (data) =>
      request("/auth/register", {
        method: "POST",
        body: JSON.stringify(data),
      }),
    me: () => request("/auth/me"),
  },

  dashboard: {
    stats: () => request("/dashboard/stats"),
    liveEvents: (limit = 50) => request(`/dashboard/live-events?limit=${limit}`),
  },

  sessions: {
    list: (params = {}) => {
      const qs = new URLSearchParams();
      Object.entries(params).forEach(([k, v]) => {
        if (v !== undefined && v !== null && v !== "") qs.append(k, v);
      });
      return request(`/sessions/?${qs.toString()}`);
    },
    get: (id) => request(`/sessions/${id}`),
    getByUuid: (uuid) => request(`/sessions/uuid/${uuid}`),
  },

  alerts: {
    list: (params = {}) => {
      const qs = new URLSearchParams();
      Object.entries(params).forEach(([k, v]) => {
        if (v !== undefined && v !== null && v !== "") qs.append(k, v);
      });
      return request(`/alerts/?${qs.toString()}`);
    },
    get: (id) => request(`/alerts/${id}`),
    update: (id, data) =>
      request(`/alerts/${id}`, {
        method: "PATCH",
        body: JSON.stringify(data),
      }),
    stats: () => request("/alerts/stats"),
  },

  nodes: {
    list: (activeOnly = false) => request(`/nodes/?active_only=${activeOnly}`),
    get: (id) => request(`/nodes/${id}`),
    create: (data) =>
      request("/nodes/", {
        method: "POST",
        body: JSON.stringify(data),
      }),
    update: (id, data) =>
      request(`/nodes/${id}`, {
        method: "PATCH",
        body: JSON.stringify(data),
      }),
    delete: (id) =>
      request(`/nodes/${id}`, { method: "DELETE" }),
  },

  settings: {
    thresholds: () => request("/settings/thresholds"),
    createThreshold: (data) =>
      request("/settings/thresholds", {
        method: "POST",
        body: JSON.stringify(data),
      }),
    updateThreshold: (id, data) =>
      request(`/settings/thresholds/${id}`, {
        method: "PATCH",
        body: JSON.stringify(data),
      }),
    deleteThreshold: (id) =>
      request(`/settings/thresholds/${id}`, { method: "DELETE" }),
    systemConfig: () => request("/settings/system"),
    updateSystemConfig: (data) =>
      request("/settings/system", {
        method: "PATCH",
        body: JSON.stringify(data),
      }),
  },

  export: {
    sessions: (params = {}) => {
      const qs = new URLSearchParams();
      Object.entries(params).forEach(([k, v]) => {
        if (Array.isArray(v)) v.forEach((item) => qs.append(k, item));
        else if (v !== undefined && v !== null && v !== "") qs.append(k, v);
      });
      return request(`/export/?${qs.toString()}`);
    },
  },
};
