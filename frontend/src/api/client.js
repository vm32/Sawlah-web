import axios from "axios";

const API_BASE = "/api";

const api = axios.create({ baseURL: API_BASE });

export const projectsApi = {
  list: () => api.get("/projects"),
  create: (data) => api.post("/projects", data),
  get: (id) => api.get(`/projects/${id}`),
  delete: (id) => api.delete(`/projects/${id}`),
};

export const toolsApi = {
  run: (toolName, params, projectId = null) =>
    api.post("/tools/run", { tool_name: toolName, params, project_id: projectId }),
  runRaw: (command, toolName = "manual") =>
    api.post("/tools/run-raw", { command, tool_name: toolName }),
  autoExploit: (data) => api.post("/tools/auto-exploit", data),
  status: (taskId) => api.get(`/tools/status/${taskId}`),
  kill: (taskId) => api.delete(`/tools/kill/${taskId}`),
  list: () => api.get("/tools/list"),
  history: (toolName = "") => api.get("/tools/history", { params: { tool_name: toolName } }),
  scans: (projectId) => api.get(`/tools/scans/${projectId}`),
};

export const automationApi = {
  run: (data) => api.post("/automation/run", data),
  quick: (data) => api.post("/automation/quick", data),
  status: (pipelineId) => api.get(`/automation/status/${pipelineId}`),
  list: () => api.get("/automation/list"),
};

export const reportsApi = {
  generate: (projectId, options = {}) =>
    api.post(`/reports/${projectId}`, options),
  download: (projectId) => `/api/reports/${projectId}/download`,
};

export const webreconApi = {
  run: (params) => api.post("/webrecon/run", params),
  status: (sessionId) => api.get(`/webrecon/status/${sessionId}`),
  sessions: () => api.get("/webrecon/sessions"),
  kill: (sessionId) => api.delete(`/webrecon/kill/${sessionId}`),
};

export const niktoApi = {
  run: (params) => api.post("/nikto/run", params),
  reports: () => api.get("/nikto/reports"),
  getReport: (filename) => `/api/nikto/reports/${filename}`,
  downloadReport: (filename) => `/api/nikto/reports/${filename}/download`,
};

export const wafw00fApi = {
  run: (params) => api.post("/wafw00f/run", params),
  reports: () => api.get("/wafw00f/reports"),
  getReport: (filename) => `/api/wafw00f/reports/${filename}`,
  downloadReport: (filename) => `/api/wafw00f/reports/${filename}/download`,
};

export default api;
