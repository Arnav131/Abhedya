const DEFAULT_API_BASE_URL = "http://localhost:8000/api";

function trimTrailingSlash(value) {
  return value.replace(/\/+$/, "");
}

export const API_BASE = trimTrailingSlash(
  import.meta.env.VITE_API_BASE_URL || DEFAULT_API_BASE_URL,
);
