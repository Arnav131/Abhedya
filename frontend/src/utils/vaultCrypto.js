/**
 * vaultCrypto.js — Zero-Knowledge Cryptography + API Client
 *
 * All encryption/decryption happens HERE in the browser.
 * Django never sees plaintext — only opaque ciphertext blobs.
 *
 * Crypto pipeline:
 *   Master Password → PBKDF2 (100k iterations) → AES-GCM-256 key
 *   Plaintext JSON → AES-GCM encrypt → { ciphertext, iv, salt }
 */

import { API_BASE } from "./config";

const enc = new TextEncoder();
const dec = new TextDecoder();

// ════════════════════════════════════════════
// Encoding helpers
// ════════════════════════════════════════════

function buf2Base64(buffer) {
  let binary = "";
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToBuf(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// ════════════════════════════════════════════
// Web Crypto — Key Derivation
// ════════════════════════════════════════════

/**
 * Derive an AES-GCM 256-bit key from a master password + salt
 * using PBKDF2 with 100,000 iterations (as per SRS §4 Phase 1).
 */
async function deriveKey(password, salt) {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"],
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: 100000,
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"],
  );
}

// ════════════════════════════════════════════
// Encrypt / Decrypt
// ════════════════════════════════════════════

/**
 * Encrypt a plaintext object using the master password.
 * Returns { ciphertext, iv, salt } as Base64 strings.
 */
export async function encryptPayload(plaintextObj, masterPassword) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(masterPassword, salt);

  const ciphertextBuf = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    enc.encode(JSON.stringify(plaintextObj)),
  );

  return {
    ciphertext: buf2Base64(ciphertextBuf),
    iv: buf2Base64(iv),
    salt: buf2Base64(salt),
  };
}

/**
 * Decrypt a ciphertext blob back to a JS object using the master password.
 * All three params (ciphertext, iv, salt) must be Base64 strings.
 */
export async function decryptPayload(
  ciphertextB64,
  ivB64,
  saltB64,
  masterPassword,
) {
  const salt = base64ToBuf(saltB64);
  const iv = base64ToBuf(ivB64);
  const ciphertext = base64ToBuf(ciphertextB64);

  const key = await deriveKey(masterPassword, salt);

  const decryptedBuf = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    ciphertext,
  );

  return JSON.parse(dec.decode(decryptedBuf));
}

// ════════════════════════════════════════════
// Auth API
// ════════════════════════════════════════════

/**
 * Register a new user account.
 */
export async function registerUser(username, email, password) {
  const res = await fetch(`${API_BASE}/auth/register/`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, email, password }),
  });
  return parseResponse(res, "Registration failed");
}

/**
 * Login and get JWT tokens.
 * Returns { access, refresh }.
 */
export async function loginUser(username, password) {
  const res = await fetch(`${API_BASE}/auth/token/`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  return parseResponse(res, "Login failed");
}

// ════════════════════════════════════════════
// Vault API
// ════════════════════════════════════════════

function authHeaders() {
  const token = sessionStorage.getItem("sv_access_token");

  if (!token || token === "null" || token === "undefined") {
    throw new Error("Missing authentication token. Please sign in again.");
  }

  return {
    "Content-Type": "application/json",
    Authorization: `Bearer ${token}`,
  };
}

async function parseResponse(res, fallbackMessage = "Request failed") {
  const raw = await res.text();
  let data = null;

  if (raw) {
    try {
      data = JSON.parse(raw);
    } catch {
      data = raw;
    }
  }

  if (!res.ok) {
    if (typeof data === "string" && data.trim()) {
      throw new Error(data);
    }

    if (data && typeof data === "object") {
      if (typeof data.detail === "string" && data.detail.trim()) {
        throw new Error(data.detail);
      }

      const firstKey = Object.keys(data)[0];
      if (firstKey) {
        const firstValue = data[firstKey];
        if (Array.isArray(firstValue) && firstValue.length > 0) {
          throw new Error(String(firstValue[0]));
        }
        if (typeof firstValue === "string" && firstValue.trim()) {
          throw new Error(firstValue);
        }
      }
    }

    throw new Error(fallbackMessage);
  }

  return data;
}

/**
 * Store a new encrypted vault entry.
 */
export async function storeVaultEntry(label, ciphertext, iv, salt) {
  const res = await fetch(`${API_BASE}/vault/store/`, {
    method: "POST",
    headers: authHeaders(),
    body: JSON.stringify({ label, ciphertext, iv, salt }),
  });
  return parseResponse(res, "Failed to store vault entry");
}

/**
 * Fetch all vault entries for the authenticated user.
 * Returns paginated results — we extract the `results` array.
 */
export async function fetchVaultEntries() {
  const res = await fetch(`${API_BASE}/vault/`, {
    headers: authHeaders(),
  });

  const data = await parseResponse(res, "Failed to fetch vault entries");

  if (Array.isArray(data)) {
    return data;
  }

  if (Array.isArray(data?.results)) {
    return data.results;
  }

  return [];
}

/**
 * Fetch honeypot status summary and alert details for the current user.
 */
export async function fetchHoneypotStatus() {
  const res = await fetch(`${API_BASE}/honeypot/status/`, {
    headers: authHeaders(),
  });

  return parseResponse(res, "Failed to fetch honeypot status");
}

/**
 * Fetch a single vault entry by UUID.
 */
export async function fetchVaultEntry(id) {
  const res = await fetch(`${API_BASE}/vault/${id}/`, {
    headers: authHeaders(),
  });

  return parseResponse(res, "Failed to fetch vault entry");
}

/**
 * Update an existing vault entry by UUID.
 */
export async function updateVaultEntry(id, payload) {
  const res = await fetch(`${API_BASE}/vault/${id}/update/`, {
    method: "PUT",
    headers: authHeaders(),
    body: JSON.stringify(payload),
  });

  return parseResponse(res, "Failed to update vault entry");
}

/**
 * Delete a vault entry by UUID.
 */
export async function deleteVaultEntry(id) {
  const res = await fetch(`${API_BASE}/vault/${id}/delete/`, {
    method: "DELETE",
    headers: authHeaders(),
  });

  if (res.status === 204) {
    return true;
  }

  await parseResponse(res, "Failed to delete entry");
  return true;
}
