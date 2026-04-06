import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import "./ToastProvider.css";

const ToastContext = createContext(null);
const MAX_TOASTS = 6;

function createToastId() {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  return `toast_${Date.now()}_${Math.random().toString(16).slice(2)}`;
}

function normalizeToast(input) {
  return {
    id: input.id || createToastId(),
    type: input.type || "info",
    title: input.title || "Notification",
    message: input.message || "",
    autoCloseMs:
      typeof input.autoCloseMs === "number" && input.autoCloseMs > 0
        ? input.autoCloseMs
        : null,
  };
}

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);
  const timersRef = useRef(new Map());

  const removeToast = useCallback((toastId) => {
    const existingTimer = timersRef.current.get(toastId);
    if (existingTimer) {
      window.clearTimeout(existingTimer);
      timersRef.current.delete(toastId);
    }

    setToasts((prev) => prev.filter((toast) => toast.id !== toastId));
  }, []);

  const showToast = useCallback(
    (input) => {
      const toast = normalizeToast(input || {});

      setToasts((prev) => [...prev, toast].slice(-MAX_TOASTS));

      if (toast.autoCloseMs) {
        const timer = window.setTimeout(() => {
          removeToast(toast.id);
        }, toast.autoCloseMs);
        timersRef.current.set(toast.id, timer);
      }

      return toast.id;
    },
    [removeToast],
  );

  useEffect(() => {
    return () => {
      timersRef.current.forEach((timerId) => window.clearTimeout(timerId));
      timersRef.current.clear();
    };
  }, []);

  const value = useMemo(
    () => ({
      toasts,
      showToast,
      removeToast,
    }),
    [toasts, showToast, removeToast],
  );

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="toast-layer" role="region" aria-label="Notifications" aria-live="polite">
        {toasts.map((toast) => (
          <div
            key={toast.id}
            className={`toast toast--${toast.type} ${toast.autoCloseMs ? "toast--timed" : "toast--sticky"}`}
            role="status"
          >
            <div className="toast__header">
              <strong className="toast__title">{toast.title}</strong>
              <button
                type="button"
                className="toast__close"
                aria-label={`Dismiss ${toast.title}`}
                onClick={() => removeToast(toast.id)}
              >
                <span className="icon icon-sm">close</span>
              </button>
            </div>
            {toast.message ? <p className="toast__message">{toast.message}</p> : null}
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  const context = useContext(ToastContext);

  if (!context) {
    throw new Error("useToast must be used within ToastProvider");
  }

  return context;
}
