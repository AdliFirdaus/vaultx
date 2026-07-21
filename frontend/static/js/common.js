/* VaultX - shared frontend helpers
   Auto-detects API base URL so the same code works on localhost and Railway. */

const API_BASE = window.location.origin;

async function apiRequest(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
    ...options,
  });

  let data = null;
  try {
    data = await res.json();
  } catch (e) {
    data = null;
  }

  if (!res.ok) {
    const message = (data && data.error) ? data.error : `Request failed (${res.status})`;
    const err = new Error(message);
    err.status = res.status;
    err.data = data;
    throw err;
  }
  return data;
}

function showBanner(el, message, type = "error") {
  if (!el) return;
  el.textContent = message;
  el.className = `banner banner-${type}`;
  el.style.display = "block";
}

function hideBanner(el) {
  if (!el) return;
  el.style.display = "none";
}

/* Wire up 6-box OTP inputs: auto-focus next box, backspace to previous, paste support */
function wireOtpBoxes(containerSelector) {
  const container = document.querySelector(containerSelector);
  if (!container) return;
  const boxes = Array.from(container.querySelectorAll("input"));

  boxes.forEach((box, idx) => {
    box.addEventListener("input", () => {
      box.value = box.value.replace(/[^0-9]/g, "").slice(0, 1);
      if (box.value && idx < boxes.length - 1) {
        boxes[idx + 1].focus();
      }
    });

    box.addEventListener("keydown", (e) => {
      if (e.key === "Backspace" && !box.value && idx > 0) {
        boxes[idx - 1].focus();
      }
    });

    box.addEventListener("paste", (e) => {
      e.preventDefault();
      const pasted = (e.clipboardData || window.clipboardData).getData("text").replace(/[^0-9]/g, "");
      pasted.split("").forEach((digit, i) => {
        if (boxes[i]) boxes[i].value = digit;
      });
      const nextEmpty = boxes.find((b) => !b.value);
      (nextEmpty || boxes[boxes.length - 1]).focus();
    });
  });

  if (boxes[0]) boxes[0].focus();
}

function getOtpValue(containerSelector) {
  const container = document.querySelector(containerSelector);
  if (!container) return "";
  return Array.from(container.querySelectorAll("input")).map((b) => b.value).join("");
}

function formatDateTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleString();
}

function formatBytes(bytes) {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${units[i]}`;
}
