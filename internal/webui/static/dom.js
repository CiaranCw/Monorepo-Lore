export function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v === undefined || v === null) continue;
    if (k === "className") {
      node.className = v;
    } else if (k === "text") {
      node.textContent = String(v);
    } else if (k === "hidden") {
      node.hidden = Boolean(v);
    } else if (k === "disabled") {
      node.disabled = Boolean(v);
    } else if (k === "checked") {
      node.checked = Boolean(v);
    } else if (k === "value") {
      node.value = String(v);
    } else if (k.startsWith("on") && typeof v === "function") {
      node.addEventListener(k.slice(2).toLowerCase(), v);
    } else {
      node.setAttribute(k, String(v));
    }
  }
  for (const child of children.flat()) {
    if (child === undefined || child === null || child === false) continue;
    if (typeof child === "string" || typeof child === "number") {
      node.appendChild(document.createTextNode(String(child)));
    } else {
      node.appendChild(child);
    }
  }
  return node;
}

export function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

export function shortID(s, len = 12) {
  if (!s) return "—";
  return s.length > len ? s.slice(0, len) : s;
}

export function fmtTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

export function toast(msg, isError = false) {
  const root = document.getElementById("toast-root");
  if (!root) return;
  const item = el("div", { className: isError ? "toast toast-error" : "toast", text: msg });
  root.appendChild(item);
  setTimeout(() => {
    if (item.parentNode) item.parentNode.removeChild(item);
  }, 3600);
}

export async function copyText(text, label = "内容") {
  try {
    await navigator.clipboard.writeText(text);
    toast(`已复制${label}`);
  } catch (_e) {
    const ta = document.createElement("textarea");
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    document.body.removeChild(ta);
    toast(`已复制${label}`);
  }
}
