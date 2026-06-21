const list = document.getElementById("file-list");
const title = document.getElementById("viewer-title");
const body = document.getElementById("viewer-body");
const dlg = document.getElementById("import-dialog");
const dlgForm = document.getElementById("import-form");
const dlgErr = document.getElementById("import-err");

async function refresh() {
  const r = await fetch("/api/files");
  if (r.status === 401) { location.href = "/unlock"; return; }
  const data = await r.json();
  list.innerHTML = "";
  for (const name of data.entries) {
    const li = document.createElement("li");
    const btn = document.createElement("button");
    btn.textContent = name;
    btn.addEventListener("click", () => openFile(name, btn));
    li.appendChild(btn);
    list.appendChild(li);
  }
}

async function openFile(name, btn) {
  document.querySelectorAll("#file-list button").forEach(b => b.classList.remove("active"));
  if (btn) btn.classList.add("active");
  const r = await fetch(`/api/files/${encodeURIComponent(name)}`);
  if (!r.ok) { title.textContent = `error: ${r.status}`; body.textContent = ""; return; }
  title.textContent = name;
  body.textContent = await r.text();
}

document.getElementById("import-btn").addEventListener("click", () => {
  dlgErr.hidden = true;
  dlgForm.reset();
  dlg.showModal();
});

dlgForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(dlgForm);
  const r = await fetch("/api/files", { method: "POST", body: fd });
  if (r.ok) {
    dlg.close();
    refresh();
  } else {
    let msg = `error ${r.status}`;
    try {
      const j = await r.json();
      if (j.error) msg = j.error;
    } catch (_) {}
    dlgErr.textContent = msg;
    dlgErr.hidden = false;
  }
});

refresh();
