(() => {
  "use strict";
  const COLUMNS = ["alert_id", "label", "analyst", "seconds_spent", "comment", "labeled_at", "attack_technique"];
  const TECHNIQUE = /^T\d{4}(\.\d{3})?$/;
  const data = JSON.parse(document.getElementById("limen-data").textContent);
  const rows = data.rows;
  const known = new Set(rows.map((r) => r.alert_id));
  const storeKey = "limen-labels-" + data.plan_id;
  const $ = (id) => document.getElementById(id);

  let labels = {};
  try {
    labels = JSON.parse(window.localStorage.getItem(storeKey) || "{}") || {};
  } catch (e) {
    labels = {};
  }
  let index = 0;
  let shownAt = performance.now();

  function save() {
    try {
      window.localStorage.setItem(storeKey, JSON.stringify(labels));
    } catch (e) {
      /* хранилище браузера недоступно: метки остаются в памяти страницы до выгрузки в CSV */
    }
  }

  function nextUnlabeled(start) {
    for (let i = 0; i < rows.length; i += 1) {
      const j = (start + i) % rows.length;
      if (!labels[rows[j].alert_id]) return j;
    }
    return -1;
  }

  function render() {
    const done = Object.keys(labels).filter((id) => known.has(id)).length;
    $("progress").max = rows.length;
    $("progress").value = done;
    $("progress-text").textContent = "Размечено " + done + " из " + rows.length;
    index = nextUnlabeled(index);
    if (index < 0) {
      $("card").hidden = true;
      $("done").hidden = false;
      return;
    }
    $("card").hidden = false;
    $("done").hidden = true;
    const row = rows[index];
    $("alert-id").textContent = row.alert_id;
    const body = $("context");
    body.replaceChildren();
    for (const [name, value] of Object.entries(row.context)) {
      const tr = document.createElement("tr");
      const th = document.createElement("th");
      const td = document.createElement("td");
      th.textContent = name;
      td.textContent = value;
      tr.append(th, td);
      body.append(tr);
    }
    $("comment").value = "";
    $("technique").value = "";
    $("technique-error").hidden = true;
    shownAt = performance.now();
  }

  function verdict(label) {
    const technique = $("technique").value.trim().toUpperCase();
    if (technique && !TECHNIQUE.test(technique)) {
      $("technique-error").hidden = false;
      return;
    }
    const row = rows[index];
    labels[row.alert_id] = {
      label: label,
      analyst: $("analyst").value.trim() || "analyst",
      seconds_spent: Math.round((performance.now() - shownAt) / 1000),
      comment: $("comment").value.trim(),
      labeled_at: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
      attack_technique: label === "attack" ? technique : "",
    };
    save();
    index += 1;
    render();
  }

  function cell(value, guard) {
    let text = String(value === undefined || value === null ? "" : value);
    if (guard && /^[=+\-@\t\r]/.test(text)) text = "'" + text;
    if (/[",\n\r]/.test(text)) text = '"' + text.replace(/"/g, '""') + '"';
    return text;
  }

  function download() {
    const lines = [COLUMNS.join(",")];
    for (const row of rows) {
      const l = labels[row.alert_id];
      if (!l) continue;
      lines.push(
        [
          cell(row.alert_id, false),
          cell(l.label, false),
          cell(l.analyst, true),
          cell(l.seconds_spent, false),
          cell(l.comment, true),
          cell(l.labeled_at, false),
          cell(l.attack_technique, false),
        ].join(",")
      );
    }
    const blob = new Blob([lines.join("\n") + "\n"], { type: "text/csv;charset=utf-8" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = "labels.csv";
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(link.href), 1000);
  }

  function parseCsv(text) {
    const out = [];
    let row = [];
    let field = "";
    let quoted = false;
    for (let i = 0; i < text.length; i += 1) {
      const ch = text[i];
      if (quoted) {
        if (ch === '"' && text[i + 1] === '"') {
          field += '"';
          i += 1;
        } else if (ch === '"') {
          quoted = false;
        } else {
          field += ch;
        }
      } else if (ch === '"') {
        quoted = true;
      } else if (ch === ",") {
        row.push(field);
        field = "";
      } else if (ch === "\n" || ch === "\r") {
        if (ch === "\r" && text[i + 1] === "\n") i += 1;
        row.push(field);
        out.push(row);
        row = [];
        field = "";
      } else {
        field += ch;
      }
    }
    if (field !== "" || row.length) {
      row.push(field);
      out.push(row);
    }
    return out;
  }

  function resume(file) {
    const reader = new FileReader();
    reader.onload = () => {
      const table = parseCsv(String(reader.result));
      const head = table.shift() || [];
      const at = (name) => head.indexOf(name);
      let loaded = 0;
      for (const r of table) {
        const id = r[at("alert_id")];
        const label = (r[at("label")] || "").trim();
        if (!known.has(id) || !["attack", "benign", "unknown"].includes(label)) continue;
        labels[id] = {
          label: label,
          analyst: r[at("analyst")] || "",
          seconds_spent: r[at("seconds_spent")] || "",
          comment: r[at("comment")] || "",
          labeled_at: r[at("labeled_at")] || "",
          attack_technique: at("attack_technique") >= 0 ? r[at("attack_technique")] || "" : "",
        };
        loaded += 1;
      }
      save();
      $("resume-status").textContent = "Загружено меток: " + loaded;
      index = 0;
      render();
    };
    reader.readAsText(file);
  }

  $("btn-attack").addEventListener("click", () => verdict("attack"));
  $("btn-benign").addEventListener("click", () => verdict("benign"));
  $("btn-unknown").addEventListener("click", () => verdict("unknown"));
  $("btn-skip").addEventListener("click", () => {
    index += 1;
    render();
  });
  $("btn-download").addEventListener("click", download);
  $("resume").addEventListener("change", (event) => {
    const file = event.target.files[0];
    if (file) resume(file);
  });
  render();
})();
