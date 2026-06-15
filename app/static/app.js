"use strict";

const form = document.getElementById("scan-form");
const urlInput = document.getElementById("url-input");
const scanButton = document.getElementById("scan-button");
const statusEl = document.getElementById("status");
const results = document.getElementById("results");

const gradeBadge = document.getElementById("grade-badge");
const summaryUrl = document.getElementById("summary-url");
const summaryScore = document.getElementById("summary-score");
const summaryPresent = document.getElementById("summary-present");
const summaryMissing = document.getElementById("summary-missing");
const findingsList = document.getElementById("findings");
const disclosureSection = document.getElementById("disclosure-section");
const disclosureList = document.getElementById("disclosure-list");

function setStatus(message, isError) {
  statusEl.textContent = message || "";
  statusEl.classList.toggle("error", Boolean(isError));
}

function gradeClass(grade) {
  const letter = (grade || "").charAt(0).toUpperCase();
  return "grade-" + (["A", "B", "C", "D"].includes(letter) ? letter.toLowerCase() : "f");
}

function clearChildren(node) {
  while (node.firstChild) {
    node.removeChild(node.firstChild);
  }
}

function renderFinding(finding) {
  const li = document.createElement("li");
  li.className = "finding " + (finding.present ? "present" : "missing");

  const head = document.createElement("div");
  head.className = "finding-head";

  const name = document.createElement("span");
  name.className = "finding-name";
  name.textContent = finding.name;

  const badge = document.createElement("span");
  badge.className = "badge " + (finding.present ? "present" : "missing");
  badge.textContent = finding.present ? "present" : "missing";

  head.appendChild(name);
  head.appendChild(badge);
  li.appendChild(head);

  const desc = document.createElement("p");
  desc.className = "finding-desc";
  desc.textContent = finding.description;
  li.appendChild(desc);

  const detail = document.createElement("p");
  detail.className = "finding-detail";
  detail.textContent = finding.present
    ? "Value: " + finding.value
    : "Suggested: " + finding.recommendation;
  li.appendChild(detail);

  return li;
}

function renderResults(data) {
  gradeBadge.textContent = data.grade;
  gradeBadge.className = "grade-badge " + gradeClass(data.grade);

  summaryUrl.textContent = data.final_url;
  summaryScore.textContent = String(data.score);
  summaryPresent.textContent = String(data.headers_present);
  summaryMissing.textContent = String(data.headers_missing);

  clearChildren(findingsList);
  data.findings.forEach((finding) => findingsList.appendChild(renderFinding(finding)));

  const disclosures = Object.entries(data.info_disclosure || {});
  clearChildren(disclosureList);
  if (disclosures.length > 0) {
    disclosures.forEach(([key, value]) => {
      const li = document.createElement("li");
      li.className = "finding missing";
      const head = document.createElement("div");
      head.className = "finding-head";
      const name = document.createElement("span");
      name.className = "finding-name";
      name.textContent = key;
      head.appendChild(name);
      li.appendChild(head);
      const detail = document.createElement("p");
      detail.className = "finding-detail";
      detail.textContent = value;
      li.appendChild(detail);
      disclosureList.appendChild(li);
    });
    disclosureSection.classList.remove("hidden");
  } else {
    disclosureSection.classList.add("hidden");
  }

  results.classList.remove("hidden");
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const url = urlInput.value.trim();
  if (!url) {
    return;
  }

  scanButton.disabled = true;
  setStatus("Scanning " + url + " ...", false);
  results.classList.add("hidden");

  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });

    const data = await response.json();
    if (!response.ok) {
      const detail = data && data.detail ? data.detail : "Scan failed.";
      setStatus(typeof detail === "string" ? detail : "Invalid URL.", true);
      return;
    }

    setStatus("", false);
    renderResults(data);
  } catch (err) {
    setStatus("Could not reach the scanner service.", true);
  } finally {
    scanButton.disabled = false;
  }
});
