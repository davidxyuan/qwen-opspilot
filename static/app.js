"use strict";

const byId = (id) => document.getElementById(id);
const apiBaseMeta = typeof document.querySelector === "function"
  ? document.querySelector('meta[name="opspilot-api-base"]')
  : null;
const API_BASE = String(apiBaseMeta?.content || "").replace(/\/+$/, "");
const apiUrl = (path) => `${API_BASE}${path}`;
const state = {
  scenario: null,
  fixtureHash: null,
  run: null,
  decision: null,
  generation: 0,
  controller: null,
  policyGeneration: 0,
};

function beginOperation() {
  state.generation += 1;
  state.controller?.abort();
  state.controller = new AbortController();
  return { generation: state.generation, controller: state.controller };
}

function isCurrentOperation(operation) {
  return state.generation === operation.generation && !operation.controller.signal.aborted;
}

function finishOperation(operation) {
  if (state.controller === operation.controller) {
    state.controller = null;
  }
}

function setRunEnabled(enabled) {
  byId("run-button").disabled = !enabled;
}

function setDecisionEnabled(enabled) {
  byId("approve-button").disabled = !enabled;
  byId("reject-button").disabled = !enabled;
}

function setStatus(label, kind = "idle") {
  const status = byId("status");
  status.textContent = label;
  status.dataset.kind = kind;
}

function clear(node) {
  node.replaceChildren();
}

function addListItem(list, text, kind = "") {
  const item = document.createElement("li");
  item.textContent = text;
  if (kind) {
    item.dataset.kind = kind;
  }
  list.append(item);
}

function renderFacts(target, records) {
  clear(target);
  records.forEach((record) => {
    const term = document.createElement("dt");
    const detail = document.createElement("dd");
    term.textContent = record.field;
    detail.textContent = `${String(record.value)} - ${record.id}`;
    target.append(term, detail);
  });
}

function renderObjectFacts(target, record) {
  clear(target);
  Object.entries(record).forEach(([field, value]) => {
    const term = document.createElement("dt");
    const detail = document.createElement("dd");
    term.textContent = field;
    detail.textContent = String(value);
    target.append(term, detail);
  });
}

function fixtureRecords(host) {
  return [
    ...host.task_definition,
    ...host.runtime_context,
    ...host.launcher_settings,
  ];
}

function clearResolution() {
  state.run = null;
  state.decision = null;
  byId("proposal-section").hidden = true;
  byId("decision-section").hidden = true;
  setDecisionEnabled(false);
  byId("report-button").disabled = true;
  [
    "proposal-changes",
    "proposal-prerequisites",
    "proposal-limitations",
    "proposal-rollback",
    "proposal-checks",
    "verification-results",
  ].forEach((id) => clear(byId(id)));
  clear(byId("before-state"));
  clear(byId("after-state"));
}

function clearRun() {
  [
    "provenance",
    "timeline",
    "plan",
    "tool-trace",
    "observed",
    "inferences",
    "decisive-evidence",
    "ruled-out",
  ].forEach((id) => clear(byId(id)));
  byId("root-cause").textContent = "Awaiting investigation.";
  byId("confidence").textContent = "Not available";
  clearResolution();
  if (state.scenario) {
    renderFacts(byId("host-a"), fixtureRecords(state.scenario.hosts.A));
    renderFacts(byId("host-b"), fixtureRecords(state.scenario.hosts.B));
  } else {
    clear(byId("host-a"));
    clear(byId("host-b"));
  }
}

async function readJson(response) {
  const payload = await response.json();
  if (!response.ok) {
    const error = new Error(payload.error?.message || "Request failed.");
    error.payload = payload;
    throw error;
  }
  return payload;
}

async function loadScenario() {
  const operation = beginOperation();
  state.scenario = null;
  state.fixtureHash = null;
  setRunEnabled(false);
  byId("symptom").textContent = "Load the bundled incident to begin.";
  byId("fixture-hash").textContent = "not loaded";
  clearRun();
  setStatus("Loading scenario...", "loading");
  try {
    const payload = await readJson(await fetch(apiUrl("/api/scenario"), {
      signal: operation.controller.signal,
    }));
    if (!isCurrentOperation(operation)) {
      return;
    }
    state.scenario = payload.scenario;
    state.fixtureHash = payload.fixture_hash;
    byId("symptom").textContent = payload.scenario.symptom;
    byId("fixture-hash").textContent = payload.fixture_hash;
    renderFacts(byId("host-a"), fixtureRecords(payload.scenario.hosts.A));
    renderFacts(byId("host-b"), fixtureRecords(payload.scenario.hosts.B));
    setRunEnabled(true);
    setStatus("Scenario loaded", "idle");
  } catch (error) {
    if (!isCurrentOperation(operation)) {
      return;
    }
    setStatus(`Failed: ${error.message}`, "failed");
  } finally {
    finishOperation(operation);
  }
}

async function runInvestigation() {
  if (!state.scenario || !state.fixtureHash) {
    setRunEnabled(false);
    setStatus("Load the scenario before running an investigation.", "failed");
    return;
  }
  const incidentId = state.scenario.incident_id;
  const expectedFixtureHash = state.fixtureHash;
  const operation = beginOperation();
  setRunEnabled(false);
  clearRun();
  setStatus("Running live Qwen investigation...", "running");
  try {
    const payload = await readJson(await fetch(apiUrl("/api/run"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ incident_id: incidentId }),
      signal: operation.controller.signal,
    }));
    if (!isCurrentOperation(operation)) {
      return;
    }
    if (state.fixtureHash !== expectedFixtureHash || payload.fixture_hash !== expectedFixtureHash) {
      throw new Error("Run evidence does not match the loaded scenario.");
    }
    state.run = payload;
    renderRun(payload);
    renderProposal(payload);
    setStatus("Investigation complete - approval required", "idle");
  } catch (error) {
    if (!isCurrentOperation(operation)) {
      return;
    }
    clearResolution();
    setStatus(`Failed: ${error.message}`, "failed");
  } finally {
    if (isCurrentOperation(operation)) {
      setRunEnabled(Boolean(state.scenario && state.fixtureHash));
    }
    finishOperation(operation);
  }
}

function renderRun(payload) {
  const provenance = byId("provenance");
  clear(provenance);
  [
    ["Provider", payload.provider],
    ["Model", payload.model],
    ["Run ID", payload.run_id],
  ].forEach(([name, value]) => {
    const term = document.createElement("dt");
    const detail = document.createElement("dd");
    term.textContent = name;
    detail.textContent = value;
    provenance.append(term, detail);
  });

  clear(byId("timeline"));
  payload.events.forEach((event) => addListItem(byId("timeline"), `${event.type}: ${event.summary}`));
  clear(byId("plan"));
  payload.plan.forEach((item) => addListItem(byId("plan"), `${item.id}: ${item.action}`));
  clear(byId("tool-trace"));
  payload.tool_trace.forEach((call) => addListItem(byId("tool-trace"), `${call.status}: ${call.name} (${call.host || "blocked"})`));
  renderFacts(byId("host-a"), payload.evidence.filter((record) => record.host === "A"));
  renderFacts(byId("host-b"), payload.evidence.filter((record) => record.host === "B"));

  const diagnosis = payload.diagnosis;
  clear(byId("observed"));
  diagnosis.observed.forEach((item) => addListItem(byId("observed"), `${item.statement} [${item.evidence_ids.join(", ")}]`));
  clear(byId("inferences"));
  diagnosis.inferences.forEach((item) => addListItem(byId("inferences"), `${item.statement} [${item.evidence_ids.join(", ")}]`));
  byId("root-cause").textContent = diagnosis.root_cause;
  byId("confidence").textContent = diagnosis.confidence;
  clear(byId("decisive-evidence"));
  diagnosis.decisive_evidence_ids.forEach((id) => addListItem(byId("decisive-evidence"), id));
  clear(byId("ruled-out"));
  diagnosis.ruled_out.forEach((item) => addListItem(byId("ruled-out"), `${item.statement} [${item.evidence_ids.join(", ")}]`));
}

function renderProposal(payload) {
  const proposal = payload.proposal;
  byId("proposal-section").hidden = false;
  byId("simulation-label").textContent = `${proposal.label} proposal`;
  byId("proposal-name").textContent = proposal.title;
  byId("proposal-outcome").textContent = proposal.expected_outcome;
  proposal.changes.forEach((change) => addListItem(
    byId("proposal-changes"),
    `${change.field}: ${String(change.from)} -> ${String(change.to)}`,
  ));
  proposal.prerequisites.forEach((item) => addListItem(byId("proposal-prerequisites"), item));
  proposal.limitations.forEach((item) => addListItem(byId("proposal-limitations"), item));
  proposal.rollback.forEach((change) => addListItem(
    byId("proposal-rollback"),
    `${change.field}: ${String(change.from)} -> ${String(change.to)}`,
  ));
  proposal.verification_checks.forEach((check) => addListItem(
    byId("proposal-checks"),
    `${check.label}; expected ${String(check.expected)}`,
  ));
  byId("run-hash").textContent = payload.run_hash;
  byId("proposal-hash").textContent = payload.proposal_hash;
  byId("approval-expiry").textContent = payload.approval.expires_at_utc;
  setDecisionEnabled(true);
}

async function submitDecision(path, pendingLabel) {
  if (!state.run || state.decision) {
    return;
  }
  const currentRun = state.run;
  const operation = beginOperation();
  setDecisionEnabled(false);
  setRunEnabled(false);
  setStatus(pendingLabel, "running");
  try {
    const payload = await readJson(await fetch(apiUrl(path), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ run: currentRun }),
      signal: operation.controller.signal,
    }));
    if (!isCurrentOperation(operation) || state.run !== currentRun) {
      return;
    }
    state.decision = payload;
    renderDecision(payload);
    setStatus(payload.applied ? "Simulated change verified" : "Proposal rejected - no change", "idle");
  } catch (error) {
    if (!isCurrentOperation(operation)) {
      return;
    }
    if (error.payload?.decision) {
      renderDecision(error.payload.decision);
    }
    setStatus(`Decision failed: ${error.message}`, "failed");
    setDecisionEnabled(Boolean(state.run && !state.decision));
  } finally {
    if (isCurrentOperation(operation)) {
      setRunEnabled(Boolean(state.scenario && state.fixtureHash));
    }
    finishOperation(operation);
  }
}

function renderDecision(decision) {
  byId("decision-section").hidden = false;
  byId("decision-label").textContent = decision.simulation_label;
  byId("decision-summary").textContent = `${decision.decision}: ${decision.reason}`;
  renderObjectFacts(byId("before-state"), decision.before);
  renderObjectFacts(byId("after-state"), decision.after);
  clear(byId("verification-results"));
  decision.verification.checks.forEach((check) => addListItem(
    byId("verification-results"),
    `${check.passed ? "PASS" : "FAIL"}: ${check.label} (expected ${String(check.expected)}, actual ${String(check.actual)})`,
    check.passed ? "passed" : "failed",
  ));
  byId("report-button").disabled = !decision.decision_token;
}

async function downloadReport() {
  if (!state.run || !state.decision?.decision_token) {
    return;
  }
  const currentRun = state.run;
  const currentDecision = state.decision;
  const operation = beginOperation();
  byId("report-button").disabled = true;
  setStatus("Building audit report...", "running");
  try {
    const response = await fetch(apiUrl("/api/report"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ run: currentRun, decision: currentDecision }),
      signal: operation.controller.signal,
    });
    if (!response.ok) {
      await readJson(response);
    }
    const blob = await response.blob();
    if (!isCurrentOperation(operation) || state.run !== currentRun || state.decision !== currentDecision) {
      return;
    }
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = "qwen-opspilot-report.md";
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
    setStatus("Audit report downloaded", "idle");
  } catch (error) {
    if (isCurrentOperation(operation)) {
      setStatus(`Report failed: ${error.message}`, "failed");
    }
  } finally {
    if (isCurrentOperation(operation)) {
      byId("report-button").disabled = !state.decision?.decision_token;
    }
    finishOperation(operation);
  }
}

async function showPolicyDenial() {
  const generation = ++state.policyGeneration;
  const result = byId("policy-result");
  result.textContent = "Checking policy...";
  try {
    const payload = await readJson(await fetch(apiUrl("/api/policy-check"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    }));
    if (generation === state.policyGeneration) {
      result.textContent = `${payload.status}: ${payload.reason}`;
    }
  } catch (error) {
    if (generation === state.policyGeneration) {
      result.textContent = `Policy check failed: ${error.message}`;
    }
  }
}

byId("load-button").addEventListener("click", loadScenario);
byId("run-button").addEventListener("click", runInvestigation);
byId("policy-button").addEventListener("click", showPolicyDenial);
byId("approve-button").addEventListener("click", () => submitDecision("/api/approve", "Validating approval..."));
byId("reject-button").addEventListener("click", () => submitDecision("/api/reject", "Recording rejection..."));
byId("report-button").addEventListener("click", downloadReport);
loadScenario();
