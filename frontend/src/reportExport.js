const sensitiveKeyPattern =
  /(^|_)(password|passwd|secret|credential|credentials|api_key|private_key|access_token|refresh_token|id_token|cookie|set_cookie|authorization|bearer_token|session_token|token)(_|$)/i

function isSensitiveKey(key) {
  const normalized = key
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
  if (
    normalized === 'token_or_session_detected' ||
    normalized.endsWith('_token_detected') ||
    normalized.endsWith('_token_available') ||
    normalized.endsWith('_token_status') ||
    normalized.endsWith('_token_count')
  ) {
    return false
  }
  return sensitiveKeyPattern.test(normalized)
}

function redactText(value) {
  return value
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/gi, '[REDACTED PRIVATE KEY]')
    .replace(/(\b(?:authorization|cookie|set-cookie|password|passwd|token|api[_-]?key|private[_-]?key|secret|credential)\s*[:=]\s*)(?:"[^"]*"|'[^']*'|Bearer\s+[^\s,;]+|[^\s,;]+)/gi, '$1[REDACTED]')
    .replace(/\bBearer\s+[A-Za-z0-9._~+/-]+=*/gi, 'Bearer [REDACTED]')
    .replace(/([a-z][a-z0-9+.-]*:\/\/)[^/@\s:]+(?::[^/@\s]*)?@/gi, '$1[REDACTED]@')
    .replace(/([?&](?:password|passwd|token|access[_-]?token|refresh[_-]?token|api[_-]?key|client[_-]?secret|secret|authorization|cookie)=)[^&#\s]*/gi, '$1[REDACTED]')
}

export function sanitizeReportData(value) {
  if (Array.isArray(value)) {
    return value.map((item) => sanitizeReportData(item))
  }
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value).map(([key, child]) => [
        key,
        isSensitiveKey(key) ? '[REDACTED]' : sanitizeReportData(child),
      ]),
    )
  }
  return typeof value === 'string' ? redactText(value) : value
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

function formatValue(value) {
  return escapeHtml(JSON.stringify(value, null, 2) ?? String(value))
}

function renderRecords(records, emptyMessage) {
  if (!Array.isArray(records) || records.length === 0) {
    return `<p>${escapeHtml(emptyMessage)}</p>`
  }
  return `<table><thead><tr><th>#</th><th>Report data</th></tr></thead><tbody>${records
    .map(
      (record, index) =>
        `<tr><th scope="row">${index + 1}</th><td><pre>${formatValue(record)}</pre></td></tr>`,
    )
    .join('')}</tbody></table>`
}

function renderSummary(summary) {
  const entries = Object.entries(summary ?? {})
  if (entries.length === 0) return '<p>No summary data was reported.</p>'
  return `<table><thead><tr><th>Field</th><th>Value</th></tr></thead><tbody>${entries
    .map(
      ([key, value]) =>
        `<tr><th scope="row">${escapeHtml(key)}</th><td><pre>${formatValue(value)}</pre></td></tr>`,
    )
    .join('')}</tbody></table>`
}

export function createReportHtml(report) {
  const safe = sanitizeReportData(report)
  const target = safe.target || 'Not reported'
  return `<!doctype html>
<html lang="vi">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>MicroScan Report</title>
  <style>
    :root { color-scheme: light; font-family: Arial, Helvetica, sans-serif; color: #172033; }
    body { max-width: 1100px; margin: 0 auto; padding: 32px; line-height: 1.5; }
    h1, h2 { color: #123b5d; }
    h2 { margin-top: 2rem; border-bottom: 1px solid #cbd5e1; padding-bottom: .35rem; }
    table { width: 100%; border-collapse: collapse; margin: 1rem 0; table-layout: fixed; }
    th, td { border: 1px solid #cbd5e1; padding: .6rem; text-align: left; vertical-align: top; overflow-wrap: anywhere; }
    thead { background: #e8f1f8; }
    pre { white-space: pre-wrap; overflow-wrap: anywhere; margin: 0; font: .85rem/1.45 Consolas, monospace; }
    .report-meta { color: #475569; }
    @media print {
      body { max-width: none; padding: 0; font-size: 10pt; }
      h2, tr { break-inside: avoid; }
      table { page-break-inside: auto; }
      thead { display: table-header-group; }
      a { color: inherit; text-decoration: none; }
    }
    @page { margin: 16mm; }
  </style>
</head>
<body>
  <header>
    <h1>MicroScan Report</h1>
    <p class="report-meta">Target: ${escapeHtml(target)}</p>
    <p class="report-meta">Scans recorded during this session: ${escapeHtml(safe.scanCount ?? 0)}</p>
  </header>
  <main>
    <section><h2>Overview and scan profile</h2>${renderSummary(safe.summary)}</section>
    <section><h2>Findings, status, severity, confidence, and evidence</h2>${renderRecords(safe.findings, 'No findings were reported.')}</section>
    <section><h2>Discovery stages and diagnostics</h2>${renderRecords(safe.scanStages, 'No scan stages were reported.')}${safe.fileDiscoveryError ? `<p><strong>File Discovery error:</strong> ${escapeHtml(safe.fileDiscoveryError)}</p>` : ''}</section>
    <section><h2>Discovery inventory and evidence</h2>${renderRecords(safe.discoveryResults, 'No discovery records were reported.')}</section>
    <section><h2>Endpoint test cases and evidence</h2>${renderRecords(safe.endpointAssessments, 'No endpoint assessments were reported.')}</section>
    <section><h2>Passive BOLA assessments and baselines</h2>${renderRecords(safe.bolaBaselines, 'No BOLA baselines were reported.')}${renderRecords(safe.bolaAssessments, 'No passive BOLA assessments were reported.')}</section>
    <section><h2>Active BOLA tests</h2>${renderRecords(safe.bolaActiveTests, 'No active BOLA tests were reported.')}</section>
  </main>
</body>
</html>`
}

export function downloadReport(report, filename, environment = {}) {
  const documentRef = environment.documentRef ?? document
  const urlRef = environment.urlRef ?? URL
  const BlobCtor = environment.BlobCtor ?? Blob
  const setTimeoutFn = environment.setTimeoutFn ?? setTimeout
  const blob = new BlobCtor([createReportHtml(report)], {
    type: 'text/html;charset=utf-8',
  })
  const objectUrl = urlRef.createObjectURL(blob)
  const link = documentRef.createElement('a')
  link.href = objectUrl
  link.download = filename
  link.style.display = 'none'
  documentRef.body.appendChild(link)
  try {
    link.click()
  } finally {
    link.remove()
    setTimeoutFn(() => urlRef.revokeObjectURL(objectUrl), 0)
  }
}
