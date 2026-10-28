import assert from 'node:assert/strict'
import test from 'node:test'
import {
  createReportHtml,
  downloadReport,
  sanitizeReportData,
} from '../src/reportExport.js'

test('exports all report sections and keeps the original report unchanged', () => {
  const report = {
    target: 'https://example.test',
    scanCount: 1,
    summary: {
      scan_mode: 'full',
      scope: 'Authorized endpoints',
      overall_conclusion: { label: 'Cần xem xét' },
    },
    findings: [{
      name: 'Authorization issue',
      status: 'potential',
      severity: 'high',
      confidence: 'medium',
      evidence: { response_body: 'Dữ liệu minh chứng' },
    }],
    scanStages: [{ stage: 'API Discovery', status: 'completed' }],
    discoveryResults: [{ url: '/api/items', verification_status: 'verified' }],
    endpointAssessments: [{
      path: '/api/items',
      test_cases: [{ status: 'skipped', reason: 'Ngoài phạm vi kiểm thử' }],
    }],
    bolaBaselines: [{ baseline_status: 'captured' }],
    bolaAssessments: [{ assessment: 'potential', evidence_summary: 'Bằng chứng đầy đủ' }],
    bolaActiveTests: [{ status: 'inconclusive', reason: 'Không đủ dữ liệu' }],
    fileDiscoveryError: '',
  }
  const original = structuredClone(report)
  const html = createReportHtml(report)

  assert.match(html, /charset="utf-8"/)
  assert.match(html, /Cần xem xét/)
  assert.match(html, /Dữ liệu minh chứng/)
  assert.match(html, /Ngoài phạm vi kiểm thử/)
  assert.match(html, /Bằng chứng đầy đủ/)
  assert.match(html, /Active BOLA tests/)
  assert.match(html, /Authorized endpoints/)
  assert.deepEqual(report, original)
})

test('redacts sensitive values and embedded credentials without dropping safe report details', () => {
  const safe = sanitizeReportData({
    findings: [{
      status: 'confirmed',
      token: 'access-token-value',
      password: 'pass-value',
      refreshToken: 'camelcase-token-value',
      privateKey: 'private-key-value',
      headers: { Authorization: 'Bearer header-token', Cookie: 'session=secret' },
      note: 'Authorization: Bearer abc.def; password=hunter2',
      bearerNote: 'Plain Bearer raw-bearer-value',
      url: 'https://alice:secret@example.test/path?access_token=query-secret',
    }],
    summary: { token_or_session_detected: true },
  })
  const output = JSON.stringify(safe)

  assert.match(output, /confirmed/)
  assert.match(output, /token_or_session_detected/)
  assert.equal(safe.findings[0].bearerNote, 'Plain Bearer [REDACTED]')
  for (const secret of [
    'access-token-value',
    'pass-value',
    'camelcase-token-value',
    'private-key-value',
    'header-token',
    'session=secret',
    'abc.def',
    'hunter2',
    'alice:secret',
    'query-secret',
  ]) {
    assert.equal(output.includes(secret), false, `${secret} should be redacted`)
  }
})

test('downloads a standalone UTF-8 HTML file and cleans up the temporary link', () => {
  const calls = []
  const link = {
    style: {},
    click: () => calls.push('click'),
    remove: () => calls.push('remove'),
  }
  const documentRef = {
    body: { appendChild: () => calls.push('append') },
    createElement: (tag) => {
      assert.equal(tag, 'a')
      return link
    },
  }
  const urlRef = {
    createObjectURL: (blob) => {
      calls.push(blob.type)
      return 'blob:report'
    },
    revokeObjectURL: (url) => calls.push(`revoke:${url}`),
  }

  downloadReport({ summary: {}, findings: [] }, 'microscan-report.html', {
    documentRef,
    urlRef,
    BlobCtor: Blob,
    setTimeoutFn: (callback) => callback(),
  })
  assert.equal(link.download, 'microscan-report.html')
  assert.equal(link.href, 'blob:report')
  assert.deepEqual(calls, [
    'text/html;charset=utf-8',
    'append',
    'click',
    'remove',
    'revoke:blob:report',
  ])
})

test('escapes report values before embedding them in HTML', () => {
  const html = createReportHtml({
    summary: { note: '<script>alert("x")</script>' },
  })

  assert.match(html, /&lt;script&gt;/)
  assert.match(html, /&lt;\/script&gt;/)
  assert.doesNotMatch(html, /<script>/)
})
