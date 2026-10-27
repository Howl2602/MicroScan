import { Component, useEffect, useMemo, useState } from 'react'
import {
  buildApiTree,
  filterDiscoveryResults,
  getApiMapPath,
} from './apiMap.js'

import {
  Box,
  Drawer,
  List,
  ListItem,
  ListItemButton,
  ListItemText,
  Toolbar,
  Typography,
  Card,
  CardContent,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  Chip,
  Alert,
  CircularProgress,
  Checkbox,
  FormControl,
  FormControlLabel,
  InputLabel,
  MenuItem,
  Select,
} from '@mui/material'

const drawerWidth = 240
const backendUrl = 'http://localhost:8000'

class ApiMapErrorBoundary extends Component {
  state = { hasError: false }

  static getDerivedStateFromError() {
    return { hasError: true }
  }

  componentDidCatch(error, info) {
    console.error('API Map rendering failed.', error, info.componentStack)
  }

  render() {
    if (this.state.hasError) {
      return (
        <Alert severity="error">
          The API Map could not render this discovery data. The scan results are still
          available in Reports; check the browser console for component details.
        </Alert>
      )
    }
    return this.props.children
  }
}

function normalizeOrigin(value) {
  try {
    return new URL(value.includes('://') ? value : `http://${value}`).origin
  } catch {
    return null
  }
}

function mergeDiscoveryResults(fileResults, kiterunnerResults, gatewayTarget, scanResultsTarget) {
  const merged = new Map()
  fileResults.forEach((item) => {
    const method =
      typeof item?.method === 'string' && item.method ? item.method.toUpperCase() : null
    if (typeof item?.url !== 'string' || !item.url) return
    merged.set(`${method ?? 'UNKNOWN'} ${item.url}`, {
      ...item,
      sources: [...new Set(item.sources ?? [])],
    })
  })

  const gatewayOrigin = normalizeOrigin(gatewayTarget)
  if (!gatewayOrigin || gatewayOrigin !== normalizeOrigin(scanResultsTarget)) {
    return [...merged.values()]
  }

  kiterunnerResults.forEach((item) => {
    const path = item.path ?? item.target
    if (!path) return

    let url
    try {
      url = new URL(path, `${gatewayOrigin}/`)
      if (url.origin !== gatewayOrigin) return
      url.search = ''
      url.hash = ''
    } catch {
      return
    }

    const method =
      typeof item.method === 'string' && item.method ? item.method.toUpperCase() : null
    const key = `${method ?? 'UNKNOWN'} ${url.href}`
    const statusCode = item.responses?.[0]?.sc ?? item.status ?? item.status_code ?? null
    const verificationStatus =
      statusCode === 401 || statusCode === 403
        ? 'blocked'
        : statusCode === 404
          ? 'not_found'
          : 'inconclusive'
    const existing = merged.get(key)
    if (existing) {
      existing.sources = [...new Set([...existing.sources, 'kiterunner'])]
      return
    }

    merged.set(key, {
      url: url.href,
      method,
      status_code: statusCode,
      content_type: null,
      verification_status: verificationStatus,
      sources: ['kiterunner'],
      evidence: [],
    })
  })

  return [...merged.values()]
}

export function ApiTreeNode({ node, depth = 0 }) {
  return (
    <>
      {Object.entries(node).map(([name, item]) => (
        <Box key={name} sx={{ ml: depth * 2, mt: 1 }}>
          <Typography sx={{ color: '#38BDF8', fontWeight: 600 }}>
            {name === 'Unresolved origin' || /^https?:\/\//i.test(name)
              ? `🌐 ${name}`
              : `📁 /${name}`}
          </Typography>

          {(Array.isArray(item.endpoints) ? item.endpoints : []).map((endpoint, index) => {
            if (!endpoint || typeof endpoint !== 'object') return null
            const rawStatus =
              endpoint.status_code ?? endpoint.responses?.[0]?.sc ?? endpoint.status
            const status =
              typeof rawStatus === 'number' || typeof rawStatus === 'string'
                ? rawStatus
                : null
            const path = getApiMapPath(endpoint) ?? '/'
            const method =
              typeof endpoint.method === 'string' && endpoint.method
                ? endpoint.method
                : 'UNKNOWN'
            const sources = Array.isArray(endpoint.sources)
              ? endpoint.sources
              : Array.isArray(endpoint.discovery_sources)
                ? endpoint.discovery_sources
                : []
            const evidence = Array.isArray(endpoint.evidence) ? endpoint.evidence : []

            return (
              <Box
                key={`${method}-${path}-${index}`}
                sx={{
                  ml: 3,
                  mt: 1,
                  display: 'flex',
                  gap: 1,
                  alignItems: 'center',
                  flexWrap: 'wrap',
                }}
              >
                <Chip label={method} size="small" color="primary" />
                <Typography variant="body2">{path}</Typography>
                {status != null && (
                  <Chip
                    label={status}
                    size="small"
                    variant="outlined"
                    color={
                      status >= 500 ? 'error' : status >= 400 ? 'warning' : 'success'
                    }
                  />
                )}
                {sources.filter((source) => typeof source === 'string').map((source) => (
                  <Chip key={source} label={source} size="small" variant="outlined" />
                ))}
                {typeof endpoint.verification_status === 'string' && endpoint.verification_status && (
                  <Chip
                    label={`Verification: ${endpoint.verification_status}`}
                    size="small"
                    variant="outlined"
                  />
                )}
                {typeof endpoint.original_url === 'string' &&
                  endpoint.original_url !== endpoint.verification_url && (
                    <Typography color="text.secondary" variant="caption">
                      Discovered URL: {endpoint.original_url}
                    </Typography>
                  )}
                {typeof endpoint.security_status === 'string' && endpoint.security_status && (
                  <Chip
                    label={`Security: ${endpoint.security_status}`}
                    size="small"
                    variant="outlined"
                  />
                )}
                {endpoint.security_status === 'skipped' &&
                  typeof endpoint.security_reason === 'string' &&
                  endpoint.security_reason && (
                  <Typography color="text.secondary" variant="caption">
                    {endpoint.security_reason}
                  </Typography>
                )}
                {typeof endpoint.classification === 'string' && endpoint.classification && (
                  <Chip label={endpoint.classification} size="small" variant="outlined" />
                )}
                {endpoint.resolution_status === 'unresolved' && (
                  <Chip label="Origin unresolved" size="small" variant="outlined" />
                )}
                {typeof endpoint.resolved_url === 'string' &&
                  endpoint.resolved_url !== endpoint.original_url && (
                  <Typography color="text.secondary" variant="caption">
                    Resolved API URL: {endpoint.resolved_url}
                  </Typography>
                )}
                {evidence.length > 0 && (
                  <Box component="details" sx={{ flexBasis: '100%', ml: 3 }}>
                    <Box component="summary" sx={{ cursor: 'pointer' }}>
                      Discovery evidence ({evidence.length})
                    </Box>
                    {evidence.map((item, evidenceIndex) => (
                      <Box key={`${item?.source_url ?? 'source'}-${evidenceIndex}`} sx={{ mt: 1 }}>
                        {item?.source_url && (
                          typeof item.source_url === 'string' &&
                          <Typography variant="caption" display="block">
                            {item.source_url}
                          </Typography>
                        )}
                        {typeof item?.snippet === 'string' && item.snippet && (
                          <Typography variant="body2" sx={{ overflowWrap: 'anywhere' }}>
                            {item.snippet}
                          </Typography>
                        )}
                      </Box>
                    ))}
                  </Box>
                )}
              </Box>
            )
          })}

          {item.children && Object.keys(item.children).length > 0 && (
            <ApiTreeNode node={item.children} depth={depth + 1} />
          )}
        </Box>
      ))}
    </>
  )
}

function DiscoveryProgress({ stages, loading }) {
  if (stages.length === 0) return null

  return (
    <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', mt: 2 }} aria-live="polite">
      {stages.map((stage) => (
        <Box key={stage.stage}>
          <Chip
            label={`${stage.stage}: ${stage.status}`}
            size="small"
            color={
              stage.status === 'error' || stage.status === 'failed'
                ? 'error'
                : stage.status === 'completed'
                  ? 'success'
                  : stage.status === 'running'
                    ? 'primary'
                    : 'default'
            }
            variant={stage.status === 'running' ? 'filled' : 'outlined'}
          />
          {(stage.stage.includes('Discovery') ||
            stage.stage === 'Authorized Scope' ||
            stage.stage === 'API Origin Candidates') && stage.detail && (
            <Typography
              color="text.secondary"
              variant="caption"
              sx={{ display: 'block', mt: 0.5 }}
            >
              {stage.detail}
            </Typography>
          )}
        </Box>
      ))}
      {loading && <CircularProgress size={18} aria-label="Scan in progress" />}
    </Box>
  )
}

function DiscoveryResultsTable({ results }) {
  return (
    <Card sx={{ overflowX: 'auto' }}>
      <Table size="small">
        <TableHead>
          <TableRow>
            <TableCell>Path / URL</TableCell>
            <TableCell>Method</TableCell>
            <TableCell>Origin</TableCell>
            <TableCell>Status</TableCell>
            <TableCell>Source</TableCell>
            <TableCell>Verification</TableCell>
            <TableCell>Evidence / observations</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {results.length === 0 ? (
            <TableRow><TableCell colSpan={7} align="center">No discovery records for this scan.</TableCell></TableRow>
          ) : results.map((item, index) => (
            <TableRow key={`${item.method}-${item.url}-${index}`}>
              <TableCell sx={{ maxWidth: 360, overflowWrap: 'anywhere' }}>
                {item.discovered_path ?? item.url ?? item.template ?? '—'}
                {item.resolved_url && item.resolved_url !== item.url && (
                  <Typography display="block" variant="caption" color="text.secondary">
                    Resolved: {item.resolved_url}
                  </Typography>
                )}
              </TableCell>
              <TableCell>{item.method ?? 'UNKNOWN'}</TableCell>
              <TableCell sx={{ maxWidth: 220, overflowWrap: 'anywhere' }}>
                {(() => {
                  try {
                    return item.resolved_url
                      ? new URL(item.resolved_url).origin
                      : item.url
                        ? new URL(item.url).origin
                        : 'Unresolved'
                  } catch {
                    return 'Unresolved'
                  }
                })()}
              </TableCell>
              <TableCell>{item.status_code ?? '—'}</TableCell>
              <TableCell>{(Array.isArray(item.sources) ? item.sources : [])
                .filter((source) => typeof source === 'string')
                .map((source) => <Chip key={source} label={source} size="small" sx={{ mr: 0.5, mb: 0.5 }} />)}</TableCell>
              <TableCell>
                {item.verification_status ?? 'discovered'}
                {item.verification_reason && (
                  <Typography display="block" variant="caption" color="text.secondary">
                    {item.verification_reason}
                  </Typography>
                )}
              </TableCell>
              <TableCell>
                {((Array.isArray(item.evidence) ? item.evidence.length : 0) > 0 ||
                  (Array.isArray(item.discovery_observations) ? item.discovery_observations.length : 0) > 0) ? (
                  <Box component="details">
                    <Box component="summary" sx={{ cursor: 'pointer' }}>
                      View evidence ({(Array.isArray(item.evidence) ? item.evidence.length : 0) + (Array.isArray(item.discovery_observations) ? item.discovery_observations.length : 0)})
                    </Box>
                    {(Array.isArray(item.discovery_observations) ? item.discovery_observations : []).map((observation, observationIndex) => (
                      observation && typeof observation === 'object' ? (
                      <Typography
                        key={`observation-${observationIndex}`}
                        display="block"
                        variant="caption"
                        color="text.secondary"
                      >
                        {observation.method ?? 'UNKNOWN'} {observation.url ?? 'URL unavailable'}
                        {observation.status_code != null ? ` · HTTP ${observation.status_code}` : ''}
                        {observation.allow ? ` · Allow: ${observation.allow}` : ''}
                        {observation.source ? ` · ${observation.source}` : ''}
                      </Typography>
                      ) : null
                    ))}
                    {(Array.isArray(item.evidence) ? item.evidence : []).map((evidence, evidenceIndex) => (
                      evidence && typeof evidence === 'object' ? (
                      <Box key={`evidence-${evidenceIndex}`} sx={{ mt: 1 }}>
                        {typeof evidence.source_url === 'string' && (
                          <Typography display="block" variant="caption">
                            {evidence.source_url}
                          </Typography>
                        )}
                        {typeof evidence.snippet === 'string' && (
                          <Typography display="block" variant="caption" color="text.secondary">
                            {evidence.snippet}
                          </Typography>
                        )}
                      </Box>
                      ) : null
                    ))}
                  </Box>
                ) : '—'}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </Card>
  )
}

function DiscoveryCategoryFilter({ id, value, onChange }) {
  return (
    <FormControl size="small" sx={{ minWidth: 190 }}>
      <InputLabel id={`${id}-label`}>Endpoint category</InputLabel>
      <Select
        labelId={`${id}-label`}
        value={value}
        label="Endpoint category"
        onChange={(event) => onChange(event.target.value)}
      >
        <MenuItem value="all">All</MenuItem>
        <MenuItem value="actionable">Actionable</MenuItem>
        <MenuItem value="not_found">Not Found</MenuItem>
        <MenuItem value="blocked">Blocked</MenuItem>
        <MenuItem value="inconclusive">Inconclusive</MenuItem>
      </Select>
    </FormControl>
  )
}

function EndpointAssessments({ assessments, findings = [] }) {
  if (assessments.length === 0) {
    return (
      <Typography color="text.secondary" sx={{ mt: 2 }}>
        No endpoint assessments are available for this scan.
      </Typography>
    )
  }

  return assessments.map((endpoint, index) => (
    <Box
      component="details"
      key={`${endpoint.method}-${endpoint.path}-${index}`}
      sx={{ mt: 1.5, border: '1px solid #334155', borderRadius: 1, px: 1.5, py: 1 }}
    >
      <Box component="summary" sx={{ cursor: 'pointer', fontWeight: 600 }}>
        {endpoint.method ?? 'UNKNOWN'} {endpoint.path} · {endpoint.assessment}
      </Box>
      <Typography color="text.secondary" variant="body2" sx={{ mt: 1 }}>
        Assessment: {endpoint.assessment}
      </Typography>
      <Typography color="text.secondary" variant="body2">
        Reason: {endpoint.reason}
      </Typography>
      {endpoint.test_cases.length === 0 ? (
        <Typography color="text.secondary" variant="body2" sx={{ mt: 1 }}>
          No test cases recorded.
        </Typography>
      ) : (
        <Table size="small" sx={{ mt: 1 }}>
          <TableHead>
            <TableRow>
              <TableCell>Case</TableCell>
              <TableCell>HTTP status</TableCell>
              <TableCell>Result</TableCell>
              <TableCell>Evidence</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {endpoint.test_cases.map((testCase, caseIndex) => (
              <TableRow key={`${testCase.test_case}-${caseIndex}`}>
                <TableCell>
                  {testCase.test_case}
                  <Typography color="text.secondary" variant="caption" display="block">
                    {testCase.request_condition}
                  </Typography>
                </TableCell>
                <TableCell>{testCase.evidence?.status_code ?? '—'}</TableCell>
                <TableCell>
                  {testCase.status === 'not_vulnerable_in_test' ||
                  testCase.status === 'not_detected_in_this_test'
                    ? 'Not detected in this test'
                    : testCase.status === 'potential'
                      ? 'Potential'
                      : testCase.status === 'confirmed'
                        ? 'Confirmed'
                        : testCase.status === 'skipped' &&
                            testCase.implementation_status === 'not_implemented'
                          ? 'Not implemented'
                          : testCase.status}
                  {testCase.reason && (
                    <Typography color="text.secondary" variant="caption" display="block">
                      {testCase.reason}
                    </Typography>
                  )}
                </TableCell>
                <TableCell>
                  {testCase.evidence && findings.some(
                    (finding) =>
                      finding.method === endpoint.method &&
                      finding.endpoint === endpoint.path &&
                      finding.test_case === testCase.test_case,
                  ) ? (
                    'Evidence is shown in the selected finding details.'
                  ) : testCase.evidence ? (
                    <Box component="details">
                      <Box component="summary" sx={{ cursor: 'pointer' }}>
                        View evidence
                      </Box>
                      <Box
                        component="pre"
                        sx={{
                          mt: 1,
                          p: 1.5,
                          borderRadius: 1,
                          backgroundColor: '#0B1120',
                          color: '#CBD5E1',
                          whiteSpace: 'pre-wrap',
                          overflowWrap: 'anywhere',
                          fontSize: '0.8rem',
                        }}
                      >
                        {JSON.stringify(testCase.evidence, null, 2)}
                      </Box>
                    </Box>
                  ) : (
                    '—'
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </Box>
  ))
}

function BolaCorrelationResults({ assessments, baselines, activeTests, summary }) {
  return (
    <Box sx={{ mt: 3 }}>
      <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
        Passive BOLA correlation
      </Typography>
      <Typography color="text.secondary" variant="body2" sx={{ mb: 1 }}>
        Uses only sanitized response evidence already captured by existing scan checks; this analysis sends no additional requests and does not confirm authorization policy.
      </Typography>
      <Typography variant="body2">
        Collection baselines: {baselines.length} · Resource correlations: {assessments.length} · Potential out-of-baseline observations: {assessments.filter((item) => item.assessment === 'potential').length}
      </Typography>
      {summary?.jwt_selection_budgets?.map((budget, index) => (
        <Typography key={`jwt-budget-${index}`} color="text.secondary" variant="body2">
          JWT selection budget ({budget.mode ?? 'unknown'}): {budget.used ?? '—'} of {budget.configured ?? 'not applicable'} group(s) used
          {budget.remaining != null ? ` · ${budget.remaining} remaining` : ''}
        </Typography>
      ))}
      {baselines.map((baseline, index) => (
        <Box
          key={`baseline-${baseline.method}-${baseline.collection_endpoint}-${index}`}
          sx={{ mt: 1, pl: 1.5, borderLeft: '2px solid #475569' }}
        >
          <Typography variant="body2">
            Baseline {baseline.method ?? 'UNKNOWN'} {baseline.collection_endpoint}: {baseline.baseline_status}
            {baseline.identifiers?.length ? ` · ${baseline.identifiers.length} identifier(s)` : ''}
          </Typography>
          {baseline.response_diagnostic && (
            <Typography color="text.secondary" variant="caption" display="block">
              JWT check: {baseline.response_diagnostic.request_outcome ?? 'unknown'}
              {' '}· Authentication available: {baseline.response_diagnostic.authentication_available == null
                ? 'unknown'
                : baseline.response_diagnostic.authentication_available
                  ? 'yes'
                  : 'no'}
              {baseline.response_diagnostic.http_status != null
                ? ` · HTTP ${baseline.response_diagnostic.http_status}`
                : ''}
              {baseline.response_diagnostic.content_type
                ? ` · ${baseline.response_diagnostic.content_type}`
                : ''}
              {baseline.response_diagnostic.skip_reason
                ? ` · ${baseline.response_diagnostic.skip_reason}`
                : ''}
            </Typography>
          )}
          <Typography color="text.secondary" variant="caption">
            {baseline.evidence_summary}
          </Typography>
        </Box>
      ))}
      {assessments.map((assessment, index) => (
        <Box
          key={`assessment-${assessment.method}-${assessment.resource_endpoint}-${index}`}
          sx={{ mt: 1, pl: 1.5, borderLeft: '2px solid #475569' }}
        >
          <Typography variant="body2">
            {assessment.method ?? 'UNKNOWN'} {assessment.resource_endpoint}: {assessment.assessment === 'not_tested'
              ? 'Not tested'
              : assessment.assessment === 'inconclusive'
                ? 'Inconclusive'
                : assessment.assessment === 'potential'
                  ? 'Potential'
                  : assessment.assessment === 'confirmed'
                    ? 'Confirmed'
                    : assessment.assessment}
            {' '}· {assessment.correlation_status}
          </Typography>
          {assessment.response_diagnostic && (
            <Typography color="text.secondary" variant="body2" sx={{ mt: 0.5 }}>
              JWT check: {assessment.response_diagnostic.request_outcome ?? 'unknown'}
              {' '}· Authentication available: {assessment.response_diagnostic.authentication_available == null
                ? 'unknown'
                : assessment.response_diagnostic.authentication_available
                  ? 'yes'
                  : 'no'}
              {assessment.response_diagnostic.http_status != null
                ? ` · HTTP ${assessment.response_diagnostic.http_status}`
                : ''}
              {assessment.response_diagnostic.content_type
                ? ` · ${assessment.response_diagnostic.content_type}`
                : ''}
              {assessment.response_diagnostic.jwt_selected === false
                ? ' · Not individually checked'
                : ''}
              {assessment.response_diagnostic.skip_reason
                ? ` · ${assessment.response_diagnostic.skip_reason}`
                : ''}
              {assessment.response_diagnostic.selection_reason
                ? ` — ${assessment.response_diagnostic.selection_reason}`
                : ''}
            </Typography>
          )}
          <Typography color="text.secondary" variant="caption">
            {assessment.evidence_summary}
            {assessment.baseline_status ? ` Baseline: ${assessment.baseline_status}.` : ''}
          </Typography>
        </Box>
      ))}
      {assessments.length === 0 && baselines.length === 0 && (
        <Typography color="text.secondary" variant="body2" sx={{ mt: 1 }}>
          No resource response evidence was available for passive correlation.
        </Typography>
      )}
      <Typography variant="subtitle1" sx={{ mt: 3, fontWeight: 700 }}>
        Active BOLA checks (authorized loopback lab)
      </Typography>
      <Typography color="text.secondary" variant="body2" sx={{ mb: 1 }}>
        Sends bounded authenticated GET requests only to discovered detail routes, using identifiers observed in captured responses. Potential results do not establish authorization policy or resource ownership.
      </Typography>
      {summary?.bola_request_budgets?.map((budget, index) => (
        <Typography key={`bola-budget-${index}`} color="text.secondary" variant="body2">
          BOLA request budget: {budget.used} of {budget.configured} used · {budget.remaining} remaining
        </Typography>
      ))}
      {activeTests.map((test, index) => (
        <Box
          key={`active-bola-${test.method}-${test.path}-${index}`}
          sx={{ mt: 1, pl: 1.5, borderLeft: '2px solid #475569' }}
        >
          <Typography variant="body2">
            {test.method ?? 'GET'} {test.path}: {test.assessment ?? test.outcome}
            {' '}· {test.selected ? 'selected' : 'not selected'}
            {' '}· {test.sent ? 'sent' : 'not sent'}
            {' '}· {test.response_received ? 'response received' : 'no response'}
            {test.http_status != null ? ` · HTTP ${test.http_status}` : ''}
            {test.content_type ? ` · ${test.content_type}` : ''}
          </Typography>
          <Typography color="text.secondary" variant="caption">
            {test.reason ?? test.outcome}
            {test.baseline_status ? ` Baseline: ${test.baseline_status}.` : ''}
            {test.baseline_limitation ? ` ${test.baseline_limitation}` : ''}
          </Typography>
        </Box>
      ))}
      {activeTests.length === 0 && (
        <Typography color="text.secondary" variant="body2" sx={{ mt: 1 }}>
          No active BOLA requests were recorded. Active checks require an opted-in loopback scan, an authenticated collection response, observed identifiers, and a discovered detail route.
        </Typography>
      )}
    </Box>
  )
}

function VulnerabilityFindings({ findings }) {
  if (findings.length === 0) {
    return (
      <Typography color="text.secondary" sx={{ mt: 1 }}>
        No confirmed or potential vulnerabilities were identified from the collected evidence.
      </Typography>
    )
  }

  return findings.map((finding, index) => (
    <Box
      key={finding.finding_id ?? `${finding.method}-${finding.endpoint}-${finding.test_case}-${index}`}
      sx={{ mt: 2, p: 2, border: '1px solid #334155', borderRadius: 1 }}
    >
      <Chip
        label={finding.status === 'confirmed' ? 'Confirmed' : 'Potential'}
        size="small"
        color={finding.status === 'confirmed' ? 'error' : 'warning'}
        sx={{ mr: 1 }}
      />
      <Typography component="span" variant="subtitle1">
        {finding.name}
      </Typography>
      <Typography color="text.secondary" variant="body2" sx={{ mt: 0.5 }}>
        {finding.method} {finding.endpoint} · Severity: {finding.severity ?? 'Not assessed'}
      </Typography>
      <Typography variant="body2" sx={{ mt: 1 }}>
        {finding.reason}
      </Typography>
      {finding.request_condition && (
        <Typography color="text.secondary" variant="body2" sx={{ mt: 1 }}>
          Request condition: {finding.request_condition}
        </Typography>
      )}
      {finding.unverified && (
        <Typography color="text.secondary" variant="body2" sx={{ mt: 1 }}>
          Not verified: {finding.unverified}
        </Typography>
      )}
      <Typography variant="body2" sx={{ mt: 1 }}>
        Recommendation: {finding.recommendation}
      </Typography>
      <Typography color="text.secondary" variant="body2" sx={{ mt: 1 }}>
        Source test case: {finding.test_case}
      </Typography>
      {finding.evidence && (
        <Box component="details" sx={{ mt: 1 }}>
          <Box component="summary" sx={{ cursor: 'pointer' }}>
            View finding evidence
          </Box>
          <Box
            component="pre"
            sx={{
              mt: 1,
              p: 1.5,
              borderRadius: 1,
              backgroundColor: '#0B1120',
              color: '#CBD5E1',
              whiteSpace: 'pre-wrap',
              overflowWrap: 'anywhere',
              fontSize: '0.8rem',
            }}
          >
            {JSON.stringify(finding.evidence, null, 2)}
          </Box>
        </Box>
      )}
    </Box>
  ))
}

function findingDescription(name = '') {
  const normalized = name.toLowerCase()
  if (normalized.includes('bola') || normalized.includes('object level')) {
    return 'An object may be accessible without confirming that the requester is authorized to access it.'
  }
  if (normalized.includes('jwt') || normalized.includes('authentication') || normalized.includes('auth') || normalized.includes('token') || normalized.includes('unauthenticated')) {
    return 'The endpoint may return protected data without successfully enforcing the expected authentication checks.'
  }
  return 'The scan recorded evidence that may indicate a security issue at this endpoint.'
}

function FindingDetail({ findings, endpointAssessments, target, onClose }) {
  if (findings.length === 0) return null
  const finding = findings[0]
  const endpoint = endpointAssessments.find(
    (item) => item.method === finding.method && item.path === finding.endpoint,
  )
  const statuses = [...new Set(findings.map((item) => item.status))]
  const statusLabel = statuses.length > 1
    ? 'Confirmed and potential'
    : statuses[0] === 'confirmed'
      ? 'Confirmed'
      : 'Potential'
  const identityEvidence = findings
    .map((item) => item.evidence?.identifier_comparison ?? item.evidence?.owner_identity_evidence)
    .filter(Boolean)

  return (
    <Card id="finding-detail" sx={{ mt: 3, scrollMarginTop: 16 }}>
      <CardContent>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', gap: 2, alignItems: 'flex-start' }}>
          <Box>
            <Typography color="text.secondary" variant="body2" aria-label="Breadcrumb">
              Scan Reports › {finding.name} › {finding.method} {finding.endpoint}
            </Typography>
            <Typography variant="h6" sx={{ mt: 1 }}>
              {finding.method} {finding.endpoint}
            </Typography>
          </Box>
          <Chip
            label={statusLabel}
            color={statuses.includes('confirmed') ? 'error' : 'warning'}
            size="small"
          />
        </Box>
        <Typography variant="subtitle2" sx={{ mt: 2 }}>What this means</Typography>
        <Typography variant="body2" color="text.secondary">
          {findingDescription(finding.name)}
        </Typography>
        <Typography variant="subtitle2" sx={{ mt: 2 }}>Why it was flagged</Typography>
        {findings.map((item, index) => (
          <Box key={`${item.test_case}-${index}`} sx={{ mb: 0.75 }}>
            <Typography variant="body2" color="text.secondary">
              {item.reason || 'The report contains evidence for this finding.'}
            </Typography>
            {item.request_condition && (
              <Typography variant="body2" color="text.secondary">
                Test condition: {item.request_condition}
              </Typography>
            )}
            {item.unverified && (
              <Typography variant="body2" color="text.secondary">
                Limitation: {item.unverified}
              </Typography>
            )}
          </Box>
        ))}
        <Typography variant="subtitle2" sx={{ mt: 2 }}>Test status and scope</Typography>
        <Typography variant="body2" color="text.secondary">
          Finding status: {statusLabel}. Endpoint assessment: {endpoint?.assessment ?? 'Not reported'}.
          {endpoint?.reason ? ` — ${endpoint.reason}` : ''}
        </Typography>
        <Typography variant="body2" color="text.secondary">
          Test case: {[...new Set(findings.map((item) => item.test_case).filter(Boolean))].join(', ') || 'Not reported'}
        </Typography>
        {identityEvidence.length > 0 && (
          <>
            <Typography variant="subtitle2" sx={{ mt: 2 }}>Observed owner / identity comparison</Typography>
            <Box component="pre" sx={technicalEvidenceStyle}>
              {JSON.stringify(identityEvidence, null, 2)}
            </Box>
          </>
        )}
        {findings.some((item) => item.evidence) && (
          <Box component="details" sx={{ mt: 2 }}>
            <Box component="summary" sx={{ cursor: 'pointer', fontWeight: 600 }}>
              View sanitized request / response evidence
            </Box>
            {findings.filter((item) => item.evidence).map((item, index) => (
              <Box key={`${item.test_case}-${index}`} component="pre" sx={technicalEvidenceStyle}>
                {JSON.stringify(item.evidence, null, 2)}
              </Box>
            ))}
          </Box>
        )}
        <Typography variant="subtitle2" sx={{ mt: 2 }}>Recommended remediation</Typography>
        {findings.map((item, index) => (
          <Typography key={`${item.test_case}-recommendation-${index}`} variant="body2">
            {item.recommendation || 'Review and enforce the intended authorization policy.'}
          </Typography>
        ))}
        {target && (
          <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 2 }}>
            Scan target: {target}
          </Typography>
        )}
        <Box component="button" type="button" onClick={onClose} sx={reportButtonStyle}>
          Close details
        </Box>
      </CardContent>
    </Card>
  )
}

const technicalEvidenceStyle = {
  mt: 1,
  p: 1.5,
  borderRadius: 1,
  backgroundColor: '#0B1120',
  color: '#CBD5E1',
  whiteSpace: 'pre-wrap',
  overflowWrap: 'anywhere',
  fontSize: '0.8rem',
}

const reportButtonStyle = {
  mt: 2,
  px: 1.5,
  py: 0.75,
  border: '1px solid #475569',
  borderRadius: 1,
  color: 'inherit',
  backgroundColor: 'transparent',
  cursor: 'pointer',
  font: 'inherit',
  '&:focus-visible': { outline: '2px solid #38BDF8', outlineOffset: 2 },
}

function FindingGroups({ findings, onSelect }) {
  if (findings.length === 0) {
    return (
      <Alert severity="info" sx={{ mt: 2 }}>
        No confirmed or potential findings were reported. Review coverage limitations before interpreting this as a clean scan.
      </Alert>
    )
  }

  const groups = new Map()
  findings.forEach((finding, index) => {
    const name = finding.name || 'Other security finding'
    if (!groups.has(name)) groups.set(name, [])
    groups.get(name).push({ finding, index })
  })

  return (
    <Box sx={{ mt: 2 }}>
      {[...groups.entries()].map(([name, entries]) => {
        const statuses = [...new Set(entries.map(({ finding }) => finding.status))]
        const groupStatus = statuses.length > 1
          ? 'Mixed status'
          : statuses[0] === 'confirmed'
            ? 'Confirmed'
            : statuses[0] === 'potential'
              ? 'Potential'
              : 'Inconclusive'
        const endpoints = new Set(entries.map(({ finding }) => `${finding.method} ${finding.endpoint}`))
        const assessedSeverity = entries
          .map(({ finding }) => finding.severity)
          .find((severity) => typeof severity === 'string' && severity.trim())

        return (
          <Box
            component="details"
            key={name}
            sx={{ mb: 1, border: '1px solid #334155', borderRadius: 1, px: 1.5, py: 1 }}
          >
            <Box
              component="summary"
              sx={{ cursor: 'pointer', '&:focus-visible': { outline: '2px solid #38BDF8' } }}
            >
              <Box sx={{ display: 'inline-flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
                <Typography component="span" variant="subtitle1" sx={{ fontWeight: 600 }}>{name}</Typography>
                <Chip
                  label={groupStatus}
                  size="small"
                  color={statuses.includes('confirmed') ? 'error' : 'warning'}
                  variant="outlined"
                />
                {assessedSeverity && <Chip label={assessedSeverity} size="small" variant="outlined" />}
                <Typography component="span" variant="body2" color="text.secondary">
                  {endpoints.size} affected endpoint{endpoints.size === 1 ? '' : 's'}
                </Typography>
              </Box>
              <Typography display="block" variant="body2" color="text.secondary" sx={{ mt: 0.75 }}>
                {findingDescription(name)}
              </Typography>
            </Box>
            <Box sx={{ display: 'grid', gap: 0.75, mt: 1.5 }}>
              {entries.map(({ finding, index }) => (
                <Box
                  component="button"
                  type="button"
                  key={finding.finding_id ?? `${finding.method}-${finding.endpoint}-${finding.test_case}-${index}`}
                  onClick={() => onSelect(finding)}
                  sx={{
                    ...reportButtonStyle,
                    mt: 0,
                    textAlign: 'left',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    gap: 1,
                  }}
                >
                  <span>{finding.method} {finding.endpoint}</span>
                  <Chip
                    label={finding.status === 'confirmed' ? 'Confirmed' : 'Potential'}
                    size="small"
                    color={finding.status === 'confirmed' ? 'error' : 'warning'}
                  />
                </Box>
              ))}
            </Box>
          </Box>
        )
      })}
    </Box>
  )
}

function ReportOverview({ summary, target, findings, fileDiscoveryError }) {
  const limitations = Array.isArray(summary.coverage_limitations)
    ? summary.coverage_limitations
    : []
  const discovered = summary.discovered_endpoints ?? summary.total_endpoints
  const tested = summary.tested_endpoints
  const endpointCoverageIncomplete =
    typeof discovered === 'number' && typeof tested === 'number' && tested < discovered
  const discoveryErrors = Object.values(summary.discovery_errors ?? {}).filter(
    (message) => typeof message === 'string' && message,
  )
  const incomplete = summary.coverage_complete === false ||
    summary.overall_conclusion?.code === 'scan_failed' ||
    limitations.length > 0 ||
    endpointCoverageIncomplete ||
    discoveryErrors.length > 0 ||
    Boolean(fileDiscoveryError)

  return (
    <Box>
      <Alert severity={incomplete ? 'warning' : 'info'} sx={{ mb: 2 }}>
        <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
          {summary.overall_conclusion?.label ?? 'Scan completed'}
        </Typography>
        {summary.overall_conclusion?.message && (
          <Typography variant="body2">{summary.overall_conclusion.message}</Typography>
        )}
      </Alert>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5 }}>
        Target: {target || 'Not reported'}
      </Typography>
      <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 1.5 }}>
        {[
          ['Confirmed findings', summary.confirmed_findings ?? findings.filter((item) => item.status === 'confirmed').length],
          ['Potential findings', summary.potential_findings ?? findings.filter((item) => item.status === 'potential').length],
          ['Endpoints tested / discovered', `${summary.tested_endpoints ?? 0} / ${summary.discovered_endpoints ?? summary.total_endpoints ?? 0}`],
        ].map(([label, value]) => (
          <Card key={label} variant="outlined">
            <CardContent sx={{ '&:last-child': { pb: 2 } }}>
              <Typography color="text.secondary" variant="body2">{label}</Typography>
              <Typography variant="h5" sx={{ mt: 0.5 }}>{value}</Typography>
            </CardContent>
          </Card>
        ))}
      </Box>
      {incomplete && (
        <Alert severity="warning" sx={{ mt: 2 }}>
          <Typography variant="subtitle2">Coverage may be incomplete</Typography>
          {limitations.length > 0 ? limitations.map((limitation) => (
            <Typography key={limitation} variant="body2">{limitation}</Typography>
          )) : endpointCoverageIncomplete ? (
            <Typography variant="body2">
              {tested} of {discovered} discovered endpoints were tested.
            </Typography>
          ) : (
            <Typography variant="body2">
              {summary.failure_reason || 'Some scan stages were incomplete or returned errors.'}
            </Typography>
          )}
          {discoveryErrors.map((message, index) => (
            <Typography key={`discovery-warning-${index}`} variant="body2">{message}</Typography>
          ))}
          {fileDiscoveryError && <Typography variant="body2">{fileDiscoveryError}</Typography>}
        </Alert>
      )}
    </Box>
  )
}

function ExecutiveSummary({ summary }) {
  const conclusion = summary.overall_conclusion
  const metrics = [
    ['Confirmed findings', summary.confirmed_findings ?? 0],
    ['Potential findings', summary.potential_findings ?? 0],
    ['Endpoints discovered by analysis', summary.discovered_endpoints ?? 0],
    ['Unique discovery endpoints', summary.unique_discovery_endpoints ?? 0],
    ['Discovery inventory records', summary.discovery_inventory_records ?? summary.discovery_inventory_endpoints ?? 0],
    ['Security input endpoints', summary.security_input_endpoints ?? 0],
    ['Endpoints selected', summary.selected_endpoints ?? 0],
    ['Endpoints with test requests', summary.attempted_endpoints ?? 0],
    ['Endpoints actually tested', summary.tested_endpoints ?? 0],
    ['Discovered endpoints skipped', summary.discovery_skipped_endpoints ?? 0],
    ['Endpoints partially tested', summary.partially_tested_endpoints ?? 0],
    ['Endpoints inconclusive', summary.inconclusive_endpoints ?? 0],
    ['Endpoints untested / skipped', summary.untested_endpoints ?? 0],
    ['Test cases attempted', summary.test_cases_attempted ?? 0],
    ['JWT endpoint requests sent', summary.request_count ?? 0],
    ['Not detected in this test', summary.not_detected_test_cases ?? 0],
    ['Test cases confirmed', summary.confirmed_test_cases ?? 0],
    ['Test cases potential', summary.potential_test_cases ?? 0],
    ['Test cases inconclusive', summary.inconclusive_tests ?? 0],
    ['Test cases errored', summary.error_tests ?? 0],
    ['Test cases skipped', summary.skipped_tests ?? 0],
    ['Test cases not implemented', summary.not_implemented_test_cases ?? 0],
  ]

  return (
    <Box sx={{ mt: 2 }}>
      <Alert
        severity={
          conclusion?.code === 'vulnerabilities_confirmed' || conclusion?.code === 'scan_failed'
            ? 'error'
            : conclusion?.code === 'potential_vulnerabilities_found'
              ? 'warning'
              : conclusion?.code === 'no_vulnerabilities_detected_in_tested_scope'
                ? 'success'
                : 'info'
        }
      >
        <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
          {conclusion?.label ?? 'Inconclusive — Further Testing Required'}
        </Typography>
        {conclusion?.message && (
          <Typography variant="body2">{conclusion.message}</Typography>
        )}
        {summary.failure_reason && (
          <Typography variant="body2" sx={{ mt: 1 }}>
            Failure: {summary.failure_reason}
          </Typography>
        )}
      </Alert>
      <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(145px, 1fr))', gap: 1, mt: 2 }}>
        {metrics.map(([label, value]) => (
          <Box
            key={label}
            sx={{ p: 1.5, border: '1px solid #334155', borderRadius: 1 }}
          >
            <Typography color="text.secondary" variant="body2">
              {label}
            </Typography>
            <Typography variant="h6">{value}</Typography>
          </Box>
        ))}
      </Box>
      <Typography color="text.secondary" variant="body2" sx={{ mt: 2 }}>
        Discovered endpoints: {summary.discovered_endpoints ?? 0}. Scope: {summary.scope ?? 'Not reported.'}
      </Typography>
      <Typography color="text.secondary" variant="body2">
        Request count: {summary.request_count_scope ?? 'Request scope not reported.'}
      </Typography>
      <Typography color="text.secondary" variant="body2">
        {summary.test_case_count_note ?? 'Skipped and not-implemented cases are separate counts.'}
      </Typography>
      {summary.coverage_limitations?.length > 0 && (
        <Box sx={{ mt: 1 }}>
          <Typography variant="subtitle2">Coverage limitations</Typography>
          {summary.coverage_limitations.map((limitation) => (
            <Typography key={limitation} color="text.secondary" variant="body2">
              • {limitation}
            </Typography>
          ))}
        </Box>
      )}
      {summary.jwt_authentication_workflow && (
        <Box
          sx={{
            mt: 2,
            p: 1.5,
            border: '1px solid #334155',
            borderRadius: 1,
          }}
        >
          <Typography variant="subtitle2">JWT authentication workflow</Typography>
          <Typography color="text.secondary" variant="body2">
            Login discovery: {summary.jwt_authentication_workflow.login_discovery_status}.
            {' '}Selected route: {summary.jwt_authentication_workflow.selected_login_route
              ? `${summary.jwt_authentication_workflow.selected_login_method} ${summary.jwt_authentication_workflow.selected_login_route}`
              : 'none'}.
            {' '}Attempt: {summary.jwt_authentication_workflow.login_attempt_status}.
            {' '}Authentication: {summary.jwt_authentication_workflow.authentication_result}.
            {' '}Token/session detected: {summary.jwt_authentication_workflow.token_or_session_detected ? 'yes' : 'no'}.
          </Typography>
          {summary.jwt_authentication_workflow.selected_login_evidence_source?.length > 0 && (
            <Typography color="text.secondary" variant="body2">
              Evidence source: {summary.jwt_authentication_workflow.selected_login_evidence_source.join(', ')}
            </Typography>
          )}
          <Typography color="text.secondary" variant="body2">
            JWT endpoint coverage: {summary.jwt_authentication_workflow.eligible_endpoints} eligible,{' '}
            {summary.jwt_authentication_workflow.selected_endpoints} selected,{' '}
            {summary.jwt_authentication_workflow.actually_tested_endpoints} tested;{' '}
            {summary.jwt_authentication_workflow.request_count} endpoint requests.
          </Typography>
          {summary.jwt_authentication_workflow.login_attempts?.map((attempt, index) => (
            <Typography
              key={`${attempt.method}-${attempt.path}-${index}`}
              color="text.secondary"
              variant="body2"
            >
              {attempt.method} {attempt.path}: {attempt.status}
              {attempt.http_status ? ` (HTTP ${attempt.http_status})` : ''}
              {attempt.reason ? ` — ${attempt.reason}` : ''}
            </Typography>
          ))}
        </Box>
      )}
    </Box>
  )
}

function App() {
  const [target, setTarget] = useState('http://localhost:3000')
  const [additionalScopeOrigins, setAdditionalScopeOrigins] = useState('')
  const [searchQuery, setSearchQuery] = useState('')
  const [scanResults, setScanResults] = useState([])
  const [scanResultsTarget, setScanResultsTarget] = useState('')
  const [scanDiscoveryResults, setScanDiscoveryResults] = useState([])
  const [scanStages, setScanStages] = useState([])
  const [findings, setFindings] = useState([])
  const [endpointAssessments, setEndpointAssessments] = useState([])
  const [bolaAssessments, setBolaAssessments] = useState([])
  const [bolaBaselines, setBolaBaselines] = useState([])
  const [bolaActiveTests, setBolaActiveTests] = useState([])
  const [summary, setSummary] = useState({})
  const [selectedFinding, setSelectedFinding] = useState(null)
  const [scanCount, setScanCount] = useState(0)
  const [activePage, setActivePage] = useState('Dashboard')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [fileTarget, setFileTarget] = useState('http://localhost:3000')
  const [gatewayTarget, setGatewayTarget] = useState('http://localhost:8085')
  const [useDefaultWordlist, setUseDefaultWordlist] = useState(true)
  const [customWordlist, setCustomWordlist] = useState('')
  const [requestsPerSecond, setRequestsPerSecond] = useState(2)
  const [fileTimeout, setFileTimeout] = useState(5)
  const [fileConcurrency, setFileConcurrency] = useState(2)
  const [verifyEndpoints, setVerifyEndpoints] = useState(false)
  const [includeKiterunner, setIncludeKiterunner] = useState(false)
  const [fileDiscoveryResults, setFileDiscoveryResults] = useState([])
  const [fileDiscoverySummary, setFileDiscoverySummary] = useState({})
  const [fileDiscoveryError, setFileDiscoveryError] = useState('')
  const [fileDiscoveryLoading, setFileDiscoveryLoading] = useState(false)
  const [sourceFilter, setSourceFilter] = useState('all')
  const [verificationFilter, setVerificationFilter] = useState('all')
  const [discoveryCategoryFilter, setDiscoveryCategoryFilter] = useState('actionable')
  const [apiMapCategory, setApiMapCategory] = useState('actionable')
  const [statusFilter, setStatusFilter] = useState('')

  useEffect(() => {
    if (selectedFinding) {
      document.getElementById('finding-detail')?.scrollIntoView({ block: 'nearest' })
    }
  }, [selectedFinding])

  const endpointSummary = useMemo(() => {
    const discovered = scanResults.filter((item) => item.discovered !== false)
    const total = discovered.length
    const auth = discovered.filter((item) => item.classification === 'authentication').length
    const resource = discovered.filter((item) => item.classification === 'resource_by_id' || item.classification === 'resource_collection').length
    return { total, auth, resource }
  }, [scanResults])

  const runScan = async () => {
    const scanTarget = target.trim()
    if (!scanTarget) {
      setError('Enter a valid target such as localhost:8085 or https://example.com.')
      return
    }

    setLoading(true)
    setError('')
    setScanStages([])

    try {
      const extraOrigins = additionalScopeOrigins
        .split(/[\n,]+/)
        .map((origin) => origin.trim())
        .filter(Boolean)
      const scanParams = new URLSearchParams({
        target: scanTarget,
        num: '200',
        auto_jwt_local_lab: 'true',
        stream: 'true',
      })
      extraOrigins.forEach((origin) => scanParams.append('scope_origins', origin))
      const response = await fetch(
        `${backendUrl}/scan?${scanParams.toString()}`
      )

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`)
      }

      const reader = response.body?.getReader()
      if (!reader) throw new Error('The scan progress stream is unavailable.')
      const decoder = new TextDecoder()
      let buffer = ''
      let completed = null
      let streamError = null

      const handleEvent = (block) => {
        const dataLine = block.split('\n').find((line) => line.startsWith('data: '))
        if (!dataLine) return
        const event = JSON.parse(dataLine.slice(6))
        if (event.type === 'progress') {
          setScanStages((current) => {
            const index = current.findIndex((stage) => stage.stage === event.stage)
            if (index < 0) return [...current, event]
            return current.map((stage, stageIndex) =>
              stageIndex === index ? event : stage
            )
          })
        } else if (event.type === 'complete') {
          completed = event
        } else if (event.type === 'error') {
          streamError = new Error(event.detail || `HTTP ${event.status_code}`)
        }
      }

      while (true) {
        const { done, value } = await reader.read()
        buffer += decoder.decode(value ?? new Uint8Array(), { stream: !done })
        const blocks = buffer.split('\n\n')
        buffer = blocks.pop() ?? ''
        blocks.forEach(handleEvent)
        if (done) break
      }
      if (buffer.trim()) handleEvent(buffer)
      if (streamError) throw streamError
      if (!completed) throw new Error('The scan ended before returning its report.')

      const payload = completed.payload
      setScanStages(payload.discovery_stages ?? [])
      setScanResults(payload.results ?? [])
      setScanResultsTarget(scanTarget)
      setScanDiscoveryResults(payload.discovery_results ?? [])
      setFileDiscoveryResults(payload.discovery_results ?? [])
      setFileDiscoverySummary(payload.discovery_summary ?? {})
      setFileDiscoveryError(payload.discovery_errors?.file_discovery ?? '')
      setFindings(payload.findings ?? [])
      setSelectedFinding(null)
      setEndpointAssessments(payload.endpoint_assessments ?? [])
      setBolaAssessments(payload.bola_assessments ?? [])
      setBolaBaselines(payload.bola_baselines ?? [])
      setBolaActiveTests(payload.bola_active_tests ?? [])
      setSummary(payload.summary ?? {})
      setScanCount((count) => count + 1)
      setActivePage('Reports')
      if (completed.status_code !== 200) {
        throw new Error(payload?.detail || `HTTP ${completed.status_code}`)
      }
    } catch (caughtError) {
      setError(caughtError.message || 'The scan could not be completed.')
    } finally {
      setLoading(false)
    }
  }

  const runFileDiscovery = async () => {
    setFileDiscoveryLoading(true)
    setFileDiscoveryError('')

    try {
      const response = await fetch(`${backendUrl}/file-discovery`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target: fileTarget.trim(),
          wordlist: useDefaultWordlist ? null : customWordlist,
          requests_per_second: Number(requestsPerSecond),
          timeout: Number(fileTimeout),
          concurrency: Number(fileConcurrency),
          analyze_javascript: true,
          verify_endpoints: verifyEndpoints,
          gateway_target: verifyEndpoints ? gatewayTarget.trim() : null,
        }),
      })
      const payload = await response.json()
      if (!response.ok) {
        throw new Error(payload?.detail || `HTTP ${response.status}`)
      }

      setFileDiscoveryResults(payload.results ?? [])
      setFileDiscoverySummary(payload.summary ?? {})
    } catch (caughtError) {
      setFileDiscoveryError(caughtError.message || 'File Discovery could not be completed.')
    } finally {
      setFileDiscoveryLoading(false)
    }
  }

  const totalPotentialFindings =
    summary.potential_findings ??
    findings.filter((item) => item.status === 'potential').length
  const apiMapResults = (Array.isArray(scanDiscoveryResults) ? scanDiscoveryResults : [])
    .filter((item) => getApiMapPath(item))
  const notFoundDiscoveryResults = filterDiscoveryResults(scanDiscoveryResults, 'not_found')
  const mergedFileResults = mergeDiscoveryResults(
    fileDiscoveryResults,
    includeKiterunner ? scanResults : [],
    gatewayTarget,
    scanResultsTarget,
  )
  const visibleFileResults = filterDiscoveryResults(
    mergedFileResults,
    discoveryCategoryFilter,
  ).filter((item) => {
    const sourceMatches = sourceFilter === 'all' || item.sources?.includes(sourceFilter)
    const verificationMatches =
      verificationFilter === 'all' || item.verification_status === verificationFilter
    const statusMatches =
      !statusFilter || String(item.status_code ?? '').startsWith(statusFilter)
    return sourceMatches && verificationMatches && statusMatches
  })
  const visibleScanDiscoveryResults = filterDiscoveryResults(
    scanDiscoveryResults,
    discoveryCategoryFilter,
  ).filter((item) => {
    const sourceMatches = sourceFilter === 'all' || item.sources?.includes(sourceFilter)
    const verificationMatches =
      verificationFilter === 'all' || item.verification_status === verificationFilter
    const statusMatches =
      !statusFilter || String(item.status_code ?? '').startsWith(statusFilter)
    const searchable = [
      item.url,
      item.resolved_url,
      item.template,
      item.method,
      ...(Array.isArray(item.sources) ? item.sources : []),
    ].filter(Boolean).join(' ').toLowerCase()
    return sourceMatches && verificationMatches && statusMatches &&
      searchable.includes(searchQuery.trim().toLowerCase())
  })

  return (
    <Box sx={{ display: 'flex', minHeight: '100vh' }}>
      <Drawer
        variant="permanent"
        sx={{
          width: drawerWidth,
          '& .MuiDrawer-paper': {
            width: drawerWidth,
            boxSizing: 'border-box',
            backgroundColor: '#0F172A',
            borderRight: '1px solid #1E293B',
          },
        }}
      >
        <Toolbar>
          <Typography variant="h6" sx={{ fontWeight: 700, color: 'primary.main', letterSpacing: 1 }}>
            ◈ MICROSCAN
          </Typography>
        </Toolbar>

        <List sx={{ px: 1 }}>
          {['Dashboard', 'Scan', 'API Map', 'Reports', 'Settings'].map((page) => (
            <ListItem key={page} disablePadding>
              <ListItemButton
                selected={activePage === page}
                onClick={() => setActivePage(page)}
                sx={{
                  borderRadius: 1,
                  mb: 0.5,
                  '&.Mui-selected': {
                    backgroundColor: '#1E293B',
                    color: '#38BDF8',
                  },
                  '&.Mui-selected:hover': {
                    backgroundColor: '#334155',
                  },
                }}
              >
                <ListItemText primary={page} />
              </ListItemButton>
            </ListItem>
          ))}
        </List>
      </Drawer>

      <Box
        component="main"
        sx={{
          flexGrow: 1,
          p: 3,
          minWidth: 0,
          backgroundColor: 'background.default',
          color: 'text.primary',
        }}
      >
        <Typography variant="h4" sx={{ fontWeight: 700, mb: 1, color: '#E5E7EB' }}>
          {activePage === 'Dashboard' && 'Security Dashboard'}
          {activePage === 'Scan' && 'Endpoint Discovery'}
          {activePage === 'File Discovery' && 'File Discovery'}
          {activePage === 'API Map' && 'API Endpoint Map'}
          {activePage === 'Reports' && 'Scan Reports'}
          {activePage === 'Settings' && 'Settings'}
        </Typography>

        <Typography sx={{ mb: 4, color: '#94A3B8' }}>
          {activePage === 'Dashboard' && 'Web & Microservice Security Scanner'}
          {activePage === 'Scan' && 'Discover API endpoints with Kiterunner'}
          {activePage === 'File Discovery' && 'Find common files and analyze frontend JavaScript'}
          {activePage === 'API Map' && 'Visualize discovered API endpoints by path and HTTP method'}
          {activePage === 'Reports' && 'Review your previous scan results'}
          {activePage === 'Settings' && 'Configure your scanner'}
        </Typography>

        {error && (
          <Alert severity="error" sx={{ mb: 3 }}>
            {error}
          </Alert>
        )}

        {activePage === 'Dashboard' && (
          <>
            <Box sx={{ display: 'flex', gap: 3, flexWrap: 'wrap' }}>
              <Card sx={{ flex: '1 1 180px' }}>
                <CardContent>
                  <Typography color="text.secondary">Endpoints</Typography>
                  <Typography variant="h3" sx={{ mt: 1, fontWeight: 700 }}>
                    {endpointSummary.total}
                  </Typography>
                </CardContent>
              </Card>

              <Card sx={{ flex: '1 1 180px' }}>
                <CardContent>
                  <Typography color="text.secondary">Potential findings</Typography>
                  <Typography variant="h3" sx={{ mt: 1, fontWeight: 700 }}>
                    {totalPotentialFindings}
                  </Typography>
                  <Typography color="text.secondary" variant="body2">
                    From executed test cases; {summary.untested_endpoints ?? 0} discovered endpoints remain untested.
                  </Typography>
                </CardContent>
              </Card>

              <Card sx={{ flex: '1 1 180px' }}>
                <CardContent>
                  <Typography color="text.secondary">Scans</Typography>
                  <Typography variant="h3" sx={{ mt: 1, fontWeight: 700 }}>
                    {scanCount}
                  </Typography>
                </CardContent>
              </Card>
            </Box>

            <Card sx={{ mt: 4 }}>
              <CardContent>
                <Typography variant="h6" sx={{ mb: 1 }}>
                  Discovery summary
                </Typography>
                <Typography color="text.secondary">
                  {endpointSummary.auth} authentication endpoints, {endpointSummary.resource} resource endpoints, and {endpointSummary.total} total endpoints discovered.
                </Typography>
              </CardContent>
            </Card>
          </>
        )}

        {activePage === 'Scan' && (
          <>
            <Typography variant="h6" sx={{ mb: 2 }}>
              Scan Target
            </Typography>

            <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
              <Box
                component="input"
                placeholder="localhost:8085"
                value={target}
                onChange={(event) => setTarget(event.target.value)}
                sx={{
                  flex: '1 1 250px',
                  minWidth: 0,
                  px: 2,
                  py: 1.5,
                  borderRadius: 1,
                  border: '1px solid #334155',
                  backgroundColor: '#111827',
                  color: '#E5E7EB',
                  fontSize: '1rem',
                }}
              />

              <Box
                component="details"
                sx={{ flexBasis: '100%', mt: 1, color: 'text.secondary' }}
              >
                <Box component="summary" sx={{ cursor: 'pointer' }}>
                  Advanced settings
                </Box>
                <Typography sx={{ mt: 1, mb: 1 }} variant="body2">
                  Additional origins you are authorized to scan (optional, comma or newline separated).
                </Typography>
                <Box
                  component="textarea"
                  value={additionalScopeOrigins}
                  onChange={(event) => setAdditionalScopeOrigins(event.target.value)}
                  placeholder="https://api.example.test"
                  rows={2}
                  aria-label="Additional authorized scan origins"
                  sx={{
                    boxSizing: 'border-box',
                    width: '100%',
                    maxWidth: 700,
                    p: 1.5,
                    borderRadius: 1,
                    border: '1px solid #334155',
                    backgroundColor: '#111827',
                    color: '#E5E7EB',
                    font: 'inherit',
                  }}
                />
                <Typography variant="caption" display="block" sx={{ mt: 1 }}>
                  Recursion and request limits are enforced by the backend. Discovered origins never
                  expand the authorized scope.
                </Typography>
              </Box>

              <Typography sx={{ flexBasis: '100%' }} color="text.secondary" variant="body2">
                {target.includes('localhost') || target.includes('127.0.0.1') || target.includes('::1')
                  ? 'Scanning configured local lab scope.'
                  : 'Scanning the entered origin; discovered origins will not expand scope.'}
              </Typography>

              <Box
                component="button"
                disabled={loading}
                onClick={runScan}
                sx={{
                  px: 3,
                  py: 1.5,
                  border: 'none',
                  borderRadius: 1,
                  backgroundColor: loading ? '#475569' : 'primary.main',
                  color: '#0B1120',
                  fontWeight: 700,
                  cursor: loading ? 'default' : 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 1,
                }}
              >
                {loading && <CircularProgress size={16} color="inherit" />}
                {loading ? 'SCANNING...' : 'SCAN'}
              </Box>
            </Box>
            <DiscoveryProgress stages={scanStages} loading={loading} />
            <Box sx={{ mt: 4 }}>
              <Typography variant="h6" sx={{ mb: 2 }}>
                Discovery Summary
              </Typography>
              <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: 1, mb: 3 }}>
                {[
                  ['Discovery inventory records', summary.discovery_inventory_records ?? summary.discovery_inventory_endpoints ?? scanDiscoveryResults.length],
                  ['Actionable endpoints', summary.actionable_discovery_endpoints ?? 0],
                  ['Not Found excluded', summary.excluded_not_found_discovery_endpoints ?? 0],
                  ['Selected for testing', summary.selected_endpoints ?? 0],
                  ['Actually tested', summary.tested_endpoints ?? 0],
                  ['New routes', (summary.discovery_rounds ?? []).reduce((total, round) => total + (round.new_results ?? 0), 0)],
                  ['Duplicate results', (summary.discovery_rounds ?? []).reduce((total, round) => total + (round.duplicate_results ?? 0), 0)],
                  ['Failed / skipped stages', scanStages.filter((stage) => ['failed', 'error', 'skipped'].includes(stage.status)).length],
                ].map(([label, value]) => (
                  <Box key={label} sx={{ p: 1.5, border: '1px solid #334155', borderRadius: 1 }}>
                    <Typography color="text.secondary" variant="body2">{label}</Typography>
                    <Typography variant="h6">{value}</Typography>
                  </Box>
                ))}
              </Box>
            </Box>

            <Typography variant="h6" sx={{ mb: 1 }}>
              Discovered Endpoints ({visibleScanDiscoveryResults.length})
            </Typography>
            <Box
              component="input"
              aria-label="Search discovered endpoints"
              placeholder="Search path, origin, method, or source"
              value={searchQuery}
              onChange={(event) => setSearchQuery(event.target.value)}
              sx={{
                boxSizing: 'border-box',
                width: '100%',
                maxWidth: 520,
                px: 1.5,
                py: 1,
                mb: 2,
                borderRadius: 1,
                border: '1px solid #334155',
                backgroundColor: '#111827',
                color: '#E5E7EB',
              }}
            />
            <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap', mb: 2 }}>
              <DiscoveryCategoryFilter
                id="scan-discovery-category"
                value={discoveryCategoryFilter}
                onChange={setDiscoveryCategoryFilter}
              />
            </Box>
            <DiscoveryResultsTable results={visibleScanDiscoveryResults} />
            <Box component="details" sx={{ mt: 2 }}>
              <Box component="summary" sx={{ cursor: 'pointer' }}>
                Excluded / Not Found ({notFoundDiscoveryResults.length})
              </Box>
              <Typography color="text.secondary" variant="body2" sx={{ my: 1 }}>
                Raw discovery observations and status codes are retained here for audit; these routes are not included in security testing.
              </Typography>
              <DiscoveryResultsTable results={notFoundDiscoveryResults} />
            </Box>

            <Card sx={{ mt: 4 }}>
              <CardContent>
                <Typography variant="h6">Pentest Analysis</Typography>
                <ExecutiveSummary summary={summary} />
                <Typography variant="subtitle1" sx={{ mt: 3, fontWeight: 700 }}>
                  Vulnerability findings
                </Typography>
                <VulnerabilityFindings findings={findings} />
                <Typography variant="subtitle1" sx={{ mt: 3, fontWeight: 700 }}>
                  Endpoint assessments and test cases
                </Typography>
                <EndpointAssessments assessments={endpointAssessments} />
                <BolaCorrelationResults
                  assessments={bolaAssessments}
                  baselines={bolaBaselines}
                  activeTests={bolaActiveTests}
                  summary={summary}
                />
              </CardContent>
            </Card>
          </>
        )}

        {activePage === 'File Discovery' && (
          <>
            <Alert severity="info" sx={{ mb: 2 }}>
              File and endpoint discovery now runs automatically from the main Scan action. This page remains an optional manual/debug tool; its findings also appear in the latest scan report.
            </Alert>
            <Card>
              <CardContent>
                <Typography variant="h6" sx={{ mb: 2 }}>
                  Discovery scope and limits
                </Typography>
                <Typography color="text.secondary" variant="body2" sx={{ mb: 2 }}>
                  Requests are restricted to localhost on lab ports 3000 and 8085. The frontend
                  target is used to read HTML and same-origin scripts. Gateway verification is
                  optional and uses the Gateway origin entered below. Redirects are not followed.
                </Typography>

                <Box sx={{ display: 'grid', gap: 2, gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))' }}>
                  <Box>
                    <Typography variant="body2" sx={{ mb: 0.5 }}>Frontend target URL</Typography>
                    <Box
                      component="input"
                      value={fileTarget}
                      onChange={(event) => setFileTarget(event.target.value)}
                      placeholder="http://localhost:3000"
                      sx={{ width: '100%', boxSizing: 'border-box', px: 1.5, py: 1.2, borderRadius: 1, border: '1px solid #334155', backgroundColor: '#111827', color: '#E5E7EB' }}
                    />
                  </Box>
                  <FormControl fullWidth size="small">
                    <InputLabel id="file-wordlist-label">Wordlist</InputLabel>
                    <Select
                      labelId="file-wordlist-label"
                      value={useDefaultWordlist ? 'default' : 'custom'}
                      label="Wordlist"
                      onChange={(event) => setUseDefaultWordlist(event.target.value === 'default')}
                    >
                      <MenuItem value="default">MicroScan default</MenuItem>
                      <MenuItem value="custom">Custom paths</MenuItem>
                    </Select>
                  </FormControl>
                  <Box>
                    <Typography variant="body2" sx={{ mb: 0.5 }}>Request rate (per second, max 5)</Typography>
                    <Box component="input" type="number" min="0.5" max="5" step="0.5" value={requestsPerSecond} onChange={(event) => setRequestsPerSecond(event.target.value)} sx={{ width: '100%', boxSizing: 'border-box', px: 1.5, py: 1.2, borderRadius: 1, border: '1px solid #334155', backgroundColor: '#111827', color: '#E5E7EB' }} />
                  </Box>
                  <Box>
                    <Typography variant="body2" sx={{ mb: 0.5 }}>Timeout (seconds, max 15)</Typography>
                    <Box component="input" type="number" min="1" max="15" value={fileTimeout} onChange={(event) => setFileTimeout(event.target.value)} sx={{ width: '100%', boxSizing: 'border-box', px: 1.5, py: 1.2, borderRadius: 1, border: '1px solid #334155', backgroundColor: '#111827', color: '#E5E7EB' }} />
                  </Box>
                  <Box>
                    <Typography variant="body2" sx={{ mb: 0.5 }}>Concurrent requests (max 5)</Typography>
                    <Box component="input" type="number" min="1" max="5" value={fileConcurrency} onChange={(event) => setFileConcurrency(event.target.value)} sx={{ width: '100%', boxSizing: 'border-box', px: 1.5, py: 1.2, borderRadius: 1, border: '1px solid #334155', backgroundColor: '#111827', color: '#E5E7EB' }} />
                  </Box>
                </Box>

                {!useDefaultWordlist && (
                  <Box
                    component="textarea"
                    aria-label="Custom wordlist"
                    placeholder={'robots.txt\nsitemap.xml\napi/v1'}
                    value={customWordlist}
                    onChange={(event) => setCustomWordlist(event.target.value)}
                    sx={{ width: '100%', boxSizing: 'border-box', mt: 2, minHeight: 120, p: 1.5, borderRadius: 1, border: '1px solid #334155', backgroundColor: '#111827', color: '#E5E7EB', fontFamily: 'monospace' }}
                  />
                )}

                <FormControlLabel
                  sx={{ display: 'flex', mt: 1 }}
                  control={<Checkbox checked={verifyEndpoints} onChange={(event) => setVerifyEndpoints(event.target.checked)} />}
                  label="Verify JavaScript endpoints on the Gateway (GET only)"
                />
                {verifyEndpoints && (
                  <Box sx={{ mt: 1, maxWidth: 520 }}>
                    <Typography variant="body2" sx={{ mb: 0.5 }}>Gateway target URL</Typography>
                    <Box component="input" value={gatewayTarget} onChange={(event) => setGatewayTarget(event.target.value)} placeholder="http://localhost:8085" sx={{ width: '100%', boxSizing: 'border-box', px: 1.5, py: 1.2, borderRadius: 1, border: '1px solid #334155', backgroundColor: '#111827', color: '#E5E7EB' }} />
                  </Box>
                )}

                <FormControlLabel
                  sx={{ display: 'flex', mt: 1 }}
                  control={<Checkbox checked={includeKiterunner} onChange={(event) => setIncludeKiterunner(event.target.checked)} />}
                  label="Include results from the current Kiterunner scan"
                />
                {includeKiterunner && normalizeOrigin(target) !== normalizeOrigin(gatewayTarget) && (
                  <Alert severity="info" sx={{ mt: 1 }}>
                    Kiterunner results are included only when the current Scan target and Gateway target have the same origin.
                  </Alert>
                )}

                <Box component="button" disabled={fileDiscoveryLoading} onClick={runFileDiscovery} sx={{ mt: 2, px: 3, py: 1.5, border: 'none', borderRadius: 1, backgroundColor: fileDiscoveryLoading ? '#475569' : 'primary.main', color: '#0B1120', fontWeight: 700, cursor: fileDiscoveryLoading ? 'default' : 'pointer', display: 'flex', alignItems: 'center', gap: 1 }}>
                  {fileDiscoveryLoading && <CircularProgress size={16} color="inherit" />}
                  {fileDiscoveryLoading ? 'DISCOVERING...' : 'START FILE DISCOVERY'}
                </Box>
                {fileDiscoveryLoading && (
                  <Typography role="status" color="text.secondary" variant="body2" sx={{ mt: 1 }}>
                    Scanning the bounded wordlist and analyzing same-origin JavaScript. This request cannot be cancelled once submitted.
                  </Typography>
                )}
              </CardContent>
            </Card>

            {fileDiscoveryError && <Alert severity="error" sx={{ mt: 2 }}>{fileDiscoveryError}</Alert>}

            <Card sx={{ mt: 3 }}>
              <CardContent>
                <Typography variant="h6" sx={{ mb: 2 }}>
                  Unified discovery results ({visibleFileResults.length})
                </Typography>
                {fileDiscoverySummary.requests_made !== undefined && (
                  <Typography color="text.secondary" variant="body2" sx={{ mb: 2 }}>
                    {fileDiscoverySummary.scripts_analyzed} JavaScript file(s) analyzed · {fileDiscoverySummary.requests_made} request(s) sent
                    {fileDiscoverySummary.execution_time_limited ? ' · execution time limit reached; remaining results are inconclusive' : ''}
                  </Typography>
                )}
                <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap', mb: 2 }}>
                  <DiscoveryCategoryFilter
                    id="file-discovery-category"
                    value={discoveryCategoryFilter}
                    onChange={setDiscoveryCategoryFilter}
                  />
                  <FormControl size="small" sx={{ minWidth: 190 }}>
                    <InputLabel id="file-source-label">Source</InputLabel>
                    <Select labelId="file-source-label" value={sourceFilter} label="Source" onChange={(event) => setSourceFilter(event.target.value)}>
                      <MenuItem value="all">All sources</MenuItem>
                      <MenuItem value="wordlist">Wordlist</MenuItem>
                      <MenuItem value="html">HTML</MenuItem>
                      <MenuItem value="javascript">JavaScript</MenuItem>
                      <MenuItem value="gateway_verification">Gateway verification</MenuItem>
                      <MenuItem value="kiterunner">Kiterunner</MenuItem>
                    </Select>
                  </FormControl>
                  <FormControl size="small" sx={{ minWidth: 190 }}>
                    <InputLabel id="file-verification-label">Verification</InputLabel>
                    <Select labelId="file-verification-label" value={verificationFilter} label="Verification" onChange={(event) => setVerificationFilter(event.target.value)}>
                      <MenuItem value="all">All states</MenuItem>
                      <MenuItem value="discovered">Discovered</MenuItem>
                      <MenuItem value="verified">Verified</MenuItem>
                      <MenuItem value="inconclusive">Inconclusive</MenuItem>
                      <MenuItem value="blocked">Blocked</MenuItem>
                      <MenuItem value="not_found">Not found</MenuItem>
                    </Select>
                  </FormControl>
                  <Box component="input" type="number" aria-label="Filter by status code" placeholder="Status code prefix" value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)} sx={{ width: 180, px: 1.5, borderRadius: 1, border: '1px solid #334155', backgroundColor: '#111827', color: '#E5E7EB' }} />
                </Box>
                <Card sx={{ overflowX: 'auto' }}>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell>URL</TableCell>
                        <TableCell>Method</TableCell>
                        <TableCell>Status</TableCell>
                        <TableCell>Content type</TableCell>
                        <TableCell>Source</TableCell>
                        <TableCell>Verification</TableCell>
                        <TableCell>Evidence</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {visibleFileResults.length === 0 ? (
                        <TableRow><TableCell colSpan={7} align="center">No matching discovery results.</TableCell></TableRow>
                      ) : visibleFileResults.map((item, index) => (
                        <TableRow key={`${item.method}-${item.url}-${index}`}>
                          <TableCell sx={{ maxWidth: 360, overflowWrap: 'anywhere' }}>{item.url}</TableCell>
                          <TableCell>{item.method ?? 'UNKNOWN'}</TableCell>
                          <TableCell>{item.status_code ?? '—'}</TableCell>
                          <TableCell>{item.content_type ?? '—'}</TableCell>
                          <TableCell>{(item.sources ?? []).map((source) => <Chip key={source} label={source} size="small" sx={{ mr: 0.5, mb: 0.5 }} />)}</TableCell>
                          <TableCell>{item.verification_status ?? 'discovered'}</TableCell>
                          <TableCell>
                            {item.evidence?.length ? (
                              <Box component="details">
                                <Box component="summary" sx={{ cursor: 'pointer' }}>View ({item.evidence.length})</Box>
                                {item.evidence.map((evidence, evidenceIndex) => (
                                  <Box key={`${evidence.source_url}-${evidenceIndex}`} sx={{ mt: 1, maxWidth: 360, overflowWrap: 'anywhere' }}>
                                    <Typography variant="caption" display="block">{evidence.source_url}</Typography>
                                    <Box component="pre" sx={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', fontSize: '0.75rem' }}>{evidence.snippet}</Box>
                                  </Box>
                                ))}
                              </Box>
                            ) : '—'}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </Card>
              </CardContent>
            </Card>
          </>
        )}

        {activePage === 'API Map' && (
          <ApiMapErrorBoundary>
            <Card>
              <CardContent>
                <Typography variant="h6" sx={{ mb: 1 }}>
                  Discovered API Structure
                </Typography>

                <Typography color="text.secondary" sx={{ mb: 3 }}>
                  Target: {target || 'No target selected'}
                </Typography>

                {apiMapResults.length === 0 ? (
                  <Typography color="text.secondary">
                    No endpoint inventory is available yet. Run a scan first; dynamic
                    JavaScript templates remain in discovery evidence until they resolve
                    to a concrete path.
                  </Typography>
                ) : (
                  <>
                    <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap', mb: 2 }}>
                      <DiscoveryCategoryFilter
                        id="api-map-category"
                        value={apiMapCategory}
                        onChange={setApiMapCategory}
                      />
                      <Typography color="text.secondary" variant="body2">
                        {filterDiscoveryResults(apiMapResults, 'actionable').length} actionable ·{' '}
                        {filterDiscoveryResults(apiMapResults, 'not_found').length} not found ·{' '}
                        {filterDiscoveryResults(apiMapResults, 'blocked').length} blocked ·{' '}
                        {filterDiscoveryResults(apiMapResults, 'inconclusive').length} inconclusive
                      </Typography>
                    </Box>
                    <ApiTreeNode
                      node={buildApiTree(apiMapResults, apiMapCategory)}
                    />
                  </>
                )}
                <Box component="details" sx={{ mt: 2 }}>
                  <Box component="summary" sx={{ cursor: 'pointer' }}>
                    Excluded / Not Found ({notFoundDiscoveryResults.length})
                  </Box>
                  <Typography color="text.secondary" variant="body2" sx={{ my: 1 }}>
                    Original status, method, source, and discovery evidence are retained for audit.
                    These records are excluded from the default API Map and security-testing input.
                  </Typography>
                  <DiscoveryResultsTable results={notFoundDiscoveryResults} />
                </Box>
              </CardContent>
            </Card>
          </ApiMapErrorBoundary>
        )}

        {activePage === 'Reports' && (
          <Box>
            <Card>
              <CardContent>
                <Typography color="text.secondary" variant="body2">
                  Scans recorded during this session: {scanCount}
                </Typography>
                {scanCount === 0 ? (
                  <Typography color="text.secondary" sx={{ mt: 2 }}>
                    No scan history yet. Run a scan from the Scan page first.
                  </Typography>
                ) : (
                  <ReportOverview
                    summary={summary}
                    target={scanResultsTarget || target}
                    findings={findings}
                    fileDiscoveryError={fileDiscoveryError}
                  />
                )}
              </CardContent>
            </Card>

            {scanCount > 0 && (
              <>
                <Typography variant="h5" sx={{ mt: 4, mb: 1 }}>Findings</Typography>
                <FindingGroups
                  findings={findings}
                  onSelect={(finding) => setSelectedFinding(finding)}
                />
                {selectedFinding && (
                  <FindingDetail
                    findings={findings.filter(
                      (finding) =>
                        finding.method === selectedFinding.method &&
                        finding.endpoint === selectedFinding.endpoint &&
                        finding.name === selectedFinding.name,
                    )}
                    endpointAssessments={endpointAssessments}
                    target={scanResultsTarget || target}
                    onClose={() => setSelectedFinding(null)}
                  />
                )}

                <Box component="details" sx={{ mt: 4, borderTop: '1px solid #334155', pt: 2 }}>
                  <Box component="summary" sx={{ cursor: 'pointer', fontWeight: 700 }}>
                    Technical diagnostics
                  </Box>
                  <Typography color="text.secondary" variant="body2" sx={{ mt: 1 }}>
                    Detailed scan output is available on request. Coverage limitations remain visible above.
                  </Typography>
                  {fileDiscoveryError && (
                    <Alert severity="warning" sx={{ mt: 2 }}>
                      File Discovery stage failed; API Discovery and remaining scan stages continued. {fileDiscoveryError}
                    </Alert>
                  )}
                  {summary.discovery_errors?.api_discovery && (
                    <Alert severity="warning" sx={{ mt: 2 }}>
                      API Discovery stage failed. {summary.discovery_errors.api_discovery}
                    </Alert>
                  )}
                  {summary.discovery_errors?.kiterunner_seed_discovery && (
                    <Alert severity="warning" sx={{ mt: 2 }}>
                      Seeded API Discovery stage failed. {summary.discovery_errors.kiterunner_seed_discovery}
                    </Alert>
                  )}

                  <Box component="details" sx={{ mt: 2 }}>
                    <Box component="summary" sx={{ cursor: 'pointer' }}>
                      Discovery stages and command diagnostics
                    </Box>
                    <DiscoveryProgress stages={scanStages} loading={loading} />
                    {scanStages.map((stage, index) => (
                      <Typography key={`${stage.stage}-${index}`} display="block" variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                        {stage.stage}: {stage.status}{stage.detail ? ` — ${stage.detail}` : ''}
                      </Typography>
                    ))}
                    <ExecutiveSummary summary={summary} />
                  </Box>

                  <Box component="details" sx={{ mt: 2 }}>
                    <Box component="summary" sx={{ cursor: 'pointer' }}>
                      Raw discovery evidence ({visibleScanDiscoveryResults.length})
                    </Box>
                    <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap', my: 2 }}>
                      <DiscoveryCategoryFilter
                        id="report-discovery-category"
                        value={discoveryCategoryFilter}
                        onChange={setDiscoveryCategoryFilter}
                      />
                      <FormControl size="small" sx={{ minWidth: 190 }}>
                        <InputLabel id="report-source-label">Discovery source</InputLabel>
                        <Select labelId="report-source-label" value={sourceFilter} label="Discovery source" onChange={(event) => setSourceFilter(event.target.value)}>
                          <MenuItem value="all">All sources</MenuItem>
                          <MenuItem value="kiterunner">Kiterunner</MenuItem>
                          <MenuItem value="kiterunner_seeded">Kiterunner seed scan</MenuItem>
                          <MenuItem value="wordlist">File Discovery</MenuItem>
                          <MenuItem value="html">HTML</MenuItem>
                          <MenuItem value="javascript">JavaScript</MenuItem>
                          <MenuItem value="gateway_verification">Gateway verification</MenuItem>
                        </Select>
                      </FormControl>
                      <FormControl size="small" sx={{ minWidth: 190 }}>
                        <InputLabel id="report-verification-label">Verification</InputLabel>
                        <Select labelId="report-verification-label" value={verificationFilter} label="Verification" onChange={(event) => setVerificationFilter(event.target.value)}>
                          <MenuItem value="all">All states</MenuItem>
                          <MenuItem value="discovered">Discovered</MenuItem>
                          <MenuItem value="verified">Verified</MenuItem>
                          <MenuItem value="inconclusive">Inconclusive</MenuItem>
                          <MenuItem value="blocked">Blocked</MenuItem>
                          <MenuItem value="not_found">Not found</MenuItem>
                        </Select>
                      </FormControl>
                      <Box component="input" type="number" aria-label="Filter discovery by status code" placeholder="Status code prefix" value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)} sx={{ width: 180, px: 1.5, borderRadius: 1, border: '1px solid #334155', backgroundColor: '#111827', color: '#E5E7EB' }} />
                    </Box>
                    <DiscoveryResultsTable results={visibleScanDiscoveryResults} />
                  </Box>

                  <Box component="details" sx={{ mt: 2 }}>
                    <Box component="summary" sx={{ cursor: 'pointer' }}>
                      Excluded / not-found discovery records ({notFoundDiscoveryResults.length})
                    </Box>
                    <Typography color="text.secondary" variant="body2" sx={{ my: 1 }}>
                      These discovered routes were not included in security testing.
                    </Typography>
                    <DiscoveryResultsTable results={notFoundDiscoveryResults} />
                  </Box>

                  <Box component="details" sx={{ mt: 2 }}>
                    <Box component="summary" sx={{ cursor: 'pointer' }}>
                      JWT selection, budgets, and allowlist
                    </Box>
                    <Typography sx={{ mt: 1 }} variant="body2">
                      JWT selection mode: {summary.jwt_selection_mode ?? 'not_confirmed'}
                    </Typography>
                    <Typography color="text.secondary" variant="body2">
                      Explicit allowlist entries: {summary.jwt_allowlist_entries ?? 0}
                      {summary.jwt_allowlist_configured ? ' (mandatory scope boundary)' : ''}
                    </Typography>
                    {summary.jwt_allowlist_targets?.map((endpoint) => (
                      <Typography key={`${endpoint.method}-${endpoint.path}`} color="text.secondary" variant="body2">
                        Allowlisted: {endpoint.method} {endpoint.path}
                      </Typography>
                    ))}
                    {summary.jwt_selection_budgets?.map((budget, index) => (
                      <Typography key={`jwt-budget-${index}`} color="text.secondary" variant="body2">
                        JWT selection budget ({budget.mode ?? 'unknown'}): {budget.used ?? '—'} of {budget.configured ?? 'not applicable'} group(s) used
                        {budget.remaining != null ? ` · ${budget.remaining} remaining` : ''}
                      </Typography>
                    ))}
                  </Box>

                  <Box component="details" sx={{ mt: 2 }}>
                    <Box component="summary" sx={{ cursor: 'pointer' }}>
                      Skipped endpoints ({summary.skipped_endpoint_reasons?.length ?? 0})
                    </Box>
                    {summary.skipped_endpoint_reasons?.map((endpoint, index) => (
                      <Typography key={`${endpoint.method}-${endpoint.path}-${index}`} color="text.secondary" variant="body2" sx={{ mt: 1 }}>
                        {endpoint.method} {endpoint.path}: {endpoint.reason}
                      </Typography>
                    ))}
                  </Box>

                  <Box component="details" sx={{ mt: 2 }}>
                    <Box component="summary" sx={{ cursor: 'pointer' }}>
                      Endpoint test cases and evidence
                    </Box>
                    <EndpointAssessments assessments={endpointAssessments} findings={findings} />
                  </Box>

                  <Box component="details" sx={{ mt: 2 }}>
                    <Box component="summary" sx={{ cursor: 'pointer' }}>
                      Passive and active BOLA diagnostics
                    </Box>
                    <BolaCorrelationResults
                      assessments={bolaAssessments}
                      baselines={bolaBaselines}
                      activeTests={bolaActiveTests}
                      summary={summary}
                    />
                  </Box>
                </Box>
              </>
            )}
          </Box>
        )}

        {activePage === 'Settings' && (
          <Card>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 1 }}>
                Scanner Configuration
              </Typography>
              <Typography color="text.secondary" sx={{ mb: 3 }}>
                Restrict the target to an authorized host, and discover endpoints using Kiterunner.
              </Typography>

              <Typography sx={{ mb: 1 }}>Default target</Typography>
              <Box
                component="input"
                value={target}
                placeholder="localhost:8085"
                onChange={(event) => setTarget(event.target.value)}
                sx={{
                  boxSizing: 'border-box',
                  width: '100%',
                  maxWidth: 500,
                  px: 2,
                  py: 1.5,
                  borderRadius: 1,
                  border: '1px solid #334155',
                  backgroundColor: '#111827',
                  color: '#E5E7EB',
                  fontSize: '1rem',
                }}
              />

              <Typography sx={{ mt: 3, mb: 1 }}>Discovery engine</Typography>
              <Chip label="Kiterunner" color="primary" variant="outlined" />

              <Typography sx={{ mt: 3 }} color="text.secondary" variant="body2">
                The backend validates the target URL and rejects malformed or out-of-scope requests.
              </Typography>
            </CardContent>
          </Card>
        )}
      </Box>
    </Box>
  )
}

export default App