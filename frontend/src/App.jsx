import { useMemo, useState } from 'react'

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
} from '@mui/material'

const drawerWidth = 240

function buildApiTree(results) {
  const root = {}

  results.forEach((result) => {
    const path = result.path ?? result.target ?? '/'
    const parts = path.split('/').filter(Boolean)

    let current = root
    let endpointNode = null

    parts.forEach((part) => {
      if (!current[part]) {
        current[part] = {
          children: {},
          endpoints: [],
        }
      }

      endpointNode = current[part]
      current = current[part].children
    })

    if (endpointNode) {
      endpointNode.endpoints.push(result)
    } else {
      root['(root)'] ??= { children: {}, endpoints: [] }
      root['(root)'].endpoints.push(result)
    }
  })

  return root
}

function ApiTreeNode({ node, depth = 0 }) {
  return (
    <>
      {Object.entries(node).map(([name, item]) => (
        <Box key={name} sx={{ ml: depth * 2, mt: 1 }}>
          <Typography sx={{ color: '#38BDF8', fontWeight: 600 }}>
            📁 /{name}
          </Typography>

          {item.endpoints.map((endpoint, index) => {
            const status = endpoint.responses?.[0]?.sc

            return (
              <Box
                key={`${endpoint.method}-${endpoint.path}-${index}`}
                sx={{
                  ml: 3,
                  mt: 1,
                  display: 'flex',
                  gap: 1,
                  alignItems: 'center',
                  flexWrap: 'wrap',
                }}
              >
                <Chip label={endpoint.method ?? 'UNKNOWN'} size="small" color="primary" />
                <Typography variant="body2">
                  {endpoint.path ?? endpoint.target ?? '/'}
                </Typography>
                <Chip
                  label={status ?? '-'}
                  size="small"
                  variant="outlined"
                  color={
                    status >= 500 ? 'error' : status >= 400 ? 'warning' : 'success'
                  }
                />
                {endpoint.classification && (
                  <Chip label={endpoint.classification} size="small" variant="outlined" />
                )}
              </Box>
            )
          })}

          {Object.keys(item.children).length > 0 && (
            <ApiTreeNode node={item.children} depth={depth + 1} />
          )}
        </Box>
      ))}
    </>
  )
}

function EndpointAssessments({ assessments }) {
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
                  {testCase.evidence ? (
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

function ExecutiveSummary({ summary }) {
  const conclusion = summary.overall_conclusion
  const metrics = [
    ['Confirmed findings', summary.confirmed_findings ?? 0],
    ['Potential findings', summary.potential_findings ?? 0],
    ['Endpoints discovered', summary.discovered_endpoints ?? 0],
    ['Endpoints selected', summary.selected_endpoints ?? 0],
    ['Endpoints actually tested', summary.tested_endpoints ?? 0],
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
    </Box>
  )
}

function App() {
  const [target, setTarget] = useState('')
  const [scanResults, setScanResults] = useState([])
  const [findings, setFindings] = useState([])
  const [endpointAssessments, setEndpointAssessments] = useState([])
  const [summary, setSummary] = useState({})
  const [scanCount, setScanCount] = useState(0)
  const [activePage, setActivePage] = useState('Dashboard')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const endpointSummary = useMemo(() => {
    const discovered = scanResults.filter((item) => item.discovered !== false)
    const total = discovered.length
    const auth = discovered.filter((item) => item.classification === 'authentication').length
    const resource = discovered.filter((item) => item.classification === 'resource_by_id' || item.classification === 'resource_collection').length
    return { total, auth, resource }
  }, [scanResults])

  const runScan = async () => {
    if (!target.trim()) {
      setError('Enter a valid target such as localhost:8085 or https://example.com.')
      return
    }

    setLoading(true)
    setError('')

    try {
      const response = await fetch(
        `http://localhost:8000/scan?target=${encodeURIComponent(target.trim())}&num=200&auto_jwt_local_lab=true`
      )

      const payload = await response.json()
      if (!response.ok) {
        if (payload?.summary?.overall_conclusion) {
          setScanResults(payload.results ?? [])
          setFindings(payload.findings ?? [])
          setEndpointAssessments(payload.endpoint_assessments ?? [])
          setSummary(payload.summary)
          setScanCount((count) => count + 1)
          setActivePage('Reports')
        }
        throw new Error(payload?.detail || `HTTP ${response.status}`)
      }

      setScanResults(payload.results ?? [])
      setFindings(payload.findings ?? [])
      setEndpointAssessments(payload.endpoint_assessments ?? [])
      setSummary(payload.summary ?? {})
      setScanCount((count) => count + 1)
      setActivePage('Reports')
    } catch (caughtError) {
      setError(caughtError.message || 'The scan could not be completed.')
    } finally {
      setLoading(false)
    }
  }

  const totalPotentialFindings =
    summary.potential_findings ??
    findings.filter((item) => item.status === 'potential').length
  const discoveredResults = scanResults.filter((item) => item.discovered !== false)

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
          {activePage === 'API Map' && 'API Endpoint Map'}
          {activePage === 'Reports' && 'Scan Reports'}
          {activePage === 'Settings' && 'Settings'}
        </Typography>

        <Typography sx={{ mb: 4, color: '#94A3B8' }}>
          {activePage === 'Dashboard' && 'Web & Microservice Security Scanner'}
          {activePage === 'Scan' && 'Discover API endpoints with Kiterunner'}
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
                {loading ? 'SCANNING...' : 'START SCAN'}
              </Box>
            </Box>
            <Box sx={{ mt: 4 }}>
              <Typography variant="h6" sx={{ mb: 2 }}>
                Scan Results ({endpointSummary.total})
              </Typography>

              <Card sx={{ maxHeight: 420, overflow: 'auto' }}>
                <Table stickyHeader>
                  <TableHead>
                    <TableRow>
                      <TableCell>Method</TableCell>
                      <TableCell>Endpoint</TableCell>
                      <TableCell>Class</TableCell>
                      <TableCell>Status</TableCell>
                    </TableRow>
                  </TableHead>

                  <TableBody>
                    {discoveredResults.length === 0 ? (
                      <TableRow>
                        <TableCell colSpan={4} align="center">
                          No results yet. Enter a target and start a scan.
                        </TableCell>
                      </TableRow>
                    ) : (
                      discoveredResults.map((result, index) => {
                        const status = result.responses?.[0]?.sc
                        return (
                          <TableRow key={`${result.method}-${result.path}-${index}`}>
                            <TableCell>{result.method ?? '-'}</TableCell>
                            <TableCell>{result.path ?? result.target ?? '-'}</TableCell>
                            <TableCell>{result.classification ?? 'unknown'}</TableCell>
                            <TableCell>
                              <Chip
                                label={status ?? '-'}
                                size="small"
                                color={
                                  status >= 500 ? 'error' : status >= 400 ? 'warning' : 'success'
                                }
                              />
                            </TableCell>
                          </TableRow>
                        )
                      })
                    )}
                  </TableBody>
                </Table>
              </Card>
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
              </CardContent>
            </Card>
          </>
        )}

        {activePage === 'API Map' && (
          <Card>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 1 }}>
                Discovered API Structure
              </Typography>

              <Typography color="text.secondary" sx={{ mb: 3 }}>
                Target: {target || 'No target selected'}
              </Typography>

              {scanResults.length === 0 ? (
                <Typography color="text.secondary">
                  No endpoints available. Run a scan first.
                </Typography>
              ) : (
                <ApiTreeNode node={buildApiTree(discoveredResults)} />
              )}
            </CardContent>
          </Card>
        )}

        {activePage === 'Reports' && (
          <Card>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 1 }}>
                Scan History
              </Typography>
              <Typography color="text.secondary" sx={{ mb: 3 }}>
                Scans recorded during this session: {scanCount}
              </Typography>

              {scanCount === 0 ? (
                <Typography color="text.secondary">
                  No scan history yet. Run a scan from the Scan page first.
                </Typography>
              ) : (
                <>
                  <Typography sx={{ mb: 2 }}>
                    Latest target: {target || 'Not specified'}
                  </Typography>
                  <ExecutiveSummary summary={summary} />
                  <Typography sx={{ mb: 1 }}>
                    JWT selection mode: {summary.jwt_selection_mode ?? 'not_confirmed'}
                  </Typography>
                  <Typography color="text.secondary" variant="body2">
                    Explicit allowlist entries: {summary.jwt_allowlist_entries ?? 0}
                    {summary.jwt_allowlist_configured ? ' (mandatory scope boundary)' : ''}
                  </Typography>
                  {summary.jwt_allowlist_targets?.map((endpoint) => (
                    <Typography
                      key={`${endpoint.method}-${endpoint.path}`}
                      color="text.secondary"
                      variant="body2"
                    >
                      Allowlisted: {endpoint.method} {endpoint.path}
                    </Typography>
                  ))}
                  {summary.skipped_endpoint_reasons?.length > 0 && (
                    <Box
                      component="details"
                      sx={{ mt: 2, mb: 2, border: '1px solid #334155', borderRadius: 1, px: 1.5, py: 1 }}
                    >
                      <Box component="summary" sx={{ cursor: 'pointer', fontWeight: 600 }}>
                        Skipped Discovery endpoints ({summary.skipped_endpoint_reasons.length})
                      </Box>
                      {summary.skipped_endpoint_reasons.map((endpoint, index) => (
                        <Typography
                          key={`${endpoint.method}-${endpoint.path}-${index}`}
                          color="text.secondary"
                          variant="body2"
                          sx={{ mt: 1 }}
                        >
                          {endpoint.method} {endpoint.path}: {endpoint.reason}
                        </Typography>
                      ))}
                    </Box>
                  )}
                  <Typography color="text.secondary" variant="body2">
                    {findings.length === 0
                      ? 'No confirmed or potential vulnerability findings were reported.'
                      : `${findings.length} confirmed or potential vulnerability finding(s) have evidence.`}
                  </Typography>
                  <Typography variant="h6" sx={{ mt: 3 }}>
                    Vulnerability findings
                  </Typography>
                  <VulnerabilityFindings findings={findings} />
                  <Typography variant="h6" sx={{ mt: 3 }}>
                    Endpoint assessments and test cases
                  </Typography>
                  <EndpointAssessments assessments={endpointAssessments} />
                </>
              )}
            </CardContent>
          </Card>
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