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

function TestFindings({ findings }) {
  if (findings.length === 0) {
    return (
      <Typography color="text.secondary" sx={{ mt: 2 }}>
        No automated authentication test results are available for this scan.
      </Typography>
    )
  }

  return findings.map((finding, index) => (
    <Box key={`${finding.endpoint}-${finding.module}-${index}`} sx={{ mt: 2 }}>
      <Chip
        label={finding.status}
        size="small"
        color={
          finding.status === 'potential' || finding.status === 'confirmed'
            ? 'warning'
            : finding.status === 'not_vulnerable_in_test'
              ? 'success'
              : finding.status === 'error'
                ? 'error'
                : 'default'
        }
        sx={{ mb: 1 }}
      />
      <Typography variant="subtitle2">
        {finding.module} · {finding.method ?? 'GET'} · {finding.endpoint}
      </Typography>
      {finding.tested_endpoint && (
        <Typography color="text.secondary" variant="body2">
          Protected endpoint tested: {finding.tested_endpoint}
        </Typography>
      )}
      {finding.endpoint_selection_reason && (
        <Typography color="text.secondary" variant="body2">
          Selection: {finding.endpoint_selection_reason}
        </Typography>
      )}
      <Typography color="text.secondary" variant="body2">
        {finding.reason}
      </Typography>
      {finding.discovery && (
        <Box sx={{ mt: 1 }}>
          <Typography variant="subtitle2">Discovery</Typography>
          <Typography color="text.secondary" variant="body2">
            Authentication mechanism: {finding.authentication_mechanism ?? 'unknown'}
          </Typography>
          {finding.discovery.note && (
            <Typography color="text.secondary" variant="body2">
              {finding.discovery.note}
            </Typography>
          )}
          {finding.discovery.discovered_login_endpoints?.map((endpoint) => (
            <Typography
              key={`${endpoint.method}-${endpoint.path}`}
              color="text.secondary"
              variant="body2"
            >
              Discovered login candidate: {endpoint.method} {endpoint.path}
              {endpoint.discovery_status
                ? ` · discovery HTTP ${endpoint.discovery_status}`
                : ''}
            </Typography>
          ))}
        </Box>
      )}
      {finding.unauthenticated_checks?.length > 0 && (
        <Box sx={{ mt: 1 }}>
          <Typography variant="subtitle2">Unauthenticated checks</Typography>
          <Box
            component="pre"
            sx={{
              mt: 0.5,
              p: 1.5,
              borderRadius: 1,
              backgroundColor: '#0B1120',
              color: '#CBD5E1',
              whiteSpace: 'pre-wrap',
              overflowWrap: 'anywhere',
              fontSize: '0.8rem',
            }}
          >
            {JSON.stringify(finding.unauthenticated_checks, null, 2)}
          </Box>
        </Box>
      )}
      {finding.authenticated_check && (
        <Box sx={{ mt: 1 }}>
          <Typography variant="subtitle2">
            Authenticated check · {finding.authenticated_check.status}
          </Typography>
          <Typography color="text.secondary" variant="body2">
            {finding.authenticated_check.reason}
          </Typography>
          {finding.authenticated_check.evidence && (
            <Box
              component="pre"
              sx={{
                mt: 0.5,
                p: 1.5,
                borderRadius: 1,
                backgroundColor: '#0B1120',
                color: '#CBD5E1',
                whiteSpace: 'pre-wrap',
                overflowWrap: 'anywhere',
                fontSize: '0.8rem',
              }}
            >
              {JSON.stringify(finding.authenticated_check.evidence, null, 2)}
            </Box>
          )}
        </Box>
      )}
      {finding.evidence?.length > 0 && (
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
      )}
    </Box>
  ))
}

function App() {
  const [target, setTarget] = useState('')
  const [scanResults, setScanResults] = useState([])
  const [findings, setFindings] = useState([])
  const [summary, setSummary] = useState({})
  const [scanCount, setScanCount] = useState(0)
  const [activePage, setActivePage] = useState('Dashboard')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const endpointSummary = useMemo(() => {
    const total = scanResults.length
    const auth = scanResults.filter((item) => item.classification === 'authentication').length
    const resource = scanResults.filter((item) => item.classification === 'resource_by_id' || item.classification === 'resource_collection').length
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
        `http://localhost:8000/scan?target=${encodeURIComponent(target.trim())}&num=200`
      )

      const payload = await response.json()
      if (!response.ok) {
        throw new Error(payload?.detail || `HTTP ${response.status}`)
      }

      setScanResults(payload.results ?? [])
      setFindings(payload.findings ?? [])
      setSummary(payload.summary ?? {})
      setScanCount((count) => count + 1)
      setActivePage('Reports')
    } catch (caughtError) {
      setError(caughtError.message || 'The scan could not be completed.')
    } finally {
      setLoading(false)
    }
  }

  const totalPotentialFindings = findings.filter((item) => item.status === 'potential').length

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
                  {endpointSummary.auth} authentication endpoints, {endpointSummary.resource} resource endpoints, and {scanResults.length} total endpoints discovered.
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
                Scan Results ({scanResults.length})
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
                    {scanResults.length === 0 ? (
                      <TableRow>
                        <TableCell colSpan={4} align="center">
                          No results yet. Enter a target and start a scan.
                        </TableCell>
                      </TableRow>
                    ) : (
                      scanResults.map((result, index) => {
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
                <TestFindings findings={findings} />
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
                <ApiTreeNode node={buildApiTree(scanResults)} />
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
                Scans completed during this session: {scanCount}
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
                  <Typography sx={{ mb: 1 }}>
                    Endpoints discovered: {summary.total_endpoints ?? scanResults.length}
                  </Typography>
                  <Typography sx={{ mb: 1 }}>
                    Authentication endpoints: {summary.auth_endpoints ?? 0}
                  </Typography>
                  <Typography sx={{ mb: 1 }}>
                    Potential findings: {summary.potential_findings ?? totalPotentialFindings}
                  </Typography>
                  <Typography color="text.secondary" variant="body2">
                    {findings.length === 0
                      ? 'No test evidence captured yet.'
                      : 'Evidence captured from the active scan.'}
                  </Typography>
                  <Typography variant="h6" sx={{ mt: 3 }}>
                    Authentication test evidence
                  </Typography>
                  <TestFindings findings={findings} />
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