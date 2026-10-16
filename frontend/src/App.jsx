import { useState } from 'react'


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
} from '@mui/material'



const drawerWidth = 240

function buildApiTree(results) {
  const root = {}

  results.forEach((result) => {
    const path = result.path ?? result.target ?? '/'
    const parts = path.split('/').filter(Boolean)

    let current = root
    let endpointNode

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
          <Typography
            sx={{ color: '#38BDF8', fontWeight: 600 }}
          >
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
                <Chip
                  label={endpoint.method ?? 'UNKNOWN'}
                  size="small"
                  color="primary"
                />

                <Typography variant="body2">
                  {endpoint.path ?? endpoint.target ?? '/'}
                </Typography>

                <Chip
                  label={status ?? '-'}
                  size="small"
                  variant="outlined"
                  color={
                    status >= 500
                      ? 'error'
                      : status >= 400
                        ? 'warning'
                        : 'success'
                  }
                />
              </Box>
            )
          })}

          {Object.keys(item.children).length > 0 && (
            <ApiTreeNode
              node={item.children}
              depth={depth + 1}
            />
          )}
        </Box>
      ))}
    </>
  )
}


function App() {

  const [target, setTarget] = useState('')
  const [scanResults, setScanResults] = useState([])
  const [scanCount, setScanCount] = useState(0)
  const [activePage, setActivePage] = useState('Dashboard')

  return (
    <Box sx={{ display: 'flex', minHeight: '100vh' }}>

      {/* Sidebar                  */}
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
          <Typography
            variant="h6"
            sx={{
              fontWeight: 700,
              color: 'primary.main',
              letterSpacing: 1,
            }}
          >
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


      {/* Main content                */}
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
        <Typography
          variant="h4"
          sx={{ fontWeight: 700, mb: 1, color: '#E5E7EB' }}
        >
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

        {/* DASHBOARD */}
        {activePage === 'Dashboard' && (
          <>
            <Box sx={{ display: 'flex', gap: 3, flexWrap: 'wrap' }}>
              <Card sx={{ flex: '1 1 180px' }}>
                <CardContent>
                  <Typography color="text.secondary">Endpoints</Typography>
                  <Typography variant="h3" sx={{ mt: 1, fontWeight: 700 }}>
                    {scanResults.length}
                  </Typography>
                </CardContent>
              </Card>

              <Card sx={{ flex: '1 1 180px' }}>
                <CardContent>
                  <Typography color="text.secondary">Vulnerabilities</Typography>
                  <Typography variant="h3" sx={{ mt: 1, fontWeight: 700 }}>
                    0
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
                  Welcome to MicroScan
                </Typography>
                <Typography color="text.secondary">
                  Use the Scan page to discover endpoints in your target application.
                </Typography>
              </CardContent>
            </Card>
          </>
        )}

        {/* SCAN       */}
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
                onClick={async () => {
                  if (!target.trim()) return

                  try {
                    const response = await fetch(
                      `http://localhost:8000/scan?target=${encodeURIComponent(target.trim())}`
                    )

                    if (!response.ok) {
                      throw new Error(`HTTP ${response.status}`)
                    }

                    const data = await response.json()
                    setScanResults(data.results ?? [])
                    setScanCount((count) => count + 1)
                  } catch (error) {
                    console.error('Scan failed:', error)
                    alert('Scan failed. Check that the backend is running.')
                  }
                }}
                sx={{
                  px: 3,
                  py: 1.5,
                  border: 'none',
                  borderRadius: 1,
                  backgroundColor: 'primary.main',
                  color: '#0B1120',
                  fontWeight: 700,
                  cursor: 'pointer',
                }}
              >
                START SCAN
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
                      <TableCell>Status</TableCell>
                    </TableRow>
                  </TableHead>

                  <TableBody>
                    {scanResults.length === 0 ? (
                      <TableRow>
                        <TableCell colSpan={3} align="center">
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
                            <TableCell>
                              <Chip
                                label={status ?? '-'}
                                size="small"
                                color={
                                  status >= 500
                                    ? 'error'
                                    : status >= 400
                                      ? 'warning'
                                      : 'success'
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
                <Chip label="COMING SOON" color="warning" size="small" sx={{ my: 2 }} />
                <Typography color="text.secondary">
                  Vulnerability testing modules will appear here when implemented.
                </Typography>
              </CardContent>
            </Card>
          </>
        )}

        {/* API MAP */}
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

        {/* REPORTS */}
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
                  <Typography sx={{ mb: 2 }}>
                    Endpoints discovered: {scanResults.length}
                  </Typography>
                  <Typography color="text.secondary" variant="body2">
                    ######
                  </Typography>
                </>
              )}
            </CardContent>
          </Card>
        )}

        {/* SETTINGS */}
        {activePage === 'Settings' && (
          <Card>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 1 }}>
                Scanner Configuration
              </Typography>
              <Typography color="text.secondary" sx={{ mb: 3 }}>
                Settings UI preview. These controls do not change backend behavior yet.
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
                Dictionary size, timeout and concurrency settings can be connected
                after the backend supports them.
              </Typography>
            </CardContent>
          </Card>
        )}
      </Box>


    </Box>
  )
}

export default App