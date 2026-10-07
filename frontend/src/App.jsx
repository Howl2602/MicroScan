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

function App() {

  const [target, setTarget] = useState('')
  const [scanResults, setScanResults] = useState([])
  const [scanCount, setScanCount] = useState(0)

  return (
    <Box sx={{ display: 'flex', minHeight: '100vh' }}>

      {/* Sidebar */}
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
          <ListItem disablePadding>
            <ListItemButton>
              <ListItemText primary="Dashboard" />
            </ListItemButton>
          </ListItem>

          <ListItem disablePadding>
            <ListItemButton>
              <ListItemText primary="Scan" />
            </ListItemButton>
          </ListItem>

          <ListItem disablePadding>
            <ListItemButton>
              <ListItemText primary="Reports" />
            </ListItemButton>
          </ListItem>

          <ListItem disablePadding>
            <ListItemButton>
              <ListItemText primary="Settings" />
            </ListItemButton>
          </ListItem>
        </List>
      </Drawer>

      {/* Main content */}
      <Box
        component="main"
        sx={{
          flexGrow: 1,
          p: 3,
          backgroundColor: 'background.default',
          color: 'text.primary',
        }}
      >
        <Typography
          variant="h4"
          sx={{
            fontWeight: 700,
            mb: 1,
            color: '#E5E7EB',
          }}
        >
          Security Dashboard
        </Typography>

        <Typography
          variant="body1"
          sx={{
            mb: 5,
            color: '#94A3B8',
          }}
        >
          Web & Microservice Security Scanner
        </Typography>

        {/* Statistics */}
        <Box sx={{ display: 'flex', gap: 3 }}>

          <Card sx={{ flex: 1 }}>
            <CardContent>
              <Typography color="text.secondary">
                Endpoints
              </Typography>

              <Typography
                variant="h3"
                sx={{ mt: 1, fontWeight: 700 }}
              >
                {scanResults.length}
              </Typography>
            </CardContent>
          </Card>

          <Card sx={{ flex: 1 }}>
            <CardContent>
              <Typography color="text.secondary">
                Vulnerabilities
              </Typography>

              <Typography
                variant="h3"
                sx={{ mt: 1, fontWeight: 700 }}
              >
                0
              </Typography>
            </CardContent>
          </Card>

          <Card sx={{ flex: 1 }}>
            <CardContent>
              <Typography color="text.secondary">
                Scans
              </Typography>

              <Typography
                variant="h3"
                sx={{ mt: 1, fontWeight: 700 }}
              >
                {scanCount}
              </Typography>
            </CardContent>
          </Card>

        </Box>
        <Box sx={{ mt: 4 }}>
          <Typography
            variant="h6"
            sx={{ fontWeight: 600, mb: 2 }}
          >
            Scan Target
          </Typography>

          <Box sx={{ display: 'flex', gap: 2 }}>
            <Box
              component="input"
              placeholder="localhost:8085"
              value={target}
              onChange={(event) => setTarget(event.target.value)}
              sx={{
                flexGrow: 1,
                px: 2,
                py: 1.5,
                borderRadius: 1,
                border: '1px solid #334155',
                backgroundColor: '#111827',
                color: '#E5E7EB',
                outline: 'none',
                fontSize: '1rem',
              }}
            />

            <Box
              component="button"
              onClick={async () => {
                const response = await fetch(
                  `http://localhost:8000/scan?target=${encodeURIComponent(target)}`
                )

                const data = await response.json()

                setScanResults(data.results)
                setScanCount((count) => count + 1)

              }}

              sx={{
                px: 3,
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


          {/* Scan Results */}

          <Box sx={{ mt: 5 }}>
            <Typography
              variant="h6"
              sx={{ fontWeight: 600, mb: 2 }}
            >
              Scan Results
            </Typography>

            <Card
              sx={{
                maxHeight: 360,
                overflow: 'auto',
              }}
            >
              <Table stickyHeader>
                <TableHead>
                  <TableRow>
                    <TableCell>Method</TableCell>
                    <TableCell>Endpoint</TableCell>
                    <TableCell>Status</TableCell>
                  </TableRow>
                </TableHead>

                <TableBody>
                  {scanResults.map((result, index) => (
                    <TableRow key={index}>
                      <TableCell>
                        {result.method}
                      </TableCell>

                      <TableCell>
                        {result.path}
                      </TableCell>

                      <TableCell>
                        <Chip
                          label={result.responses?.[0]?.sc ?? '-'}
                          size="small"
                          color={
                            result.responses?.[0]?.sc >= 500
                              ? 'error'
                              : result.responses?.[0]?.sc >= 400
                                ? 'warning'
                                : 'success'
                          }
                        />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </Card>
          </Box>


          {/* Pentest Analysis */}
          <Box sx={{ mt: 5 }}>
            <Typography
              variant="h6"
              sx={{ fontWeight: 600, mb: 2 }}
            >
              Pentest Analysis
            </Typography>

            <Card>
              <CardContent sx={{ py: 5, textAlign: 'center' }}>
                <Typography
                  variant="h6"
                  sx={{ fontWeight: 600, mb: 1 }}
                >
                  Pentest Engine
                </Typography>

                <Chip
                  label="COMING SOON"
                  size="small"
                  color="warning"
                  sx={{ mb: 2 }}
                />

                <Typography
                  variant="body2"
                  color="text.secondary"
                >
                  BOLA, XSS, SQLi, SSRF, RCE, LFI, and more...
                </Typography>
              </CardContent>
            </Card>
          </Box>

        </Box>
      </Box>
    </Box>
  )
}

export default App