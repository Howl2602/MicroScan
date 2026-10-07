import { createTheme } from '@mui/material/styles'

const theme = createTheme({
  palette: {
    mode: 'dark',

    background: {
      default: '#0B1120',
      paper: '#111827',
    },

    primary: {
      main: '#22D3EE',
    },

    text: {
      primary: '#E5E7EB',
      secondary: '#94A3B8',
    },
  },
})

export default theme