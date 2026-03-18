import './app.css'
import NetCapture from './lib/NetCapture.svelte'

// Standalone mode — wsUrl and apiBase default to auto-detect from window.location
const app = new NetCapture({
  target: document.getElementById('app')!,
})

export default app
