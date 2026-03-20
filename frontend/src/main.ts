import './app.css'
import { mount } from 'svelte'
import NetCapture from './lib/NetCapture.svelte'

// Standalone mode — wsUrl and apiBase default to auto-detect from window.location
const app = mount(NetCapture, {
  target: document.getElementById('app')!,
})

export default app
