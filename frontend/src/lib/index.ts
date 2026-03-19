export { default } from './NetCapture.svelte'
export { default as NetCapture } from './NetCapture.svelte'

// Types useful for TypeScript consumers building around the component
export type {
  Packet,
  NetworkInterface,
  CaptureProfile,
  AddressBookEntry,
  DecodedFrame,
  DecodedField,
  DecodedValue,
  Stats,
  ChartPoint,
  CaptureMode,
  ConnectionStatus,
} from './types'
