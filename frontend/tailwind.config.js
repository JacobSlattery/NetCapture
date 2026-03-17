/** @type {import('tailwindcss').Config} */
export default {
  content: [
    './index.html',
    './src/**/*.{svelte,js,ts}',
  ],
  theme: {
    extend: {},
  },
  plugins: [],
  safelist: [
    // Protocol badge backgrounds
    'bg-blue-600', 'bg-green-600', 'bg-amber-600', 'bg-purple-600',
    'bg-orange-600', 'bg-cyan-600', 'bg-pink-600', 'bg-gray-600',
    // Protocol row tints
    'bg-blue-950/20', 'bg-green-950/20', 'bg-amber-950/20', 'bg-purple-950/20',
    'bg-orange-950/20', 'bg-cyan-950/20', 'bg-pink-950/20',
    // Protocol mini-bar colors
    'bg-blue-500', 'bg-green-500', 'bg-amber-500', 'bg-purple-500',
    'bg-orange-500', 'bg-cyan-500', 'bg-pink-500', 'bg-gray-500',
    // Status indicator
    'bg-green-400', 'bg-yellow-400', 'bg-red-400',
    'text-green-400', 'text-yellow-400', 'text-red-400',
  ],
}
