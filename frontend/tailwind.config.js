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
    // Row hover — built dynamically inside rowClass(), Tailwind can't scan it statically
    'hover:bg-[var(--nc-row-hover)]', 'hover:border-blue-400/60',
  ],
}
