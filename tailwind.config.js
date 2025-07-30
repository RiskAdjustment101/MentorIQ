/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        'inter': ['Inter', 'sans-serif'],
      },
      width: {
        '7/10': '70%',
        '3/10': '30%',
      },
      colors: {
        // Anthropic color palette
        'slate': {
          900: '#0f172a',
          800: '#1e293b',
          700: '#334155',
          600: '#475569',
          500: '#64748b',
          400: '#94a3b8',
          300: '#cbd5e1',
        },
        'orange': {
          500: '#ff6b35',
          600: '#ea5a2a',
        },
        'blue': {
          400: '#38bdf8',
        }
      },
      animation: {
        'fade-in': 'fadeIn 0.4s ease-out',
        'slide-in-right': 'slideInRight 0.3s ease-out',
        'slide-in-left': 'slideInLeft 0.3s ease-out',
        'pulse-subtle': 'pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
      },
      letterSpacing: {
        'tight': '-0.025em',
      },
      lineHeight: {
        'relaxed': '1.75',
      }
    },
  },
  plugins: [],
}