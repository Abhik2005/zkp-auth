/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
      colors: {
        brand: {
          50:  '#f0f4ff',
          100: '#dce6ff',
          200: '#b8ccff',
          300: '#85a8ff',
          400: '#527aff',
          500: '#2b4fff',
          600: '#1433eb',
          700: '#1028cc',
          800: '#1126a5',
          900: '#122682',
        },
      },
    },
  },
  plugins: [],
};
