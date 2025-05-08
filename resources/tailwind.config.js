/** @type {import('tailwindcss').Config} */
module.exports = {
  theme: {
    extend: {
      // fontFamily: {
      //   'awesome': 'FontAwesome',
      //   'roboto': 'Roboto Mono',
      //   'lucida': 'Lucida Grande',
      //   'mono': ['ui-monospace', '"Roboto Mono"', 'SFMono-Regular', 'Consolas', 'Menlo', 'monospace'],
      //   'sans': ['Inter', 'ui-sans-serif', 'system-ui', '-apple-system', 'BlinkMacSystemFont', '"Segoe UI"', 'Roboto', '"Helvetica Neue"', 'Arial', '"Noto Sans"', 'sans-serif', '"Apple Color Emoji"', '"Segoe UI Emoji"', '"Segoe UI Symbol"', '"Noto Color Emoji"']
      // },
      // maxWidth: {
      //   '8xl': '1440px'
      // },
      // colors: {
      //   'darkblue': '#00008B',
      //   'dark-all': 'rgba(45, 47, 50, 1)',
      //   'dark-content': 'rgba(35, 35, 37, 1)',
      //   'dark-text': '#86889A',
      // },
      typography: () => ({
        DEFAULT: {
          css: {
            pre: {
              backgroundColor: 'var(--color-gray-300)',
              color: 'var(--color-black)',
            },
            code: {
              backgroundColor: 'var(--color-gray-200)',
              borderRadius: '.25rem',
              padding: '0 5px',
            },
            a: {
              textDecoration: 'none',
              color: 'var(--color-blue-600)',
            },
            h2: {
              borderWidth: '0 0 1px 0',
            },
            h3: {
              borderWidth: '0 0 1px 0',
            },
            table: {
              tableLayout: 'fixed',
              borderWidth: '1px 1px 1px 1px',
              borderColor: 'var(--color-black)',
            },
            'thead th:first-child': {
              paddingLeft: '.5rem',
            },
            'thead th:last-child': {
              paddingRight: '.5rem',
            },
            'tbody td:first-child, tfoot td:first-child': {
              paddingLeft: '.5rem',
            },
            'tbody td:last-child, tfoot td:last-child': {
              paddingRight: '.5rem',
            },
            'thead th': {
              padding: '0.5rem',
              backgroundColor: 'var(--color-black)',
              color: 'var(--color-white)',
              fontWeight: '700',
            },
            'tbody td:not(first-child)': {
              borderLeftWidth: '1px',
              borderLeftColor: 'var(--color-black)'
            },
          },
        },
      }),
    },
  },
};