import severityContract from './src/generated/severity.v1.json' with { type: 'json' };

const severityColors = Object.fromEntries(
  severityContract.levels.map((level) => [`severity-${level.id.toLowerCase()}`, level.color]),
);

export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        'brand-primary': '#10b981',
        'brand-secondary': '#059669',
        ...severityColors,
        'bg-primary': '#ffffff',
        'bg-secondary': '#f8f9fa',
        'bg-tertiary': '#f1f3f5',
        'bg-dark-primary': '#0f0f0f',
        'bg-dark-secondary': '#1a1a1a',
        'bg-dark-tertiary': '#2d2d2d',
        'text-primary': '#1a1a1a',
        'text-secondary': '#666666',
        'text-tertiary': '#999999',
        'text-dark-primary': '#ffffff',
        'text-dark-secondary': '#e0e0e0',
        'text-dark-tertiary': '#a0a0a0',
        'border-light': '#e5e7eb',
        'border-dark': '#333333',
        'status-success': '#10b981',
        'status-error': '#ef4444',
        'status-warning': '#f59e0b',
        'status-info': '#3b82f6',
      },
      boxShadow: {
        'soft': '0 1px 3px 0 rgb(0 0 0 / 0.1)',
        'soft-lg': '0 4px 6px -1px rgb(0 0 0 / 0.1)',
      },
      fontFamily: {
        sans: ['Inter', 'sans-serif'],
      },
    },
  },
  darkMode: 'class',
  plugins: [],
};
