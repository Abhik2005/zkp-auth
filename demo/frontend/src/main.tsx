import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { ZKPProvider } from '@zkp-auth/react';
import { App } from "./App";
import './index.css';

/**
 * Backend base URL.
 * With the Vite proxy configured, using a relative base means the browser
 * calls localhost:5173/auth/... which Vite forwards to localhost:3001/auth/...
 * — no CORS required.
 */
const API_BASE = '/';

const rootEl = document.getElementById('root');
if (rootEl === null) {
  throw new Error('Root element #root not found in index.html');
}

createRoot(rootEl).render(
  <StrictMode>
    <ZKPProvider options={{ baseUrl: API_BASE }}>
      <App />
    </ZKPProvider>
  </StrictMode>,
);
