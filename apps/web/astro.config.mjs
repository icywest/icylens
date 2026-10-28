import react from '@astrojs/react';
import tailwindcss from '@tailwindcss/vite';
import { defineConfig } from 'astro/config';
import process from 'node:process';
import { loadEnv } from 'vite';

const environment = loadEnv(
  process.env.NODE_ENV || 'development',
  process.cwd(),
  '',
);
const apiProxyTarget = environment.API_PROXY_TARGET || 'http://127.0.0.1:8000';

export default defineConfig({
  integrations: [react()],
  vite: {
    plugins: [tailwindcss()],
    server: {
      proxy: {
        '/api': {
          target: apiProxyTarget,
          changeOrigin: true,
        },
      },
    },
  },
});
