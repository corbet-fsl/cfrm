import { defineConfig } from 'vite';
import { nodePolyfills } from 'vite-plugin-node-polyfills';
export default defineConfig({
  plugins: [nodePolyfills({ globals: { Buffer: true, global: true, process: true }, protocolImports: true })],
  build: { target: 'esnext', sourcemap: true },
  optimizeDeps: { exclude: ['@aztec/bb.js'] },
});
