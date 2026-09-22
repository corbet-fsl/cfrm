import { defineConfig } from 'vite';
import { nodePolyfills } from 'vite-plugin-node-polyfills';
import { fileURLToPath } from 'node:url';
export default defineConfig({
  plugins: [nodePolyfills({ globals: { Buffer: true, global: true, process: true }, protocolImports: true })],
  // The extracted runtime has its own install directory. Resolve injected
  // shims from this fixture's pinned toolchain, and share identical SDK copies.
  // Select their ESM exports: a CJS namespace used as the injected Buffer has
  // no constructor prototype and fails during msgpackr's module initialization.
  resolve: {
    dedupe: ['@aztec/bb.js', '@noir-lang/noir_js'],
    alias: Object.fromEntries(['buffer', 'global', 'process'].map(name => {
      const specifier = `vite-plugin-node-polyfills/shims/${name}`;
      return [specifier, fileURLToPath(import.meta.resolve(specifier))];
    })),
  },
  build: { target: 'esnext', sourcemap: true },
  optimizeDeps: { exclude: ['@aztec/bb.js'] },
});
