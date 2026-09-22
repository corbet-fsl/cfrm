# cfrm-browser

Portable Rust/Wasm logic for signed roster verification and blind permits.
The application owns all frontend, trusted configuration, transport and storage.
This companion package is separate from the JavaScript `cfrm` package, which
provides profiles and accounting. It has no runtime npm dependencies.

Install the `cfrm-browser-0.1.0-alpha.0.tgz` archive from a successful browser CI
receipt after checking its source revision and `SHA256SUMS`. It is a private,
locally installable package; no registry publication is required:

```sh
npm install ./cfrm-browser-0.1.0-alpha.0.tgz
```

For a Vite/Svelte consumer, initialize after browser hydration:

```js
import init, {
  BrowserMeetingBoard, BrowserPreparedPermit, BrowserRecipientClaim,
} from 'cfrm-browser';
import wasmUrl from 'cfrm-browser/wasm?url';

await init({ module_or_path: wasmUrl });
```

Other bundlers must serve the exported `cfrm-browser/wasm` asset and pass its
URL or bytes to `init`. When loading the generated module directly with native
ES modules, `init()` resolves the sibling `cfrm_bg.wasm`. Keep all four generated
`pkg` files together; the package includes TypeScript declarations.

Supply independently pinned roster trust and explicit resource limits. Keep
permit epochs independently pinned, save encrypted checkpoints before network
requests, retry exact saved requests, and call `free()` on Wasm objects when
finished. The generated types and the
[binding contract](https://github.com/cmtymeet/cfrm/blob/main/browser/README.md)
describe the constructors and lifecycle. Preserve the CI source revision when
consulting source documentation.

These are aggregate bearer permits. This package does not establish roster
completeness, Tor transport or private reciprocity proof acceptance. The CI
receipt distinguishes its synthetic native fixture from production services.
