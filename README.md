# Local Redactor (PWA)

Find and redact personal data entirely in the browser, with three engines:

- **Pattern rules**: a Go engine compiled to WebAssembly, embedded in `index.html`. Works offline immediately.
- **Entity model**: Transformers.js 4.3.1 running `Xenova/bert-base-NER` (ONNX Runtime Web, WASM backend).
- **Local language model**: wllama 3.8.1 (llama.cpp in WebAssembly) running a small GGUF instruct model.

## Run it

Service workers need `https://` or `localhost`, so serve the folder rather than opening the file directly:

    npx serve .            # or: python3 -m http.server 8080

Open the URL, then use the browser's "Install app" option (or the Install button in the header).

## Offline behaviour

- The service worker caches the app shell and the pinned libraries from cdn.jsdelivr.net, including their `.wasm` files.
- Transformers.js caches model files in the Cache API; wllama caches GGUF files in OPFS.
- Load each AI model once while online. After that, all three engines work in airplane mode.
- The app asks for persistent storage after a model loads so the browser is less likely to evict it.

## Threads

The service worker adds `Cross-Origin-Opener-Policy: same-origin` and
`Cross-Origin-Embedder-Policy: credentialless` to page responses, which enables
multi-threaded WebAssembly in Chromium browsers after the first reload. Safari and
Firefox fall back to a single thread.

## Rebuilding the rules engine

The Go source is in `engine/`. Build and embed:

    GOOS=js GOARCH=wasm go build -ldflags="-s -w" -trimpath -o pii.wasm .
    gzip -9 pii.wasm   # then base64 the .gz into window.PII_WASM_GZ in index.html

Use the `wasm_exec.js` that ships with the same Go version (`$(go env GOROOT)/lib/wasm/`).
