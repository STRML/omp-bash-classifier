# Repository context

## Source locations

- This plugin's source is `./index.ts`.
- The installed OMP host package is available locally at
  `./node_modules/@oh-my-pi/pi-coding-agent/`.
- Read host TypeScript source under
  `./node_modules/@oh-my-pi/pi-coding-agent/src/`.
- Read the built runtime and declarations under
  `./node_modules/@oh-my-pi/pi-coding-agent/dist/`.
- `node_modules/@oh-my-pi` is deliberately symlinked to bun's global installation; resolve
  it with `realpath` when an absolute path is required. Read the installed package's
  `package.json` for the current version instead of assuming one.
- The active CLI is `~/.bun/bin/omp`.
- OMP's maintained runtime documentation is available through `omp://`; read the relevant
  document directly instead of searching the filesystem for generated docs.

The host source is not part of this repository's git tree, but it **is on disk**. Do not
clone OMP, run `npm pack`, or hunt through unrelated directories to inspect it. Verification
subagents should use the local `node_modules/@oh-my-pi/pi-coding-agent/{src,dist}` paths.
