# AgentFirewall documentation

## The website

**Live at → https://mmedabo.github.io/AIAgentFirewall/**

The site lives at the **repository root** (`index.html`, `features.html`,
`reference.html`, plus `fonts/` and `favicon.svg`), which is where GitHub Pages
publishes from — so the URLs stay short and no redirect is involved.

It is plain, self-contained HTML: no build step, no dependencies, and no
third-party requests (the two webfonts are vendored under `fonts/`). Preview it
locally by serving the repository root:

```bash
python3 -m http.server 8080     # → http://localhost:8080
```

It's written as three layers, so a reader can stop at the depth they need:

| Layer | File | For whom | What's in it |
|---|---|---|---|
| **01 · Overview** | [`index.html`](../index.html) | Anyone | Plain-English intro — what this is and why it matters. No jargon. |
| **02 · Features** | [`features.html`](../features.html) | Evaluators | Every capability: why it's needed, use cases, and honest pros **and cons**. |
| **03 · Reference** | [`reference.html`](../reference.html) | Implementers | Architecture, all commands/flags, the full detection catalogue, framework glossary, guardrails API. |

Every page carries the same layer switcher in the header, so moving between
depths is one click.

### GitHub Pages setup

Settings → Pages → Source: *Deploy from a branch* → branch `main`, folder
`/ (root)`. The `.nojekyll` file at the repository root disables Jekyll, so every
file is served exactly as committed — without it, Jekyll rewrites `.md` files to
`.html`, ignores anything whose name starts with an underscore, and renders
`README.md` as the homepage when no `index.html` is present.

### Keeping the catalogue accurate

The detection catalogue in `reference.html` is generated from the tool's own
output. After adding or changing detections, regenerate the numbers with:

```bash
afw rules --format json
```

and update the rule rows, the `59 detections / 23 categories` counts in
`reference.html`, and the stat strip in `index.html`.

## The Markdown docs

These stay in `docs/` so the repository root isn't cluttered:

| Doc | What's in it |
|---|---|
| [`USAGE.md`](USAGE.md) | Task-oriented cookbook for every command, incl. the web UI |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Module map, data flow, and how to extend each layer |
| [`THREAT-MODEL.md`](THREAT-MODEL.md) | Threat model, firewall-mechanics mapping, rule→framework table |
| [`ROADMAP.md`](ROADMAP.md) | Phases: what's shipped and what's planned |
