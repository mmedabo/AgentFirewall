# AgentFirewall documentation

## The website (three layers)

**Live at → https://mmedabo.github.io/AgentFirewall/docs/**

(The bare `…/AgentFirewall/` URL also works — a redirect at the repository root
forwards to this folder. See *Publishing on GitHub Pages* below.)

The docs site is plain, self-contained HTML — no build step, no dependencies, no
external assets. Open `index.html` in a browser, or serve the folder:

```bash
python3 -m http.server -d docs 8080     # → http://localhost:8080
```

It's written as three layers, so a reader can stop at the depth they need:

| Layer | File | For whom | What's in it |
|---|---|---|---|
| **01 · Overview** | [`index.html`](index.html) | Anyone | Plain-English intro — what this is, why it matters, one clear verdict. No jargon. |
| **02 · Features** | [`features.html`](features.html) | Evaluators | Every capability: why it's needed, use cases, and honest pros **and cons**. |
| **03 · Reference** | [`reference.html`](reference.html) | Implementers | Architecture, all commands/flags, the full 59-detection catalogue, framework glossary, guardrails API. |

Every page carries the same layer switcher in the header, so moving between
depths is one click.

### Publishing on GitHub Pages

This repository publishes from **branch `main`, folder `/ (root)`**, so the site
is served at `https://<owner>.github.io/<repo>/docs/`. A redirect at
`index.html` in the repository root forwards the bare `/<repo>/` URL here, and
a `.nojekyll` at the root stops Jekyll rendering `README.md` as the homepage.

To get shorter URLs instead, change the folder to `/docs` under
Settings → Pages. The site then serves straight from `https://<owner>.github.io/<repo>/`,
and the two root files become inert (they are simply not published).

The `.nojekyll` file in this folder disables Jekyll processing, so every file is
served exactly as committed. Keep it — without it, Jekyll rewrites `.md` files to
`.html` and ignores anything whose name starts with an underscore.

### Keeping the catalogue accurate

The detection catalogue in `reference.html` is generated from the tool's own
output. After adding or changing detections, regenerate the numbers with:

```bash
afw rules --format json
```

and update the rule rows, the `59 detections / 23 categories` counts in
`reference.html`, and the stat strip in `features.html`.

## The Markdown docs

| Doc | What's in it |
|---|---|
| [`USAGE.md`](USAGE.md) | Task-oriented cookbook for every command, incl. the web UI |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Module map, data flow, and how to extend each layer |
| [`THREAT-MODEL.md`](THREAT-MODEL.md) | Threat model, firewall-mechanics mapping, rule→framework table |
| [`ROADMAP.md`](ROADMAP.md) | Phases: what's shipped and what's planned |
