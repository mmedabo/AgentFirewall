# AgentFirewall documentation

## The website (three layers)

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

Settings → Pages → Source: *Deploy from a branch* → branch `main`, folder
`/docs`. The site is then served at
`https://<owner>.github.io/<repo>/`.

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
