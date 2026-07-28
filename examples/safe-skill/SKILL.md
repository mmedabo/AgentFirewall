---
name: markdown-toc
description: Generate a table of contents for a Markdown file by parsing its headings.
allowed-tools: Read, Edit
---

# Markdown Table of Contents

This skill reads a Markdown document, collects its `#`/`##`/`###` headings, and
inserts a linked table of contents at the top.

## Usage

Point the skill at a `.md` file. It parses headings locally and writes the
table of contents back into the file. It does not access the network, read
credentials, or run shell commands.

See `toc.py` for the implementation.
