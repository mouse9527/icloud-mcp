# Notices

This repository builds a container image from third-party open-source code.
It does not vendor that code; the Dockerfile fetches it at a pinned commit and
applies the patches in `patches/`. Their licenses apply to the built image.

## tomernation/icloud-mcp

Source: https://github.com/tomernation/icloud-mcp
Pinned commit: c027fd74c3f1e8435313830b70adcc63bad898ca
The files in `patches/` are modifications of that project and are distributed
under its license, reproduced verbatim below. Its own `THIRD_PARTY_NOTICES.md`
(Go module licenses) applies to the compiled binary.

```
MIT License

Copyright (c) 2026 Thomas Crouzet

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## timlaing/pyicloud

Source: https://github.com/timlaing/pyicloud
Pinned commit: 86c4bc90d5632bcaf7507e5335e127f7450a177a (installed via the
upstream `scripts/reminders-probe-requirements.txt`, MIT License,
Copyright (c) 2025 The PyiCloud Authors).
