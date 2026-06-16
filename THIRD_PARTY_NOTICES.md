# Third-Party Notices

This repository is distributed under the Apache License, Version 2.0. The
following notices document upstream projects, copied or adapted material, and
runtime tools used by the project.

## CBOMkit

The Docker Compose setup, backend integration flow, and parts of the static
frontend structure were adapted from or designed around CBOMkit.

Preserved upstream notice appearing in copied or adapted material:

```text
CBOMkit
Copyright (C) 2026 PQCA
Licensed to the Apache Software Foundation (ASF) under one or more contributor
license agreements.
```

CBOMkit is referenced by container images under `ghcr.io/cbomkit/*` and by the
frontend API integration with the CBOMkit scan service. CBOMkit names are used
only to identify interoperability and upstream origin.

## Open Policy Agent / Rego

The local policy service uses the Open Policy Agent container image and Rego
policy language for policy evaluation.

Project: https://www.openpolicyagent.org/

## Semgrep

The local Semgrep service installs and invokes Semgrep to evaluate repository
source files against the rules in `configs/`.

Project: https://semgrep.dev/

## NGINX

The local OPA proxy uses the official NGINX Alpine container image to expose
OPA with browser-friendly CORS headers.

Project: https://nginx.org/

## Project Assets

Logos and marks in `cbomkit-site-html/img/` may be subject to separate trademark
or branding terms. Their inclusion in this repository does not grant trademark
rights beyond normal descriptive use.
