# Third-Party Notices

This repository is distributed under the Apache License, Version 2.0. The
following notices document upstream projects, copied and modified material,
design inspiration, and runtime tools used by the project.

## CBOMkit

The Docker Compose setup was copied from CBOMkit and modified for this project.
The upstream notice is preserved in `docker-compose.yml`.

Preserved upstream notice appearing in the copied and modified Compose file:

```text
CBOMkit
Copyright (C) 2026 PQCA
Licensed to the Apache Software Foundation (ASF) under one or more contributor
license agreements.
```

The static frontend was independently implemented for this project. Its user
input model and workflow were inspired by CBOMkit concepts, including scanning a
Git URL, optionally selecting a scan path, and evaluating generated CBOM data
with Rego policies. No CBOMkit frontend source code was copied into this
repository.

The similar repository-scan input flow includes:

- Git URL
- Scan path
- Branch
- Commit
- Personal access token
- Check compliance action

The Rego policy-evaluation flow is an independently implemented approach
inspired by CBOMkit's use of policy evaluation. No CBOMkit policy-evaluation
source code was copied into this repository.

CBOMkit is referenced by container images under `ghcr.io/cbomkit/*` and by the
frontend API integration with the CBOMkit scan service. CBOMkit names are used
only to identify interoperability, inspiration, and upstream origin of the
copied Compose file.

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
