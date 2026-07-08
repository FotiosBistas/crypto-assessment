# CBOM Generator Detection Accuracy

This report documents a known-answer test of `cbom-generator` against a controlled test corpus containing both real cryptographic material and intentionally non-cryptographic decoys.

The goal was to check whether the tool could:

1. Detect known certificates and private keys.
2. Avoid reporting fake or non-cryptographic files as cryptographic assets.
3. Produce entries in the CBOM that correspond to the expected key and certificate files.

For this controlled corpus, `cbom-generator` correctly detected every intentionally generated cryptographic asset and ignored every negative decoy file.

That means the test passed for both:

- **Detection accuracy**: all real keys and certificates were found.
- **False-positive resistance**: files that merely looked suspicious or contained crypto-related words were not reported as detected assets.

## Test Corpus

The test corpus was divided into two groups:

- `positive/`: files that should be detected by the CBOM generator.
- `negative/`: files that should not be detected as real cryptographic assets.

## Detailed Results

| File | Expected Type | Components Found | Scalar Hits | Result |
|---|---:|---:|---:|---|
| `/opt/cbom-accuracy/positive/real-rsa-2048-key.pem` | Key | 1 | 4 | True Positive |
| `/opt/cbom-accuracy/positive/real-rsa-2048-cert.pem` | Certificate | 1 | 4 | True Positive |
| `/opt/cbom-accuracy/positive/weak-rsa-1024-key.pem` | Key | 1 | 4 | True Positive |
| `/opt/cbom-accuracy/positive/weak-rsa-1024-cert.pem` | Certificate | 1 | 4 | True Positive |
| `/opt/cbom-accuracy/positive/real-ec-p256-key.pem` | Key | 1 | 4 | True Positive |
| `/opt/cbom-accuracy/positive/real-ec-p256-cert.pem` | Certificate | 1 | 4 | True Positive |
| `/opt/cbom-accuracy/positive/encrypted-rsa-2048-key.pem` | Key | 1 | 4 | True Positive |
| `/opt/cbom-accuracy/negative/crypto-words.txt` | Negative | 0 | 0 | True Negative |
| `/opt/cbom-accuracy/negative/fake-private-key.pem` | Negative | 0 | 0 | True Negative |
| `/opt/cbom-accuracy/negative/fake-certificate.pem` | Negative | 0 | 0 | True Negative |
| `/opt/cbom-accuracy/negative/random.bin` | Negative | 0 | 0 | True Negative |
| `/opt/cbom-accuracy/negative/hash-only.txt` | Negative | 0 | 0 | True Negative |

## Positive Detection Coverage

The tool successfully detected the following cryptographic asset types in this test:

| Asset Type | Tested Example | Detected |
|---|---|---|
| RSA private key | RSA 2048-bit private key | Yes |
| RSA certificate | RSA 2048-bit self-signed certificate | Yes |
| Weak RSA private key | RSA 1024-bit private key | Yes |
| Weak RSA certificate | RSA 1024-bit self-signed certificate | Yes |
| Elliptic curve private key | P-256 EC private key | Yes |
| Elliptic curve certificate | P-256 self-signed certificate | Yes |
| Encrypted private key | AES-encrypted RSA 2048-bit private key | Yes |

## False-Positive Checks

The tool did not detect any of the negative canary files as cryptographic assets.

| Negative Test Case | Purpose | Detected |
|---|---|---:|
| Text file mentioning crypto terms | Checks whether keyword-only files are falsely detected | No |
| Fake PEM private key | Checks whether invalid PEM-like content is falsely detected | No |
| Fake PEM certificate | Checks whether invalid certificate-like content is falsely detected | No |
| Random binary file | Checks whether random bytes are falsely detected | No |
| Hash-only text file | Checks whether a hash string alone is treated as crypto material | No |

## Reproducibility

This section contains the full set of steps needed to reproduce the test from a clean working directory. The commands assume Docker is already installed on the host. 
### 1. Create a clean working directory

```bash
mkdir -p cbom-accuracy-test/out
cd cbom-accuracy-test
```

### 2. Create the base CBOM generator image

Create `Dockerfile`:

```Dockerfile
FROM fedora:latest

ARG CBOM_VERSION=1.9.3

RUN dnf -y update && \
    dnf -y install \
      bash \
      ca-certificates \
      wget \
      tar \
      gzip \
      coreutils \
      findutils \
      jq \
      openssl \
      openssh-clients \
      curl \
      nginx \
      jansson && \
    dnf clean all

# Add a small generated certificate/key so the base image also has
# obvious crypto material available for quick smoke tests.
RUN mkdir -p /etc/cbom-test && \
    openssl req -x509 -newkey rsa:2048 \
      -keyout /etc/cbom-test/test-key.pem \
      -out /etc/cbom-test/test-cert.pem \
      -days 7 \
      -nodes \
      -subj "/CN=cbom-test.local"

WORKDIR /tmp/cbom-install

RUN wget -q https://github.com/CipherIQ/cbom-generator/releases/download/v${CBOM_VERSION}/cbom-generator-${CBOM_VERSION}-linux-amd64.tar.gz && \
    wget -q https://github.com/CipherIQ/cbom-generator/releases/download/v${CBOM_VERSION}/checksums.txt && \
    grep "cbom-generator-${CBOM_VERSION}-linux-amd64.tar.gz" checksums.txt | sha256sum -c - && \
    tar -xzf cbom-generator-${CBOM_VERSION}-linux-amd64.tar.gz && \
    install -m 755 cbom-generator-${CBOM_VERSION}-linux-amd64 /usr/local/bin/cbom-generator && \
    mkdir -p /usr/local/share/cbom-generator && \
    cp -r plugins registry /usr/local/share/cbom-generator/ && \
    rm -rf /tmp/cbom-install

WORKDIR /work

CMD ["/bin/bash"]
```

Build the base image:

```bash
docker build -t cbom-generator-test:latest .
```

Optional smoke test:

```bash
docker run --rm cbom-generator-test:latest cbom-generator --version
```

The binary may print warnings similar to the following on Fedora-based images:

```text
/lib64/libtinfo.so.6: no version information available
/lib64/libncurses.so.6: no version information available
```

In this test environment those warnings did not prevent successful CBOM generation.

### 3. Create the known-answer accuracy image

Create `Dockerfile.known-answer`:

```Dockerfile
FROM cbom-generator-test:latest

RUN mkdir -p /opt/cbom-accuracy/positive /opt/cbom-accuracy/negative

# Positive: real RSA 2048-bit key + certificate.
RUN openssl genpkey \
      -algorithm RSA \
      -pkeyopt rsa_keygen_bits:2048 \
      -out /opt/cbom-accuracy/positive/real-rsa-2048-key.pem && \
    openssl req -new -x509 \
      -key /opt/cbom-accuracy/positive/real-rsa-2048-key.pem \
      -out /opt/cbom-accuracy/positive/real-rsa-2048-cert.pem \
      -days 30 \
      -subj "/CN=CBOM_ACCURACY_REAL_RSA_2048"

# Positive: weak RSA 1024-bit key + certificate.
RUN openssl genpkey \
      -algorithm RSA \
      -pkeyopt rsa_keygen_bits:1024 \
      -out /opt/cbom-accuracy/positive/weak-rsa-1024-key.pem && \
    openssl req -new -x509 \
      -key /opt/cbom-accuracy/positive/weak-rsa-1024-key.pem \
      -out /opt/cbom-accuracy/positive/weak-rsa-1024-cert.pem \
      -days 30 \
      -subj "/CN=CBOM_ACCURACY_WEAK_RSA_1024"

# Positive: EC P-256 key + certificate.
RUN openssl ecparam \
      -name prime256v1 \
      -genkey \
      -noout \
      -out /opt/cbom-accuracy/positive/real-ec-p256-key.pem && \
    openssl req -new -x509 \
      -key /opt/cbom-accuracy/positive/real-ec-p256-key.pem \
      -out /opt/cbom-accuracy/positive/real-ec-p256-cert.pem \
      -days 30 \
      -subj "/CN=CBOM_ACCURACY_REAL_EC_P256"

# Positive: encrypted RSA private key.
RUN openssl genpkey \
      -algorithm RSA \
      -pkeyopt rsa_keygen_bits:2048 \
      -aes-256-cbc \
      -pass pass:cbomtest \
      -out /opt/cbom-accuracy/positive/encrypted-rsa-2048-key.pem

# Negative: decoy files that mention or resemble crypto material,
# but should not be treated as valid keys or certificates.
RUN printf 'This is just documentation mentioning RSA, AES, TLS, and certificates.\n' \
      > /opt/cbom-accuracy/negative/crypto-words.txt && \
    printf '%s\n' \
      '-----BEGIN PRIVATE KEY-----' \
      'this is not valid base64' \
      '-----END PRIVATE KEY-----' \
      > /opt/cbom-accuracy/negative/fake-private-key.pem && \
    printf '%s\n' \
      '-----BEGIN CERTIFICATE-----' \
      'not a real certificate' \
      '-----END CERTIFICATE-----' \
      > /opt/cbom-accuracy/negative/fake-certificate.pem && \
    head -c 4096 /dev/urandom > /opt/cbom-accuracy/negative/random.bin && \
    printf 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' \
      > /opt/cbom-accuracy/negative/hash-only.txt

# Manifest used as the ground truth for the report script.
RUN cat > /opt/cbom-accuracy/manifest.tsv <<'EOF'
path	expected
/opt/cbom-accuracy/positive/real-rsa-2048-key.pem	key
/opt/cbom-accuracy/positive/real-rsa-2048-cert.pem	certificate
/opt/cbom-accuracy/positive/weak-rsa-1024-key.pem	key
/opt/cbom-accuracy/positive/weak-rsa-1024-cert.pem	certificate
/opt/cbom-accuracy/positive/real-ec-p256-key.pem	key
/opt/cbom-accuracy/positive/real-ec-p256-cert.pem	certificate
/opt/cbom-accuracy/positive/encrypted-rsa-2048-key.pem	key
/opt/cbom-accuracy/negative/crypto-words.txt	negative
/opt/cbom-accuracy/negative/fake-private-key.pem	negative
/opt/cbom-accuracy/negative/fake-certificate.pem	negative
/opt/cbom-accuracy/negative/random.bin	negative
/opt/cbom-accuracy/negative/hash-only.txt	negative
EOF
```

Build the known-answer image:

```bash
docker build -f Dockerfile.known-answer -t cbom-generator-accuracy:latest .
```

### 4. Run the CBOM scan

```bash
mkdir -p out

docker run --rm \
  -v "$PWD/out:/out:Z" \
  cbom-generator-accuracy:latest \
  bash -lc '
    cp /opt/cbom-accuracy/manifest.tsv /out/manifest.tsv

    cbom-generator \
      --no-personal-data \
      --format cyclonedx \
      --cyclonedx-spec 1.7 \
      --output /out/cbom-accuracy.json \
      /opt/cbom-accuracy \
      2>&1 | tee /out/cbom-accuracy.log
  '
```

Expected output files:

```text
out/cbom-accuracy.json
out/cbom-accuracy.log
out/manifest.tsv
```

### 5. Validate the generated CBOM shape

```bash
jq -e '
  .bomFormat == "CycloneDX"
  and .specVersion == "1.7"
  and (.components | type == "array")
  and (.components | length > 0)
' out/cbom-accuracy.json
```

A successful validation exits with status code `0`.

### 6. Generate the entry report

Create `show_cbom_entries.py`:

```python
import json
from pathlib import Path
from typing import Any

CBOM_PATH = Path("out/cbom-accuracy.json")
MANIFEST_PATH = Path("out/manifest.tsv")
OUT_PATH = Path("out/cbom-entry-report.json")

cbom = json.loads(CBOM_PATH.read_text())


def contains_text(obj: Any, needles: list[str]) -> bool:
    if isinstance(obj, dict):
        return any(contains_text(v, needles) for v in obj.values())
    if isinstance(obj, list):
        return any(contains_text(v, needles) for v in obj)
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        s = str(obj)
        return any(n in s for n in needles)
    return False


def scalar_hits(obj: Any, needles: list[str], path: str = "$") -> list[dict[str, str]]:
    hits = []

    if isinstance(obj, dict):
        for k, v in obj.items():
            hits.extend(scalar_hits(v, needles, f"{path}.{k}"))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            hits.extend(scalar_hits(v, needles, f"{path}[{i}]"))
    else:
        s = str(obj)
        for n in needles:
            if n in s:
                hits.append({"path": path, "needle": n, "value": s})

    return hits


def short_component(c: dict[str, Any]) -> dict[str, Any]:
    return {
        "bom-ref": c.get("bom-ref"),
        "type": c.get("type"),
        "name": c.get("name"),
        "version": c.get("version"),
        "description": c.get("description"),
        "properties": c.get("properties"),
        "evidence": c.get("evidence"),
        "hashes": c.get("hashes"),
    }


rows = []
for line in MANIFEST_PATH.read_text().splitlines()[1:]:
    file_path, expected = line.split("\t")
    basename = Path(file_path).name
    needles = [file_path, basename]

    components = [
        c for c in cbom.get("components", [])
        if contains_text(c, needles)
    ]

    services = [
        s for s in cbom.get("services", [])
        if contains_text(s, needles)
    ]

    vulnerabilities = [
        v for v in cbom.get("vulnerabilities", [])
        if contains_text(v, needles)
    ]

    matching_bom_refs = {
        c.get("bom-ref")
        for c in components
        if c.get("bom-ref")
    }

    dependencies = [
        d for d in cbom.get("dependencies", [])
        if contains_text(d, list(matching_bom_refs))
    ]

    all_hits = scalar_hits(cbom, needles)

    rows.append({
        "file": file_path,
        "expected": expected,
        "seen": bool(components or services or vulnerabilities or all_hits),
        "component_count": len(components),
        "service_count": len(services),
        "dependency_count": len(dependencies),
        "vulnerability_count": len(vulnerabilities),
        "scalar_hit_count": len(all_hits),
        "component_summaries": [short_component(c) for c in components],
        "components_full": components,
        "services_full": services,
        "dependencies_full": dependencies,
        "vulnerabilities_full": vulnerabilities,
        "scalar_hits": all_hits,
    })

OUT_PATH.write_text(json.dumps(rows, indent=2))
print(f"Wrote {OUT_PATH}")

for row in rows:
    status = "SEEN" if row["seen"] else "MISSING"
    print(
        f'{status}\t{row["expected"]}\t'
        f'components={row["component_count"]}\t'
        f'hits={row["scalar_hit_count"]}\t'
        f'{row["file"]}'
    )
```

Run it:

```bash
python3 show_cbom_entries.py | tee out/accuracy-report.tsv
```

The script writes the full matching CBOM objects to:

```text
out/cbom-entry-report.json
```

### 7. Inspect certificate and key entries

Show only the positive key and certificate matches:

```bash
jq '
  .[]
  | select(.expected != "negative")
  | {
      file,
      expected,
      seen,
      component_summaries
    }
' out/cbom-entry-report.json
```

Show possible false positives:

```bash
jq '
  .[]
  | select(.expected == "negative" and .seen == true)
  | {
      file,
      expected,
      seen,
      component_summaries,
      scalar_hits
    }
' out/cbom-entry-report.json
```

For the reported run, the false-positive query returned no entries.

### 8. Observed output summary

```text
SEEN    key             components=1    hits=4  /opt/cbom-accuracy/positive/real-rsa-2048-key.pem
SEEN    certificate     components=1    hits=4  /opt/cbom-accuracy/positive/real-rsa-2048-cert.pem
SEEN    key             components=1    hits=4  /opt/cbom-accuracy/positive/weak-rsa-1024-key.pem
SEEN    certificate     components=1    hits=4  /opt/cbom-accuracy/positive/weak-rsa-1024-cert.pem
SEEN    key             components=1    hits=4  /opt/cbom-accuracy/positive/real-ec-p256-key.pem
SEEN    certificate     components=1    hits=4  /opt/cbom-accuracy/positive/real-ec-p256-cert.pem
SEEN    key             components=1    hits=4  /opt/cbom-accuracy/positive/encrypted-rsa-2048-key.pem
MISSING negative        components=0    hits=0  /opt/cbom-accuracy/negative/crypto-words.txt
MISSING negative        components=0    hits=0  /opt/cbom-accuracy/negative/fake-private-key.pem
MISSING negative        components=0    hits=0  /opt/cbom-accuracy/negative/fake-certificate.pem
MISSING negative        components=0    hits=0  /opt/cbom-accuracy/negative/random.bin
MISSING negative        components=0    hits=0  /opt/cbom-accuracy/negative/hash-only.txt
```

In this output, `MISSING negative` is a successful result because the negative files were expected not to appear in the CBOM.




