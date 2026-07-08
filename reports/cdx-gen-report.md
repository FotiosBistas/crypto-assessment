Created the following `Dockerfile`: 

```bash
fotis@fotis-MS-7B86:~/test/cdxgen-cert-key-image-test$ cat Dockerfile 
FROM alpine:3.20 AS certs

RUN apk add --no-cache openssl

RUN mkdir -p /certs && \
    openssl req \
      -x509 \
      -newkey rsa:2048 \
      -nodes \
      -sha256 \
      -days 365 \
      -subj "/CN=cdxgen-test.local/O=Test Org/C=GR" \
      -keyout /certs/test-private-key.pem \
      -out /certs/test-certificate.pem && \
    openssl pkcs12 \
      -export \
      -inkey /certs/test-private-key.pem \
      -in /certs/test-certificate.pem \
      -out /certs/test-keystore.p12 \
      -passout pass:changeit

FROM eclipse-temurin:17-jdk

WORKDIR /app

COPY --from=certs /certs /app/certs

RUN keytool \
      -importcert \
      -noprompt \
      -alias cdxgen-test \
      -file /app/certs/test-certificate.pem \
      -keystore /app/certs/test-truststore.jks \
      -storepass changeit

CMD ["sh", "-c", "ls -lah /app/certs && sleep infinity"]
```

The detection, must be one of:

| Name                          | Description                                                                                            |
| ----------------------------- | ------------------------------------------------------------------------------------------------------ |
| **"algorithm"**               | Mathematical function commonly used for data encryption, authentication, and digital signatures.       |
| **"certificate"**             | An electronic document that is used to provide the identity or validate a public key.                  |
| **"protocol"**                | A set of rules and guidelines that govern the behavior and communication with each other.              |
| **"related-crypto-material"** | Other cryptographic assets related to algorithms, certificates, and protocols such as keys and tokens. |

This is the classification that should be detected. 

| File                   | What it is                                       | Ideal `assetType`                                                        |
| ---------------------- | ------------------------------------------------ | ------------------------------------------------------------------------ |
| `test-certificate.pem` | X.509 certificate                                | `certificate`                                                            |
| `test-private-key.pem` | Private key                                      | `related-crypto-material`                                                |
| `test-keystore.p12`    | PKCS#12 keystore containing key/cert material    | `related-crypto-material`                                                |
| `test-truststore.jks`  | Java truststore containing trusted cert material | `related-crypto-material`, or extracted contained certs as `certificate` |

And the detection: 

```json
{
  "name": "test-truststore.jks",
  "type": "cryptographic-asset",
  "version": "c70e7450b1d03784d3c42d7a354cae81966f826ac96c89451ff8e725aabe2aa1",
  "bom-ref": "crypto/certificate/test-truststore.jks@sha256:c70e7450b1d03784d3c42d7a354cae81966f826ac96c89451ff8e725aabe2aa1",
  "cryptoProperties": {
    "assetType": "certificate",
    "algorithmProperties": {
      "executionEnvironment": "unknown",
      "implementationPlatform": "unknown"
    }
  },
  "properties": [
    {
      "name": "SrcFile",
      "value": "/app/certs/test-truststore.jks"
    }
  ],
  "tags": [
    "cryptographic-asset"
  ]
}
{
  "name": "test-private-key.pem",
  "type": "cryptographic-asset",
  "version": "ad13e7d2738cd454ce54b783f05524bacbe4dc5243fa8481d9c2d6fe9f7658ea",
  "bom-ref": "crypto/certificate/test-private-key.pem@sha256:ad13e7d2738cd454ce54b783f05524bacbe4dc5243fa8481d9c2d6fe9f7658ea",
  "cryptoProperties": {
    "assetType": "certificate",
    "algorithmProperties": {
      "executionEnvironment": "unknown",
      "implementationPlatform": "unknown"
    }
  },
  "properties": [
    {
      "name": "SrcFile",
      "value": "/app/certs/test-private-key.pem"
    }
  ],
  "tags": [
    "cryptographic-asset"
  ]
}
{
  "name": "test-keystore.p12",
  "type": "cryptographic-asset",
  "version": "3a644700746678ce6a905d679da097aa508cdd7a6355e01c9f30c49ccb736cbd",
  "bom-ref": "crypto/certificate/test-keystore.p12@sha256:3a644700746678ce6a905d679da097aa508cdd7a6355e01c9f30c49ccb736cbd",
  "cryptoProperties": {
    "assetType": "certificate",
    "algorithmProperties": {
      "executionEnvironment": "unknown",
      "implementationPlatform": "unknown"
    }
  },
  "properties": [
    {
      "name": "SrcFile",
      "value": "/app/certs/test-keystore.p12"
    }
  ],
  "tags": [
    "cryptographic-asset"
  ]
}
{
  "name": "test-certificate.pem",
  "type": "cryptographic-asset",
  "version": "348baaca18c097585b7a1162ed98c2729222c9e2f8ed54ad6097b90129d37f4a",
  "bom-ref": "crypto/certificate/test-certificate.pem@sha256:348baaca18c097585b7a1162ed98c2729222c9e2f8ed54ad6097b90129d37f4a",
  "cryptoProperties": {
    "assetType": "certificate",
    "algorithmProperties": {
      "executionEnvironment": "unknown",
      "implementationPlatform": "unknown"
    }
  },
  "properties": [
    {
      "name": "SrcFile",
      "value": "/app/certs/test-certificate.pem"
    }
  ],
  "tags": [
    "cryptographic-asset"
  ]
}
```


It also doesn't seem to generate anything from local source: 

```bash
fotis@fotis-MS-7B86:~/test/cdxgen-cert-key-image-test$ cdxgen -o bom.json ./extracted-certs/
┌────────────────────────┬────────────┬──────────────────────────┬────────────────────────────────────────────────────┐
│                                           SECURE MODE: Environment audit                                            │
│                                                        1 low                                                        │
├────────────────────────┼────────────┼──────────────────────────┼────────────────────────────────────────────────────┤
│ Category               │ Severity   │ Variable(s)              │ Details                                            │
├────────────────────────┼────────────┼──────────────────────────┼────────────────────────────────────────────────────┤
│ Credential Exposure    │ LOW        │ DESKTOP_SESSION          │ Credential-like environment variables are set. Bui │
│                        │            │                          │ ld tools or install scripts invoked during SBOM ge │
│                        │            │                          │ neration may read inherited environment variables. │
│                        │            │                          │ Mitigation: Unset unneeded secrets when scanning u │
│                        │            │                          │ ntrusted repositories. Prefer ephemeral, scoped CI │
│                        │            │                          │  credentials injected only for the step that needs │
│                        │            │                          │  them.                                             │
└────────────────────────┴────────────┴──────────────────────────┴────────────────────────────────────────────────────┘
fotis@fotis-MS-7B86:~/test/cdxgen-cert-key-image-test$ cat bom.json | npx json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.7",
  "serialNumber": "urn:uuid:7022c32e-14b7-4120-834a-bf0ccbb45d6f",
  "version": 1,
  "metadata": {
    "timestamp": "2026-06-17T23:32:13Z",
    "tools": {
      "components": [
        {
          "group": "@cyclonedx",
          "name": "cdxgen",
          "version": "12.6.0",
          "purl": "pkg:npm/%40cyclonedx/cdxgen@12.6.0",
          "type": "application",
          "bom-ref": "pkg:npm/@cyclonedx/cdxgen@12.6.0",
          "publisher": "OWASP Foundation",
          "authors": [
            {
              "name": "OWASP Foundation"
            }
          ]
        }
      ]
    },
    "authors": [
      {
        "name": "OWASP Foundation"
      }
    ],
    "lifecycles": [
      {
        "phase": "build"
      }
    ],
    "properties": []
  },
  "components": [],
  "services": [],
  "dependencies": [],
  "annotations": [
    {
      "bom-ref": "metadata-annotations",
      "subjects": [
        "urn:uuid:7022c32e-14b7-4120-834a-bf0ccbb45d6f"
      ],
      "annotator": {
        "component": {
          "group": "@cyclonedx",
          "name": "cdxgen",
          "version": "12.6.0",
          "purl": "pkg:npm/%40cyclonedx/cdxgen@12.6.0",
          "type": "application",
          "bom-ref": "pkg:npm/@cyclonedx/cdxgen@12.6.0",
          "publisher": "OWASP Foundation",
          "authors": [
            {
              "name": "OWASP Foundation"
            }
          ]
        }
      },
      "timestamp": "2026-06-17T23:32:13Z",
      "text": "This Software Bill-of-Materials (SBOM) document was created on Wednesday, June 17, 2026 with cdxgen. The data was captured during the build lifecycle phase. BOM file is empty without components."
    }
  ]
}
```

Tried putting it in a Repo first and it doesn't seem to work it produces the same empty output.



With this command it works: 
```bash
fotis@fotis-MS-7B86:~/test/cdxgen-cert-key-image-test$ cdxgen --include-crypto -o bom.json ./extracted-certs/
```
This is the following output: 
```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.7",
  "serialNumber": "urn:uuid:86a04f46-f7c0-4165-851b-0c4eedd63351",
  "version": 2,
  "metadata": {
    "timestamp": "2026-06-17T23:52:30Z",
    "tools": {
      "components": [
        {
          "group": "@cyclonedx",
          "name": "cdxgen",
          "version": "12.6.0",
          "purl": "pkg:npm/%40cyclonedx/cdxgen@12.6.0",
          "type": "application",
          "bom-ref": "pkg:npm/@cyclonedx/cdxgen@12.6.0",
          "publisher": "OWASP Foundation",
          "authors": [
            {
              "name": "OWASP Foundation"
            }
          ]
        }
      ]
    },
    "authors": [
      {
        "name": "OWASP Foundation"
      }
    ],
    "lifecycles": [
      {
        "phase": "build"
      }
    ],
    "properties": [
      {
        "name": "cdx:bom:componentSrcFiles",
        "value": "extracted-certs/test-certificate.pem\\nextracted-certs/test-keystore.p12\\nextracted-certs/test-private-key.pem\\nextracted-certs/test-truststore.jks"
      }
    ]
  },
  "components": [
    {
      "name": "test-truststore.jks",
      "type": "cryptographic-asset",
      "version": "c70e7450b1d03784d3c42d7a354cae81966f826ac96c89451ff8e725aabe2aa1",
      "bom-ref": "crypto/certificate/test-truststore.jks@sha256:c70e7450b1d03784d3c42d7a354cae81966f826ac96c89451ff8e725aabe2aa1",
      "cryptoProperties": {
        "assetType": "certificate",
        "algorithmProperties": {
          "executionEnvironment": "unknown",
          "implementationPlatform": "unknown"
        }
      },
      "properties": [
        {
          "name": "SrcFile",
          "value": "extracted-certs/test-truststore.jks"
        }
      ],
      "tags": [
        "cryptographic-asset"
      ]
    },
    {
      "name": "test-private-key.pem",
      "type": "cryptographic-asset",
      "version": "ad13e7d2738cd454ce54b783f05524bacbe4dc5243fa8481d9c2d6fe9f7658ea",
      "bom-ref": "crypto/certificate/test-private-key.pem@sha256:ad13e7d2738cd454ce54b783f05524bacbe4dc5243fa8481d9c2d6fe9f7658ea",
      "cryptoProperties": {
        "assetType": "certificate",
        "algorithmProperties": {
          "executionEnvironment": "unknown",
          "implementationPlatform": "unknown"
        }
      },
      "properties": [
        {
          "name": "SrcFile",
          "value": "extracted-certs/test-private-key.pem"
        }
      ],
      "tags": [
        "cryptographic-asset"
      ]
    },
    {
      "name": "test-keystore.p12",
      "type": "cryptographic-asset",
      "version": "3a644700746678ce6a905d679da097aa508cdd7a6355e01c9f30c49ccb736cbd",
      "bom-ref": "crypto/certificate/test-keystore.p12@sha256:3a644700746678ce6a905d679da097aa508cdd7a6355e01c9f30c49ccb736cbd",
      "cryptoProperties": {
        "assetType": "certificate",
        "algorithmProperties": {
          "executionEnvironment": "unknown",
          "implementationPlatform": "unknown"
        }
      },
      "properties": [
        {
          "name": "SrcFile",
          "value": "extracted-certs/test-keystore.p12"
        }
      ],
      "tags": [
        "cryptographic-asset"
      ]
    },
    {
      "name": "test-certificate.pem",
      "type": "cryptographic-asset",
      "version": "348baaca18c097585b7a1162ed98c2729222c9e2f8ed54ad6097b90129d37f4a",
      "bom-ref": "crypto/certificate/test-certificate.pem@sha256:348baaca18c097585b7a1162ed98c2729222c9e2f8ed54ad6097b90129d37f4a",
      "cryptoProperties": {
        "assetType": "certificate",
        "algorithmProperties": {
          "executionEnvironment": "unknown",
          "implementationPlatform": "unknown"
        }
      },
      "properties": [
        {
          "name": "SrcFile",
          "value": "extracted-certs/test-certificate.pem"
        }
      ],
      "tags": [
        "cryptographic-asset"
      ]
    }
  ],
  "services": [],
  "dependencies": [],
  "annotations": [
    {
      "bom-ref": "metadata-annotations",
      "subjects": [
        "urn:uuid:86a04f46-f7c0-4165-851b-0c4eedd63351"
      ],
      "annotator": {
        "component": {
          "group": "@cyclonedx",
          "name": "cdxgen",
          "version": "12.6.0",
          "purl": "pkg:npm/%40cyclonedx/cdxgen@12.6.0",
          "type": "application",
          "bom-ref": "pkg:npm/@cyclonedx/cdxgen@12.6.0",
          "publisher": "OWASP Foundation",
          "authors": [
            {
              "name": "OWASP Foundation"
            }
          ]
        }
      },
      "timestamp": "2026-06-17T23:52:30Z",
      "text": "This Cryptography Bill-of-Materials (CBOM) document was created on Wednesday, June 17, 2026 with cdxgen. The data was captured during the build lifecycle phase. There are 4 components."
    }
  ]
}
```


Again the detection as a certificates seems to be wrong.
