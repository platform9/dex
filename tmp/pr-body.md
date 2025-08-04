# 🚨 Gosec Vulnerability Report (High/Critical)
* File: /home/runner/work/dex/dex/storage/kubernetes/storage.go
    • Line: 737
    • Rule ID: G404
    • Details: Use of weak random number generator (math/rand or math/rand/v2 instead of crypto/rand)
    • Confidence: MEDIUM
    • Severity: HIGH
* File: /home/runner/work/dex/dex/storage/sql/config.go
    • Line: 320
    • Rule ID: G402
    • Details: TLS MinVersion too low.
    • Confidence: HIGH
    • Severity: HIGH
* File: /home/runner/work/dex/dex/storage/ent/mysql.go
    • Line: 130
    • Rule ID: G402
    • Details: TLS MinVersion too low.
    • Confidence: HIGH
    • Severity: HIGH
* File: /home/runner/work/dex/dex/examples/grpc-client/client.go
    • Line: 33-36
    • Rule ID: G402
    • Details: TLS MinVersion too low.
    • Confidence: HIGH
    • Severity: HIGH
* File: /home/runner/work/dex/dex/examples/example-app/main.go
    • Line: 44
    • Rule ID: G402
    • Details: TLS MinVersion too low.
    • Confidence: HIGH
    • Severity: HIGH
* File: /home/runner/work/dex/dex/connector/openshift/openshift.go
    • Line: 272
    • Rule ID: G402
    • Details: TLS MinVersion too low.
    • Confidence: HIGH
    • Severity: HIGH
* File: /home/runner/work/dex/dex/connector/openshift/openshift.go
    • Line: 268
    • Rule ID: G402
    • Details: TLS MinVersion too low.
    • Confidence: HIGH
    • Severity: HIGH
* File: /home/runner/work/dex/dex/connector/github/github.go
    • Line: 213
    • Rule ID: G402
    • Details: TLS MinVersion too low.
    • Confidence: HIGH
    • Severity: HIGH
* File: /home/runner/work/dex/dex/connector/openshift/openshift.go
    • Line: 270
    • Rule ID: G402
    • Details: TLS InsecureSkipVerify set true.
    • Confidence: HIGH
    • Severity: HIGH
* File: /home/runner/work/dex/dex/connector/oauth/oauth.go
    • Line: 129
    • Rule ID: G402
    • Details: TLS InsecureSkipVerify set true.
    • Confidence: HIGH
    • Severity: HIGH
* File: /home/runner/work/dex/dex/connector/ldap/ldap.go
    • Line: 257
    • Rule ID: G402
    • Details: TLS InsecureSkipVerify may be true.
    • Confidence: LOW
    • Severity: HIGH
* File: /home/runner/work/dex/dex/connector/keystone/keystone.go
    • Line: 186
    • Rule ID: G402
    • Details: TLS InsecureSkipVerify may be true.
    • Confidence: LOW
    • Severity: HIGH
* File: /home/runner/work/dex/dex/connector/saml/saml.go
    • Line: 46
    • Rule ID: G101
    • Details: Potential hardcoded credentials
    • Confidence: LOW
    • Severity: HIGH
* File: /home/runner/work/dex/dex/connector/linkedin/linkedin.go
    • Line: 21
    • Rule ID: G101
    • Details: Potential hardcoded credentials
    • Confidence: LOW
    • Severity: HIGH
