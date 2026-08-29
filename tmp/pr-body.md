# 🚨 Gosec Vulnerability Report for branch `master`
* File: /home/runner/work/dex/dex/storage/kubernetes/storage.go
  • Line: 748
  • Rule ID: G404
  • Details: Use of weak random number generator (math/rand or math/rand/v2 instead of crypto/rand)
  • Confidence: MEDIUM
  • Severity: HIGH

* File: /home/runner/work/dex/dex/cmd/dex/serve.go
  • Line: 479-484
  • Rule ID: G402
  • Details: TLS MinVersion too low.
  • Confidence: HIGH
  • Severity: HIGH

* File: /home/runner/work/dex/dex/cmd/dex/serve.go
  • Line: 177-182
  • Rule ID: G402
  • Details: TLS MinVersion too low.
  • Confidence: HIGH
  • Severity: HIGH

* File: /home/runner/work/dex/dex/pkg/httpclient/httpclient.go
  • Line: 40
  • Rule ID: G402
  • Details: TLS InsecureSkipVerify may be set to true.
  • Confidence: LOW
  • Severity: HIGH

* File: /home/runner/work/dex/dex/connector/ldap/ldap.go
  • Line: 265
  • Rule ID: G402
  • Details: TLS InsecureSkipVerify may be set to true.
  • Confidence: LOW
  • Severity: HIGH

* File: /home/runner/work/dex/dex/connector/keystone/keystone.go
  • Line: 41
  • Rule ID: G402
  • Details: TLS InsecureSkipVerify may be set to true.
  • Confidence: LOW
  • Severity: HIGH

* File: /home/runner/work/dex/dex/connector/github/github.go
  • Line: 465
  • Rule ID: G704
  • Details: SSRF via taint analysis
  • Confidence: HIGH
  • Severity: HIGH

* File: /home/runner/work/dex/dex/connector/github/github.go
  • Line: 460
  • Rule ID: G704
  • Details: SSRF via taint analysis
  • Confidence: HIGH
  • Severity: HIGH

* File: /home/runner/work/dex/dex/storage/kubernetes/transport.go
  • Line: 87-91
  • Rule ID: G101
  • Details: Potential hardcoded credentials
  • Confidence: LOW
  • Severity: HIGH

* File: /home/runner/work/dex/dex/server/oauth2.go
  • Line: 145
  • Rule ID: G101
  • Details: Potential hardcoded credentials
  • Confidence: LOW
  • Severity: HIGH

* File: /home/runner/work/dex/dex/server/oauth2.go
  • Line: 144
  • Rule ID: G101
  • Details: Potential hardcoded credentials
  • Confidence: LOW
  • Severity: HIGH

* File: /home/runner/work/dex/dex/server/oauth2.go
  • Line: 143
  • Rule ID: G101
  • Details: Potential hardcoded credentials
  • Confidence: LOW
  • Severity: HIGH

* File: /home/runner/work/dex/dex/server/oauth2.go
  • Line: 142
  • Rule ID: G101
  • Details: Potential hardcoded credentials
  • Confidence: LOW
  • Severity: HIGH

* File: /home/runner/work/dex/dex/server/oauth2.go
  • Line: 141
  • Rule ID: G101
  • Details: Potential hardcoded credentials
  • Confidence: LOW
  • Severity: HIGH

* File: /home/runner/work/dex/dex/server/oauth2.go
  • Line: 140
  • Rule ID: G101
  • Details: Potential hardcoded credentials
  • Confidence: LOW
  • Severity: HIGH

* File: /home/runner/work/dex/dex/server/oauth2.go
  • Line: 135
  • Rule ID: G101
  • Details: Potential hardcoded credentials
  • Confidence: LOW
  • Severity: HIGH

* File: /home/runner/work/dex/dex/connector/saml/saml.go
  • Line: 45
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

* File: /home/runner/work/dex/dex/api/api_grpc.pb.go
  • Line: 32
  • Rule ID: G101
  • Details: Potential hardcoded credentials
  • Confidence: LOW
  • Severity: HIGH

* File: /home/runner/work/dex/dex/api/api_grpc.pb.go
  • Line: 28
  • Rule ID: G101
  • Details: Potential hardcoded credentials
  • Confidence: LOW
  • Severity: HIGH

* File: /home/runner/work/dex/dex/api/api_grpc.pb.go
  • Line: 27
  • Rule ID: G101
  • Details: Potential hardcoded credentials
  • Confidence: LOW
  • Severity: HIGH

* File: /home/runner/work/dex/dex/api/api_grpc.pb.go
  • Line: 26
  • Rule ID: G101
  • Details: Potential hardcoded credentials
  • Confidence: LOW
  • Severity: HIGH

* File: /home/runner/work/dex/dex/api/api_grpc.pb.go
  • Line: 25
  • Rule ID: G101
  • Details: Potential hardcoded credentials
  • Confidence: LOW
  • Severity: HIGH

* File: /home/runner/work/dex/dex/cmd/docker-entrypoint/main.go
  • Line: 58
  • Rule ID: G702
  • Details: Command injection via taint analysis
  • Confidence: HIGH
  • Severity: HIGH

* File: /home/runner/work/dex/dex/cmd/docker-entrypoint/main.go
  • Line: 37
  • Rule ID: G702
  • Details: Command injection via taint analysis
  • Confidence: HIGH
  • Severity: HIGH

