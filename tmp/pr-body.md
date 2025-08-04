# 🚨 Trivy Vulnerability Report (High/Critical)

| Target | Package | Severity | Title | CVE | Installed | Fixed |
|--------|---------|----------|-------|-----|-----------|-------|
| api/v2/go.mod | golang.org/x/net | HIGH | golang: net/http, x/net/http2: rapid stream resets can cause excessive work (CVE-2023-44487) | CVE-2023-39325 | v0.7.0 | 0.17.0 |
| api/v2/go.mod | google.golang.org/grpc | HIGH | gRPC-Go HTTP/2 Rapid Reset vulnerability | GHSA-m425-mq94-257g | v1.47.0 | 1.56.3, 1.57.1, 1.58.3 |
| examples/go.mod | golang.org/x/crypto | CRITICAL | golang.org/x/crypto/ssh: Misuse of ServerConfig.PublicKeyCallback may cause authorization bypass in golang.org/x/crypto | CVE-2024-45337 | v0.0.0-20220112180741-5e0467b6c7ce | 0.31.0 |
| examples/go.mod | golang.org/x/crypto | HIGH | golang: crash in a golang.org/x/crypto/ssh server | CVE-2022-27191 | v0.0.0-20220112180741-5e0467b6c7ce | 0.0.0-20220314234659-1baeb1ce4c0b |
| examples/go.mod | golang.org/x/crypto | HIGH | golang.org/x/crypto/ssh: Denial of Service in the Key Exchange of golang.org/x/crypto/ssh | CVE-2025-22869 | v0.0.0-20220112180741-5e0467b6c7ce | 0.35.0 |
| examples/go.mod | golang.org/x/net | HIGH | golang: net/http, x/net/http2: rapid stream resets can cause excessive work (CVE-2023-44487) | CVE-2023-39325 | v0.7.0 | 0.17.0 |
| examples/go.mod | golang.org/x/oauth2 | HIGH | golang.org/x/oauth2/jws: Unexpected memory consumption during token parsing in golang.org/x/oauth2/jws | CVE-2025-22868 | v0.0.0-20211104180415-d3ed0bb246c8 | 0.27.0 |
| examples/go.mod | google.golang.org/grpc | HIGH | gRPC-Go HTTP/2 Rapid Reset vulnerability | GHSA-m425-mq94-257g | v1.43.0 | 1.56.3, 1.57.1, 1.58.3 |
| go.mod | golang.org/x/crypto | CRITICAL | golang.org/x/crypto/ssh: Misuse of ServerConfig.PublicKeyCallback may cause authorization bypass in golang.org/x/crypto | CVE-2024-45337 | v0.0.0-20220622213112-05595931fe9d | 0.31.0 |
| go.mod | golang.org/x/crypto | HIGH | golang.org/x/crypto/ssh: Denial of Service in the Key Exchange of golang.org/x/crypto/ssh | CVE-2025-22869 | v0.0.0-20220622213112-05595931fe9d | 0.35.0 |
| go.mod | golang.org/x/net | HIGH | golang: net/http, x/net/http2: rapid stream resets can cause excessive work (CVE-2023-44487) | CVE-2023-39325 | v0.7.0 | 0.17.0 |
| go.mod | golang.org/x/oauth2 | HIGH | golang.org/x/oauth2/jws: Unexpected memory consumption during token parsing in golang.org/x/oauth2/jws | CVE-2025-22868 | v0.0.0-20220822191816-0ebed06d0094 | 0.27.0 |
| go.mod | google.golang.org/grpc | HIGH | gRPC-Go HTTP/2 Rapid Reset vulnerability | GHSA-m425-mq94-257g | v1.49.0 | 1.56.3, 1.57.1, 1.58.3 |
