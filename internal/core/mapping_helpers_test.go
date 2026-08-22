package core

import "github.com/ssyno/evidenced/mapping"

const testMappingYAML = `
framework: TESTFW
controls:
  - id: fw-1
    article: "Article 1"
    title: Certificate hygiene
    summary: Certificates must be rotated before expiry.
  - id: fw-2
    article: "Article 2"
    title: Access control
    summary: Access rights are reviewed.
rules:
  - collector: certs
    targetType: tls/certificate
    controls: [fw-1]
  - collector: certs
    controls: [fw-2]
  - collector: rbac
    controls: [fw-2]
`

func loadTestMapping() (*mapping.Mapping, error) {
	return mapping.Load([]byte(testMappingYAML))
}
