/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// export_test.go exposes unexported fields and helpers for use by the external
// test package (package interactive_test). It is compiled only during testing.
package interactive

import "github.com/hyperledger-labs/fabric-token-sdk/token/token"

// ServiceBackend returns the backend wired into a CertificationService.
func ServiceBackend(s *CertificationService) Backend { return s.backend }

// ServiceWallets returns the wallets map of a CertificationService.
func ServiceWallets(s *CertificationService) map[string]string { return s.wallets }

// ServiceMetrics returns the metrics of a CertificationService.
func ServiceMetrics(s *CertificationService) *Metrics { return s.metrics }

// InjectToken sends a token ID directly into the client's input channel,
// simulating what OnReceive does without going through the events system.
func InjectToken(cc *CertificationClient, id *token.ID) { cc.tokens <- id }

// ClientTokensChan returns the raw tokens channel of a CertificationClient.
func ClientTokensChan(cc *CertificationClient) chan *token.ID { return cc.tokens }

// CRVIDs returns the token IDs stored in a CertificationRequestView.
func CRVIDs(crv *CertificationRequestView) []*token.ID { return crv.ids }
