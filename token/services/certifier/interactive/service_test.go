/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package interactive_test

import (
	"testing"

	"github.com/hyperledger-labs/fabric-smart-client/pkg/utils/errors"
	"github.com/hyperledger-labs/fabric-smart-client/platform/view/services/metrics/disabled"
	"github.com/hyperledger-labs/fabric-smart-client/platform/view/view"
	"github.com/hyperledger-labs/fabric-token-sdk/token/services/certifier/interactive"
	"github.com/hyperledger-labs/fabric-token-sdk/token/services/certifier/interactive/mock"
	"github.com/hyperledger-labs/fabric-token-sdk/token/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewCertificationService verifies construction of a new CertificationService.
func TestNewCertificationService(t *testing.T) {
	responderRegistry := &mock.ResponderRegistry{}
	backend := &mock.Backend{}
	mp := &disabled.Provider{}

	service := interactive.NewCertificationService(responderRegistry, mp, backend)

	assert.NotNil(t, service)
	assert.Equal(t, responderRegistry, service.ResponderRegistry)
	assert.Equal(t, backend, interactive.ServiceBackend(service))
	assert.NotNil(t, interactive.ServiceWallets(service))
	assert.NotNil(t, interactive.ServiceMetrics(service))
	assert.Empty(t, interactive.ServiceWallets(service))
}

// TestCertificationService_Start_Success verifies that Start succeeds when
// RegisterResponder succeeds.
func TestCertificationService_Start_Success(t *testing.T) {
	responderRegistry := &mock.ResponderRegistry{}
	backend := &mock.Backend{}
	mp := &disabled.Provider{}

	service := interactive.NewCertificationService(responderRegistry, mp, backend)

	err := service.Start()
	require.NoError(t, err)
	assert.Equal(t, 1, responderRegistry.RegisterResponderCallCount())
}

// TestCertificationService_Start_RegistrationError verifies that Start propagates
// errors returned by RegisterResponder.
func TestCertificationService_Start_RegistrationError(t *testing.T) {
	expectedErr := errors.New("registration failed")
	responderRegistry := &mock.ResponderRegistry{}
	responderRegistry.RegisterResponderReturns(expectedErr)

	backend := &mock.Backend{}
	mp := &disabled.Provider{}

	service := interactive.NewCertificationService(responderRegistry, mp, backend)

	err := service.Start()
	require.ErrorIs(t, err, expectedErr)
	assert.Equal(t, 1, responderRegistry.RegisterResponderCallCount())
}

// TestCertificationService_Start_OnlyOnce verifies that repeated Start calls only
// register the responder once.
func TestCertificationService_Start_OnlyOnce(t *testing.T) {
	responderRegistry := &mock.ResponderRegistry{}
	backend := &mock.Backend{}
	mp := &disabled.Provider{}

	service := interactive.NewCertificationService(responderRegistry, mp, backend)

	require.NoError(t, service.Start())
	require.NoError(t, service.Start())
	require.NoError(t, service.Start())

	// RegisterResponder must have been called exactly once.
	assert.Equal(t, 1, responderRegistry.RegisterResponderCallCount())
}

// TestCertificationRequest_String verifies the String summary.
func TestCertificationRequest_String(t *testing.T) {
	cr := &interactive.CertificationRequest{
		Network:   "test-network",
		Channel:   "test-channel",
		Namespace: "test-namespace",
		IDs:       nil,
		Request:   []byte("test-request"),
	}

	str := cr.String()
	assert.NotEmpty(t, str, "String() should return non-empty string")
	assert.Contains(t, str, "CertificationRequest")
	assert.Contains(t, str, "test-channel")
	assert.Contains(t, str, "test-namespace")
}

// TestNewCertificationRequestView verifies construction of a CertificationRequestView.
func TestNewCertificationRequestView(t *testing.T) {
	channel := "test-channel"
	namespace := "test-namespace"
	certifier := view.Identity([]byte("certifier-identity"))
	ids := []*token.ID{
		{TxId: "tx1", Index: 0},
		{TxId: "tx2", Index: 1},
	}

	v := interactive.NewCertificationRequestView(channel, namespace, certifier, ids...)

	assert.NotNil(t, v)
}
