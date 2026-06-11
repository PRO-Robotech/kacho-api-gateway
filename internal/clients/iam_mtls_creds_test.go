// iam_mtls_creds_test.go — SEC-E: the gateway→iam dials (iam-subject +
// iam-authorize) must accept an injectable transport-credentials dial-option so
// main.go can hand them the per-edge mTLS creds under KACHO_API_GATEWAY_MTLS_IAM_ENABLE
// (acceptance §1.2, §3.2). RED-first: these fail to compile until the
// constructors grow a transport-creds parameter; before SEC-E both clients
// hardcode insecure with no injection seam.
//
// We do not assert handshake behaviour here (that is covered by the cmd bufconn
// tests against a real TLS server). We assert the *seam* exists: a custom
// transport-creds dial-option is accepted and the client constructs without a
// network round-trip (grpc.NewClient is lazy).
package clients_test

import (
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/clients"
)

// SEC-E — NewIAMSubjectClient accepts a transport-creds dial-option. nil ⇒
// insecure default (backward-compat); a non-nil option (mTLS in production) is
// applied to the dial.
func TestSECE_IAMSubjectClient_AcceptsTransportCreds(t *testing.T) {
	logger := slog.Default()

	// nil → insecure default (current dev behaviour preserved).
	c1, err := clients.NewIAMSubjectClient("iam.kacho.svc.cluster.local:9091", logger, nil)
	require.NoError(t, err)
	require.NotNil(t, c1)
	t.Cleanup(func() { _ = c1.Close() })

	// Explicit transport-creds option (this is where main.go injects mTLS).
	opt := grpc.WithTransportCredentials(insecure.NewCredentials())
	c2, err := clients.NewIAMSubjectClient("iam.kacho.svc.cluster.local:9091", logger, opt)
	require.NoError(t, err)
	require.NotNil(t, c2)
	t.Cleanup(func() { _ = c2.Close() })
}

// SEC-E — IAMAuthorizeClientConfig carries an injectable transport-creds
// dial-option. nil ⇒ insecure default; non-nil ⇒ applied (mTLS in production).
func TestSECE_IAMAuthorizeClient_AcceptsTransportCreds(t *testing.T) {
	logger := slog.Default()

	opt := grpc.WithTransportCredentials(insecure.NewCredentials())
	c, err := clients.NewIAMAuthorizeClient(clients.IAMAuthorizeClientConfig{
		Addr:           "iam.kacho.svc.cluster.local:9090",
		Timeout:        200 * time.Millisecond,
		Logger:         logger,
		TransportCreds: opt,
	})
	require.NoError(t, err)
	require.NotNil(t, c)
	t.Cleanup(func() { _ = c.Close() })

	// nil TransportCreds → insecure default (backward-compat).
	c2, err := clients.NewIAMAuthorizeClient(clients.IAMAuthorizeClientConfig{
		Addr:    "iam.kacho.svc.cluster.local:9090",
		Timeout: 200 * time.Millisecond,
		Logger:  logger,
	})
	require.NoError(t, err)
	require.NotNil(t, c2)
	t.Cleanup(func() { _ = c2.Close() })
}
