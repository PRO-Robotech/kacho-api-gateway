// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package middleware

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestAuthzMiddleware_MaybeFlushOnMutation — a successful AccessBinding
// mutation flushes the whole decision cache so a just-revoked grant cannot be
// served stale from cache.
func TestAuthzMiddleware_MaybeFlushOnMutation(t *testing.T) {
	m, err := NewAuthzMiddleware(AuthzMiddlewareConfig{Enabled: false})
	require.NoError(t, err)
	m.cache = newDecisionCache(100, 5*time.Second, time.Now)
	m.cache.put("user:nob|iam.projects.get|project|prj1|", decisionCacheEntry{allowed: true})

	// Non-mutation / non-2xx — cache untouched.
	m.MaybeFlushOnMutation("kacho.cloud.iam.v1.ProjectService/Get", 200)
	require.Equal(t, 1, m.cache.Size())
	m.MaybeFlushOnMutation("kacho.cloud.iam.v1.AccessBindingService/Delete", 500)
	require.Equal(t, 1, m.cache.Size())

	// Successful AccessBinding mutation — full flush.
	m.MaybeFlushOnMutation("kacho.cloud.iam.v1.AccessBindingService/Delete", 200)
	require.Equal(t, 0, m.cache.Size())
}
