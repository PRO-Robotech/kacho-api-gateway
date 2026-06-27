// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package middleware_test

// stepup_gate_test.go — step-up (ACR / MFA freshness) gate scenarios.

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/middleware"
)

func TestStepUp_ACR_RequiresElevation(t *testing.T) {
	g := middleware.NewStepUpGate(nil)
	tok := &middleware.VerifiedToken{ACR: "2"}
	err := g.Check(tok, middleware.PermissionRequirement{RequiredACRMin: "3"})
	assert.ErrorIs(t, err, middleware.ErrStepUpRequired)
}

func TestStepUp_ACR_Satisfied(t *testing.T) {
	g := middleware.NewStepUpGate(nil)
	tok := &middleware.VerifiedToken{ACR: "3"}
	assert.NoError(t, g.Check(tok, middleware.PermissionRequirement{RequiredACRMin: "3"}))
	assert.NoError(t, g.Check(tok, middleware.PermissionRequirement{RequiredACRMin: "2"}))
	assert.NoError(t, g.Check(tok, middleware.PermissionRequirement{RequiredACRMin: "1"}))
}

func TestStepUp_NoRequirement_AlwaysPass(t *testing.T) {
	g := middleware.NewStepUpGate(nil)
	tok := &middleware.VerifiedToken{ACR: ""}
	assert.NoError(t, g.Check(tok, middleware.PermissionRequirement{}))
}

func TestStepUp_MFAStale(t *testing.T) {
	g := middleware.NewStepUpGate(func() time.Time {
		return time.Unix(1_000_000, 0)
	})
	tok := &middleware.VerifiedToken{
		ACR:      "3",
		AuthTime: time.Unix(900_000, 0), // 100k seconds ago
	}
	err := g.Check(tok, middleware.PermissionRequirement{
		RequiredACRMin: "3",
		MFAMaxAge:      1 * time.Hour,
	})
	assert.ErrorIs(t, err, middleware.ErrMFAStale)
}

func TestStepUp_MFAStale_NoAuthTime(t *testing.T) {
	g := middleware.NewStepUpGate(nil)
	tok := &middleware.VerifiedToken{ACR: "3"}
	err := g.Check(tok, middleware.PermissionRequirement{
		RequiredACRMin: "3",
		MFAMaxAge:      1 * time.Hour,
	})
	assert.ErrorIs(t, err, middleware.ErrMFAStale)
}

func TestStepUp_BuildChallenge(t *testing.T) {
	c := middleware.BuildStepUpChallenge(middleware.PermissionRequirement{
		RequiredACRMin: "3",
	}, "2")
	assert.Contains(t, c, `Bearer error="insufficient_user_authentication"`)
	assert.Contains(t, c, `acr_values="3"`)
	assert.Contains(t, c, "Required ACR 3")
	assert.Contains(t, c, "presented ACR 2")
}

func TestStepUp_BuildChallenge_WithMaxAge(t *testing.T) {
	c := middleware.BuildStepUpChallenge(middleware.PermissionRequirement{
		RequiredACRMin: "3",
		MFAMaxAge:      5 * time.Minute,
	}, "")
	assert.Contains(t, c, `max_age="300"`)
}

func TestStepUp_UnknownACRTreatedAsZero(t *testing.T) {
	g := middleware.NewStepUpGate(nil)
	tok := &middleware.VerifiedToken{ACR: "weird-value"}
	err := g.Check(tok, middleware.PermissionRequirement{RequiredACRMin: "1"})
	assert.ErrorIs(t, err, middleware.ErrStepUpRequired)
}
