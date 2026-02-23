#!/bin/bash

# Test script to verify OAuth endpoints work without organization_id
# This tests the fix for the "Google OAuth is not configured for this organization" error

API_BASE="http://localhost:5001/api/v1"

echo "=== Testing OAuth Authorization Endpoint (without organization_id) ==="
echo ""
echo "1. Initiating Google OAuth login flow (NO organization_id)..."
RESPONSE=$(curl -s -X GET "${API_BASE}/auth/external/google/authorize?flow=login")
echo "Response: $RESPONSE"
echo ""

# Check if we get an authorization URL
if echo "$RESPONSE" | grep -q "authorization_url"; then
    echo "✅ SUCCESS: Got authorization URL without requiring organization_id"
    AUTH_URL=$(echo "$RESPONSE" | jq -r '.data.authorization_url')
    STATE=$(echo "$RESPONSE" | jq -r '.data.state')
    echo "Authorization URL: $AUTH_URL"
    echo "State: $STATE"
else
    echo "❌ FAILED: Did not get authorization URL"
    echo "Error: $(echo "$RESPONSE" | jq -r '.message')"
fi

echo ""
echo "=== Testing with organization_id hint (should still work) ==="
echo ""
echo "2. Initiating Google OAuth login flow (WITH organization_id hint)..."
# You'll need to replace this with an actual organization ID from your database
ORG_ID="test-org-id"
RESPONSE=$(curl -s -X GET "${API_BASE}/auth/external/google/authorize?flow=login&organization_id=${ORG_ID}")
echo "Response: $RESPONSE"
echo ""

if echo "$RESPONSE" | grep -q "authorization_url"; then
    echo "✅ SUCCESS: OAuth works with organization_id hint (backward compatible)"
else
    echo "⚠️  Note: This may fail if the organization ID doesn't exist or if app-level config is not set"
fi

echo ""
echo "=== Testing Register Flow ==="
echo ""
echo "3. Initiating Google OAuth register flow (NO organization_id)..."
RESPONSE=$(curl -s -X GET "${API_BASE}/auth/external/google/authorize?flow=register")
echo "Response: $RESPONSE"
echo ""

if echo "$RESPONSE" | grep -q "authorization_url"; then
    echo "✅ SUCCESS: Register flow works without organization_id"
else
    echo "❌ FAILED: Register flow did not work"
    echo "Error: $(echo "$RESPONSE" | jq -r '.message')"
fi

echo ""
echo "=== Summary ==="
echo ""
echo "The key fix addresses the error:"
echo "  'Google OAuth is not configured for this organization'"
echo ""
echo "Now OAuth flows work at the APPLICATION level, not requiring"
echo "an organization context during initial authentication."
echo ""
echo "After OAuth callback:"
echo "  - Single org user → Automatic login"
echo "  - Multi org user → Organization selection UI"
echo "  - New user → Organization creation/selection UI"
