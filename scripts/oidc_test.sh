#!/usr/bin/env bash
set -euo pipefail

ISSUER="https://oidctest.wsweet.org"
CLIENT_ID="secret"
CLIENT_SECRET="tardis"
REDIRECT_URI="http://127.0.0.1:5556/callback"
SCOPE="openid profile email offline_access"

# ---------------------------
# Discover OIDC endpoints
# ---------------------------
DISCOVERY=$(curl -s "$ISSUER/.well-known/openid-configuration")

AUTH_ENDPOINT=$(echo "$DISCOVERY" | jq -r .authorization_endpoint)
TOKEN_ENDPOINT=$(echo "$DISCOVERY" | jq -r .token_endpoint)
USERINFO_ENDPOINT=$(echo "$DISCOVERY" | jq -r .userinfo_endpoint)

echo "Auth endpoint : $AUTH_ENDPOINT"
echo "Token endpoint: $TOKEN_ENDPOINT"
echo

# ---------------------------
# PKCE
# ---------------------------
CODE_VERIFIER=$(openssl rand -base64 32 | tr -d '=+/')
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | openssl dgst -sha256 -binary | openssl base64 | tr -d '=+/' | tr '/+' '_-')

STATE=$(openssl rand -hex 16)
NONCE=$(openssl rand -hex 16)

# ---------------------------
# Build auth URL
# ---------------------------
AUTH_URL="$AUTH_ENDPOINT?response_type=code\
&client_id=$CLIENT_ID\
&redirect_uri=$(printf '%s' "$REDIRECT_URI" | jq -s -R -r @uri)\
&scope=$(printf '%s' "$SCOPE" | jq -s -R -r @uri)\
&state=$STATE\
&nonce=$NONCE\
&code_challenge=$CODE_CHALLENGE\
&code_challenge_method=S256"

echo "Open this URL in a browser:"
echo
echo "$AUTH_URL"
echo
echo "After login you will be redirected to:"
echo "$REDIRECT_URI?code=XXXX&state=YYYY"
echo
read -p "Paste the full redirect URL: " REDIRECT

CODE=$(echo "$REDIRECT" | sed -n 's/.*code=\([^&]*\).*/\1/p')
RETURNED_STATE=$(echo "$REDIRECT" | sed -n 's/.*state=\([^&]*\).*/\1/p')

if [ "$RETURNED_STATE" != "$STATE" ]; then
  echo "STATE MISMATCH"
  exit 1
fi

# ---------------------------
# Exchange code for tokens
# ---------------------------
TOKENS=$(curl -s -X POST "$TOKEN_ENDPOINT" \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=$CODE" \
  -d "redirect_uri=$REDIRECT_URI" \
  -d "code_verifier=$CODE_VERIFIER")

echo
echo "Token response:"
echo "$TOKENS" | jq .

ACCESS_TOKEN=$(echo "$TOKENS" | jq -r .access_token)
ID_TOKEN=$(echo "$TOKENS" | jq -r .id_token)

# ---------------------------
# JWT decode function
# ---------------------------
decode() {
  echo "$1" | awk -F. '{print $2}' | tr '_-' '/+' | base64 -d 2>/dev/null | jq .
}

echo
echo "================ ID TOKEN ================"
decode "$ID_TOKEN"

echo
echo "============== ACCESS TOKEN =============="
decode "$ACCESS_TOKEN"

# ---------------------------
# Userinfo (optional)
# ---------------------------
if [ "$USERINFO_ENDPOINT" != "null" ]; then
  echo
  echo "=============== USERINFO ================="
  curl -s -H "Authorization: Bearer $ACCESS_TOKEN" "$USERINFO_ENDPOINT" | jq .
fi

