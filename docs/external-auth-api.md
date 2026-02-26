# External Authentication API Documentation

## Overview

The Gatehouse External Authentication API provides endpoints for integrating external OAuth providers (Google, GitHub, Microsoft) for user authentication and account linking. This API supports three main workflows:

1. **Provider Configuration** - Organization admins can configure OAuth credentials
2. **Account Linking** - Users can link external accounts to their Gatehouse account
3. **OAuth Authentication** - Users can authenticate using their external provider credentials

## Base URL

```
https://api.gatehouse.dev/v1
```

## Authentication

All endpoints require Bearer token authentication except for OAuth callback endpoints.

```
Authorization: Bearer <your-jwt-token>
```

## Error Codes

| Code | Type | Description |
|------|------|-------------|
| 400 | BAD_REQUEST | Invalid request parameters |
| 401 | UNAUTHORIZED | Authentication required |
| 403 | FORBIDDEN | Insufficient permissions |
| 404 | NOT_FOUND | Resource not found |
| 500 | INTERNAL_ERROR | Server error |

### External Auth Specific Error Types

| Error Type | HTTP Code | Description |
|------------|-----------|-------------|
| PROVIDER_NOT_CONFIGURED | 400 | Provider not configured for organization |
| INVALID_REDIRECT_URI | 400 | Redirect URI not allowed |
| INVALID_STATE | 400 | Invalid or expired OAuth state |
| INVALID_FLOW_TYPE | 400 | Invalid flow type |
| PROVIDER_MISMATCH | 400 | Provider mismatch in flow |
| PROVIDER_NOT_LINKED | 400 | Provider not linked to account |
| CANNOT_UNLINK_LAST | 400 | Cannot unlink last authentication method |
| ACCOUNT_NOT_FOUND | 400 | No matching Gatehouse account |
| EMAIL_EXISTS | 400 | Email already exists |
| UNSUPPORTED_PROVIDER | 400 | Provider not supported |

---

## Endpoints

### Provider Configuration

#### List Available Providers

**GET** `/api/v1/auth/external/providers`

List all available external authentication providers for the current organization.

**Authentication:** Required (any authenticated user)

**Response (200):**

```json
{
  "version": "1.0",
  "success": true,
  "code": 200,
  "data": {
    "providers": [
      {
        "id": "google",
        "name": "Google",
        "type": "google",
        "is_configured": true,
        "is_active": true,
        "settings": {
          "requires_domain": false,
          "supports_refresh_tokens": true
        }
      },
      {
        "id": "github",
        "name": "GitHub",
        "type": "github",
        "is_configured": false,
        "is_active": false,
        "settings": {
          "requires_domain": false,
          "supports_refresh_tokens": true
        }
      }
    ]
  }
}
```

---

#### Get Provider Configuration

**GET** `/api/v1/auth/external/providers/{provider}/config`

Get provider configuration (admin only).

**Authentication:** Required (Organization Admin or Owner)

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| provider | string | Provider type (google, github, microsoft) |

**Response (200):**

```json
{
  "version": "1.0",
  "success": true,
  "code": 200,
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "organization_id": "550e8400-e29b-41d4-a716-446655440001",
    "provider_type": "google",
    "client_id": "client-id.apps.googleusercontent.com",
    "auth_url": "https://accounts.google.com/o/oauth2/v2/auth",
    "token_url": "https://oauth2.googleapis.com/token",
    "userinfo_url": "https://www.googleapis.com/oauth2/v3/userinfo",
    "scopes": ["openid", "profile", "email"],
    "redirect_uris": [
      "https://app.gatehouse.dev/auth/external/google/callback"
    ],
    "is_active": true,
    "settings": {
      "hosted_domain": "example.com"
    },
    "created_at": "2024-01-15T10:30:00Z",
    "updated_at": "2024-01-20T14:45:00Z"
  }
}
```

**Error Response (403):**

```json
{
  "version": "1.0",
  "success": false,
  "code": 403,
  "message": "Admin access required",
  "error_type": "FORBIDDEN"
}
```

**Error Response (404):**

```json
{
  "version": "1.0",
  "success": false,
  "code": 404,
  "message": "Google OAuth is not configured",
  "error_type": "NOT_FOUND"
}
```

---

#### Create/Update Provider Configuration

**POST** `/api/v1/auth/external/providers/{provider}/config`

Create or update provider configuration (admin only).

**Authentication:** Required (Organization Admin or Owner)

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| provider | string | Provider type (google, github, microsoft) |

**Request Body:**

```json
{
  "client_id": "client-id.apps.googleusercontent.com",
  "client_secret": "client-secret",
  "scopes": ["openid", "profile", "email"],
  "redirect_uris": [
    "https://app.gatehouse.dev/auth/external/google/callback",
    "http://localhost:3000/callback"
  ],
  "settings": {
    "hosted_domain": "example.com",
    "access_type": "offline",
    "prompt": "consent"
  },
  "is_active": true
}
```

**Response (201 - Created):**

```json
{
  "version": "1.0",
  "success": true,
  "code": 201,
  "message": "Provider configuration created successfully",
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "provider_type": "google",
    "client_id": "client-id.apps.googleusercontent.com",
    "is_active": true
  }
}
```

**Response (200 - Updated):**

```json
{
  "version": "1.0",
  "success": true,
  "code": 200,
  "message": "Provider configuration updated successfully",
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "provider_type": "google",
    "client_id": "updated-client-id",
    "is_active": true
  }
}
```

---

#### Delete Provider Configuration

**DELETE** `/api/v1/auth/external/providers/{provider}/config`

Delete provider configuration (admin only).

**Authentication:** Required (Organization Admin or Owner)

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| provider | string | Provider type (google, github, microsoft) |

**Response (200):**

```json
{
  "version": "1.0",
  "success": true,
  "code": 200,
  "message": "Google provider configuration deleted successfully"
}
```

---

### Account Linking

#### List Linked Accounts

**GET** `/api/v1/auth/external/linked-accounts`

List all linked external accounts for the current user.

**Authentication:** Required (any authenticated user)

**Response (200):**

```json
{
  "version": "1.0",
  "success": true,
  "code": 200,
  "data": {
    "linked_accounts": [
      {
        "id": "550e8400-e29b-41d4-a716-446655440002",
        "provider_type": "google",
        "provider_user_id": "123456789",
        "email": "user@gmail.com",
        "name": "John Doe",
        "picture": "https://lh3.googleusercontent.com/...",
        "verified": true,
        "linked_at": "2024-01-15T10:30:00Z",
        "last_used_at": "2024-01-20T14:45:00Z"
      },
      {
        "id": "550e8400-e29b-41d4-a716-446655440003",
        "provider_type": "github",
        "provider_user_id": "987654321",
        "email": "user@github.com",
        "name": "johndoe",
        "picture": "https://avatars.githubusercontent.com/...",
        "verified": true,
        "linked_at": "2024-01-10T08:00:00Z",
        "last_used_at": null
      }
    ],
    "unlink_available": true
  }
}
```

---

#### Initiate Account Linking

**POST** `/api/v1/auth/external/{provider}/link`

Initiate OAuth flow to link an external account.

**Authentication:** Required (any authenticated user)

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| provider | string | Provider type (google, github, microsoft) |

**Request Body:**

```json
{
  "redirect_uri": "https://app.gatehouse.dev/settings/security"
}
```

**Response (200):**

```json
{
  "version": "1.0",
  "success": true,
  "code": 200,
  "data": {
    "authorization_url": "https://accounts.google.com/o/oauth2/v2/auth?...",
    "state": "eyJmbG93X3R5cGUiOiJsaW5rIiwicHJvdmlkZXIiOiJnb29nbGUifQ..."
  },
  "message": "Link flow initiated. Redirect to authorization URL."
}
```

**Error Response (400 - Provider not configured):**

```json
{
  "version": "1.0",
  "success": false,
  "code": 400,
  "message": "Google OAuth is not configured for this organization",
  "error_type": "PROVIDER_NOT_CONFIGURED"
}
```

---

#### Unlink Account

**DELETE** `/api/v1/auth/external/{provider}/unlink`

Unlink an external account from the user's profile.

**Authentication:** Required (any authenticated user)

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| provider | string | Provider type (google, github, microsoft) |

**Response (200):**

```json
{
  "version": "1.0",
  "success": true,
  "code": 200,
  "message": "Google account unlinked successfully"
}
```

**Error Response (400 - Last auth method):**

```json
{
  "version": "1.0",
  "success": false,
  "code": 400,
  "message": "Cannot unlink the last authentication method",
  "error_type": "CANNOT_UNLINK_LAST"
}
```

**Error Response (404 - Not linked):**

```json
{
  "version": "1.0",
  "success": false,
  "code": 400,
  "message": "Provider not linked",
  "error_type": "PROVIDER_NOT_LINKED"
}
```

---

### OAuth Flow

#### Initiate OAuth Authorization

**GET** `/api/v1/auth/external/{provider}/authorize`

Initiate OAuth authentication or account registration flow.

**Authentication:** Not required (for login/register flows)

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| provider | string | Provider type (google, github, microsoft) |

**Query Parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| flow | Yes | Flow type: `login` or `register` |
| redirect_uri | No | Override redirect URI (must be in allowed list) |
| organization_id | No | Organization context for SSO |

**Response (200):**

```json
{
  "version": "1.0",
  "success": true,
  "code": 200,
  "data": {
    "authorization_url": "https://accounts.google.com/o/oauth2/v2/auth?...",
    "state": "eyJmbG93X3R5cGUiOiJsb2dpbiIsInByb3ZpZGVyIjoiZ29vZ2xlIn0..."
  },
  "message": "OAuth login flow initiated"
}
```

**Error Response (400 - Invalid flow):**

```json
{
  "version": "1.0",
  "success": false,
  "code": 400,
  "message": "Invalid flow type. Must be 'login' or 'register'",
  "error_type": "VALIDATION_ERROR"
}
```

---

#### Handle OAuth Callback

**GET** `/api/v1/auth/external/{provider}/callback`

Handle OAuth callback from provider.

**Authentication:** Not required

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| provider | string | Provider type (google, github, microsoft) |

**Query Parameters:**

| Parameter | Description |
|-----------|-------------|
| code | Authorization code from provider |
| state | State parameter (contains flow context) |
| error | Error code if auth failed |
| error_description | Human-readable error description |

**Success Response (200 - Login Flow):**

```json
{
  "version": "1.0",
  "success": true,
  "code": 200,
  "data": {
    "token": "gatehouse-jwt-token...",
    "expires_in": 86400,
    "token_type": "Bearer",
    "user": {
      "id": "550e8400-e29b-41d4-a716-446655440004",
      "email": "user@example.com",
      "full_name": "John Doe",
      "organization_id": "550e8400-e29b-41d4-a716-446655440001"
    }
  },
  "message": "Login successful"
}
```

**Success Response (200 - Register Flow):**

```json
{
  "version": "1.0",
  "success": true,
  "code": 200,
  "data": {
    "token": "gatehouse-jwt-token...",
    "expires_in": 86400,
    "token_type": "Bearer",
    "user": {
      "id": "550e8400-e29b-41d4-a716-446655440005",
      "email": "newuser@gmail.com",
      "full_name": "New User",
      "organization_id": "550e8400-e29b-41d4-a716-446655440001"
    }
  },
  "message": "Registration successful"
}
```

**Success Response (200 - Link Flow):**

```json
{
  "version": "1.0",
  "success": true,
  "code": 200,
  "data": {
    "linked_account": {
      "id": "550e8400-e29b-41d4-a716-446655440006",
      "provider_type": "google",
      "provider_user_id": "123456789",
      "verified": true
    }
  },
  "message": "Account linked successfully"
}
```

**Error Response (400 - Invalid state):**

```json
{
  "version": "1.0",
  "success": false,
  "code": 400,
  "message": "Invalid or expired OAuth state",
  "error_type": "INVALID_STATE"
}
```

**Error Response (400 - Account not found):**

```json
{
  "version": "1.0",
  "success": false,
  "code": 400,
  "message": "No Gatehouse account matches this external account. Please register first.",
  "error_type": "ACCOUNT_NOT_FOUND"
}
```

**Error Response (400 - Email exists):**

```json
{
  "version": "1.0",
  "success": false,
  "code": 400,
  "message": "An account with email user@gmail.com already exists. Please log in with your password and link your Google account from settings.",
  "error_type": "EMAIL_EXISTS"
}
```

**Error Response (400 - Provider error):**

```json
{
  "version": "1.0",
  "success": false,
  "code": 400,
  "message": "User denied access",
  "error_type": "ACCESS_DENIED"
}
```

---

## OAuth Flow Documentation

### Account Linking Flow

```
1. User clicks "Connect Google" in settings
2. Frontend calls POST /api/v1/auth/external/google/link
3. API returns authorization_url and state
4. Frontend redirects user to authorization_url
5. User authenticates with Google and grants permission
6. Google redirects to /api/v1/auth/external/google/callback?code=xxx&state=yyy
7. API validates state, exchanges code for tokens, links account
8. API returns success response
9. Frontend shows confirmation
```

### Login Flow

```
1. User clicks "Login with Google" on login page
2. Frontend redirects to /api/v1/auth/external/google/authorize?flow=login
3. API creates state, returns authorization_url
4. User authenticates with Google
5. Google redirects to callback with code and state
6. API validates state, exchanges code, authenticates user
7. API returns JWT token and user info
8. Frontend stores token and redirects to dashboard
```

### Registration Flow

```
1. User clicks "Sign up with Google" on registration page
2. Frontend redirects to /api/v1/auth/external/google/authorize?flow=register
3. API creates state, returns authorization_url
4. User authenticates with Google
5. Google redirects to callback with code and state
6. API validates state, exchanges code, creates new user
7. API returns JWT token and user info
8. Frontend stores token and redirects to onboarding
```

---

## Security Considerations

### State Parameter

The OAuth state parameter provides CSRF protection and carries flow context:
- Cryptographically random (256-bit)
- Short-lived (10 minutes)
- Single-use (marked as used after callback)
- Bound to user (for link flows)
- Bound to redirect_uri

### PKCE Implementation

PKCE protects against authorization code interception attacks:
- Code verifier: 43-128 character random string
- Code challenge: S256 hash of verifier
- Verifier sent in token request
- Server validates challenge matches

### Token Storage

Provider tokens are encrypted at rest:
- Access tokens: Short-lived, minimal protection needed
- Refresh tokens: Encrypted using Fernet symmetric encryption
- ID tokens: Encrypted at rest
- Encryption keys stored separately from database

---

## Provider-Specific Configuration

### Google OAuth

**Endpoints:**
- Auth URL: `https://accounts.google.com/o/oauth2/v2/auth`
- Token URL: `https://oauth2.googleapis.com/token`
- UserInfo URL: `https://www.googleapis.com/oauth2/v3/userinfo`

**Default Scopes:**
- `openid` - OpenID Connect authentication
- `profile` - Basic profile information
- `email` - Email address

**Settings:**
- `hosted_domain` - Restrict to specific domain (optional)
- `access_type` - Request refresh token (`offline`)
- `prompt` - Force consent (`consent`)

### GitHub OAuth

**Endpoints:**
- Auth URL: `https://github.com/login/oauth/authorize`
- Token URL: `https://github.com/login/oauth/access_token`
- UserInfo URL: `https://api.github.com/user`

**Default Scopes:**
- `read:user` - Read user profile data
- `user:email` - Access user email addresses

### Microsoft OAuth

**Endpoints:**
- Auth URL: `https://login.microsoftonline.com/common/oauth2/v2.0/authorize`
- Token URL: `https://login.microsoftonline.com/common/oauth2/v2.0/token`
- UserInfo URL: `https://graph.microsoft.com/oidc/userinfo`
- JWKS URL: `https://login.microsoftonline.com/common/discovery/v2.0/keys`

**Default Scopes:**
- `openid` - OpenID Connect
- `profile` - User profile
- `email` - Email address
- `offline_access` - Required by Microsoft to return a refresh token (unlike Google which uses `access_type=offline`)


#### Azure App Registration steps

1. Go to [Azure Portal](https://portal.azure.com) → **App registrations** → **New registration**
2. Under **"Supported account types"** choose the option that matches your use case (see table above)
3. Set **Redirect URI** (Web platform) to:
   `https://<your-api-host>/api/v1/auth/external/microsoft/callback`
4. Under **Certificates & secrets** → **New client secret** — copy the *Value* (not the Secret ID)
5. Under **API permissions** → **Add a permission** → **Microsoft Graph** → **Delegated**:
   add `openid`, `profile`, `email`, `offline_access`
6. Configure Gatehouse:
   ```bash
   # Multi-tenant (work + personal accounts):
   MICROSOFT_CLIENT_ID=<Application (client) ID> \
   MICROSOFT_CLIENT_SECRET=<client secret value> \
   python scripts/configure_oauth_provider.py create microsoft \
       --redirect-url "https://<your-api-host>/api/v1/auth/external/microsoft/callback"

   # Work/school accounts only (replace with your tenant ID for single-org):
   MICROSOFT_CLIENT_ID=<Application (client) ID> \
   MICROSOFT_CLIENT_SECRET=<client secret value> \
   python scripts/configure_oauth_provider.py create microsoft \
       --tenant-id organizations \
       --redirect-url "https://<your-api-host>/api/v1/auth/external/microsoft/callback"
   ```

**Behaviour notes:**
- Microsoft is a **confidential client** — PKCE is not used (the client secret authenticates the app).
- The `email_verified` claim is implicitly `true` for all Azure AD accounts; Gatehouse defaults it to `true` when Microsoft omits it.
- `prompt=select_account` is sent by default so users can choose between multiple signed-in Microsoft accounts.

---

## Rate Limiting

| Endpoint | Limit | Window |
|----------|-------|--------|
| `/authorize` | 10 | per minute |
| `/callback` | 20 | per minute |
| `/link` | 5 | per minute |
| `/unlink` | 10 | per minute |

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2024-01-20 | Initial release |

---

*Document Version: 1.0*
*Last Updated: 2024-01-20*
*Gatehouse Identity Platform*