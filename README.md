# Authy2 Backend - Authentication & Authorization API

Production-ready Flask/SQLAlchemy API for authentication and authorization services.

## Features

- 🔐 **Multi-method Authentication**: Password, OAuth (Google, GitHub, Microsoft), SAML, OIDC
- 👥 **Multi-tenancy**: Organization-based access control with roles
- 🔑 **Session Management**: Secure session handling with Redis
- 📝 **Audit Logging**: Comprehensive activity tracking
- 🛡️ **Security**: Bcrypt password hashing, CORS, security headers, rate limiting
- 📊 **API Response Envelope**: Consistent response format across all endpoints
- ✅ **Validation**: Marshmallow schemas for request/response validation
- 🧪 **Testing**: Comprehensive unit and integration tests
- 📚 **Documentation**: OpenAPI/Swagger compatible

## Tech Stack

- **Framework**: Flask 3.0
- **Database**: PostgreSQL with SQLAlchemy ORM
- **Caching/Sessions**: Redis
- **Validation**: Marshmallow
- **Testing**: Pytest
- **Security**: Flask-Bcrypt, Flask-CORS
- **Migration**: Flask-Migrate (Alembic)

## Quick Start

### Prerequisites

- Python 3.11+
- PostgreSQL 14+
- Redis 6+

### Installation

1. **Clone the repository**:
```bash
git clone <repository-url>
cd authy2/backend
```

2. **Create virtual environment**:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**:
```bash
pip install -r requirements/development.txt
```

4. **Set up environment variables**:
```bash
cp .env.example .env
# Edit .env with your configuration
```

5. **Initialize database**:
```bash
python scripts/init_db.py
```

6. **Seed sample data** (optional):
```bash
python scripts/seed_data.py
```

7. **Run the application**:
```bash
flask run
# Or using the WSGI file
python wsgi.py
```

The API will be available at `http://localhost:5000`


## API Endpoints

### Authentication
- `POST /api/v1/auth/register` - Register new user
- `POST /api/v1/auth/login` - Login
- `POST /api/v1/auth/logout` - Logout
- `GET /api/v1/auth/me` - Get current user
- `GET /api/v1/auth/sessions` - Get user sessions
- `DELETE /api/v1/auth/sessions/:id` - Revoke session

### Users
- `GET /api/v1/users/me` - Get current user profile
- `PATCH /api/v1/users/me` - Update profile
- `DELETE /api/v1/users/me` - Delete account
- `POST /api/v1/users/me/password` - Change password
- `GET /api/v1/users/me/organizations` - Get user organizations

### Organizations
- `POST /api/v1/organizations` - Create organization
- `GET /api/v1/organizations/:id` - Get organization
- `PATCH /api/v1/organizations/:id` - Update organization
- `DELETE /api/v1/organizations/:id` - Delete organization
- `GET /api/v1/organizations/:id/members` - Get members
- `POST /api/v1/organizations/:id/members` - Add member
- `DELETE /api/v1/organizations/:id/members/:userId` - Remove member
- `PATCH /api/v1/organizations/:id/members/:userId/role` - Update role


### Health
- `GET /api/health` - Health check


## O-auth Setup

- Redirect URI

```http://localhost:5000/api/v1/auth/external/[google|microsoft]/callback```


## API Response Format

All API responses follow the standardized envelope format:

```json
{
  "version": "1.0",
  "success": true,
  "code": 200,
  "message": "Success message",
  "request_id": "uuid-v4",
  "data": {},
  "meta": {}
}
```

Error responses:

```json
{
  "version": "1.0",
  "success": false,
  "code": 400,
  "message": "Error message",
  "request_id": "uuid-v4",
  "error": {
    "type": "VALIDATION_ERROR",
    "details": {}
  }
}
```

## Database Migrations

Create a new migration:
```bash
flask db migrate -m "Description of changes"
```

Apply migrations:
```bash
flask db upgrade
```

Rollback:
```bash
flask db downgrade
```

### Environment Configuration

- **Development**: `FLASK_ENV=development`
- **Testing**: `FLASK_ENV=testing`
- **Production**: `FLASK_ENV=production`

## Production Deployment

### Using Gunicorn

```bash
pip install -r requirements/production.txt
gunicorn -w 4 -b 0.0.0.0:8000 wsgi:app
```


## Security Considerations

- All passwords hashed with Bcrypt (12+ rounds in production)
- CORS configured for allowed origins
- Security headers enabled (CSP, HSTS, etc.)
- Rate limiting on sensitive endpoints
- SQL injection protection via SQLAlchemy ORM
- Session management with secure cookies
- Request ID tracking for audit trails


# Boostrap db
python manage.py db upgrade



## running seed
python -m scripts.seed_data

## Running flask in dev
FLASK_ENV=development flask run --debug --port 8888


# Test creds
## OIDC Client
client_id: acme-portal-001
client_secret: acme_secret_portal_2024

## User
email: bob@acme-corp.com
password: UserPass123!


## Sqlite editor
sqlite_web instance/db_file.db --port 9999 --host 0.0.0.0