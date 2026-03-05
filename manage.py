"""Management script for Flask application."""
import os
import click
from dotenv import load_dotenv

# Load environment variables FIRST, before any app imports
load_dotenv(dotenv_path=os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env'))

from flask.cli import FlaskGroup
from gatehouse_app import create_app

# Create application
app = create_app(os.getenv("FLASK_ENV", "development"))

# Create Flask CLI group
cli = FlaskGroup(create_app=lambda: app)


@cli.command("run_mfa_compliance_job")
def run_mfa_compliance_job():
    """Run the MFA compliance scheduled job.
    
    This command processes MFA compliance transitions:
    - Transitions users from PAST_DUE to SUSPENDED status
    - Sends deadline reminder notifications
    - Updates notification tracking metadata
    
    Usage:
        python manage.py run_mfa_compliance_job
    
    This can be called via cron or a task scheduler:
        0 * * * * cd /path/to/app && python manage.py run_mfa_compliance_job
    """
    from datetime import datetime, timezone
    from gatehouse_app.jobs.mfa_compliance_job import process_mfa_compliance, get_job_status
    
    print("=" * 60)
    print("MFA Compliance Job")
    print("=" * 60)
    
    now = datetime.now(timezone.utc)
    print(f"Start time: {now.isoformat()}")
    print()
    
    # Show current status before processing
    print("Current Compliance Status:")
    status = get_job_status(now)
    for status_name, count in status["status_counts"].items():
        print(f"  {status_name}: {count}")
    print(f"  Approaching deadline: {status['approaching_deadline_count']}")
    print(f"  Past due: {status['past_due_count']}")
    print()
    
    # Run the job
    print("Processing compliance...")
    result = process_mfa_compliance(now)
    
    print()
    print("Job Results:")
    print(f"  Users suspended: {result['suspended_count']}")
    print(f"  Notifications sent: {result['notified_count']}")
    print(f"  Records processed: {result['processed_count']}")
    
    if result['errors']:
        print()
        print("Errors:")
        for error in result['errors']:
            print(f"  - {error}")
    
    print()
    print("=" * 60)
    print("Job completed successfully")
    print("=" * 60)


@cli.command("mfa_compliance_status")
def mfa_compliance_status():
    """Show current MFA compliance status.
    
    Usage:
        python manage.py mfa_compliance_status
    """
    from datetime import datetime, timezone
    from gatehouse_app.jobs.mfa_compliance_job import get_job_status
    
    print("=" * 60)
    print("MFA Compliance Status Report")
    print("=" * 60)
    
    now = datetime.now(timezone.utc)
    status = get_job_status(now)
    
    print(f"Report time: {status['timestamp']}")
    print()
    
    print("Compliance Records by Status:")
    for status_name, count in sorted(status["status_counts"].items()):
        bar = "█" * min(count, 50)
        print(f"  {status_name:20s}: {count:5d} {bar}")
    
    print()
    print("Summary:")
    print(f"  Approaching deadline: {status['approaching_deadline_count']}")
    print(f"  Past due (pending suspension): {status['past_due_count']}")
    
    total = sum(status["status_counts"].values())
    compliant = status["status_counts"].get("compliant", 0)
    if total > 0:
        compliance_rate = (compliant / total) * 100
        print(f"  Compliance rate: {compliance_rate:.1f}%")
    
    print("=" * 60)


@cli.command("configure_oauth")
@click.argument("provider", required=False)
@click.option("--client-id", default=None, help="OAuth client ID")
@click.option("--client-secret", default=None, help="OAuth client secret")
@click.option("--redirect-url", default=None, help="Default redirect URL (e.g. https://yourdomain.com/api/v1/auth/external/<provider>/callback)")
def configure_oauth(provider, client_id, client_secret, redirect_url):
    """Configure an OAuth provider at the application level.

    Usage (interactive):
        python manage.py configure_oauth

    Usage (non-interactive):
        python manage.py configure_oauth google --client-id ID --client-secret SECRET

    Supported providers: google, github, microsoft
    """
    import getpass
    from gatehouse_app.models.auth.authentication_method import ApplicationProviderConfig
    from gatehouse_app.extensions import db

    SUPPORTED = ["google", "github", "microsoft"]

    # Well-known endpoints — stored in additional_config so the adapter can
    # resolve auth_url / token_url / userinfo_url without extra logic.
    PROVIDER_DEFAULTS = {
        "google": {
            "auth_url": "https://accounts.google.com/o/oauth2/v2/auth",
            "token_url": "https://oauth2.googleapis.com/token",
            "userinfo_url": "https://www.googleapis.com/oauth2/v3/userinfo",
        },
        "github": {
            "auth_url": "https://github.com/login/oauth/authorize",
            "token_url": "https://github.com/login/oauth/access_token",
            "userinfo_url": "https://api.github.com/user",
        },
        "microsoft": {
            "auth_url": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
            "token_url": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            "userinfo_url": "https://graph.microsoft.com/oidc/userinfo",
        },
    }

    if not provider:
        print("=" * 60)
        print("OAuth Provider Configuration")
        print("=" * 60)
        print(f"Supported providers: {', '.join(SUPPORTED)}")
        provider = input("Provider [google/github/microsoft]: ").strip().lower()

    provider = provider.strip().lower()
    if provider not in SUPPORTED:
        print(f"❌ Unknown provider: {provider}")
        return

    if not client_id:
        client_id = input("Client ID: ").strip()
    if not client_id:
        print("❌ client_id is required")
        return

    if not client_secret:
        client_secret = getpass.getpass("Client Secret (leave blank to keep existing): ").strip()

    if not redirect_url:
        base_url = os.getenv("API_BASE_URL", "http://localhost:5000/api/v1")
        default = f"{base_url}/auth/external/{provider}/callback"
        entered = input(f"Default redirect URL [{default}]: ").strip()
        redirect_url = entered or default

    additional_config = PROVIDER_DEFAULTS[provider].copy()

    with app.app_context():
        config = ApplicationProviderConfig.query.filter_by(provider_type=provider).first()
        if config:
            config.client_id = client_id
            if client_secret:
                config.set_client_secret(client_secret)
            config.is_enabled = True
            config.default_redirect_url = redirect_url
            config.additional_config = {
                **(config.additional_config or {}),
                **additional_config,
            }
            db.session.commit()
            print(f"✅ Updated {provider} provider config.")
        else:
            config = ApplicationProviderConfig(
                provider_type=provider,
                client_id=client_id,
                is_enabled=True,
                default_redirect_url=redirect_url,
                additional_config=additional_config,
            )
            if client_secret:
                config.set_client_secret(client_secret)
            db.session.add(config)
            db.session.commit()
            print(f"✅ Created {provider} provider config.")
        print(f"   redirect_url : {redirect_url}")
        print(f"   auth_url     : {additional_config['auth_url']}")


@cli.command("list_oauth")
def list_oauth():
    """List all configured OAuth providers.

    Usage:
        python manage.py list_oauth
    """
    from gatehouse_app.models.auth.authentication_method import ApplicationProviderConfig

    with app.app_context():
        configs = ApplicationProviderConfig.query.all()
        if not configs:
            print("No OAuth providers configured.")
            return
        print(f"{'Provider':<15} {'Client ID':<40} {'Enabled'}")
        print("-" * 65)
        for c in configs:
            print(f"{c.provider_type:<15} {c.client_id:<40} {c.is_enabled}")


if __name__ == "__main__":
    cli()
