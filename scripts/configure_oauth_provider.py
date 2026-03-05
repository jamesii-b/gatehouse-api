#!/usr/bin/env python3
"""
OAuth Provider Configuration Script for Gatehouse

This script allows administrators to configure OAuth providers at the application level
using the new ApplicationProviderConfig architecture.

Usage:
    # Create a new provider configuration
    python scripts/configure_oauth_provider.py create google \\
        --client-id "YOUR_CLIENT_ID" \\
        --client-secret "YOUR_CLIENT_SECRET" \\
        --redirect-url "http://localhost:5173/auth/callback"

    # Create a Microsoft provider configuration
    python scripts/configure_oauth_provider.py create microsoft \\
        --client-id "YOUR_AZURE_APP_ID" \\
        --client-secret "YOUR_AZURE_CLIENT_SECRET" \\
        --redirect-url "http://localhost:5000/api/v1/auth/external/microsoft/callback"

    # List all configured providers
    python scripts/configure_oauth_provider.py list

    # Show details of a specific provider
    python scripts/configure_oauth_provider.py show google

    # Update a provider configuration
    python scripts/configure_oauth_provider.py update google --enabled false

    # Delete a provider configuration
    python scripts/configure_oauth_provider.py delete google

    # Use environment variables
    GOOGLE_CLIENT_ID=xxx GOOGLE_CLIENT_SECRET=yyy \\
        python scripts/configure_oauth_provider.py create google

    # Use environment variables (Microsoft)
    MICROSOFT_CLIENT_ID=xxx MICROSOFT_CLIENT_SECRET=yyy \\
        python scripts/configure_oauth_provider.py create microsoft

"""

import os
import sys
import argparse
from typing import Optional, Dict, Any

# Add the parent directory to the path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Load environment variables from .env file before any other imports
# This ensures database and other configurations are available
from dotenv import load_dotenv
script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
env_file = os.path.join(script_dir, '.env')
if os.path.exists(env_file):
    load_dotenv(env_file)

# Import after path setup
from gatehouse_app import create_app
from gatehouse_app.services.external_auth import ExternalAuthService, ExternalAuthError


def _microsoft_defaults() -> dict:
    """
    Build Microsoft provider defaults, honouring MICROSOFT_TENANT_ID if set.

    Tenant options:
      - "common"    : work/school AND personal Microsoft accounts (app must be
                      registered with "Accounts in any organizational directory
                      and personal Microsoft accounts" in Azure Portal)
      - "consumers" : personal Microsoft accounts only (MSA)
      - "organizations": work/school accounts only (AAD)
      - "<tenant-id>": single specific Azure AD tenant (most secure for enterprise)

    Set MICROSOFT_TENANT_ID env var or pass --tenant-id to the script.
    """
    tenant = os.environ.get("MICROSOFT_TENANT_ID", "common")
    base = f"https://login.microsoftonline.com/{tenant}"
    return {
        "auth_url": f"{base}/oauth2/v2.0/authorize",
        "token_url": f"{base}/oauth2/v2.0/token",
        "userinfo_url": "https://graph.microsoft.com/oidc/userinfo",
        "jwks_url": f"{base}/discovery/v2.0/keys",
        # offline_access is required by Microsoft to receive a refresh token
        # (unlike Google which uses access_type=offline as a query param)
        "scopes": ["openid", "profile", "email", "offline_access"],
    }


# Provider endpoint configurations
PROVIDER_DEFAULTS = {
    "google": {
        "auth_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "userinfo_url": "https://openidconnect.googleapis.com/v1/userinfo",
        "jwks_url": "https://www.googleapis.com/oauth2/v3/certs",
        "scopes": ["openid", "profile", "email"],
    },
    "github": {
        "auth_url": "https://github.com/login/oauth/authorize",
        "token_url": "https://github.com/login/oauth/access_token",
        "userinfo_url": "https://api.github.com/user",
        "scopes": ["read:user", "user:email"],
    },
    "microsoft": _microsoft_defaults(),
}


class Colors:
    """ANSI color codes for terminal output."""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def print_success(message: str):
    """Print success message in green."""
    print(f"{Colors.OKGREEN}✓ {message}{Colors.ENDC}")


def print_error(message: str):
    """Print error message in red."""
    print(f"{Colors.FAIL}✗ {message}{Colors.ENDC}", file=sys.stderr)


def print_warning(message: str):
    """Print warning message in yellow."""
    print(f"{Colors.WARNING}⚠ {message}{Colors.ENDC}")


def print_info(message: str):
    """Print info message in blue."""
    print(f"{Colors.OKBLUE}ℹ {message}{Colors.ENDC}")


def print_header(message: str):
    """Print header message."""
    print(f"\n{Colors.BOLD}{Colors.HEADER}{message}{Colors.ENDC}")


def get_env_credentials(provider_type: str) -> Dict[str, Optional[str]]:
    """
    Get OAuth credentials from environment variables.
    
    Supports the following patterns:
    - {PROVIDER}_CLIENT_ID
    - {PROVIDER}_CLIENT_SECRET
    - {PROVIDER}_REDIRECT_URL
    
    Args:
        provider_type: Provider type (google, github, microsoft)
    
    Returns:
        Dictionary with client_id, client_secret, and redirect_url if found
    """
    provider_upper = provider_type.upper()
    return {
        "client_id": os.environ.get(f"{provider_upper}_CLIENT_ID"),
        "client_secret": os.environ.get(f"{provider_upper}_CLIENT_SECRET"),
        "redirect_url": os.environ.get(f"{provider_upper}_REDIRECT_URL"),
    }


def create_provider(args):
    """Create a new OAuth provider configuration."""
    provider_type = args.provider.lower()
    
    print_header(f"Creating {provider_type.title()} OAuth Provider Configuration")
    
    # Get credentials from args or environment
    env_creds = get_env_credentials(provider_type)
    client_id = args.client_id or env_creds.get("client_id")
    client_secret = args.client_secret or env_creds.get("client_secret")
    redirect_url = args.redirect_url or env_creds.get("redirect_url")
    
    # Validation
    if not client_id:
        print_error(f"Client ID is required. Provide via --client-id or {provider_type.upper()}_CLIENT_ID environment variable.")
        return 1
    
    if not client_secret:
        print_error(f"Client secret is required. Provide via --client-secret or {provider_type.upper()}_CLIENT_SECRET environment variable.")
        return 1
    
    # Get provider defaults
    if provider_type not in PROVIDER_DEFAULTS:
        print_error(f"Unknown provider: {provider_type}. Supported providers: {', '.join(PROVIDER_DEFAULTS.keys())}")
        return 1
    
    defaults = PROVIDER_DEFAULTS[provider_type]

    # For Microsoft, allow --tenant-id / MICROSOFT_TENANT_ID to override URLs at create time
    if provider_type == "microsoft":
        tenant_id = getattr(args, "tenant_id", None) or os.environ.get("MICROSOFT_TENANT_ID")
        if tenant_id and tenant_id != os.environ.get("MICROSOFT_TENANT_ID", "common"):
            # Recompute URLs with the supplied tenant
            os.environ["MICROSOFT_TENANT_ID"] = tenant_id
            defaults = _microsoft_defaults()
            print_info(f"Using Microsoft tenant: {tenant_id}")
        elif tenant_id:
            print_info(f"Using Microsoft tenant: {tenant_id}")
        else:
            print_warning(
                "No --tenant-id provided; using 'common'.\n"
                "  • For personal Microsoft accounts: your Azure app must be registered with\n"
                "    'Accounts in any organizational directory and personal Microsoft accounts'.\n"
                "  • For work/school only: use --tenant-id organizations\n"
                "  • For a single Azure AD tenant: use --tenant-id <your-tenant-id>"
            )
    
    # Build configuration
    config_data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "default_redirect_url": redirect_url,
        "is_enabled": not args.disabled,
        **defaults,
    }
    
    # Add custom settings if provided
    if args.settings:
        settings = {}
        for setting in args.settings:
            try:
                key, value = setting.split("=", 1)
                settings[key] = value
            except ValueError:
                print_warning(f"Skipping invalid setting format: {setting}")
        config_data["settings"] = settings
    
    try:
        # Create the provider configuration
        config = ExternalAuthService.create_app_provider_config(
            provider_type=provider_type,
            **config_data
        )
        
        print_success(f"{provider_type.title()} provider created successfully!")
        print_info(f"Provider ID: {config.id}")
        print_info(f"Client ID: {config.client_id}")
        if redirect_url:
            print_info(f"Default Redirect URL: {redirect_url}")
        print_info(f"Enabled: {config.is_enabled}")
        
        return 0
        
    except ExternalAuthError as e:
        print_error(f"Failed to create provider: {e.message}")
        if e.error_type == "PROVIDER_EXISTS":
            print_info("Use 'update' command to modify existing provider configuration.")
        return 1
    except Exception as e:
        print_error(f"Unexpected error: {str(e)}")
        return 1


def update_provider(args):
    """Update an existing OAuth provider configuration."""
    provider_type = args.provider.lower()
    
    print_header(f"Updating {provider_type.title()} OAuth Provider Configuration")
    
    # Build updates dictionary
    updates = {}
    
    if args.client_id:
        updates["client_id"] = args.client_id
    
    if args.client_secret:
        updates["client_secret"] = args.client_secret
    
    if args.redirect_url:
        updates["default_redirect_url"] = args.redirect_url
    
    if args.enabled is not None:
        updates["is_enabled"] = args.enabled
    
    if args.scopes:
        updates["scopes"] = [s.strip() for s in args.scopes.split(",")]

    if args.settings:
        settings = {}
        for setting in args.settings:
            try:
                key, value = setting.split("=", 1)
                settings[key] = value
            except ValueError:
                print_warning(f"Skipping invalid setting format: {setting}")
        updates["settings"] = settings
    
    if not updates:
        print_warning("No updates specified. Use --help to see available options.")
        return 1
    
    try:
        config = ExternalAuthService.update_app_provider_config(
            provider_type=provider_type,
            **updates
        )
        
        print_success(f"{provider_type.title()} provider updated successfully!")
        print_info(f"Provider ID: {config.id}")
        print_info(f"Client ID: {config.client_id}")
        if config.default_redirect_url:
            print_info(f"Default Redirect URL: {config.default_redirect_url}")
        print_info(f"Enabled: {config.is_enabled}")
        
        return 0
        
    except ExternalAuthError as e:
        print_error(f"Failed to update provider: {e.message}")
        if e.error_type == "PROVIDER_NOT_FOUND":
            print_info("Use 'create' command to add a new provider configuration.")
        return 1
    except Exception as e:
        print_error(f"Unexpected error: {str(e)}")
        return 1


def list_providers(args):
    """List all configured OAuth providers."""
    print_header("Configured OAuth Providers")
    
    try:
        configs = ExternalAuthService.list_app_provider_configs()
        
        if not configs:
            print_info("No OAuth providers configured yet.")
            print_info("Use 'create' command to add a provider.")
            return 0
        
        print()
        for config in configs:
            status = f"{Colors.OKGREEN}enabled{Colors.ENDC}" if config.get("is_enabled") else f"{Colors.WARNING}disabled{Colors.ENDC}"
            print(f"  {Colors.BOLD}{config['provider_type']}{Colors.ENDC} - {status}")
            print(f"    Client ID: {config['client_id']}")
            if config.get('default_redirect_url'):
                print(f"    Redirect URL: {config['default_redirect_url']}")
            print(f"    Created: {config.get('created_at', 'N/A')}")
            
            # Show endpoint info if available
            additional_config = config.get('additional_config', {})
            if additional_config:
                if additional_config.get('auth_url'):
                    print(f"    Auth URL: {additional_config['auth_url']}")
                if additional_config.get('scopes'):
                    scopes = ', '.join(additional_config['scopes'])
                    print(f"    Scopes: {scopes}")
            print()
        
        return 0
        
    except Exception as e:
        print_error(f"Failed to list providers: {str(e)}")
        return 1


def show_provider(args):
    """Show details of a specific OAuth provider."""
    provider_type = args.provider.lower()
    
    print_header(f"{provider_type.title()} OAuth Provider Details")
    
    try:
        config = ExternalAuthService.get_app_provider_config(provider_type)
        config_dict = config.to_dict()
        
        print()
        print(f"{Colors.BOLD}Basic Information:{Colors.ENDC}")
        print(f"  Provider Type: {config_dict['provider_type']}")
        print(f"  Provider ID: {config_dict['id']}")
        print(f"  Client ID: {config_dict['client_id']}")
        
        status = f"{Colors.OKGREEN}enabled{Colors.ENDC}" if config_dict['is_enabled'] else f"{Colors.WARNING}disabled{Colors.ENDC}"
        print(f"  Status: {status}")
        
        if config_dict.get('default_redirect_url'):
            print(f"  Default Redirect URL: {config_dict['default_redirect_url']}")
        
        print()
        print(f"{Colors.BOLD}Timestamps:{Colors.ENDC}")
        print(f"  Created: {config_dict.get('created_at', 'N/A')}")
        print(f"  Updated: {config_dict.get('updated_at', 'N/A')}")
        
        # Show additional configuration
        additional_config = config_dict.get('additional_config', {})
        if additional_config:
            print()
            print(f"{Colors.BOLD}OAuth Configuration:{Colors.ENDC}")
            
            if additional_config.get('auth_url'):
                print(f"  Authorization URL: {additional_config['auth_url']}")
            if additional_config.get('token_url'):
                print(f"  Token URL: {additional_config['token_url']}")
            if additional_config.get('userinfo_url'):
                print(f"  User Info URL: {additional_config['userinfo_url']}")
            if additional_config.get('jwks_url'):
                print(f"  JWKS URL: {additional_config['jwks_url']}")
            if additional_config.get('scopes'):
                scopes = ', '.join(additional_config['scopes'])
                print(f"  Scopes: {scopes}")
            
            # Show any custom settings
            custom_settings = {k: v for k, v in additional_config.items() 
                             if k not in ['auth_url', 'token_url', 'userinfo_url', 'jwks_url', 'scopes']}
            if custom_settings:
                print()
                print(f"{Colors.BOLD}Custom Settings:{Colors.ENDC}")
                for key, value in custom_settings.items():
                    print(f"  {key}: {value}")
        
        print()
        return 0
        
    except ExternalAuthError as e:
        print_error(f"Failed to get provider: {e.message}")
        return 1
    except Exception as e:
        print_error(f"Unexpected error: {str(e)}")
        return 1


def delete_provider(args):
    """Delete an OAuth provider configuration."""
    provider_type = args.provider.lower()
    
    print_header(f"Deleting {provider_type.title()} OAuth Provider Configuration")
    
    # Confirm deletion unless --yes flag is provided
    if not args.yes:
        print_warning("This will permanently delete the provider configuration.")
        response = input(f"Are you sure you want to delete {provider_type}? (yes/no): ")
        if response.lower() not in ['yes', 'y']:
            print_info("Deletion cancelled.")
            return 0
    
    try:
        ExternalAuthService.delete_app_provider_config(provider_type)
        print_success(f"{provider_type.title()} provider deleted successfully!")
        return 0
        
    except ExternalAuthError as e:
        print_error(f"Failed to delete provider: {e.message}")
        return 1
    except Exception as e:
        print_error(f"Unexpected error: {str(e)}")
        return 1


def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(
        description="Configure OAuth providers for Gatehouse authentication",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Create Google OAuth configuration
  %(prog)s create google --client-id "CLIENT_ID" --client-secret "SECRET"
  
  # Create with environment variables
  GOOGLE_CLIENT_ID=xxx GOOGLE_CLIENT_SECRET=yyy %(prog)s create google
  
  # List all providers
  %(prog)s list
  
  # Show provider details
  %(prog)s show google
  
  # Update provider
  %(prog)s update google --enabled true
  
  # Delete provider
  %(prog)s delete google --yes

Supported Providers:
  - google
  - github
  - microsoft
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    subparsers.required = True
    
    # Create command
    create_parser = subparsers.add_parser("create", help="Create a new OAuth provider configuration")
    create_parser.add_argument("provider", help="Provider type (google, github, microsoft)")
    create_parser.add_argument("--client-id", help="OAuth client ID")
    create_parser.add_argument("--client-secret", help="OAuth client secret")
    create_parser.add_argument("--redirect-url", help="Default redirect URL for OAuth callbacks")
    create_parser.add_argument("--disabled", action="store_true", help="Create provider in disabled state")
    create_parser.add_argument("--settings", action="append", help="Custom settings (key=value format)")
    create_parser.add_argument(
        "--tenant-id",
        help=(
            "Microsoft only: Azure AD tenant ID (or 'common' / 'consumers' / 'organizations'). "
            "Defaults to the MICROSOFT_TENANT_ID env var, then 'common'."
        ),
    )
    create_parser.set_defaults(func=create_provider)
    
    # Update command
    update_parser = subparsers.add_parser("update", help="Update an existing OAuth provider configuration")
    update_parser.add_argument("provider", help="Provider type to update")
    update_parser.add_argument("--client-id", help="New OAuth client ID")
    update_parser.add_argument("--client-secret", help="New OAuth client secret")
    update_parser.add_argument("--redirect-url", help="New default redirect URL")
    update_parser.add_argument("--enabled", type=lambda x: x.lower() in ['true', '1', 'yes'], 
                              help="Enable or disable the provider (true/false)")
    update_parser.add_argument("--scopes", help="Comma-separated list of OAuth scopes to set (e.g. 'openid,profile,email,offline_access')")
    update_parser.add_argument("--settings", action="append", help="Custom settings to update (key=value format)")
    update_parser.set_defaults(func=update_provider)
    
    # List command
    list_parser = subparsers.add_parser("list", help="List all configured OAuth providers")
    list_parser.set_defaults(func=list_providers)
    
    # Show command
    show_parser = subparsers.add_parser("show", help="Show details of a specific OAuth provider")
    show_parser.add_argument("provider", help="Provider type to show")
    show_parser.set_defaults(func=show_provider)
    
    # Delete command
    delete_parser = subparsers.add_parser("delete", help="Delete an OAuth provider configuration")
    delete_parser.add_argument("provider", help="Provider type to delete")
    delete_parser.add_argument("--yes", "-y", action="store_true", help="Skip confirmation prompt")
    delete_parser.set_defaults(func=delete_provider)
    
    args = parser.parse_args()
    
    # Create Flask app context
    app = create_app()
    
    with app.app_context():
        return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
