from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "sqlite:///./edr.db"
    secret_key: str = "dev-secret-change-me-please-32chars-min"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 120
    admin_password: str = "ChangeMe123!"
    agent_api_key: str = "agent-dev-key-change-me"
    cors_origins: str = "http://localhost:5173"
    public_base_url: str = "http://localhost:5173"
    deployment_mode: str = "local"  # local | vpn

    # QR + biometric transaction
    # both      = authenticator app (TOTP) if the user enrolled one, otherwise the simulated dev reference (default)
    # totp      = authenticator app only (use this outside the lab: the demo reference is ignored)
    # simulated = dev reference only
    biometric_mode: str = "both"
    totp_issuer: str = "Sentry EDR"  # label shown inside Microsoft Authenticator / Google Authenticator / Authy
    auth_tx_ttl_seconds: int = 120
    auth_tx_max_attempts: int = 3
    demo_biometric_secret: str = "demo-fingerprint"

    # Password change / reset / authenticator re-enrolment: failed attempts before a temporary lockout
    recovery_max_attempts: int = 5
    recovery_lockout_minutes: int = 15

    # Active Directory
    ad_enabled: bool = False
    ad_server: str = "ldaps://dc01.corp.local"
    ad_base_dn: str = "DC=corp,DC=local"
    ad_bind_dn: str = ""
    ad_bind_password: str = ""

    backup_dir: str = "./backups"


settings = Settings()
