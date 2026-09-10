"""Loads config from settings.yaml (defaults) and .env (secrets/overrides)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

import yaml
from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parents[2]
SETTINGS_YAML = REPO_ROOT / "config" / "settings.yaml"

VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}

# Mirror .env.example so the package is runnable even before the user creates a .env.
_ENV_DEFAULTS: Dict[str, str] = {
    "KAFKA_BOOTSTRAP_SERVERS": "localhost:9092",
    "KAFKA_TOPIC": "cve_events",
    "MONGODB_URI": "mongodb://localhost:27017",
    "MONGODB_DATABASE": "cve_analysis_dev",
    "MONGODB_COLLECTION": "cve_events",
    "SNOWFLAKE_ACCOUNT": "",
    "SNOWFLAKE_USER": "",
    "SNOWFLAKE_PASSWORD": "",
    "SNOWFLAKE_WAREHOUSE": "cve_analysis_wh",
    "SNOWFLAKE_DATABASE": "cve_analysis",
    "NVD_API_KEY": "",
    "NVD_RESULTS_PER_PAGE": "100",
    "LOG_LEVEL": "INFO",
}


class ConfigError(RuntimeError):
    """Raised when configuration is missing or invalid."""


@dataclass
class Config:
    """Typed, validated application configuration."""

    # from .env / os.environ (secrets & environment-specific) 
    kafka_bootstrap_servers: str
    kafka_topic: str
    mongodb_uri: str
    mongodb_database: str
    mongodb_collection: str
    snowflake_account: str
    snowflake_user: str
    snowflake_password: str
    snowflake_warehouse: str
    snowflake_database: str
    nvd_api_key: str
    nvd_results_per_page: int
    log_level: str

    # from config/settings.yaml (non-secret defaults) 
    nvd_api_url: str
    nvd_default_days_back: int
    nvd_request_delay_seconds: float
    raw_path: str
    processed_path: str
    spark_app_name: str
    producer_delay_seconds: float
    producer_max_events: int

    repo_root: Path = field(default=REPO_ROOT, repr=False)

    def __init__(
        self,
        *,
        env: Optional[Dict[str, str]] = None,
        settings_file: Optional[Path] = None,
    ) -> None:

        #Load .env first so it can override settings.yaml defaults, then override with env dict if provided.
        load_dotenv(REPO_ROOT / ".env")
        env = dict(os.environ) if env is None else dict(env)

        yaml_path = settings_file or SETTINGS_YAML
        yaml_data = self._load_yaml(yaml_path)

        nvd = yaml_data.get("nvd", {})
        paths = yaml_data.get("paths", {})
        etl = yaml_data.get("etl", {})
        producer = yaml_data.get("producer", {})

        self.kafka_bootstrap_servers = self._get_str(env, "KAFKA_BOOTSTRAP_SERVERS")
        self.kafka_topic = self._get_str(env, "KAFKA_TOPIC")
        self.mongodb_uri = self._get_str(env, "MONGODB_URI")
        self.mongodb_database = self._get_str(env, "MONGODB_DATABASE")
        self.mongodb_collection = self._get_str(env, "MONGODB_COLLECTION")
        self.snowflake_account = self._get_str(env, "SNOWFLAKE_ACCOUNT", required=False)
        self.snowflake_user = self._get_str(env, "SNOWFLAKE_USER", required=False)
        self.snowflake_password = self._get_str(env, "SNOWFLAKE_PASSWORD", required=False)
        self.snowflake_warehouse = self._get_str(env, "SNOWFLAKE_WAREHOUSE")
        self.snowflake_database = self._get_str(env, "SNOWFLAKE_DATABASE")
        self.nvd_api_key = self._get_str(env, "NVD_API_KEY", required=False)

        self.nvd_results_per_page = self._get_int(env, "NVD_RESULTS_PER_PAGE", min_value=1, max_value=2000)
        self.log_level = self._get_str(env, "LOG_LEVEL").upper()
        if self.log_level not in VALID_LOG_LEVELS:
            raise ConfigError(
                f"LOG_LEVEL must be one of {sorted(VALID_LOG_LEVELS)}, got {self.log_level!r}"
            )

        self.nvd_api_url = str(nvd.get("api_url", "")).strip()
        self.nvd_default_days_back = int(nvd.get("default_days_back", 7))
        self.nvd_request_delay_seconds = float(nvd.get("request_delay_seconds", 6.0))

        self.raw_path = str(paths.get("raw", "data/raw"))
        self.processed_path = str(paths.get("processed", "data/processed"))

        self.spark_app_name = str(etl.get("spark_app_name", "CveAnalysisBatchETL"))
        self.producer_delay_seconds = float(producer.get("delay_seconds", 1.0))
        self.producer_max_events = int(producer.get("max_events", 100))

        self._validate()

    # loaders
    @staticmethod
    def _load_yaml(path: Path) -> Dict[str, Any]:
        if not path.exists():
            raise ConfigError(f"Settings file not found: {path}")
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:  # pragma: no cover - defensive
            raise ConfigError(f"Invalid YAML in {path}: {exc}") from exc
        return data if isinstance(data, dict) else {}

    @staticmethod
    def _get_str(env: Dict[str, str], key: str, required: bool = True) -> str:
        value = env.get(key, _ENV_DEFAULTS.get(key, "")).strip()
        if required and not value:
            raise ConfigError(
                f"Missing required environment variable '{key}'. "
                f"Copy .env.example to .env and fill it in."
            )
        return value

    @staticmethod
    def _get_int(
        env: Dict[str, str], key: str, min_value: Optional[int] = None, max_value: Optional[int] = None
    ) -> int:
        raw = env.get(key, _ENV_DEFAULTS.get(key, "")).strip()
        try:
            value = int(raw)
        except ValueError as exc:
            raise ConfigError(f"Environment variable '{key}' must be an integer, got {raw!r}") from exc
        if min_value is not None and value < min_value:
            raise ConfigError(f"'{key}' must be >= {min_value}, got {value}")
        if max_value is not None and value > max_value:
            raise ConfigError(f"'{key}' must be <= {max_value}, got {value}")
        return value

    # validation
    def _validate(self) -> None:
        if self.nvd_default_days_back < 1:
            raise ConfigError(f"nvd.default_days_back must be >= 1, got {self.nvd_default_days_back}")
        if self.nvd_request_delay_seconds < 0:
            raise ConfigError(f"nvd.request_delay_seconds must be >= 0, got {self.nvd_request_delay_seconds}")
        if self.producer_delay_seconds < 0:
            raise ConfigError(f"producer.delay_seconds must be >= 0, got {self.producer_delay_seconds}")

    # helpers
    def raw_dir(self) -> Path:
        return (self.repo_root / self.raw_path).resolve()

    def processed_dir(self) -> Path:
        return (self.repo_root / self.processed_path).resolve()
