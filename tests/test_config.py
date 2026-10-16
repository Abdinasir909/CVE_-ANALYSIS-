# Tests for the config module (no services required).

import pytest

from src.utils.config import Config, ConfigError


def test_config_defaults():
    cfg = Config(env={})
    assert cfg.kafka_bootstrap_servers == "localhost:9092"
    assert cfg.kafka_topic == "cve_events"
    assert cfg.mongodb_uri == "mongodb://localhost:27017"
    assert cfg.mongodb_database == "cve_analysis_dev"
    assert cfg.mongodb_collection == "cve_events"
    assert cfg.nvd_api_key == ""
    assert cfg.nvd_results_per_page == 2000
    assert cfg.log_level == "INFO"
    assert cfg.nvd_api_url == "https://services.nvd.nist.gov/rest/json/cves/2.0"
    assert cfg.nvd_default_days_back == 7
    assert cfg.nvd_request_delay_seconds == 6.0
    assert cfg.spark_app_name == "CveAnalysisBatchETL"
    assert cfg.producer_delay_seconds == 1.0
    assert cfg.producer_max_events == 100


def test_config_env_overrides_defaults():
    cfg = Config(
        env={
            "KAFKA_TOPIC": "other_topic",
            "NVD_RESULTS_PER_PAGE": "250",
            "LOG_LEVEL": "debug",
        }
    )
    assert cfg.kafka_topic == "other_topic"
    assert cfg.nvd_results_per_page == 250
    assert cfg.log_level == "DEBUG"


def test_config_missing_required_key_raises():
    with pytest.raises(ConfigError):
        Config(env={"KAFKA_TOPIC": ""})


def test_config_invalid_log_level_raises():
    with pytest.raises(ConfigError):
        Config(env={"LOG_LEVEL": "VERBOSE"})


# Non-integer and out-of-range NVD_RESULTS_PER_PAGE values raise ConfigError.
@pytest.mark.parametrize("value", ["abc", "0"])
def test_config_invalid_results_per_page_raises(value):
    with pytest.raises(ConfigError):
        Config(env={"NVD_RESULTS_PER_PAGE": value})
