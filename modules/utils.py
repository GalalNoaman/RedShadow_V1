# Developed by Galal Noaman – RedShadow_V1
# For educational and lawful use only.
# Do not copy, redistribute, or resell without written permission.

# RedShadow_v1/modules/utils.py

import yaml
import os

def load_config(path="config.yaml"):
    default_config = {}  # fallback config if needed

    if not os.path.exists(path):
        print(f"[!] Warning: Config file not found at {path}. Using default settings.")
        return default_config

    try:
        with open(path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
            return config if config else default_config
    except yaml.YAMLError as parse_err:
        print(f"[!] YAML parse error in {path}: {parse_err}")
    except Exception as e:
        print(f"[!] Failed to load config from {path}: {e}")

    return default_config
