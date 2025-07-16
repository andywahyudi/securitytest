import json
import yaml
import logging
from pathlib import Path

class TestConfig:
    def __init__(self, config_file=None):
        self.config = self.load_default_config()
        if config_file:
            self.load_config_file(config_file)
    
    def load_default_config(self):
        """Load default configuration"""
        return {
            'scanning': {
                'max_depth': 2,
                'delay_between_requests': 0.1,
                'request_timeout': 10,
                'max_concurrent_requests': 5,
                'follow_redirects': True,
                'verify_ssl': False
            },
            'authentication': {
                'retry_attempts': 3,
                'session_timeout': 3600,
                'maintain_session': True,
                'export_session': False
            },
            'xss_testing': {
                'payloads_file': 'payloads/xss_payloads.txt',
                'custom_payloads': [],
                'test_all_parameters': True,
                'test_headers': True,
                'encoding_tests': True
            },
            'csrf_testing': {
                'test_token_absence': True,
                'test_token_prediction': True,
                'test_referer_bypass': True,
                'test_origin_bypass': True
            },
            'session_testing': {
                'test_fixation': True,
                'test_timeout': True,
                'test_concurrent': True,
                'test_regeneration': True
            },
            'reporting': {
                'include_screenshots': False,
                'include_request_response': True,
                'severity_threshold': 'Low',
                'export_formats': ['markdown']
            }
        }
    
    def load_config_file(self, config_file):
        """Load configuration from file"""
        try:
            config_path = Path(config_file)
            
            if not config_path.exists():
                logging.warning(f"Config file {config_file} not found, using defaults")
                return
            
            with open(config_path, 'r') as f:
                if config_path.suffix.lower() in ['.yml', '.yaml']:
                    file_config = yaml.safe_load(f)
                else:
                    file_config = json.load(f)
            
            # Merge with default config
            self.merge_config(self.config, file_config)
            logging.info(f"Configuration loaded from {config_file}")
            
        except Exception as e:
            logging.error(f"Failed to load config file {config_file}: {e}")
    
    def merge_config(self, default, override):
        """Recursively merge configuration dictionaries"""
        for key, value in override.items():
            if key in default and isinstance(default[key], dict) and isinstance(value, dict):
                self.merge_config(default[key], value)
            else:
                default[key] = value
    
    def get(self, section, key=None, default=None):
        """Get configuration value"""
        if key is None:
            return self.config.get(section, default)
        return self.config.get(section, {}).get(key, default)
    
    def set(self, section, key, value):
        """Set configuration value"""
        if section not in self.config:
            self.config[section] = {}
        self.config[section][key] = value
    
    def save_config(self, filename):
        """Save current configuration to file"""
        try:
            with open(filename, 'w') as f:
                if filename.endswith('.yml') or filename.endswith('.yaml'):
                    yaml.dump(self.config, f, default_flow_style=False)
                else:
                    json.dump(self.config, f, indent=2)
            logging.info(f"Configuration saved to {filename}")
        except Exception as e:
            logging.error(f"Failed to save config: {e}")