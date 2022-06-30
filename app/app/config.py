import yaml
import sys

CONFIG_FILE = "/etc/metaflow/app.yaml"

class Config(object):
    
    def __init__(self):
        pass

    def parse_log(self, cfg):
        self.log_level = cfg.get('log-level', 'info')
        self.log_file = cfg.get('log-file', '/etc/metaflow/app.log')

    def parse_spec(self, cfg):
        spec = cfg.get('spec')
        self.l7_tracing_limit = spec.get('l7_tracing_limit', 100)

    def parse_querier(self, cfg):
        querier = cfg.get('querier', dict())
        self.querier_server = querier.get('host', 'metaflow-server')
        self.querier_port = querier.get('port', 20416)
        self.querier_timeout = querier.get('timeout', 60)

    def parse_controller(self, cfg):
        controller = cfg.get('controller', dict())
        self.controller_server = controller.get('host', 'metaflow-server')
        self.controller_port = controller.get('port', 20417)
        self.controller_timeout = controller.get('timeout', 60)

    def parse(self, config_path):
        with open(config_path, 'r') as config_file:
            cfg = yaml.load(config_file).get("app", {})
            self.listen_port = cfg.get('listen-port')
            self.http_request_timeout = cfg.get('http_request_timeout', 600)
            self.http_response_timeout = cfg.get('http_response_timeout', 600)
            self.parse_log(cfg)
            self.parse_spec(cfg)
            self.parse_querier(cfg)
            self.parse_controller(cfg)

    def is_valid(self, config_path):
        try:
            self.parse(config_path)
        except Exception as e:
            print("Yaml Error: %s" % e)
            sys.exit(1)
            
config = Config()
config.is_valid(CONFIG_FILE)