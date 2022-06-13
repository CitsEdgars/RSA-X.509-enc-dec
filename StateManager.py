import configparser

class StateManager():
    def __init__(self, conf_name = "config.ini") -> None:
        self.parser = configparser.ConfigParser()
        self.parser.read(conf_name)
        self.conf_name = conf_name

    def get(self, category, field) -> str:
        return self.parser.get(category, field)

    def store(self, category, field, value):
        cfgfile = open(self.conf_name, 'w+')
        self.parser.set(category, field, value)
        self.parser.write(cfgfile)
        cfgfile.close()
