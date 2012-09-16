
from ConfigParser import SafeConfigParser, NoOptionError
import os
import io


class SectionAttribute(object):
    def __init__(self, section, parent):
        self.section = section
        self.parent = parent

    def __getattr__(self, attr):
        try:
            return self.parent.get(self.section, attr)
        except NoOptionError, e:
            raise AttributeError(e)

    def __setattr__(self, attr, value):
        if attr in ["section", "parent"]:
            object.__setattr__(self, attr, value)
        else:
            self.parent.set(self.section, attr, value)


class AttributeConfig(SafeConfigParser):
    """
    Addition to RawConfigParser to allow attribute access.

    this:
    config.get("section", "value")

    becomes simply:
    config.section.value
    """
    def __getattr__(self, attr):
        if not self.has_section(attr):
            raise AttributeError("no such section '%s'" % attr)
        return SectionAttribute(attr, self)

    @classmethod
    def fromfiles(cls, *filenames):
        config = cls()
        for filename in filenames:
            config.read(filename)
        prepConfig(config)
        return config

    @classmethod
    def fromstr(cls, string):
        config = cls()
        config.readfp(io.BytesIO(string))
        prepConfig(config)
        return config


#TODO
#class CustomizedConfig(AttributeConfig):
#    def __init__(self):
#        self.session, self.engine = 


def prepConfig(config):
    config.debug = config.general.debug.lower() == "true"
    try:
        bindhost = config.sharing.bindhost
    except AttributeError:
        config.sharing.bindhost = config.general.localip

def getDefaultConfigFile():
    filedir = os.path.dirname(__file__)
    parentdir = os.path.dirname(filedir)
    return os.path.join(parentdir, "socialscan.defaults.config")

def loadDefaultConfig():
    filedir = os.path.dirname(__file__)
    parentdir = os.path.dirname(filedir)
    defaultsfile = getDefaultConfigFile()
    configfile = os.path.join(parentdir, "socialscan.config")
    config = AttributeConfig.fromfiles(defaultsfile, configfile)

    return config


def loadConfig(config_path):
    defaultconfig = getDefaultConfigFile()
    config = AttributeConfig.fromfiles(defaultconfig, config_path)
    return config


def test():
    config = getConfig()
    print config.database.url


if __name__ == "__main__":
    test()
