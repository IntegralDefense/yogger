from configparser import ConfigParser
import logging
import logging.config
import os
import sys

# initialize logging
try:
    logging.config.fileConfig(os.path.join(sys.path[0], "config", "logging.ini"))
except Exception as e:
    sys.stderr.write("ERROR: unable to load logging config from {0}: {1}\n".format(logConfigPath, str(e)))
    sys.exit(1)

# load configuration
config = None
try:
    temp = ConfigParser(allow_no_value=True)
    temp.read(os.path.join(sys.path[0], "config/config.ini"))
    config = temp
except Exception as e:
    logging.error("unable to load configuration: {}".format(str(e)))
    sys.exit(1)
