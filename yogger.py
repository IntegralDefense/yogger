#!/usr/bin/env python3
from lib import config
from lib import YaraLogScanner
import logging
import logging.config
import os
import signal
import subprocess
import sys
import traceback

# sends keyboard interrupt to shutdown
def Shutdown(signal, frame):
    raise KeyboardInterrupt()

# handle sigterm so service stop shutdowns nicely
signal.signal(signal.SIGTERM, Shutdown)

# create a log scanner
yaraLogScanner = YaraLogScanner()

# process files until shutdown
while True:
    try:
        # process jobs in order
        jobs = sorted([job for job in os.listdir(config["main"]["input_dir"])])

        # get list of files that are open by logstash
        open_files = []
        process = subprocess.Popen("systemctl status logstash | grep PID | awk '{print $3}'", stdout=subprocess.PIPE, shell=True)
        pid, err = process.communicate()
        pid = pid.decode("utf-8").strip()
        if len(pid) > 0:
            proc_dir = "/proc/{}/fd".format(pid)
            for fd in os.listdir(proc_dir):
                link = os.path.join(proc_dir, fd)
                try:
                    path = os.readlink(link)
                    if path.startswith(config["main"]["input_dir"]):
                        open_files.append(path)
                except KeyboardInterrupt as e:
                    raise(e)
                except:
                    continue

        # process all job files that are no longer open by logstash
        for job in jobs:
            jobPath = os.path.join(config["main"]["input_dir"], job)
            if jobPath not in open_files:
                logging.info("processing {}".format(jobPath))

                try:
                    yaraLogScanner.Scan(jobPath)
                except KeyboardInterrupt as e:
                    raise(e)
                except:
                    # report unhandled exception and continue
                    logging.error("Failed to scan job {}\n{}".format(jobPath, traceback.format_exc()))

                # remove the job
                os.remove(jobPath)
                logging.info("finished processing {}".format(jobPath))

    except KeyboardInterrupt:
        # shutdown when KeyboardInterrupt is raised
        print
        logging.info("Stopped")
        break
    except:
        # report unhandled exception and continue
        logging.error("Unhandled exception\n{}".format(traceback.format_exc()))
