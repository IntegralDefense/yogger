from configparser import ConfigParser
import json
from .config import config
import logging
import mmap
import os
import requests
import sys
import time
import traceback
import yara

class YaraLogScanner:
    def __init__(self):
        self.last_commit = ""
        self.rules = {}
        self.all_rules = None
        self.whitelist_rules = None

        # global variables
        baseDir = sys.path[0]
        configDir = os.path.join(baseDir, "config")
        self.indicatorsDir = os.path.join(baseDir, "indicators")
        self.whitelistsDir = os.path.join(baseDir, "whitelists")

        # load observable mappings
        temp1 = ConfigParser(allow_no_value=True)
        temp1.read(os.path.join(configDir, "observable_mappings.ini"))
        self.observable_mappings = temp1

        # load indicator mappings
        temp2 = ConfigParser(allow_no_value=True)
        temp2.read(os.path.join(configDir, "indicator_mappings.ini"))
        self.indicator_mappings = temp2

        # set max string limit
        yara.set_config(max_strings_per_rule=20000)

    def Scan(self, logPath):
        # recompile rules if they have changed
        if self.IndicatorsRepoHasChanged():
            self.UpdateRules()

        # scan the log
        matches = self.all_rules.match(logPath, timeout=60)

        lineOffsets = {}
        with open(logPath, "r") as f:
            # get line start of every hit
            for match in matches:
                for offset, indicator_id, matched_string in match.strings:
                    logging.debug("{}.{} hit {} at {}".format(match.rule, indicator_id, matched_string, offset))

                    file_map = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
                    lineStartOffset = file_map.rfind(b'\x0a', 0, offset)
                    lineStartOffset += 1
                    lineOffsets[lineStartOffset] = True

            # load every line that was hit and scan for realsies
            for lineOffset in lineOffsets.keys():
                f.seek(lineOffset, 0)
                logString = f.readline().strip()
                log = json.loads(logString)

                logging.debug("extracted log {}".format(logString))

                # keep track of hits in dictionaries to prevent duplicates
                hits = {}

                # scan the log
                index = log['index']
                if index in self.rules:
                    for field in log.keys():
                        if field in self.rules[index]:
                            fieldVal = log[field]

                            # join if array and match all at once
                            if isinstance(fieldVal, list):
                                fieldVal = "|".join(fieldVal)
                            
                            # match against corresponding rules
                            matches = self.rules[index][field].match(data=fieldVal, timeout=60)

                            # examine matches
                            for match in matches:
                                logging.debug("hit {}".format(match.rule))

                                # add matched rule to hits
                                if match.rule not in hits:
                                    hits[match.rule] = {}

                                # add matched indicator and string to hits
                                for offset, indicator_id, matched_string in match.strings:
                                    # get crits id from indicator id
                                    indicator_id = indicator_id[1:]
                                    indicator_id = indicator_id.split('_', 1)[0]

                                    # if there is no entry for indicator id then make one
                                    if indicator_id not in hits[match.rule]:
                                        hits[match.rule][indicator_id] = str(matched_string, 'utf-8')

                # if any rules hit the correct field
                if len(hits) > 0:
                    # if log doesn't match any whitelist rule then alert
                    whitelist_matches = self.whitelist_rules.match(data=logString, timeout=60)
                    if len(whitelist_matches) == 0:
                        # create alert json
                        alert_json = {}
                        alert_json['tool'] = "yogger"
                        alert_json['alert_type'] = log['index']
                        rule_name = next(iter(hits))
                        indicator_id = next(iter(hits[rule_name]))
                        matched_string = hits[rule_name][indicator_id]
                        alert_json['name'] = "{} - {}".format(rule_name, matched_string)
                        alert_json['group'] = "{}-{}".format(rule_name, indicator_id)
                        alert_json['details'] = log
                        alert_json['observables'] = {}

                        # add hits observables
                        for rule in hits:
                            oType = "yara_rule"
                            oValue = rule
                            oKey = "{}|{}".format(oType, oValue)
                            alert_json['observables'][oKey] = { "type": oType, "value": oValue }
                            for indicator in hits[rule]:
                                oType = "indicator"
                                oValue = indicator
                                oKey = "{}|{}".format(oType, oValue)
                                alert_json['observables'][oKey] = { "type": oType, "value": oValue }


                        # add log observables
                        if log['index'] in self.observable_mappings:
                            for mapping in self.observable_mappings[log['index']].keys():
                                if mapping in log:
                                    # if field is a list add each entry as observable otherwise add just the field
                                    if isinstance(log[mapping], list):
                                        for entry in log[mapping]:
                                            oType = self.observable_mappings[log['index']][mapping]
                                            oValue = entry
                                            oKey = "{}|{}".format(oType, oValue)
                                            alert_json['observables'][oKey] = { "type": oType, "value": oValue }
                                    else:
                                        oType = self.observable_mappings[log['index']][mapping]
                                        oValue = log[mapping]
                                        oKey = "{}|{}".format(oType, oValue)
                                        alert_json['observables'][oKey] = { "type": oType, "value": oValue }

                        # submit alert to saq_aggreator
                        headers = {"Content-Type":"application/json"}
                        data = json.dumps(alert_json)
                        logging.info("Sending alert to aggregator {}".format(data))
                        r = requests.post(config['YaraLogScanner']['saq_aggregator_uri'], headers=headers, data=data)
                        if r.status_code == 200:
                            logging.debug("alert sent")
                        else:
                            logging.error("failed to send alert to aggregator")
                    else:
                        logging.debug("whitelisted by {}".format(whitelist_matches[0].rule))

    def UpdateRules(self):
        logging.info("compiling rules")

        # dictionary containing rule sources
        sources = {}
        all_sources = {}
        whitelist_sources = {}

        # for each rule in indicator_mappings
        for rule_name in self.indicator_mappings.sections():
            # get path to rule file
            rulePath = os.path.join(self.indicatorsDir, rule_name)

            # add rule to master list of rules
            all_sources[rule_name] = rulePath
            
            # for each mapped field in rule section
            for (field, empty_value) in self.indicator_mappings.items(rule_name):
                # split into index and field
                info = field.split('.', 1)

                # if index is not already in sources then add a dictionary for it
                if info[0] not in sources:
                    sources[info[0]] = {}

                # if field is not already in sources index then add a dictionary for it
                if info[1] not in sources[info[0]]:
                    sources[info[0]][info[1]] = {}

                # add source to sources[index][field] dictionary
                sources[info[0]][info[1]][rule_name] = rulePath

        # compile master rule
        try:
            self.all_rules = yara.compile(filepaths=all_sources)
        except:
            logging.error("failed to compile master rules: {}".format(traceback.format_exc()))

        # compile individual field rules
        self.rules = {}
        for index in sources.keys():
            self.rules[index] = {}
            for field in sources[index]:
                try:
                    self.rules[index][field] = yara.compile(filepaths=sources[index][field])
                except:
                    logging.error("failed to compile rules for {}.{}: {}".format(index, field, traceback.format_exc()))

        # compile whitelists
        for whitelist in os.listdir(self.whitelistsDir):
            whitelist_path = os.path.join(self.whitelistsDir, whitelist)
            whitelist_sources[whitelist] = whitelist_path
        try:
            self.whitelist_rules = yara.compile(filepaths=whitelist_sources)
        except:
            logging.error("failed to compile whitelist rules: {}".format(traceback.format_exc()))

        logging.info("finished compiling rules")

    # returns true if the indicators repo has changed
    def IndicatorsRepoHasChanged(self):
        # get path to the repos HEAD file
        repoGit = os.path.join(self.indicatorsDir, ".git")
        repoHead = os.path.join(repoGit, "HEAD")

        # determine where the commit is stored
        with open(repoHead) as fp:
            ref = fp.readline()[5:-1]

        # get current commit hash
        with open(os.path.join(repoGit, ref)) as fp:
            current_commit = fp.readline()[:-1]
            if current_commit != self.last_commit:
                self.last_commit = current_commit
                return True
        return False
