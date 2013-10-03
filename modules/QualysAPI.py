#!/usr/bin/env python

"""A library for interfacing with Qualys's Web-based API
"""

__author__ = "William McVey"
__date__ = "3 December, 2007"
__revision__ = "$Id:$"

import os
import sys
import logging
import urllib2
import urllib
import cookielib
from datetime import datetime
from ConfigParser import RawConfigParser

try:
    import cElementTree as ElementTree
except ImportError:
    try:
        from xml.etree import cElementTree as ElementTree
    except ImportError:
        try:
            from lxml import etree as ElementTree
        except ImportError:
            try:
                from xml.etree import ElementTree
            except ImportError:
                try:
                    from elementtree import ElementTree
                except ImportError:
                    raise ("Unable to load any XML libraries for ElementTree!" \
                           "Please install an xml library or Python 2.5 at least")


class QualysAPIError(RuntimeError):
    pass


class ScanReport:
    """Details about a scan report
    """
    def __init__(self, node):
        self.ref = node.get("ref")
        self.date = node.get("date")
        self.status = node.get("status", "")
        self.assets = [e.text for e in node.findall("ASSET_GROUPS/ASSET_GROUP/ASSET_GROUP_TITLE")]
        self.options = [e.text for e in node.findall("OPTION_PROFILE/OPTION_PROFILE_TITLE")]

    def __repr__(self):
        return "<ScanReport %s: %s: %s>" % (self.ref, self.date, ", ".join(self.assets))


class AssetGroup:
    """Details of an asset group
    """
    def __init__(self, node):
        self.id = node.findtext("ID")
        self.title = node.findtext("TITLE")
        self.scanips = [ip.text for ip in node.findall("SCANIPS/IP")]
        self.mapdomains = [domain.text for domain in node.findall("MAPDOMAINS/DOMAIN")]
        self.comments = node.findtext("COMMENTS")
        self.lastupdate = node.findtext("LAST_UPDATE")

    def __repr__(self):
        return "<AssetGroup: %s: %s" % (self.id, self.title)


class QualysScan(dict):
    """
    Maps a Qualys SCAN result to a python object (a customized dict)

    Fields within the dict include:
        REF, TYPE, TITLE, USER_LOGIN, LAUNCH_DATETIME, STATUS, TARGET
    No details on the result of the scan are included. For that, use
    a ScanReport object.
    """

    def __init__(self, node):
        self.node = node
        dict.__init__(self, [(node.tag, node.text) for node in self.node])
        self["STATUS"] = self.node.findtext("STATUS/STATE")

    def __repr__(self):
        return "<QualysScan: %s: %s>" % (self['TITLE'], self['STATUS'])


class QualysAPI:
    # api_url = "http://localhost:9080/api/%(version)s/%(interface)s/%(resource)s/"
    api_url = "https://qualysapi.qualys.com/api/%(version)s/%(interface)s/%(resource)s/"
    agent_string = "QualysAPI.py"

    api_version = "2.0"
    api_interface = "fo"

    def __init__(self):
        self.log = logging.getLogger(self.__class__.__name__)
        cj = cookielib.CookieJar()
        self.opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))

    def api_call(self, resource, action, **params):
        url = self.api_url % {
            "version": self.api_version,
            "interface": self.api_interface,
            "resource": resource,
        }
        post_data = urllib.urlencode(
            [("action", action)] + params.items()
        )
        hdrs = {"X-Requested-With": self.agent_string,
                "User-Agent": self.agent_string,
                "Accept": "*/*",
        }
        request = urllib2.Request(url, data=post_data, headers=hdrs)
        # Error messages are returned with response codes of 400
        try:
            return self.opener.open(request)
        except:
            (exc_type, exc_value, exc_tb) = sys.exc_info()
            try:
                result = ElementTree.parse(exc_value)
                self.log.warn("Caught a traceback: %r. elementtree result = %r", exc_value, result)
                code = result.findtext("RESPONSE/CODE")
                text = result.findtext("RESPONSE/TEXT")
                mesg = "Error %s: %s" % (code, text)
            except:
                mesg = exc_value
            raise QualysAPIError(mesg)


    def Login(self, username, pw):
        reply = self.api_call("session", "login", username=username, password=pw)
        return reply

    def ScanList(self):
        reply = self.api_call("scan", "list")
        tree = ElementTree.parse(reply)
        return [QualysScan(node) for node in tree.findall("RESPONSE/SCAN_LIST/SCAN")]

    def Logout(self):
        reply = self.api_call("session", "logout")
        return reply


def GetQualysCreds(filename=None):
    """Pull Credentials out of a config file
    """
    log = logging.getLogger("GetQualysCreds")
    config = RawConfigParser()
    paths = []
    if filename:
        paths.append(filename)
    for path in [".", "~", "~/lib"]:
        for base in ["qualys.rc", ".qualysrc"]:
            paths.append(os.path.join(os.path.expanduser(path), base))
    config_files = config.read(paths)
    if not config_files:
        log.error("Could not find Qualys config file in any of %r", paths)
        return None
    log.info("Read qualys config from %r", config_files)
    userid, password = [config.get("QualysCreds", param) for param in ("username", "password")]
    return userid, password


def main(argv=sys.argv, Progname=None):
    from optparse import OptionParser, SUPPRESS_HELP       # aka Optik
    import pprint

    # set up commandline arguments
    if not Progname:
        Progname = os.path.basename(argv[0])
    Usage = "%prog usage: [-v] [--config FILENAME] [--assetgroup-list] [--scan-list] [--report-list]\n" \
            "%prog usage: -h\n" \
            "%prog usage: -V"
    optparser = OptionParser(usage=Usage, version="%prog: $Id:$")
    optparser.remove_option("--version")    # we add our own that knows -V
    optparser.add_option("-V", "--version", action="version",
                         help="show program's version number and exit")
    optparser.add_option("-d", "--debug", dest="debug",
                         action="store_true", help=SUPPRESS_HELP)
    optparser.add_option("-v", "--verbose", dest="verbose",
                         action="store_true", help="be verbose")
    optparser.add_option("-c", "--config", dest="configfile",
                         default=None, action="store",
                         help="specify path to a config file with qualys creds")
    optparser.add_option("-r", "--report-list", dest="report_list",
                         action="store_true", help="list the available reports")
    optparser.add_option("-s", "--scan-list", dest="scan_list",
                         action="store_true", help="list the available reports")
    optparser.add_option("-a", "--assetgroup-list", dest="assetgroup_list",
                         action="store_true", help="list the available asset groups")
    optparser.add_option("-k", "--knowledgebase", dest="knowledgebase",
                         action="store_true", help="pull down the latest knowledgbase")
    (options, params) = optparser.parse_args(argv[1:])

    # set up logging environment
    root_log = logging.getLogger()          # grab the root logger
    if options.debug:
        root_log.setLevel(logging.DEBUG)
    elif options.verbose:
        root_log.setLevel(logging.INFO)
    else:
        root_log.setLevel(logging.WARN)
    handler = logging.StreamHandler()
    logformat = "%(name)s: %(levelname)s: %(message)s"
    handler.setFormatter(logging.Formatter(logformat))
    root_log.addHandler(handler)
    log = logging.getLogger(Progname)

    creds = GetQualysCreds(options.configfile)
    if not creds:
        sys.exit("Couldn't retreive Qualys Credentials")
    userid, password = creds

    if options.scan_list:
        client2 = QualysAPI()
        client2.Login(userid, password)
        print "Scan List:"
        for scan in client2.ScanList():
            print scan
            pprint.pprint(scan.items)
            print


if __name__ == '__main__':
    progname = os.path.basename(sys.argv[0])
    try:
        main()
    except SystemExit, value:
        sys.exit(value)
    except:
        (exc_type, exc_value, exc_tb) = sys.exc_info()
        sys.excepthook(exc_type, exc_value, exc_tb)    # if debugging
        sys.exit("%s: %s: %s" % (progname, exc_type.__name__, exc_value))
    sys.exit(0)
