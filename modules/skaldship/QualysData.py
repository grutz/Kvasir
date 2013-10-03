#!/usr/bin/env python
"""Routines to manipulate and processes a Qualys XML output format
"""

__author__ = "William McVey <wam@cisco.com>"
__date__ = "16 November, 2005"
__revision__ = "$Id: QualysData.py,v 1.26 2008/12/05 19:21:23 wam Exp $"

import logging, string, re, sys
import csv, itertools
# For OS strings
import SPAData

try:
    from lxml import etree as ElementTree
except ImportError:
    try:
        from xml.etree import cElementTree as ElementTree
    except ImportError:
        try:
            import cElementTree as ElementTree
        except ImportError:
            try:
                from xml.etree import ElementTree
            except ImportError:
                try:
                    from elementtree import ElementTree
                except ImportError:
                    raise ("Unable to load any XML libraries for ElementTree!" \
                           "Please install an xml library or Python 2.5 at least")


class Container(object):
    """A generic object that initializes its attributes from the init params
    If a subclass defines a 'params' list at the class definition level,.
    only those parameters will be assigned and extra keyword arguments will.
    raise a NameError. Failure to provide a field specified by the.
    subclass' params list will result in None being assigned that value
    """
    params = []

    def __init__(self, *args, **kwargs):
        if not self.params:
            self.__dict__.update(kwargs)
            return
        for param in self.params:
            self.__dict__[param] = kwargs.get(param, None)
            try:
                del (kwargs[param])
            except KeyError:
                pass
        if kwargs:
            raise NameError(
                "%s initialized with extra params: %r" % (self.__class__.__name__, kwargs.keys())
            )

    def __repr__(self):
        return "%s(%s)" % (
            self.__class__.__name__,
            ", ".join(["%s=%r" % t for t in self.__dict__.items()]))


class InfoRecord(Container):
    """Holds the Qualys to Vulntag params"""
    params = [
        "qid", "vulntag", "vulntype", "severity", "category", "title",
        "cve", "bid", "compliance", "cvss_base", "cvss_temporal"
    ]


class Port:
    """Object container for port/protocol
    """
    # The primary reason this is needed over a (port, protocol) tuple is
    # that it becomes very ugly to evaluate a two item tool in boolean
    # context, especially if one or the other items may or may not exist.
    # If you use None for the fields that don't exist, then (None, None)
    # is what you have in case no info is present, but that doesn't evaluate
    # to false as a boolean. If you special case None, for when no info exists
    # we run into lots of checking for the single item None special case.
    # As an object, I have the fields to store, and can over-ride boolean
    # evaluation.

    def __init__(self, port=None, protocol=None, category_value=None):
        self.port = port
        # Strip spaces
        if self.port:
            self.port = re.sub(' ', '', port, 0)
        self.protocol = protocol
        self.value = category_value

    def __str__(self):
        if not self.port and not self.protocol:
            return re.sub(' ', '_', self.value, 0)
        if not self.port:
            return self.protocol
        if not self.protocol:
            return self.port
        return "%s%s" % (self.port.zfill(5), self.protocol[0])

    def __repr__(self):
        return "<Port: %s>" % str(self)

    def __cmp__(self, other):
        try:
            my_port = int(self.port)
            other_port = int(other.port)
        except:
            my_port, other_port = self.port, other.port
        return cmp(my_port, other_port) or \
               cmp(self.protocol, other.protocol) or \
               cmp(self.value, other.value)

    def __hash__(self):
        if self.port is None and self.protocol is None:
            return hash(self.value)
        return hash((self.port, self.protocol))

    def __eq__(self, other):
        if self.protocol or self.port or other.protocol or other.port:
            return self.protocol == other.protocol and self.port and other.port
        return self.value == other.value


class Account:
    """Model information relevant to user or system accounts
    """

    def __init__(self, user=None, pw=None, source=None, uid=None, gid=None,
                 level=None, status="ACTIVE", gecos=None, comment=None):
        self.user = user
        self.pw = pw
        self.source = source
        self.uid = uid
        self.gid = gid
        self.level = level
        self.status = status
        self.gecos = gecos
        self.comment = comment

    def __str__(self):
        if self.pw:
            return "%s[%s]" % (self.user, self.pw)
        return str(self.user)

    def __repr__(self):
        return "<Account: %s>" % str(self)


class Database:
    """Model information relevant to databases
    """

    def __init__(self, port=None, dbtype=None, dbname=None, version=None, addlinfo="COMMENT"):
        self.port = port
        self.dbtype = dbtype
        self.dbname = dbname
        self.version = version
        self.addlinfo = addlinfo

    def __str__(self):
        return "%s/%s/%s" % (self.dbtype, self.port, self.dbname)

    def __repr__(self):
        return "<Database: %s>" % str(self)


class ServiceNameSet(set):
    """Case insensitive Set()
    a set() where elements are case-insensitive on insertion, but
    upper case words will replace lower case ones.
    """

    def add(self, element):
        if not element:
            return
        element = element.strip()
        lowered = element.lower()
        if lowered == element:
            if element.upper() in self:
                return
        elif lowered in self:
            self.remove(lowered)
        set.add(self, element)


class Finding:
    """The Qualys Data object holds the information about a finding
    """
    snmp_string_findings = ["78030", "78031", "78048"]

    def __init__(self, node, category_attrs={}, finding_type=None, id=None):
        """Stores the info found in a particular datafinding

        node - elementtree XML Node
        """
        self.log = logging.getLogger("QualysData.%s" % self.__class__.__name__)
        if node is None:
            if not (finding_type and id):
                raise RuntimeError("Finding attempted instantiation " \
                                   "with neither xml node or type/id")
            node = ElementTree.Element(finding_type, attrib={"number": id})
        self.node = node
        self.cat_attrs = category_attrs

    def __str__(self):
        return "QID: %s on Port %s" % (self.Number(), str(self.Port()))

    def Type(self):
        """ Return vuln type of finding"""
        return self.node.tag

    def setType(self, vulntype):
        self.node.tag = vulntype

    def Title(self):
        """ Return the title of the finding """
        # Make sure title does not contain quotes
        return re.sub('"', '', self.node.findtext("TITLE"), 0)

    def Last_Update(self):
        """ Return the last update of the finding """
        return self.node.findtext("LAST_UPDATE")

    def Diagnosis(self):
        """ Return the diagnosis of the finding """
        return self.node.findtext("DIAGNOSIS")

    def Consequence(self):
        """ Return the consequence of the finding """
        return self.node.findtext("CONSEQUENCE")

    def Solution(self):
        """ Return the solution of the finding """
        return self.node.findtext("SOLUTION")

    def Result(self):
        """ Return the result of the finding """
        return self.node.findtext("RESULT")

    def ResultTable(self, include_header=False, max_cols=None, coldelim="\t"):
        """Parse the Result as a data table

        Returns a list of tuples, where each tuple represents
        the fields with a row of the table.

        Parameters are:
          include_header  -  boolean of should we return the first
                             row (typically a header for the column)
          max_cols -         only return specified number of columns.
                             unlike string.split(), other column
                             data after max_cols are not returned joined
                             to the last col, they just are dropped
          coldelim -         column deliminator (default is tab)
        """
        rows = self.Result().split('\n')
        if not include_header:
            rows = rows[1:]        # skip first row
        if max_cols:
            return [row.split(coldelim)[:max_cols] for row in rows if row]
        return [row.split(coldelim) for row in rows if row]

    def nfsResultTable(self, include_header=False, max_cols=None, coldelim="\t"):
        """Parse the NFS Result as a data table

        This is a special one-off for Qualys broken NFS export
        filesystem table, which is not newline-separated rows.

        Use this until a fix is applied.

        Returns a list of tuples, where each tuple represents
        the fields with a row of the table.

        Parameters are:
          include_header  -  boolean of should we return the first
                             row (typically a header for the column)
          max_cols -         only return specified number of columns.
                             unlike string.split(), other column
                             data after max_cols are not returned joined
                             to the last col, they just are dropped
          coldelim -         column deliminator (default is tab)
        """
        #rows = self.Result().split('\n')
        rows = re.sub('\t([^ /]+)/', '\t\\1\n/', self.Result()).split('\n')
        if not include_header:
            rows = rows[2:]        # skip first two rows
        if max_cols:
            return [row.split(coldelim)[:max_cols] for row in rows if row]
        return [row.split(coldelim) for row in rows if row]

    def Number(self):
        """Return the Qualys ID number of the finding"""
        return self.node.get("number")

    def Severity(self):
        """ Return the severity of the finding """
        return self.node.get("severity")

    def Banner(self):
        """Return a banner string if this vulnid is expected to have
        one, Returns None if there isn't
        """
        if not vulninfo.has_banner(self.Number()):
            return None
        extractor = getattr(self, "ExtractBanner_%s" % self.Number(), None)
        if extractor:
            try:
                banner = extractor()
            except (IndexError, KeyError):
                # Most likely, we're being called from a CSV formed
                # dataset, which simply populates the Result(), and doesn't
                # have the finding specific table data, so fall through and
                # use the default banner extraction
                banner = None
            if banner:
                return banner
        return self.Result()

    def ExtractBanner_row2_field2(self):
        """Extracts banner from table of the form:
            Server Version\tServer Banner\n
            version_info\tbanner_string
        """
        line = self.Result().split('\n')[1]
        return line.split("\t")[1]

    ExtractBanner_86000 = ExtractBanner_row2_field2        # Web Svr Version

    ExtractBanner_86001 = ExtractBanner_row2_field2        # SSL Web Svr Vers

    def ExtractBanner_9(self):
        """Extract the service names out of an RPC dump and return a
           comma seperated string as the banner
        """
        services = set()
        for row in self.ResultTable(max_cols=5):
            try:
                prog, ver, proto, port, svc_name = row
            except:
                self.log.error("Result of finding 9 couldn't be split on tabs (skipping): %s", row)
                continue
            services.add(svc_name)
        services = list(services)
        services.sort()
        return ",".join(services)

    def ExtractBanner_11(self):
        """Extract the service names out of a hidden RPC dump and
           return a comma seperated string as the banner
        """
        services = set()
        for row in self.ResultTable(max_cols=5):
            try:
                svc_name, prog, ver, proto, port = row
            except:
                self.log.error("Result of finding 11 couldn't be split on tabs (skipping): %s", row)
                continue
            services.add(svc_name)
        services = list(services)
        services.sort()
        return ",".join(services)

    def setBanner(self, banner_string):
        result = self.node.find("RESULT")
        if not result:
            result = ElementTree.Element("RESULT")
            self.node.append(result)
        result.text = banner_string

    def ServiceName(self):
        """Returns the name of the service associated with the this
        vulnid as a string, or None this vulnid isn't known
        """
        name = vulninfo.service_name(self.Number())
        if name:
            return name.lower()
        return None

    def Port(self):
        """Return the Port object containing port/protocol info for
        this finding
        """
        attrs = self.cat_attrs
        return Port(attrs.get("port", None),
                    attrs.get("protocol", None), \
                    attrs.get("value", None))

    def setPort(self, portobj):
        self.cat_attrs["port"] = portobj.port
        self.cat_attrs["protocol"] = portobj.protocol
        self.cat_attrs["value"] = portobj.value

    def ExtractPortTable(self):
        """Extracts the ports from the table of discovered ports and returns
        a list of (PortObject, servicename)

        Currently only handles vulnids 82004 (udp) & 82023 (tcp)
        """
        ports = []
        if self.Number() == "82004":
            proto = "udp"
        elif self.Number() == "82023":
            proto = "tcp"
        else:
            self.log.warn("ExtractPortTable on unrecognized vulnid: %s",
                          self.Number())
            return []
        #for portnum, service, descr, detected in self.ResultTable(max_cols=4):
        for row in self.ResultTable(max_cols=4):
            try:
                portnum, service, descr, detected = row
            except:
                self.log.error("Result of finding %s couldn't be " \
                               "split on tabs (skipping): %s", self.Number(), row)
                continue

            if detected.strip() != "unknown":
                service = detected.upper()      # detected
            else:
                if service.strip() != "unknown":
                    service = service.upper()       # IANA assigned
                else:
                    service = ""

            ports.append((Port(portnum, proto), service))
        return ports

    def ExtractAccounts(self):
        """Return a list of accounts by calling specialized methods to
        extract account info from various Qualys findings
        """
        qid = self.Number()
        extractor = getattr(self, "ExtractAccounts_%s" % self.Number(), None)
        if extractor:
            return extractor()
        return []

    def ExtractAccounts_5005(self):
        """Extracts accounts from QID 5005: NetBIOS Brute Force
        of Accounts
        """
        accounts = []
        for row in self.ResultTable():
            try:
                user, pw = row
            except:
                self.log.error("Result of finding 5005 couldn't be " \
                               "split on tabs (skipping): %s", row)
                continue
            if re.search("(empty)", pw): pw = "<No Password>"
            accounts.append(Account(source="QID#5005",
                                    user=user, pw=pw, level="USER",
                                    comment="QID:5005"))
        return accounts

    def ExtractAccounts_19001(self):
        """Extracts accounts from QID 19001: Microsoft SQL Weak
        Database Password
        TODO: Add NeXpose parsing
        """
        accounts = []
        for row in self.ResultTable():
            try:
                user, pw = row
            except:
                self.log.error("Result of finding 19001 couldn't be " \
                               "split on tabs (skipping): %s", row)
                continue
            if re.search("NO PASSWORD", pw): pw = "<No Password>"
            accounts.append(Account(source="%s" % self.Port(),
                                    user=user, pw=pw, level="ADMIN",
                                    comment="QID:19001"))
        return accounts

    def ExtractAccounts_19003(self):
        """Extracts accounts from QID 19003: Default Oracle Login(s) Found
        """
        accounts = []
        for row in self.ResultTable():
            try:
                user, pw, sid = row
            except:
                self.log.error("Result of finding 19003 couldn't be " \
                               "split on tabs (skipping): %s", row)
                continue
            accounts.append(Account(source="oracle/%s/%s" % (self.Port(), sid),
                                    user=user, pw=pw, level="USER",
                                    comment="QID:19003"))
        return accounts

    def ExtractAccounts_19085(self):
        """Extracts accounts from QID 19085: Oracle Database User List
        Note: Port and SID for these accounts is not available.
        Bug filed with Qualys.
        """
        accounts = []
        for row in self.ResultTable(max_cols=6):
            try:
                user, j1, hash, j2, ustatus, j3 = row
            except:
                self.log.error("Result of finding 19085 couldn't be " \
                               "split on tabs (skipping): %s", row)
                continue
            accounts.append(
                Account(source="oracle/%s/%s" % (self.Port(), "?"), user=user, pw=hash, level="USER", status=ustatus,
                        comment="QID:19085"))
        return accounts

    def ExtractAccounts_43021(self):
        """Extract accounts from QIDs 43021:
        Cisco Router/Switch Default Password Vulnerability
        The RESULT is raw form. Ex:
        <RESULT><![CDATA[Username: &lt;BLANK&gt;
        Password: cisco
        show version
        Cisco Internetwork Operating System Software
        """
        accounts = []
        user, pw = ("", "")
        for line in self.Result().split('\n'):
            if re.search("/", line):
                line = re.sub('^\[|\]$', '', line, 0)
                user, pw = line.split("/")
                break
            user_pattern = re.search("Username: (.*)", line)
            if user_pattern:
                user = user_pattern.group(1)
            pass_pattern = re.search("Password: (.*)", line)
            if pass_pattern:
                pw = pass_pattern.group(1)
                break
        if re.search("BLANK", user):
            user = "login"
        accounts.append(Account(user=user, pw=pw, level="USER", status="ACTIVE", comment="Default Password;QID:43021"))
        return accounts

    def ExtractAccounts_45002(self):
        """Extracts accounts from QID 45002: Global User List
        """
        accounts = []
        for row in self.ResultTable():
            try:
                user, src_finding = row
            except:
                self.log.error("Result of finding 45002 couldn't be " \
                               "split on tabs (skipping): %s", row)
                continue
            accounts.append(Account(user=user, source="QID#%s" % src_finding,
                                    level="USER", comment="QID:45002"))
        return accounts

    def ExtractAccounts_45003(self):
        """Extracts accounts from QID 45003:
        Remote Windows User List Disclosure Vulnerability
        """
        accounts = []
        for row in self.ResultTable(include_header=True):
            try:
                user, uid = row
            except:
                self.log.error("Result of finding 45003 couldn't be " \
                               "split on tabs (setting to user only): %s", row)
                user = row
            accounts.append(Account(user=user, uid=uid, source="NetBIOS Null Session",
                                    comment="QID:45003"))
        return accounts

    def ExtractAccounts_45027(self):
        """Extract accounts from QIDs 45027:
        Disabled Accounts Enumerated From SAM Database
        """
        accounts = []
        for line in self.Result().split('\n')[1:]:
            for user in line.split():
                accounts.append(Account(user=user, level="USER", status="DISABLED",
                                        comment="QID:45027"))
        return accounts

    def ExtractAccounts_45031(self):
        """Extract accounts from QIDs 45031:
        Accounts Enumerated From SAM Database Whose Passwords Do Not Expire
        """
        accounts = []
        for line in self.Result().split('\n')[1:]:
            for user in line.split():
                accounts.append(Account(user=user, comment="QID:45031;doesn't expire"))
        return accounts

    def ExtractAccounts_45032(self):
        """Extract accounts from QIDs 45032:
        Administrator Account's Real Name Found From LSA Enumeration
        """
        return [Account(user=self.Result(), uid="500", level="ADMIN",
                        comment="QID:45032;real Administrator account")]

    def ExtractAccounts_90266(self):
        """Extract accounts from QIDs 90266:
        Real Name of  Built-in Guest Account Enumerated
        """
        return [Account(user=self.Result(), uid="501",
                        comment="QID:90266;real 'Guest' account")]

    def ExtractAccounts_66016(self):
        """Extract accounts from QIDs 66016:
        [based on MD's code, not from structure of vuln]
        """
        accounts = []
        for user in self.Result().split('\n'):
            # Valid users are formatted: user@host
            if '@' not in user:
                continue
            accounts.append(Account(user=user, comment="QID:66016;rusers RPC"))
        return accounts

    def ExtractAccounts_105231(self):
        """Extract accounts from QIDs 105231:
        Administrator Group Members Enumerated
        """
        accounts = []
        for row in self.Result().split('\n'):
            try:
                user = " ".join(row.split()[1:])
            except:
                self.log.error("Result of finding 105231 couldn't be " \
                               "split (setting user to all): %s", row)
                user = row
            accounts.append(Account(user=user, comment="QID:105231;Administrator group member"))
        return accounts

    def ExtractAccounts_105234(self):
        """Extract accounts from QIDs 105234:
        Unused Active Windows Accounts Found
        """
        accounts = []
        for user in self.Result().split():
            accounts.append(Account(user=user, comment="QID:105234;never been used"))
        return accounts

    def ExtractAccounts_105236(self):
        """Extract accounts from QIDs 105236:
        Windows User Accounts With Unchanged Passwords
        """
        accounts = []
        for user in self.Result().split():
            accounts.append(Account(user=user,
                                    comment="QID:105236;PW has never changed"))
        return accounts

    def ExtractSNMP(self):
        """Extracts a list of tuples of containing SNMP strings
        the permission associated with it

        Any additional SNMP related Qualys finding should be
        recorded in the class's snmp_string_findings attribute as well
        """
        if self.Number() == '78030':    # Readable SNMP
            if self.Result():
                return [(c, "READ") for c in self.Result().split("\n")]
        if self.Number() == '78031':    # Writable SNMP
            if self.Result():
                return [(c, "WRITE") for c in self.Result().split("\n")]
        if self.Number() == '78048':    # SNMP ANYString
            if "write access" in self.Result():
                return [("[any-community-string]", "WRITE")]
            else:
                return [("[any-community-string]", "READ")]

    def ExtractDatabases(self):
        """Return a list of databases by calling specialized methods to
        extract database info from various Qualys findings
        """
        qid = self.Number()
        extractor = getattr(self, "ExtractDatabases_%s" % self.Number(), None)
        if extractor:
            return extractor()
        return []

    def ExtractDatabases_19002(self):
        """Extracts Oracle SIDs from QID 19002: Guessed Oracle
        Database Name
        """
        sids = []
        for row in self.ResultTable(include_header=True, coldelim=" = "):
            try:
                tagnm, sid = row
            except:
                self.log.error("Result of finding 19002 couldn't be " \
                               "split on tabs (skipping): %s", row)
                continue
            #sids.append(Database(version=self.OracleVersion(), port=self.Port(), dbtype="oracle", dbname=sid, addlinfo=self.OraclePath()))
            sids.append(Database(port=self.Port(), dbtype="oracle", dbname=sid))
        return sids

    def ExtractWindowsServicePacks(self):
        """Extracts Installed Service Packs from QID 105313: Windows
        Service Pack Information
        """
        return self.Result().split("\n")

    def ExtractInstalledSoftware(self):
        """Extracts installed software from QID:78014
        returns a list of software.
        """
        results = []
        for line in self.Result().split('\n')[1:]:
            results.append(line.split('\t')[0])
        return results

    def ExtractVirusInfo_105001(self):
        """Extracts Installed Virus Scanner information
        returns:
            None if no data
        or:
            (Product, Product Version, Dat file Version, Last Update)
        """
        data = dict(self.ResultTable(include_header=False, coldelim=" = "))
        if not data:
            return None
        # ZZZ: Dunno what relevance szEngineVer has... is it more important than szProductVer?
        return tuple([data.get(x, None) for x in "Product", "szProductVer", "szVirDefVer", "Date"])

    def CVSS_Base(self):
        """Return the CVSS Base value
        """
        return self.node.findtext("CVSS_BASE")

    def CVSS_Base_source(self):
        """Return the CVSS Base source
        """
        return self.node.find("CVSS_BASE").get("source")

    def CVSS_Temporal(self):
        """Return the CVSS Temporal value
        """
        return self.node.findtext("CVSS_TEMPORAL")

    def PCI_Flag(self):
        """Return the PCI Flag. If 1, QID needs to be fixed for
        PCI compliance.
        """
        if self.node.findtext("PCI_FLAG") == "1":
            return True
        return False

    def Bugtraq(self):
        """Return a list of the bugtraq identifiers for the finding
        """
        bid = set([id.findtext("ID") \
                   for id in self.node.findall("BUGTRAQ_ID_LIST/BUGTRAQ_ID")])
        bid.discard("nosf")    # junk entry in the XML
        bid = list(bid)
        bid.sort()
        return bid

    def CVE(self):
        """Return a list of all CVE identifiers related to the finding
        """
        cveid = set([id.findtext("ID") \
                     for id in self.node.findall("CVE_ID_LIST/CVE_ID")])
        cveid = list(cveid)
        cveid.sort()
        return cveid

    def Compliance_text(self):
        """ Return the compliance text
        """
        compliance_info = ""
        for cinfo in self.node.findall("COMPLIANCE/COMPLIANCE_INFO"):
            comp_type = cinfo.findtext("COMPLIANCE_TYPE")
            comp_section = cinfo.findtext("COMPLIANCE_SECTION")
            comp_descript = cinfo.findtext("COMPLIANCE_DESCRIPTION")
            compliance_info = "\n".join(["<BR>".join(['<P><B>Type</B>: %s' % comp_type,
                                                      '<B>Section</B>: %s' % comp_section,
                                                      '%s' % comp_descript]), compliance_info])
        return compliance_info

    def Compliance(self):
        """ Return the compliance type (GLBA, CobIT, SOX, etc)
        Structure is:
            compliance_info[compliance_type]["section"] = section
            compliance_info[compliance_type]["description"] = compliance description
        """
        compliance_info = {}
        for cinfo in self.node.findall("COMPLIANCE/COMPLIANCE_INFO"):
            comp_type = cinfo.findtext("COMPLIANCE_TYPE")
            comp_section = cinfo.findtext("COMPLIANCE_SECTION")
            comp_descript = cinfo.findtext("COMPLIANCE_DESCRIPTION")
            compliance_info[comp_type] = {"section": comp_section,
                                          "description": comp_descript}
        return compliance_info

    def ComplianceType(self):
        """ Return the compliance type (GLBA, CobIT, SOX, etc)
        """
        compliance_type = set([cinfo.findtext("COMPLIANCE_TYPE") \
                               for cinfo in self.node.findall("COMPLIANCE/COMPLIANCE_INFO")])
        compliance_type = list(compliance_type)
        compliance_type.sort()
        return compliance_type

    def ClassType(self):
        """ Return the CAT type associated with the finding """
        return self.cat_attrs["value"]

    def Exploits(self):
        """ Return a list of exploits:
        Structure:
           exploit = ( 'source', exploit module: "reference", "description","link", ""
        """
        exploits = {}
        for source in self.node.findall("EXPLOITABILITY/SOURCE_LIST"):
            sname = source.findtext("EXPLOIT_SOURCE")
            for elist in source.findall("EXPLOIT_LIST"):
                ref = elist.findtext("EXPLOIT/REFERENCE")
                descr = elist.findtext("EXPLOIT/DESCRIPTION")
                url = elist.findtext("EXPLOIT/LINK")
                exploits.setdefault(sname, []).append((ref, descr, url))
        return exploits


class QualysHost:
    """Contains all the info for the IP. Including the finding objects.

    Most information is cached in dictionaries for efficient lookups by
    methods and other pieces of automation. Major structures include:

    findings:  {"INFO": [], "SERVICE": [], "VULN": [], "PRACTICE": []}
        the lists are of finding objects. Note, multiple finding object of
        same id are likely to be in the list together, but on different
        ports
    services_by_port: {PortObject: ServiceNameSet(name, ...),}
    findings_by_port_id: {PortObject: {'VulnID': FindingObject, ...}, ...}
    findings_by_port_type: {PortObject: {"INFO": [finding,...], "SERVICE": [],
                                         "VULN": [], "PRACTICE": []}
    findings_by_id: {id: [finding_obj, finding_obj], ...}
    accounts:	{}
    """
    def __init__(self, node=None):
        self.log = logging.getLogger("QualysData.%s" % self.__class__.__name__)
        if node == None:
        # allows a host object to be populated with set* methods
            node = ElementTree.Element("IP", attrib={"value": "", "name": ""})
        self.node = node

        self.findings = {"INFO": [], "SERVICE": [], "VULN": [], "PRACTICE": []}
        self.services_by_port = {}
        self.findings_by_port_id = {}
        self.findings_by_id = {}
        self.findings_by_port_type = {}
        self.accounts = {}
        self._os_tuple = None        # allows setting an OS tuple from a CSV

        for category_node in node.findall("*/CAT"):
            cat_attrs = category_node.attrib
            for finding_node in category_node.getchildren():
                finding = Finding(finding_node, cat_attrs)
                self.addFinding(finding)

    def __str__(self):
        return self.IP()

    def __repr__(self):
        return '<QualysHost ip="%s">' % self.IP()

    def lookupUniqFinding(self, id):
        findings = self.findings_by_id.get(id, None)
        if not findings:
            return None
        if len(findings) > 1:
            self.log.warn("More than one finding %s on %s, using the first one.", id, self)
        return findings[0]

    def FindingsList(self):
        """Return a list of finding objects found on this host

        It's important to note that this *loses* findings, all we are returning
        is a single instance of each finding type, with the assumption that info
        like Title(), and Severity() aren't host/port specific.
        """
        return [findings[0] for tag, findings in self.findings_by_id.items()]

    def IP(self):
        """Get the IP address of the host or returns None"""
        return self.node.get("value", None)

    def setIP(self, ip):
        """Set the IP address of the host"""
        self.node.set("value", ip)

    def Hostname(self):
        """The hostname of the host, or None if there is no hostname
        """
        hostname = self.node.get("name")
        if hostname == "No registered hostname":
            hostname = None
        return hostname

    def setHostname(self, hostname):
        """Set the hostname of the host"""
        if hostname is None:
            hostname = "No registered hostname"
        self.node.set("name", hostname)

    def Ports(self, sorted=False):
        """Returns a list of (portobject, [servicenames, ...]) tuples
        """
        ports = self.services_by_port.items()
        if sorted:
            ports.sort(key=lambda (x, y): x)
        return ports

    def ServiceNames(self, portobj):
        return list(self.services_by_port.get(portobj, []))

    def addServiceToPort(self, portobj, service):
        if not service:
            return self.services_by_port.setdefault(portobj, ServiceNameSet())
        service = " ".join(service.split(","))
        self.services_by_port.setdefault(portobj, ServiceNameSet()).add(service)

    def NetBIOSname(self):
        """NetBIOS hostname of the host if known. None if not known
        """
        finding = self.lookupUniqFinding("82044")
        if finding:
            return finding.Result()
        return None

    def NetBIOSdomain(self):
        """NetBIOS domain/workgroup if known. None if not known
        """
        finding = self.lookupUniqFinding("82062")
        if finding:
            return finding.Result()
        return None

    def NetBIOSrole(self):
        """NetBIOS role. Return "DC" if known. None if not known
        """
        qid45022 = self.lookupUniqFinding("45022")
        qid45024 = self.lookupUniqFinding("45024")
        qid45025 = self.lookupUniqFinding("45025")
        if qid45022 or qid45024 or qid45025:
            return "DC"
        return None

    def NetBIOSattributes(self):
        """Get the NetBIOS attributes/values of the host

        returns a list of (service, value) tuples
        """
        finding = self.lookupUniqFinding("70004")
        if not finding:
            return []
        result = set()
        for line in finding.Result().split('\n')[1:]:
            try:
                (value, service, suffix) = line.split('\t', 2)
                result.add((service, value, suffix))
            except:
                (value, service) = line.split('\t', 1)
                result.add((service, value))
        return list(result)

    def OracleVersion(self, portobj):
        """Oracle version of listener. None if not known
        Note: Qualys' oracle version check is not exactly
        correct. It is the TNSLSNR version and not the database
        version, since the two are not necessarily the same.
        """
        for finding in self.Findings(portobj):
            if finding.Number() == "19014":
                for line in finding.Result().split('\n'):
                    if "TNSLSNR" in line:
                        return line.split(": ")[1]
        return None

    def OraclePath(self, portobj):
        """Oracle path. None if not known
        """
        for finding in self.Findings(portobj):
            if finding.Number() == "19017":
                for line in finding.Result().split('\n'):
                    if "PATH" in line:
                        return line
        return None

    def Findings(self, portobj=None, finding_type=None):
        """Returns a list of Finding objects on this host.

        If no portobj parameter is specified, will return a list of all
        unique findings (same finding on multiple hosts will be collapsed).
        The value for 'finding_type' will generally be one of 'INFO',
        'SERVICE', 'VULN', or 'PRACTICE'. If 'None' is specified, will
        return all.
        """
        if portobj is None:
            findings = set()     # A set, and not a list, to weed out duplicates
            for port in self.Ports():
                findings.update(self.Findings(portobj=port, finding_type=finding_type))
            return list(findings)
        if finding_type is None:
            return self.findings_by_port_id.get(portobj, {}).values()
        return self.findings_by_port_type.get(portobj, {}).get(finding_type, [])

    def addFinding(self, finding):
        id = finding.Number()
        portobj = finding.Port()
        finding_type = finding.Type()
        if not self.findings.has_key(finding_type):
            self.log.error("Unknown type of finding on %s: %s", self,
                           finding_type)
        self.findings[finding_type].append(finding)
        self.addServiceToPort(portobj, finding.ServiceName())
        self.findings_by_port_id.setdefault(portobj, {})[id] = finding
        self.findings_by_port_type.setdefault(portobj, {}).setdefault(finding_type, []).append(finding)
        self.findings_by_id.setdefault(id, []).append(finding)

        if id in ("82004", "82023"):        # UDP and TCP ports found open
            for portobj, service in finding.ExtractPortTable():
                self.addServiceToPort(portobj, service)

    def Accounts(self):
        """Returns a list of Account objects for this host
        """
        accounts = []
        for port in self.Ports():
            for finding in self.Findings(port):
                accounts.extend(finding.ExtractAccounts())
        return accounts

    def Databases(self):
        """Returns a list of database objects for this host
        """
        databases = []
        for port in self.Ports():
            for finding in self.Findings(port):
                databases.extend(finding.ExtractDatabases())
        return databases

    def SNMPcommunities(self):
        """Returns a list of (port, community_string, permission) tuples
        """
        strings = []
        for snmp_id in Finding.snmp_string_findings:
            for finding in self.findings_by_id.get(snmp_id, []):
                # Make sure we have some strings to extract
                if not finding.ExtractSNMP() is None:
                    for string, perm in finding.ExtractSNMP():
                        strings.append((finding.Port(), string, perm))
        return strings

    def OS(self):
        """Return OS information as a list of (method, value) tuples

        methods include:
            CIFS-TCP-139, CIFS-TCP-445, MS-RPC, NTP, SNMP sysDescr
            SRVSVC TCP/IP Fingerprint, NetBIOS Name Service Leakage

        OS info from NetBIOS can be found from:
        PRACTICE number="90067
            Detected service netbios_ns and os Windows 2003
            Detected service netbios_ns and os Windows XP Service Pack 0-1
        SERVICE number="45017"
            Operating System	Technique			ID
            Linux 2.4-2.6		TCP/IP Fingerprint	U1141:22
        """
        results = []
        qid45017 = self.lookupUniqFinding("45017")
        qid90067 = self.lookupUniqFinding("90067")
        if qid45017:    # SERVICE: Operating System Detected
            for os, how in qid45017.ResultTable(max_cols=2):
                how = {"CIFS via TCP Port 139": "CIFS-TCP-139",
                       "CIFS via TCP Port 445": "CIFS-TCP-445"}.get(how, how)
                results.append((how, os))
        if qid90067:    # NetBIOS Name Service Reply Leakage
            os_pattern = re.search(r"Detected .* os (.*)$",
                                   qid90067.Result(), re.MULTILINE)
            if os_pattern:
                results.append(("NetBIOS Name Service Leakage",
                                os_pattern.group(1)))
        return results

    def sort_os(self, a, b):
        """Sort an OS result list as returned by OS() method based on
        order of reliablity.

        reliablity is hardcoded as from:
            "SRVSVC","MS-RPC","NTP","CIFS","SNMP","TCP/IP",anything else
        sequential os results from the same "source" is ordered longest
        os string first.
        """
        order = {"SRVSVC": 6,
                 "MS-RPC": 5,
                 "NTP": 7,
                 "CIFS-TCP-139": 1,
                 "CIFS-TCP-445": 2,
                 "SNMP": 3,
                 "TCP/IP": 4}
        a_src = a[0].split()[0]
        b_src = b[0].split()[0]
        return cmp(order.get(a_src, 10), order.get(b_src, 10)) or \
               cmp(len(b[1]), len(a[1])) or cmp(a[0], b[0])

    def ServicePacks(self, short_name=False):
        """Returns a list of Windows Service Packs found installed. If no
        data is available, returns None. If parameter 'short_name' is
        True, results will have the common HKLM prefix stripped.
        """
        finding = self.lookupUniqFinding("105313")
        if not finding:
            return None
        if short_name:
            prefix = 'HKLM\\SOFTWARE\\Microsoft\\Updates\\'
            prefix_len = len(prefix)
            result = []
            for sp in finding.ExtractWindowsServicePacks():
                if sp.startswith(prefix):
                    result.append(sp[prefix_len:])
                else:
                    result.append(sp)
            return result
        else:
            return finding.ExtractWindowsServicePacks()

    def VirusScanner(self):
        """If a virus scanner was found running, returns a tuple with
        following fields:
        (Product, Product Version, Dat file Version, Last Update)
        if any piece of info is unknown, a None value will be in the tuple's field
        If no information is known or if the the host is not running a virus
        scanner, a None will be returned.
        """
        finding = self.lookupUniqFinding("105001")
        if not finding:
            return None
        return finding.ExtractVirusInfo_105001()

    def InstalledSoftware(self):
        """Returns a list of software packages installed, or
        None, if the required finding wasn't available.
        """
        finding = self.lookupUniqFinding("78014")
        if not finding:
            return None
        return finding.ExtractInstalledSoftware()

    def NetBIOSsharelist(self):
        """Get the NetBIOS shares list for the host
        """
        shares = set()
        for finding in itertools.chain(self.findings_by_id.get("70001", []),
                                       self.findings_by_id.get("70030", [])):
            for line in finding.Result().split('\n')[1:]:
                shares.add(line.split("\t")[0])
        shares = list(shares)
        shares.sort()
        return shares

    def NetBIOSLockoutPolicy(self):
        """Get the lockout policy for netbios host
        """
        finding = self.lookupUniqFinding("45028")
        maxfail = None
        attempts = None
        duration = None
        if finding:
            for row in finding.ResultTable(max_cols=2, coldelim=" - "):
                try:
                    (ltype, lock) = row
                except:
                    continue
                if "Maximum Failed" in ltype:
                    maxfail = lock.split()[0]
                if "Lockout Logon-Attempts" in ltype:
                    attempts = lock.split()[0]
                if "Lockout Duration" in ltype:
                    duration = lock.split()[0]
            return (maxfail, attempts, duration)
        return None

    def RPCprogramlist(self):
        """return a list of tuples for the rpc services running on the host

        tuples are of the form:
            (program, version, protocol, port, name)
        """
        results = []
        for finding in self.findings_by_id.get("9", []):
            for row in finding.ResultTable():
                results.append(tuple(row))
        return results

    def NetBIOSDomainTrustlist(self):
        """return a list of tuples for the Netbios trust
        relationships for the host

        tuples are of the form:
            (program, version, protocol, port, name)
        """
        trusts = []
        for finding in self.findings_by_id.get("45024", []):
            for row in finding.ResultTable(max_cols=1):
            #if re.search("Trusting Domains", row[0]):
            #continue
                if re.search("\$$", row[0]):
                    trusts.append(row[0].strip('$'))
        return trusts

    def NfsExportlist(self):
        """return a list of tuples for the nfs exports on the host

        QIDs = [ '66002', 66003' ]
        tuples are of the form:
            (export, network)
        """
        exports = []
        for finding in itertools.chain(self.findings_by_id.get("66002", []), self.findings_by_id.get("66003", [])):
            #for row in finding.ResultTable():
            for row in finding.nfsResultTable():
                exports.append(tuple(row))
        return exports


class QualysData:
    """Stores Qualys results data

    initialized with the filename of the Qualys.XML data file

    Public Attributes:
    'hosts'   dictionary of QualysHost instances, indexed by ip

    """

    def __init__(self, filename=None, ignorefile=None):
        self.log = logging.getLogger(self.__class__.__name__)
        self.tree = None
        self.headerkeys = {}
        self.hosts = {}
        self._vulns = {}
        self.OptionProfileTitle = None
        if ignorefile:
            self.log.info("Ignore IP file: %s", ignorefile)
        if filename:
            self.Load(filename, ignorefile)

    def __nonzero__(self):
        return bool(self.tree)

    def __len__(self):
        return len(self.hosts)

    def Load(self, filename, ignorefile=None):
        """ Load the Qualys Data from a passed in file """
        self.log.info("Loading %s into QualysData", `filename`)
        self.headerkeys = {}
        self.hosts = {}
        self.skip_ip_list = []
        self.tree = ElementTree.parse(filename)

        # take a file of IP addresses and add them to a list of addresses to skip
        if ignorefile:
            try:
                self.fIN = open(ignorefile, "r+")
                self.data = self.fIN.readline()
                while self.data:
                    # load each line into skip_ip_list, stripping the '\n' if it exists
                    self.skip_ip_list.append(self.data.rstrip())
                    self.data = self.fIN.readline()
                self.fIN.close()
                self.log.info("Ignoring %s IP addresses", len(self.skip_ip_list))
                self.log.debug("List of ignored IPs: %s", self.skip_ip_list)
            except Exception, e:
                self.log.info("Error loading ignore list: %s", e)
                pass

        header = self.tree.find("HEADER")
        for child in header.getchildren():
            if child.tag == "KEY":
                self.headerkeys[child.get("value")] = child.text
            elif child.tag == "OPTION_PROFILE":
                self.OptionProfileTitle = child.findtext("OPTION_PROFILE_TITLE")
        for ip_node in self.tree.findall("IP"):
            # API scans includes a "status" value for each
            # IP - up/down.
            if ip_node.get("status") == "down":
                self.log.debug("Skipping IP, %s, with 'down' status", ip_node.get("value"))
                continue
            #self.log.debug("Loading IP %s...", ip_node.get("value"))
            if ip_node.get("value") in self.skip_ip_list:
                self.log.debug("Skipping %s because it's in the do-not-load list", ip_node.get("value"))
                continue
            host = QualysHost(ip_node)
            ip = host.IP()
            if self.hosts.has_key(ip):
                self.log.warn("Duplicate IP node found for `%s`. " \
                              "Overwriting with later one", ip)
            self.hosts[ip] = host
            for vuln in host.FindingsList():
                # See docstring for QualysHost.FindingList()
                self._vulns.setdefault(vuln.Number(), []).append(vuln)

    def GetSeenCatValues(self):
        """ We dyamically store a list of cat values seen, return
        a list to the user """
        dummyv = QualysCat(node=None, type=None)
        return dummyv.GetCatValues()

    def GetFinding(self, ip, port, tag):
        """Return a finding node specified by params

        Parameters are:
            ip, as a string
            port, as a (PORT_NUMBER, PROTOCOL)
            tag, as a string (tag being equivalent to QID
        If specified ip, port, and/or tag does not exist, returns None
        """
        host = self.hosts.get(ip, None)
        if not host: return None
        # ZZZ: there has *got* to be a better way to do this...
        port = [p for p, names in host.Ports() \
                if (p.protocol == port[1].lower() and p.port == str(port[0])) or \
                   (p.value == port[0] and port[1] == '')]
        if not port: return None
        # For pseudo-services, more than 1 port may get returned
        for p in port:
            fnode = host.findings_by_port_id.get(p, {}).get(tag, None)
            if fnode:
                return fnode
        return None

    def Hosts(self, sorted=False, *deprecated_args, **deprecated_kwargs):
        """Return a list of the Hosts objects
        """
        if deprecated_args or deprecated_kwargs:
            raise DeprecationWarning("Hosts() no longer takes 'port' or " \
                                     "'vulnerable' arguments")
        hosts = self.hosts.values()
        if sorted:
            hosts.sort(cmp=SPAData.sortby.IP, key=lambda x: x.IP())
        return hosts

    def XMLSummary(self, qidslist, extra_attrs=""):
        """Print an XML summary of the data contained in this dataobj
        """
        vulns, servicenames = {}, {}
        xml = ['<qualysdata %s>' % extra_attrs]
        for host in self.Hosts():
            for port, services in host.Ports():
                servicenames.setdefault(str(port), set()).update(services)
                vulns.setdefault(str(port), {})
                for finding in host.Findings(portobj=port):
                    # sure, we overwrite earlier findings, but we don't care
                    # since one is as good as the other
                    vulns[str(port)][finding.Number()] = finding
        for port, services in servicenames.items():
            try:
                # skip service if not in findings.db,
                # aka qidslist
                x = qidslist[port]
            except:
                continue
            xml.append("""  <service port="%s">""" % port)
            for name in services:
                xml.append("<servicename><![CDATA[%s]]></servicename>" % name)
            for finding in vulns[port].values():
            # Don't include writeups for QIDs not in
                # findings.db
                if finding.Number() in qidslist[port]:
                    xml.append('<finding type="%s" qid="%s" severity="%s">' % (
                    finding.Type(), finding.Number(), finding.Severity()))
                    xml.append("""<title><![CDATA[%s]]></title>""" % finding.Title())
                    # ZZZ: Eventually these CDATA blocks should get replaced
                    # with invocations that properly convert the QualysMarkup.
                    xml.append("""<diagnosis><![CDATA[%s]]></diagnosis>""" % finding.Diagnosis())
                    xml.append("""<consequence><![CDATA[%s]]></consequence>""" % finding.Consequence())
                    xml.append("""<compliance><![CDATA[%s]]></compliance>""" % finding.Compliance_text())
                    xml.append("""<solution><![CDATA[%s]]></solution>""" % finding.Solution())
                    xml.append("""</finding>""")
                else:
                    self.log.warn("Skipped QID = %s", finding.Number())
            xml.append("""  </service>""")
        xml.append("""  </qualysdata>""")
        return "\n".join(xml)

    def FindingByNum(self, number):
        """Return a prototypical Finding object for specified QID.

        Be aware though, this finding is simply representative of a particular
        finding of that ID number. Some attributes/Methods of the returned object
        (such as Port(), Result(), ResultTable(), Banner() and more) are specific
        to a particular finding/port/host combination and shouldn't be evaluated
        from here.
        """
        vulns = self._vulns.get(number, [])
        if vulns:
            return vulns[0]
        return None

    def AllFindingsByNum(self, number):
        """Returns a sequence of all Findings for the specified QID
        """
        return self._vulns.get(number, [])

    def ListFindings(self):
        """Returns a list of the QID's found in this dataset
        """
        return self._vulns.keys()

    # Deprecated interfaces
    def Key(self, key):
        raise DeprecationWarning("Use headerkeys dictionary")

    def Keys(self, key):
        raise DeprecationWarning("Use headerkeys dictionary")

    def getHost(self, ip):
        raise DeprecationWarning("Use OBJECT.hosts.get(IP, None)")


# Deprecated Classes
class QualysHeaderKey:
    def __init__(self, *arg, **kwargs):
        raise DeprecationWarning("Use QualysData.headerkeys dictionary")


if __name__ == '__main__':
    import sys
    import os
    from optparse import OptionParser       # aka Optik

    # Command line is only provided for debugging it is not a supported
    # feature. All interaction should be through other modules

    # set up commandline arguments
    Progname = os.path.basename(sys.argv[0])
    Usage = "%prog [options] QualysFile.xml"
    optparser = OptionParser(usage=Usage, version="%prog: $Id: QualysData.py,v 1.26 2008/12/05 19:21:23 wam Exp $")
    optparser.add_option("-d", "--debug", dest="debug",
                         action="store_true", help="log debugging messages")
    (options, params) = optparser.parse_args()

    # set up logging environment
    root_log = logging.getLogger()          # grab the root logger
    root_log.setLevel((logging.INFO, logging.DEBUG)[options.debug == True])
    handler = logging.StreamHandler()
    # handler = logging.FileHandler(options.logfile)
    logformat = "%(name)s: %(levelname)s: %(message)s"
    handler.setFormatter(logging.Formatter(logformat))
    # logformat = "%(asctime)s %(levelname)s:%(name)s:%(message)s"
    #handler.setFormatter(logging.Formatter(logging.BASIC_FORMAT))
    root_log.addHandler(handler)
    log = logging.getLogger(Progname)

    for param in params:
        data = QualysData(param)

        # The following lines just print out all header keys
        # commented out after they were verified
        #
        #print "Header Key Values:"
        #for x in data.Keys():
        #	print "   ", x.Value(), "-", x.ValueData()

        print "Qualys Report stats for:", data.Key("TITLE"), "by", data.Key("USERNAME")
        print

        for host in data.Hosts():
            print host.IP(), host.Hostname()
            print host.Ports().__len__(), "Open Ports"
            print host.Ports(False)
            print "=" * 70
            #	print "Confirmed Vulnerabilities"
            #	for x in host.Vulns():
            #		print " ", x.ClassType(), "\t", x.Port(), "\t", x.Title()
            #	print "Potential Vulnerabilities"
            #	for x in host.PotentialVulns():
            #		print " ", x.ClassType(), "\t", x.Port(), "\t", x.Title()
            #	print "Information Gathered"
            #	for x in host.Infos():
            #		print " ", x.ClassType(), "\t", x.Port(), "\t", x.Title()
            #	print "Findings on 23t"
            #	for x in host.Findings("23t"):
            #		print " ", x.ClassType(), "\t", x.Port(), "\t", x.Title()
            #	print "tcp-ip Information"
            #	for x in host.Infos("tcp-ip"):
            #		print " ", x.ClassType(), "\t", x.Port(), "\t", x.Title()
            print

        print data.GetSeenCatValues()

