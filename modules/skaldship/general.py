# encoding: utf-8

__version__ = "1.0"

"""
##--------------------------------------#
## Kvasir
##
## (c) 2010-2013 Cisco Systems, Inc.
##
## General utility module
##
## Author: Kurt Grutzmacher <kgrutzma@cisco.com>
##--------------------------------------#
"""

import logging
logger = logging.getLogger("web2py.app.kvasir")


##-------------------------------------------------------------------------

def severity_mapping(sevnum='1', totype='color'):
    """
    Convert a severity number (1-10) to a name (Info, Low, Medium, High)
    or color
    """
    severitymap = [ (0, 'Informational', 'grey'),
                    (1, 'Informational', 'grey'),
                    (2, 'Informational', 'grey'),
                    (3, 'Low', 'green'),
                    (4, 'Low', 'green'),
                    (5, 'Medium', 'orange'),
                    (6, 'Medium', 'orange'),
                    (7, 'Medium', 'orange'),
                    (8, 'High', 'red'),
                    (9, 'High', 'red'),
                    (10, 'High', 'red'),
                  ]
    return severitymap[int(sevnum)]

##-------------------------------------------------------------------------

def vulntype_mapping(vulntype='exploited'):
    """
    Converts a vulnerability type to a color.

    >>> vulntype_mapping('potential')
    'grey'

    >>> vulntype_mapping('vulnerable-version')
    'green'

    >>> vulntype_mapping('vulnerable-exploited')
    'orange'

    >>> vulntype_mapping('exploited')
    'red'

    >>> vulntype_mapping('doesnotexist')
    'grey'
    """
    vulnmap = {
        'potential': 'grey',
        'vulnerable-version': 'green',
        'vulnerable-exploited': 'orange',
        'exploited': 'red',
    }

    if vulntype in vulnmap:
        mapping = vulnmap[vulntype]
    else:
        mapping = 'grey'

    return mapping


##-------------------------------------------------------------------------

def cvss_metrics(record):
    """
    Converts a record's cvss fields to a string
    """
    if record is None:
        return "NO RECORD SUBMITTED"

    return "AV:%s/AC:%s/Au:%s/C:%s/I:%s/A:%s" % (record.f_cvss_av,
                                                 record.f_cvss_ac,
                                                 record.f_cvss_au,
                                                 record.f_cvss_c,
                                                 record.f_cvss_i,
                                                 record.f_cvss_a)


##-------------------------------------------------------------------------

def vuln_data(vuln, html=True, full=True):
    """
    Returns a dict of all useful vulnerability data from a record,
    including printable cvss, references and exploits
    """

    from gluon.contrib.markmin.markmin2html import markmin2html
    from gluon import current

    db = current.globalenv['db']
    cache = current.globalenv['cache']

    if type(vuln) is type(int):
        vuln = db.t_vulndata[vuln]

    if vuln is None:
        return "NO RECORD SUBMITTED"

    if current.globalenv['settings'].use_cvss:
        severity = vuln.f_cvss_score
    else:
        severity = vuln.f_severity

    if full:
        # full == True means all information including references and exploits
        refdata = []
        for ref in db(db.t_vuln_references.f_vulndata_id == vuln.id).select(cache=(cache.ram, 300)):
            refdata.append([ db.t_vuln_refs[ref.f_vuln_ref_id].f_source,
                             db.t_vuln_refs[ref.f_vuln_ref_id].f_text ])

        expdata = []
        for exp_ref in db(db.t_exploit_references.f_vulndata_id == vuln.id).select(cache=(cache.ram, 300)):
            exp = db.t_exploits[exp_ref.id]
            if exp is not None:
                expdata.append([exp.f_name,
                                exp.f_title,
                                markmin2html(exp.f_description),
                                exp.f_source,
                                exp.f_rank,
                                exp.f_level
                              ])

        return (vuln.id,
                vuln.f_vulnid,
                vuln.f_title,
                severity_mapping(severity),
                vuln.f_cvss_score,
                cvss_metrics(vuln),
                markmin2html(vuln.f_description),
                markmin2html(vuln.f_solution),
                vuln.f_pci_sev,
                refdata,
                expdata,
               )

    else:
        # full = False means just the header info (vulnid, title, sevs, cvss)
        return (vuln.id,
                vuln.f_vulnid,
                vuln.f_title,
                severity_mapping(severity),
                vuln.f_cvss_score,
                cvss_metrics(vuln),
                vuln.f_pci_sev,
               )


##-------------------------------------------------------------------------

def get_oreally_404(rfolder):
    """
    Picks a random oreally image and returns the filename
    """
    import os
    from random import choice
    imgdir = os.path.join(rfolder, 'static/images/oreally')
    if os.path.isdir(imgdir):
        files = os.listdir(imgdir)
        return choice(files)


##-------------------------------------------------------------------------

def html_to_markmin(html):
    """
    Replace HTML with Markmin, converting unicode to references first

    >>> html_to_markmin('<p class="foo"><b>Bold</b><i>Italics</i><ol><li>Item 1</li><li><a href="http://kvasir.io">Kvasir</a></li></ol><br>')
    "**Bold**''Italics''\\n- Item 1\\n- [[Kvasir http://kvasir.io]]\\n\\n\\n\\n"

    >>> html_to_markmin(u'<p>asdfsadf</p>')
    'asdfsadf\\n\\n'

    >>> html_to_markmin(u'<p>\ufffdq\ufffd</p>')
    '\xef\xbf\xbdq\xef\xbf\xbd\\n\\n'

    >>> html_to_markmin('[[ a link http://url.com]]')
    '[[a link http://url.com]]'
    """
    if html is None:
        return ''
    from gluon.html import markmin_serializer, TAG
    html = html.encode('ascii', 'xmlcharrefreplace')    # cleanup unicode
    html = TAG(html).flatten(markmin_serializer)        # turn to markmin
    html = html.replace('[[ ', '[[')                      # fix bad url
    html = html.replace(' ]]', ']]')                      # fix bad url
    return html


##-------------------------------------------------------------------------

def check_datadir(folder=None):
    """
    Checks to see if data/ folder and sub-folders exist. Creates them if not.
    """
    if not folder:
        return False

    import os
    datadir = os.path.join(folder, 'data')
    if not os.path.exists(datadir):
        logger.info("Creating data directories in %s..." % datadir)
        os.mkdir(datadir, 0775)

    for dirname in [
        'passwords', 'passwords/unix', 'passwords/win', 'passwords/other', 'passwords/misc',
        'db', 'db/oracle', 'db/mysql', 'db/mssql', 'db/psql', 'db/other', 'stats',
        'screenshots', 'scanfiles', 'configs', 'misc', 'rpcclient', 'session-logs', 'backups'
    ]:
        d = os.path.join(datadir, dirname)
        if not os.path.exists(d):
            os.mkdir(d, 0755)

    return True


##-------------------------------------------------------------------------

def exploitdb_update(indexfile):
    """
    Update the t_exploitdb table
    """
    if not indexfile:
        return "No file sent to process"

    import csv
    from gluon import current
    db = current.globalenv['db']

    db.t_exploitdb.truncate()
    db.commit()

    count = 0
    reader = csv.DictReader(open(indexfile, 'rb'), delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
    for line in reader:
        db.t_exploitdb.insert(
            f_eid=line['id'],
            f_file=line['file'],
            f_description=line['description'],
            f_date=line['date'],
            f_author=line['author'],
            f_platform=line['platform'],
            f_type=line['type'],
            f_port=line['port'],
        )
        count += 1

    db.commit()
    if db(db.t_exploitdb).count() == 0:
        message = 'Unable to load data'
    else:
        message = 'Load complete: %s records created' % (count)

    return message


##-------------------------------------------------------------------------

def cve_fixup(cve):
    """
    Fix a provided CVE to ensure it meets CVE standards (CVE-YYYY-ZZZZ)

    >>> cve_fixup(None)

    >>> cve_fixup('CVE-12345-1234567')

    >>> cve_fixup('cep-1000-1234')

    >>> cve_fixup('cve-2001-1234567')
    'CVE-2001-1234567'

    >>> cve_fixup('cve-1999-1234')
    'CVE-1999-1234'

    >>> cve_fixup('1999-1234')
    'CVE-1999-1234'

    >>> cve_fixup('CVE-1999-123')
    'CVE-1999-0123'

    """
    if not isinstance(cve, (str, unicode)):
        return None

    import re
    cve_re = re.compile("CVE-\d{4}-\d{4,7}$")

    # some basic 'fixups'
    cve = cve.upper()
    cve = cve.strip()
    if not cve.startswith('CVE-'):
        cve = "CVE-%s" % (cve)

    while not cve_re.match(cve):
        # remove any duplicate --
        cve = re.sub('\-+', '-', cve)
        cve = re.sub('(CPE\-)+', 'CPE-', cve)

        # try some fixes until we run out
        if cve.count('-') == 2:
            # we have the requisite dashes, lets figure out numerical count and can we fix it?
            (nom, yr, numbr) = cve.split('-')[0:3]
            if len(yr) < 4:
                yr = yr.zfill(4)
            if len(numbr) < 4:
                numbr = numbr.zfill(4)
            cve = '-'.join([nom, yr, numbr])
            if not cve_re.match(cve):
                # still not good, lets skeedaddle
                logger.warn('Couldnt fix %s' % (cve))
                return None

        elif cve.count('CVE-') > 1:
            # multiple CVE- strings:
            pass

        elif cve_re.match(cve):
            # must be next to last
            break

        else:
            # we can't fix it
            logger.warn('Invalid CVE: %s' % (cve))
            return None

    return cve


##-------------------------------------------------------------------------

if __name__ == "__main__":
    import doctest
    doctest.testmod()
