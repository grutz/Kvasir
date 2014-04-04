# -*- coding: utf-8 -*-

__version__ = "1.0"

"""
##--------------------------------------#
## Kvasir
##
## (c) 2010-2014 Cisco Systems, Inc.
##
## CORE Impact Utilities for Kvasir
##
## Author: Kurt Grutzmacher <kgrutzma@cisco.com>
##--------------------------------------#
"""

from log import log
import logging


##----------------------------------------------------------------------------

def process_exploits(filename=None):
    """
    Process CORE Impact exported exploits file into the database.

    To generate the exploits file, create the following .sql file:

        SET NOCOUNT ON
        USE corevuln

        SELECT ('CVE-' + CAST(v.vuln_ncve_year as VARCHAR) + '-' + CAST(v.vuln_ncve_number as VARCHAR)) as 'CVE',
        v.vuln_description as 'Vulnerability Description', e.expl_id as 'Impact Exploit ID',
        e.expl_name as 'Impact Exploit Name', e.expl_date_create as 'Exploit Created'
        FROM exploit e INNER JOIN expl_vuln ev
            ON e.expl_id = ev.exvu_expl_id INNER JOIN vulnerability v
            ON ev.exvu_vuln_id = v.vuln_id
        ORDER BY v.vuln_ncve_year ASC, v.vuln_ncve_number ASC

    Execute the sql file replacing "hostname" with your localhost or database hostname

        sqlcmd -S "{hostname}\impact" -i core_impact_exploits.sql -o core_impact_exploits.txt -W -s "|" -m1 -h-1
    """
    if filename is None:
        log("No filename provided")

    log("Processing %s ..." % (filename))

    import csv
    from general import cve_fixup
    from exploits import add_exploit, connect_exploits
    counter = 0
    exploits_added = []

    try:
        csvfile = open(filename, 'rb')
    except IOError, e:
        log("Error opening %s: %s" % (filename, e), logging.ERROR)
        return

    try:
        reader = csv.reader(csvfile, delimiter=',')
    except IOError, e:
        log("Error reading %s: %s" % (csvfile, e), logging.ERROR)
        return

    for line in reader:
        # CVE | Description | Number | Exploit Name | Date
        if len(line) != 5:
            log("Not enough values in line", logging.WARN)
            continue

        cve = cve_fixup(line[0])
        if not cve:
            log("Error with CVE: " % line, logging.WARN)
            continue

        f_name = line[2]
        f_title = line[3]
        f_description = line[1]
        f_source = 'core'
        f_rank = 'average'              # rank is not defined in xml, default to average
        f_level = 'Intermediate'        # level is not defined in xml, default to Intermediate

        res = add_exploit(
            cve=cve,
            f_name=f_name,
            f_title=f_title,
            f_description=f_description,
            f_source=f_source,
            f_rank=f_rank,
            f_level=f_level,
        )
        if res > 0:
            counter += 1
        else:
            log("Error importing exploit: %s (%s)" % (f_title, f_name), logging.ERROR)

    connect_exploits()
    log("%d exploits added/updated" % (counter))
    return True

##----------------------------------------------------------------------------
