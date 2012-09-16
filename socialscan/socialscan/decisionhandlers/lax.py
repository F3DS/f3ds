"""
Lax: Only require a single result, local or remote (within a certain max
socialdistance), with a signature set updated in the last 10 days. A
positive (malicious) will block the object.
"""

# Standard Python modules
import time

# Our modules
from socialscan.util import Safety, update_counts

def process(core, request):
	
    core.logger.log("determining confidence for url %r" % request.url)
    found = 0
    malicious = 0

    # TODO: Verify algorithm:
    # Check for result in digests, if found, use.
    # Otherwise, if no scans exist, request them.
    # Look for result in scans, if not found use local scan.
    core.logger.log('searching digests')
    for ds in request.digestscans():
        found, malicious = update_counts(found, malicious, ds,
                                         days=core.config.core.signature_age)
        if malicious >= 1:
            break
    scans = request.getRelevantScans()
    if not scans:
        core.logger.log("performing active scan requests")
        request.requestActiveScans()
        core.logger.log('giving peers time to respond')
        # TODO: get sleep amount from config.  The current amount is based
        # on being greater than the response time from one host with a
        # particular AV product, for a particular file, for which getting
        # the hash failed, and being less than 1 second.
        time.sleep(0.92)
    core.logger.log('checking scans')
    scans = request.getRelevantScans()
    for scan in scans:
        found, malicious = update_counts(found, malicious, scan,
                                         days=core.config.core.signature_age)
        if malicious >= 1:
            break
    if not found > 0:
        core.logger.log('performing local scan')
        found, malicious = update_counts(found, malicious, request.localscan,
                                         days=core.config.core.signature_age)

    return Safety (found > 0, malicious >= 1)
