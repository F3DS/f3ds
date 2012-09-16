"""
Paranoid: Require a result from X distinct scanners, with
a signature set updated in the last Y days. Any single
positive (malicious) result will block the object.
"""
# Standard Python modules
from datetime import datetime
import time

# Our modules
from socialscan.model import Scan
from socialscan.util import Safety, paranoid_update_counts

def process(core, request):
    core.logger.log('using paranoid decision handler')
    core.logger.log('determining confidence for url %r' % request.url)
    found = 0
    confident = False
    malicious = 0
    max_days = int(core.config.core.signature_age)
    required = int(core.confidence_threshold)
    scans_to_consider = []

    def evaluate_scans(required, scans, max_days):
        """
        If all the results are in, and there are no malicious, it is benign.
        Otherwise, if any one result indicates malicious, call it malicious.
        Lastly, if not all the results are in, but so far it is benign, keep gathering
        evidence, but call it malicious in case of timeout expiring.
        """
        found, malicious = paranoid_update_counts(scans, days=max_days)
        msg = 'confident? required: %d, found: %d, malicious: %d'
        core.logger.log(msg % (required, found, malicious))
        confident = found >= required
        malicious = malicious > 0
        if malicious:
            confident = True
        if not confident:
            malicious = True
        return confident, malicious

    def resolver():
        scans = request.getRelevantActiveScans()
        core.logger.log('checking %d scans' % len(scans))
        for scan in scans:
            scans_to_consider.append(scan)
        yield
        digestscans = request.digestscans()
        core.logger.log('checking %d digestscans' % len(digestscans))
        for scan in digestscans:
            scans_to_consider.append(scan)
        yield
        core.logger.log('performing active scan requests')
        request.requestActiveScans()
        core.logger.log('checking local scan')
        scans_to_consider.append(request.localscan)
        yield # To let evaluate_scans run with local scan results

    for pause in resolver():
        confident, malicious = evaluate_scans(required, scans_to_consider, max_days)
        if confident:
            break
    return Safety (confident, malicious)

