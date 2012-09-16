from socialscan.util import Safety
from socialscan.model import Scan

def process(core, request):
    core.logger.log("determining confidence for url %r" % request.url)
    confident = False
    malicious = False
    core.logger.log('searching local scans')
    scan = request.localscan
    if scan:
        confident = True
        core.logger.log('got local scan')
        if scan.safety == Safety.malicious:
            malicious = True
            core.logger.log('file was deemed malicious by scanner')
    return Safety(confident, malicious)

