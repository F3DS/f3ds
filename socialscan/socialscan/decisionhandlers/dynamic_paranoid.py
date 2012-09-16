"""
Dynamic paranoid: Require a result from X distinct scanners, with
a signature set updated in the last Y days. Any single
positive (malicious) result will block the object.

X decreases inversely with the log of the age of the object in days.

"""
# Standard Python modules
from datetime import datetime
import math
import time

# Our modules
from socialscan.decisionhandlers.paranoid import process as normal_process
from socialscan.model import Scan
from socialscan.util import Safety, paranoid_update_counts

def process(core, request):
    core.logger.log('using dynamic paranoid decision handler')
    core.logger.log('determining confidence for url %r' % request.url)
    age_in_days = (datetime.now() - request.age).total_seconds() / (24.0 * 3600.0)
    freshness_limit = float(core.config.core.freshness_limit)
    core.confidence_threshold = math.ceil(1/math.log(max(freshness_limit, age_in_days), 10))
    msg = 'age in days: %s, freshness_limit: %s, confidence_threshold: %s'
    core.logger.log(msg % (age_in_days, freshness_limit, core.confidence_threshold))

    return normal_process(core, request)

