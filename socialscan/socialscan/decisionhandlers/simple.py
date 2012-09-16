from socialscan.util import Safety, WeightedAverager

def process(core, request):
    core.logger.log("determining confidence for url %r" % request.url)
    maliciousness = WeightedAverager()

    safetyWeights = {
        Safety.malicious: 1.0,
        Safety.possibly_malicious: 0.2,
        Safety.possibly_benign: -0.2,
        Safety.benign: -1.0
    }

    request.retrieveHeaders()  # try to get the filesize, if possible via the headers

    def resolver():
        core.logger.log("searching digests")
        for scan in request.digestscans():
            maliciousness.add(safetyWeights[scan.safety], 0.8)
        yield
        core.logger.log("searching previous scans")
        for scan in request.getRelevantScans():
            maliciousness.add(safetyWeights[scan.safety])
        yield
        core.logger.log("performing active scan requests")
        request.requestActiveScans()
        yield
        core.logger.log("performing local scan")
        maliciousness.add(safetyWeights[request.localscan.safety])

    for pause in resolver():
        if abs(maliciousness.average) > core.confidence_threshold:
            break

    core.logger.log("average: %f - scan" % maliciousness.average)
    return Safety(abs(maliciousness.average) > core.confidence_threshold,
                  maliciousness.average > 0)
