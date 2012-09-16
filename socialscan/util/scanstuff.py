
'''
from socialscan import scanhandlers
from socialscan.config import loadDefaultConfig
from socialscan.db import setupDB
from socialscan.scanning import ScannableRequest
from socialscan.model import Peer
from socialscan import log
import json
import sys'''

urls = '''
http://malwarerepo.trustproxy.org/contents/b8ecd89afdd09c840ced54258da68e2fc4d6a0478caaa6679ce64e57a5b9437b <all>
http://malwarerepo.trustproxy.org/contents/398d82f9419304fd4dd25491a55db6cf6d6f89e39782447efc6e1ae8c15346b5 <all>
http://malwarerepo.trustproxy.org/contents/ba75145dfbee681496b20625ee24811ecdeca6a86f23a36474d542800dacbc1b <none>
http://malwarerepo.trustproxy.org/contents/bbb3c52f918c099ffdb128c978e764d102bd984e4d6061fd46ce3a01ed76e72f <all>
http://malwarerepo.trustproxy.org/contents/3c1b8e661c3ecc66832756c67b1b859b53181568730a21d2b10c5a1f2fb99d0c <all>
http://malwarerepo.trustproxy.org/contents/3f18f29699a2cdf0813da42f76acd252876195b88ab8a704afcc0e9dbffaabbc <all>
http://malwarerepo.trustproxy.org/contents/3fa00398eac8e6f5a2eda6994831af370f246a2d0615f020e98384a78ba2d19c Kaspersky Emsisoft
http://malwarerepo.trustproxy.org/contents/bfb18101eccb2ff33e575b7c664b7c471dcf95dc7689dc95336a64fe3b85c2fa <all>
http://malwarerepo.trustproxy.org/contents/4051a2fe420b5dfd48bf016df9cf0b8f078083ff3a667f8409c9360b0d86dd09 Kaspersky Emsisoft
http://malwarerepo.trustproxy.org/contents/c08326d13543bf1767a7b13b6fd93133f101c90007941d3a2426d0e386ee03da Emsisoft
http://malwarerepo.trustproxy.org/contents/c0ccff2a79ccb567a766308add7ca19072eaee523b799575b6c8b55f33dd6437 <none>
http://malwarerepo.trustproxy.org/contents/7bf4458e1822c15174c67c7646200ca5c8af44a525ff1bd66ac196f1c94b7e7a <none>
http://malwarerepo.trustproxy.org/contents/fc754edc69cd9101ee1a1be07405299120b3d105ed60553ad5341e1c33cad0ae <all>
http://malwarerepo.trustproxy.org/contents/fc4253fe50d2568ddc852b8dff564c4116b619e847cb45346aff55f5716969b7 <all>
http://malwarerepo.trustproxy.org/contents/7d585766c17239d64b17a23e6740fa46143a860a82fab80438dc3eb0fafbf795 McAfee Emsisoft
http://malwarerepo.trustproxy.org/contents/7d480532ba1c7847073c8bfff6c13e6d24cdfff1012c41ebb937408e053bbf7f <none listed>
http://malwarerepo.trustproxy.org/contents/fd8fbc68a1b2b352232d5a506f952c7f9ed9826ed519898ed66450d1af8563a4 Kaspersky
http://malwarerepo.trustproxy.org/contents/7fecf9be3c0b1134d755007415b946c98aba773d75b7231ac75b6445e8e311e8 <all>
http://malwarerepo.trustproxy.org/contents/fdb24a321bdfd887db74b16c1ec236f1a41de3eaf45601e9217ee158b96e5d8c Kaspersky Emsisoft
http://malwarerepo.trustproxy.org/contents/fed3ccee3bd8ce3a71c10f408fb86a59fc10ea6e70bfc68d4f79bf587c5310c5 Emsisoft
http://malwarerepo.trustproxy.org/contents/fe55b04fbc3a045f6baaaee4a74e02ade74c532a0138d2136b220e434bd5ad04 <all>
http://malwarerepo.trustproxy.org/contents/7f1ec741c9d791b01bbda1205ceb8928af70d17e1f32c9792f68cf885ec3051b McAfee Emsisoft
'''.split("\n")
strippedurls = []

for url in urls:
    if not url:
        continue
    strippedurls.append(url.split()[0])
urls = set(strippedurls)
print urls

'''
class Derp(object):
    def log(self, message):
        sys.stdout.write(json.loads(message))
        sys.stdout.flush()

log.stdoutlogger = Derp()



def main():
    config = loadDefaultConfig()
    session, engine = setupDB("sqlite:///:memory:")
    logger = log.Logger("scanthingy")

    owner = Peer("owner", "owner", "owner")
    config.owner = owner
    session.add(owner)
    session.commit()

    discovered = set()

    for url in urls:
        if not url:
            logger.log("skipping url: %r" % url)
            continue
        request = ScannableRequest(config, session, url)
        scan = request.localscan
        logger.log(repr(scan))
        if scan.malicious:
            discovered.add(url)

    print discovered



if __name__ == "__main__":
    main()
'''