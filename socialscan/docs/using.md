Using the system
================

### Dependencies:

- Twisted (tested on 10.1.0 and 11.0)
- pybloom (on pypi)
- pywin32 (soft dependency of twisted, only required on windows)
- squid (if you want to use squid)
- sqlalchemy >= 0.7

Setup
-----

Before the system can be run, the peers must be set up. This requires things:

1. at least one peer in the database, to provide the local peer indentification
2. the config file to point to this peer's name
3. Optionally, any other peers that should be communicated with

To generate a list of peers for testing and set up the config file, you can use the testutils.py
script. Run it as `python testutils.py makepeers [IP...]`. If the IP "127.0.0.1" is provided to
makepeers, then the ip assigned to the local peer will be 127.0.0.1. Otherwise, it will attempt
to use ifconfig or ipconfig (depending if it is run on windows or linux) to determine the local
IP, so that it sends the correct "return address" when sending requests to peers.

The reason for the local peer is that the peers database is intended to store many peers, and the
config will point to the one that represents "this computer".

For more information about this, see [docs/config.md](config.html).

Running with squid
------------------

The system is made up of two components which must be started: socialscan, and squid. Socialscan
can be started simply by running main.py. Squid must first be configured to use redirector.py
as a squid redirector. The configuration used to run the windows VMs can be found in docs/squid.conf.
The relevant lines are 85-88.

To use, simply support anything that supports a squid protocol (I believe squid
supports SOCKSv5) at the relevant port squid opens.

On the cygwin environment on the windows VMs, ctrl+c does not properly stop background processes
(ie, squid), so a master.sh is provided for the cygwin environment which will start both squid
and main.py, and then kill them through windows's kill mechanism when enter is pressed.


Running without squid
---------------------

You can also use redirector.py directly. It follows the squid redirector protocol on stdin/stdout:
http://wiki.squid-cache.org/Features/Redirectors - feed it a url, get either a url or an empty line
in response. at the moment, the "empty line" indicates a safe url, while returning the url to an
"access denied" page indicates unsafe.

note that since only the url is being used by socialscan (subject to change), redirector.py will
accept a line with nothing but a url on it.

You can also access the socialscan core using the protocol redirector.py and core.py provide. See
the documentation of core.py in [docs/epydoc/socialscan.core-module.html](epydoc/socialscan.core-module.html) for details.
