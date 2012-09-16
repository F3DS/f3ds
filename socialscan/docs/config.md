Config Options
==============

Config goes in socialscan.config. Each config option that you can place in socialscan.config
has an equivalent default in socialscan.defaults.config. Both of these files are ini format,
parsed by python's ConfigParser. The defaults are intended to be fairly sane;
The only absolutely required config option that you must set is general.localpeer.

Config options will be identified in this document either "fully qualified" in the form of
"sectionname.optionname", or "contextually" in the form of simply "optionname" (referring to
config options in the same section).

Section: general
----------------

### localpeer

This config option is used to indicate the name of the peer which should be used as the
"local peer" or "owner". for more information, see the database section of [docs/architecture.md](architecture.html).

### debug

a True or False value indicating whether debug should be enabled; currently mostly unused.

Section: core
-------------

### timeout

Indicates how long the system should wait before cancelling handling of a request and returning
a "best guess in available time". Is an integer value representing number of seconds.

### confidence_threshold

A value used by some decision handlers as a threshold to determine when confidence has been reached.

### decision_handler

The decision handler which should be loaded and used in Core. The name provided here will be used
as the module name to load from socialscan.decisionhandlers.MODULENAMEHERE - for instance, if
foo is provided here, then the module socialscan.decisionhandlers.foo
(socialscan/decisionhandlers/foo.py) will be loaded.

Section: database
-----------------

### url

This is the only option from this section that is directly accessed by the code; It is the
sqlalchemy URL that indicates what database should be used. From the sqlalchemy documentation:

    The string form of the URL is dialect+driver://user:password@host/dbname[?key=value..],
    where dialect is a database name such as mysql, oracle, postgresql, etc., and driver the
    name of a DBAPI, such as psycopg2, pyodbc, cx_oracle, etc.

For information on how to connect to a specific database, see the sqlalchemy documentation for that
database. The default provided by socialscan.defaults.config is `sqlite:///database.db`, which should
be sufficient for most needs (including those of the research experiments.)


Section: sdmanager
------------------

### share_location

the format string used when determining where to store a scan digest in order to share it (ie, for
locally created digests). the {uuid} format will be replaced with the uuid of the scan digest.

### share_url

the url sent to other peers when sharing a scan digest. {bindhost} will be replaced with
sharing.bindhost, {port} will be replaced with sharing.port, and {uuid} will be replaced with the
digest's uuid.

### storage_location

the format string used when determining where to store a scan digest in order to save it for later
(ie, for digests retrieved from other peers). the {uuid} format will be replaced with the local uuid
of the scan digest.

### loadlimit

The maximum number of digests to keep in memory at one time.

### maxcapacity

The maximum number of scans to put into a locally created scan digest.

### include_content

a True or False value indicating whether to include the sha256 sum of the file's content when creating
the scan digest. This is False by default.

### digest_distance

The maximum socialdistance to peers to share digests with.

### updateoursd_interval

the time interval in seconds to update our local scan digest with any new scans that have occured,
and possibly create a new scandigest and share the old one to peers.

### retrievesd_interval

the time interval in seconds to retrieve a scan digest that a peer has offered us.

### activescan_interval

the time interval in seconds to perform an active scan request sent from a peer.

### redemption_hours

the time interval in hours to update the percieved social distances of relationships

### redemption_amount

the amount to blend over to the original relationship distance

Section: sharing
----------------

### bindhost

The host to which to bind for the sharing http server. Should be changed from the default of
127.0.0.1 if sharing with actual peers.

### port

the port on which to host the sharing server. Defaults to 8123, should probably not be changed.


Section: scanning
-----------------

### max_active_distance

The maximum socialdistance to peers to send active scan requests to. May be ignored or overridden by
a decisionhandler.

### download_location

Directory to store files downloaded in before scanning them.

### scan_handler

The scan handler to use to scan files. Defaults to "dummy", which is a simply fake scanhandler which
searches files for lines starting with "evil". Scanhandlers are loaded in the same way as the
core.decision_handler is, but for socialscan.scanhandlers instead of socialscan.decisionhandlers.

*Note that there are not currently any real scanhandlers which will work on linux or mac, via wine
or otherwise.*

### _core_port

the port to use for redirector/core communication. Doesn't matter much what this is set to, so long
as it does not conflict with anything on the system.
