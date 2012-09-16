Architecture of the system
==========================

*Note: this is not intended to replace matt's documentation explaining the ideas behind
socialscan, but rather the overall architecture of how they have been implemented.*


Components
----------

The main components of the system are initialized from main.py. They are, in approximate
order of initialization:

#### Config

The config uses an attribute-proxy system to allow very simple access of config attributes - 
for instance, the config entry "localpeer" in the section "general" is accessed as
config.general.localpeer. The config is designed such that generated config can be assigned
to attributes on the config object easily; for instance, config.owner is created at startup.

For more information, see [docs/config.md](config.html) and the documentation in
[socialscan/config.py](epydoc/socialscan.config-module.html).

#### Database

The database is constructed using SQLAlchemy's declarative mode. For information about the
tables, see the docstrings in socialscan/model.py.

As part of the database initialization, the "localpeer" config option is used to retrieve a
peer from the database and put it in config.owner. This peer object is then used in most of the
database tables (with the notable exceptions of "peers" and "socialrelationship") to identify
which peer owns a url; this is intended for use when multiple socialscan instances share the same
database, for instance when a shared mysql server is used in an office or in the case of the
research experiments, when all the results from different peers are merged into a single database.

#### DigestManager

the DigestManager runs all looping-interval tasks in the system and manages the adding scans to
scandigests and sharing and retrieving scandigests with other peers.

For more information on the digest manager, see
[socialscan/sdmanager.py](epydoc/socialscan.sdmanager-module.html)'s code and docstrings.

#### HTTP Server and RPC

The http server is a twisted.web server used for XMLRPC and sharing of digests between peers.
It also hosts the (currently static) url_malicious.html file, such that a url to
`http://localhost:someport/malicious` can be returned to show an error message to the user when
using squid.

The http server is entirely constructed in main.py, and the RPC commands and their documentation
can be found in [socialscan/rpccommands.py](epydoc/socialscan.sdmanager-module.html)'s.

#### Core

The "Core" is the actual request handler which recieves requests to get information about urls and
returns a decision on what should be done about the url. To allow main processing to occur in the
twisted process, a client/server system is used; the server is run from main.py, and the clients are
run from redirector.py.

The server portion of this system loads a decisionmanager module from socialscan/decisionhandlers/
based on the appropriate config option. For information on how those work, please see
docs/writing_decisionhandlers.md. For more information on how the core works, see the docstrings
of [socialscan/core.py](epydoc/socialscan.core-module.html).

#### Scanhandlers

The scanhandler is a module loaded dynamically from socialscan/scanhandlers/ and called indirectly
through socialscan.scanning.ScannableRequest by DigestManager and Core when files must be scanned.
For more information, see [docs/witing_scanhandlers.md](writing_scanhandlers.html).


### Communication between components ###
****************************************

The components of the system communicate in two main ways: by calling methods on each other's objects,
and in the case of digestmanager, some components put requests into the queue in the database which
are then handled by digestmanager in order of how close the social distance is to the peer which caused
that request to happen.
