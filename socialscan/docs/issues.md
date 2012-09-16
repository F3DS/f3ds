this is a file where I have been sticking issues as I think of them. Feel free to move this data around.

    -- C. horne

config
******

- the share urls are stored in the database; that would be a serious problem if the ip changed
- scanning.max_active_distance probably should be in the core section

scan digests
************

- siginfo for each digest is stored in two places; the database and the serialized digest file

sdmanager
*********

- retrieveScanDigest only tries once; if that try fails, the request is considered a failure
- no sorting by time is done in the handling of requests; may or may not be important
- no shutdown handling; if the system is shut down, the most recent scan digest might not be saved to disk
   (note that the digest is saved regularly to deal with this potential issue)
- "ourdigest" and "ourdigestfile" are unsatisfactory names, due to being unclear on how they differ (the first is the digest data, the second is the database metadata)
- digest usefulness tracking is rather simplistic, needs an upgrade

scanning
********

- files downloaded are not deleted

general
*******

- line wrapping is inconsistent
- lots of code is never used; many things are not consistently used; due to changing plans often as ideas are created
- peer discovery system to allow automatic configuration of peer ips in the databases is needed;
   probably a server on coredev which the system offers .. stuff
