Writing Scanhandlers
====================

To write a scanhandler, you need:

- The command to invoke the virus scanner
- Example output
- A VM with the scanner installed, to test on
- Some malware urls to test with (test_malware.md contains some)


A scanhandler is a python module placed in socialscan/scanhandlers. It is automatically imported
by socialscan depending on a config value; The module name should be the same as the name of the virus
scanner it provides an interface to.

The module must contain two functions:

scan(filename)
**************

Scan a file and return a tuple of (malicious, siginfo).
The first element of the tuple is a boolean value, true if the file is determined to be malicious
by the scanner. The second element is a socialscan.util.SigInfo namedtuple object.


getSigInfo()
************

get the current siginfo of the scanner. should return the current signature information
of the scanner, as of no more than an hour ago, in the form of a socialscan.util.SigInfo object.

Many of the scanners only provide this in the output of the scan code; the strategy that I
have been using to deal with this is to cache the sigversion from the scan output, and then
if it is not cached when getSigInfo is called or is more than an hour old, scan an empty temporary file.


#### For information on socialscan.util.SigInfo, see the docstring of SigInfo in [socialscan/util.py](epydoc/socialscan.util-pysrc.html#SigInfo)
