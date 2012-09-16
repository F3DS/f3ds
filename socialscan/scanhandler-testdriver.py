
import argparse
import os
import glob

from socialscan import scanhandlers

parser = argparse.ArgumentParser(description='Scan a file based on the available scanners.')
parser.add_argument('scanner', help='which scanner will be used')
parser.add_argument('file_to_scan', help='The file that will be scanned')


def main(args):

    try:
        handler = scanhandlers.get(args.scanner)
    except ImportError:
        print "no such scanhandler!"
        print "available scanhandlers:"
        theglob = os.path.join(os.path.dirname(__file__), "socialscan/scanhandlers/*.py")
        for filename in glob.glob(theglob):
            filename = os.path.basename(filename)
            filename = filename.replace(".py", "")
            if filename == "__init__":
                continue
            print "\t", filename
        return


    print "Scanning %s with scanhandler %s" % (args.file_to_scan, args.scanner)
    malicious, cursiginfo = handler.scan(args.file_to_scan)
    print malicious, cursiginfo

if __name__ == "__main__":
    args = parser.parse_args()
    main(args)
