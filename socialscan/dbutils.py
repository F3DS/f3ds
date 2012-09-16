# Convert existing sqlite3 database to SQL dump file dump.sql

import os
import sys
import sqlite3
import traceback

from os import path


def verify_dump(dump_path, verbose=False):
    # Check that it was dumped
    dump_dir, dump_name = path.split(dump_path)
    if dump_name not in os.listdir(dump_dir):
        return False
    
    try:
        with open(dump_path, 'rU') as dumpfile:
            for line in dumpfile:
                line = line[:-1] # remove newline
                if verbose:
                    print line
    except:
        print traceback.format_exc(sys.exc_info()[2])
        return False
    return True


def want_to_execute(statement):
    if statement and statement.find(';') >= 0 and statement.find('COMMIT') < 0:
        return True
    return False


def load():
    database_name = 'database.db'
    dump_name = 'dump.sql'
    database_path = path.join('.', database_name)
    dump_path = path.join('.', dump_name)
    if path.isfile(database_path):
        try:
            os.remove(database_path)
        except:
            print traceback.format_exc(sys.exc_info()[2])
            return
    if not path.isfile(dump_path):
        print "Can't load a database from ASCII sql if there is no ASCII sql."
        return

    con = sqlite3.connect(database_path)
    c = con.cursor()
    raw = ''
    with open(dump_path, 'rU') as dumpfile:
        for line in dumpfile:
            raw += line
            if want_to_execute(raw) and sqlite3.complete_statement(raw):
                c.execute(raw)
                raw = ''
    if want_to_execute(raw) and sqlite3.complete_statement(raw):
        c.execute(raw)
    try:
        con.commit()
    except sqlite3.OperationalError, e:
        print 'Received error: %s' % e
        print 'Ignored said error.'
    c.close()
    msg = 'Done loading %s from %s.  You may want to dump it again to verify the load worked.'
    print msg % (database_path, dump_path)


def merge_load():
    database_name = 'database.db'
    dump_name = 'dump.sql'
    database_path = path.join('.', database_name)
    dump_path = path.join('.', dump_name)
    if not path.isfile(dump_path):
        print "Can't merge a database from ASCII sql if there is no ASCII sql."
        return

    con = sqlite3.connect(database_path)
    c = con.cursor()
    raw = ''
    with open(dump_path, 'rU') as dumpfile:
        for line in dumpfile:
            split = line.split()
            if line.startswith('INSERT INTO') and split[2].find('scans') >= 0:
                values = line.find('VALUES(') + len('VALUES(')
                comma = line.find(',', values)
                raw += line[:values] + 'NULL' + line[comma:]
            if want_to_execute(raw) and sqlite3.complete_statement(raw):
                c.execute(raw)
                raw = ''
    if want_to_execute(raw) and sqlite3.complete_statement(raw):
        c.execute(raw)
    try:
        con.commit()
    except sqlite3.OperationalError, e:
        print 'Received error: %s' % e
        print 'Ignored said error.'
    c.close()
    msg = 'Done merging %s with %s.  You may want to dump it again to verify the merge worked.'
    print msg % (dump_path, database_path)


def dump():
    database_name = 'database.db'
    dump_name = 'dump.sql'
    database_path = path.join('.', database_name)
    dump_path = path.join('.', dump_name)

    con = sqlite3.connect(database_path)
    with open(dump_path, 'w') as dumpfile:
        for line in con.iterdump():
            dumpfile.write('%s\n' % line)

    if '--verify' in sys.argv[1:]:
        verbose = '-v' in sys.argv[1:]
        if not verify_dump(dump_path, verbose):
            error_msg = """
            Something is amiss with the database dump:
            database_name:%s
            database_path:%s
            dump_name:%s
            dump_path:%s
            """
            print error_msg % (database_name, database_path, dump_name, dump_path)
    return dump_path


def export_csv(dump_path, description='', verbose=False):
    create_scans_table = 'CREATE TABLE scans'
    insert_scans = 'INSERT INTO "scans" VALUES('
    csv_path = path.splitext(dump_path)[0] + ('.' + description if description else '') + '.csv'
    reserved = ['PRIMARY', 'FOREIGN', 'CHECK', ');', 'CREATE', 'INSERT']
    fields = []
    try:
        found_scans = False
        found_insert = False
        csv = open(csv_path, 'w')
        with open(dump_path, 'rU') as dumpfile:
            for line in dumpfile:
                if line.find(create_scans_table) >= 0:
                    found_scans = True
                if not found_scans:
                    continue
                if not found_insert:
                    items = line.strip().split()
                    if len(items):
                        item = items[0]
                        if item not in reserved:
                            fields.append('"' + item.strip("'") + '"')
                index = line.find(insert_scans)
                if index >= 0:
                    if not found_insert:
                        found_insert = True
                        csv.write(','.join(fields)+'\n')
                    line = line[index+len(insert_scans):-3]
                    data = line.split(',')
                    data[:] = ['"' + d.strip("'") + '"' for d in data]
                    line = ','.join(data)
                    if verbose:
                        print line
                    csv.write(line + '\n')
    except:
        print traceback.format_exc(sys.exc_info()[2])
        return False
    finally:
        csv.close()
    return True


def mysql_import(dump_path):
    pass

def mysql_convert(dump_path):
    pass
    # Clean up for MySQL - based off of answers on stackoverflow, etc.:
    # TODO: Replace " (double-quotes) with ` (grave accent)
    # TODO: Remove "BEGIN TRANSACTION;" "COMMIT;", "CREATE UNIQUE INDEX",
    #       and lines related to "sqlite_sequence"
    #       NB: "sqlite_sequence" is probably a non-issue
    # TODO: Replace "autoincrement" with "auto_increment" (or UC versions)
    #       NB: probably a non-issue
    # TODO: If there are boolean columns with default values, replace 
    #       DEFAULT 't' -> DEFAULT '1', DEFAULT 'f' -> DEFAULT '0'
    #       NB: probably a non-issue
    # TODO: Remove "" around INSERT INTO "<table_name>"
    # TODO: Are the following true or an issue?
    #       MySQL doesn't use quotes inside the schema definition
    #       SQLlite and MySQL have different ways of escaping strings inside INSERT INTO clauses
    # TODO: make sure data imports to MySQL


def sqlite_to_mysql():
    from socialscan.db import setupDB
    from socialscan.config import loadDefaultConfig
    from socialscan.model import Scan, ScanDigestFile, SocialRelationship
    from socialscan.model import  QueuedRequest, SentScanRequest, Peer

    config = loadDefaultConfig()
    session_local, engine_local = setupDB(config.database.url)
    coredev_url = '%s://%s:%s@%s:%s/%s' % ('mysql+pymysql', 'socialscanexp', 
                                        't@uc3u6e*h', '10.214.131.48', '3306',
                                        'socialscanexp')
    config.database.coredev_url = coredev_url
    session_remote, engine_remote = setupDB(config.database.coredev_url)
    for table in [Scan(), ScanDigestFile(), SocialRelationship(), QueuedRequest(),
                  SentScanRequest(), Peer()]:
        merged_table = session_local.merge(table)
        session_remote.add_all(session_local.query(merged_table).all())
    session_remote.commit()


def print_usage():
    usage = """
    usage: %s [mysql|dump|dumpcsv|dumpmysql] [options]
    
    mysql     convert sqlite data to mysql data using sqlalchemy
    dump      dump the sqlite data to ASCII sql
    dumpcsv   dump, then convert "interesting" tables to csv
    dumpsql   dump, then clean up the sql for mysql, and execute
    load      load from an ASCII sql dump
    merge     merge from an ASCII sql dump to existing db (assumes all tables
              in dump exist in db) (only considers "scans" table for now)
    
    options:
    --verify  check that the dump file was written
    -v        in conjunction with --verify, print the ASCII sql
    """
    print usage % path.split(__file__)[1]


def main():
    if len(sys.argv) > 1:
        command = sys.argv[1]
        if command == 'mysql':
            sqlite_to_mysql()
        elif command in ['dump', 'dumpcsv', 'dumpmysql']:
            command = '' if len(command) < 5 else command[4:]
            extra = []
            if len(sys.argv) > 2:
                extra = sys.argv[2:]
            sys.argv = sys.argv[:1] + extra
            dump_path = dump()
            if command == 'csv':
                export_csv(dump_path)
            elif command == 'mysql':
                mysql_convert(dump_path)
                mysql_import(dump_path)
        elif command in ['load']:
            load()
        elif command in ['merge']:
            merge_load()
        else:
            print_usage()
    else:
        print_usage()


if __name__ == "__main__":
    try:
        main()
    except AttributeError, e:
        print 'Received error: %s' % e
        print 'Ignored.'
        traceback.print_exc()

