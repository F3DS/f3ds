#!/usr/bin/python

"""
SQLAlchemy handlers

Classes: DBHandlers
"""

__author__ = 'Jun Park and Matt Probst'
__version__ = '0.1'

from socialscan import model
from socialscan.log import Logger

from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
#from sqlalchemy import event

Session = sessionmaker()


#def onconnect(dbapi_con, con_record):
    #dbapi_con.execute('PRAGMA journal_mode=WAL;')


def setupDB(url):
    logger = Logger("db")
    logger.log("Setting up database")
    engine = create_engine(url, encoding='utf-8')

    #if url.startswith("sqlite"):
    #    event.listen(engine, 'connect', onconnect)

    session = Session()
    session.configure(bind=engine)
    model.Base.metadata.bind = engine
    model.Base.metadata.create_all()

    return session, engine
