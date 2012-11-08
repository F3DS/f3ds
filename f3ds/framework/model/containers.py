#!/usr/bin/python

# Standard Python modules
import os

# 3rd party modules

# Our modules
from f3ds.framework.log import Logger
from f3ds.framework.util import UrlObject
from socialscan.model import relationshipsQuery
from socialscan.searchutil import SearchResult


class ContainerManager(object):
    """
    Container manager object which stores and manages loaded containers, and runs jobs related to them.
    For example, containers may be of type ScanLogFile or ScanDigestFile

    @ivar logger: "ContainerManager" logger
    @type logger: L{Logger}

    @ivar config: socialscan configuration
    @type config: L{AttributeConfig}

    @ivar session: SQLAlchemy database session
    @type session: C{sqlalchemy.orm.session.Session}

    @ivar loadlimit: C{int} version of C{config.container_manager.loadlimit}
    @type loadlimit: C{int}

    @ivar containers: foreign containers currently loaded
    @type containers: C{list} of L{ContainerMixin}

    @ivar ourcontainer: the container that is currently being built by this container manager
    @type ourcontainer: L{ContainerMixin}

    @ivar announcequeue: local containers to announce to peers
    @type announcequeue: C{list} of L{ContainerMixin}
    """

    def __init__(self, config, session, container_mixin):
        self.container = container_mixin
        self.cname = self.container.__name__.lower()
        self.name = '%sManager' % (self.container.__name__)
        self.logger = Logger('%s' % self.name)
        self.logger.log('initializing %s' % (self.name))
        self.config = config
        self.session = session
        self.loaded = False

        sharedir = os.path.dirname(config.container_manager.share_location)
        storedir = os.path.dirname(config.container_manager.storage_location)
        if not os.path.exists(sharedir):
            self.logger.log('creating share dir %r' % sharedir)
            os.makedirs(sharedir)
        if not os.path.exists(storedir):
            self.logger.log('creating storage dir %r' % storedir)
            os.makedirs(storedir)

        self.loadlimit = int(config.container_manager.loadlimit)
        self.announcequeue = []
        self.containers = []
        allcontainers = session.query(self.container)\
                            .filter(self.container.owner == config.owner)\
                            .filter(self.container.creator != config.owner)\
                            .all()
                            # TODO: get the below filter working
                            #.filter(self.container.tainted == False)\
        sortedcontainers = sorted(allcontainers, key=lambda container: container.usefulness)
        for container in sortedcontainers[:self.loadlimit]:
            try:
                container.container_type = eval(container.container_type_name)
                self.containers.append(container.load())
            except (ValueError, AttributeError, IOError), error:
                msg = 'Error while loading %s %s: %s'
                self.logger.log(msg % (self.cname, container, error))

        self.ourcontainer = session.query(self.container)\
                                .filter(self.container.owner == config.owner)\
                                .filter(self.container.creator == config.owner)\
                                .filter(self.container.complete == False)\
                                .order_by(self.container.date.desc())\
                                .first()
        if self.ourcontainer:
            try:
                self.ourcontainer.container_type = eval(self.ourcontainer.container_type_name)
                self.ourcontainer.load()
            except:
                self.logger.exception()
                self.ourcontainer = None
            else:
                self.loaded = True
        if not self.ourcontainer:
            self._newcontainer(None)

    def __del__(self):
        'Attempt to preserve container when exiting.'
        try:
            if self.ourcontainer:
                self.ourcontainer.save()
        except (IOError, WindowsError, AttributeError):
            pass

    def _announceContainers(self):
        """
        Send our current container out to peers.
        """
        pass

    def _newcontainer(self, siginfo):
        """
        Create a new local container and, if it exists, flush the old one to disk and 
        add it to the L{announcequeue}.
        """
        pass

    def updateOurContainer(self):
        """
        Recurring job: Update our container.  For the base class, only announces
        containers.
        """
        pass

    def _retrieve_progress(self, block_count, block_size, total_size):
        log_msg = '%s of %s downloaded' % (block_count * block_size, total_size)
        self.logger.log(log_msg)

    def retrieveContainer(self):
        """
        Recurring job: retrieve a container that a peer has offered to us and, if a slot can be
        made available, load it up.
        """
        pass

    def _unloadone(self):
        """
        Unload the least useful container.
        """
        self.logger.log('attempting to unload some containers [stub]')
        if not len(self.containers):
            self.logger.log('no %s loaded to unload!' % (self.cname))
        containers = sorted(self.containers, key=lambda container: container.usefulness)
        tounload = containers[0]
        self.containers.remove(tounload)
        tounload.unload()
        self.logger.log('unloaded %s %r' % (self.cname, (tounload,)))

    def search(self, url, size, contenthash, aggregate=False):
        """
        Search the loaded containers. 
        """
        raise Exception('Empty stub ContainerManager.search called!')

    def relationshipRedemption(self):
        """
        redeem relationships of all peers
        """
        try:
            relationships = relationshipsQuery(self.session, self.config)
            amount = float(self.config.container_manager.redemption_amount)
            for relationship in relationships:
                relationship.redemption(amount)
                self.session.add(relationship)
            self.session.commit()
        except:
            self.logger.exception()
            raise

    def _initJobs(self):
        """
        initialize jobs with the twisted reactor. Separate from __init__ so that
        C{ContainerManager} can be instantiated by non-main code.
        """
        pass

