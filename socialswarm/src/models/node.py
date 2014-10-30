"""
Node representing a social entity in a social network for social swarm.

Authored by Henry Longmore.
"""

# Standard python library imports
import sys
import uuid

from collections import deque
from copy import deepcopy
from os import path

# 3rd party imports
try:
    import yaml
except:
    import json as yaml

# modify the path to see the source we are testing,
# this makes it easy to run the unit test from its own directory
# and to make the relative paths work correctly.
# __file__ is <workspace root>/src/models/node.py
pdn = path.dirname
thisdir = pdn(path.abspath(__file__))
wsdir = pdn(pdn(pdn(path.abspath(__file__))))
for d in [path.join(wsdir, 'src'), path.join(wsdir, 'test')]:
    if d not in sys.path:
        sys.path.append(d)

# Our code
from models import NoInteractionsSetException
from models.altruism import Altruism
from models.interaction import Interaction


class Node(object):
    IDS = {'': ''}
    max_social_distance = 600
    hop_decay = 0.95

    def __init__(self, node_id='', interactions=[]):
        super(Node, self).__init__()
        self.set_id(node_id)
        self.set_interactions(interactions)
        self.altruism = {} # For directly connected peers
        self.indirect_social_distance = {} # For indirectly connected peers

    @classmethod
    def set_defaults(cls):
        "Needed mostly for testing, so I can reset these values to test reading and configuring."
        cls.max_social_distance = 600
        cls.hop_decay = 0.95

    def set_id(self, node_id):
        if not node_id or node_id in self.IDS:
            node_id = '' # If we got here due to node_id == [] or node_id == None, etc.
            while node_id in self.IDS:
                node_id = uuid.uuid4()
        self.id = node_id
        self.IDS[node_id] = node_id

    def set_interactions(self, a):
        self.interactions = [a] if not hasattr(a, 'sort') else a

    def reset(self, what='', default=None):
        if what:
            setattr(self, what, default)

    def reset_all(self):
        self.reset('interactions', None)
        self.reset('altruism', {})
        self.reset('indirect_social_distance', {})

    def is_directly_connected(self, other):
        # Have we already determined these nodes are directly connected?
        if other.id in self.altruism:
            return True
        # If not, determine it.
        altruism = Altruism(self.interactions, other.interactions)
        av = altruism.altruism()
        if av > 0:
            self.altruism[other.id] = altruism
            return True
        else:
            return False

    def social_distance(self, other, nodes={}):
        if self.is_directly_connected(other):
            return self.altruism[other.id].social_distance()
        else:
            return self.approximate_social_distance(other, nodes)

    def approximate_social_distance(self, other, nodes={}):
        """ Do a breadth-first search along self's direct connections:
                i. for each direct connection, b, calculate Direct Social Distance (equation 1)
                   for each of those direct connections, calculate their direct peers social distances
                ii. calculate Combined SocialDistance(a,b) with SocialDistance(b,c) (equation 2) to get
                    all of the candidate SocialDistance(a,c)'s.
                iii. take the min (shortest path) of these candidate SocialDistance(a,c)'s to yield
                     the final SocialDistance(a,c)
                iv. if at any point a calculated SocialDistance(a,y) for any y is greater than
                    max_social_distance, stop searching.
                v. if no paths are found that do not exceed the max_social_distance before connecting
                   a and c, then a and c are not connected.
        """
        queue = deque()
        visited = set()
        visited.add(self.id)
        queue.append(self.id)
        while queue and stop_search:
            a = queue.popleft()
            if a.is_directly_connected(other):
                return a.altruism[other.id].social_distance()
            elif other.id in a.indirect_social_distance:
                return a.indirect_social_distance[other.id]
            candidate_social_distances = []
            for b in nodes:
                if a.is_directly_connected(b): # Calculates altruism if known, and thus social distance
                    if b.id not in visited:
                        visited.add(b.id)
                        queue.append(b.id)
                    for c in nodes:
                        if b.is_directly_connected(c):
                            visited.add(c.id)
                            queue.append(c.id)
                            candidate = Node.candidate_social_distance(a, b, c)
                            if candidate > self.max_social_distance:
                                stop_search = True
                                break
                            candidate_social_distances.append((a.id, c.id, candidate))
                    if stop_search:
                        break
            a.indirect_social_distance[c.id] = Node.find_min_candidate_social_distance(candidate_social_distances)

    @classmethod
    def candidate_social_distance(cls, a, b, c):
        return (a.social_distance(b) * b.social_distance(c)) / (cls.hop_decay)
        #return 1 / (hop_decay / (a.social_distance(b) * b.social_distance(c)))

    @classmethod
    def find_min_candidate_social_distance(cls, candidates):
        min_so_far = candidates[0][2]
        index_of_min_so_far = 0 # Not needed, but helpful for debugging purposes.
        for i in xrange(1, len(candidates)):
            if min_so_far > candidates[i][2]:
                min_so_far = candidates[i][2]
                index_of_min_so_far = i
        #print 'index of min_so_far: %s, min: %s' % (index_of_min_so_far, min_so_far)
        #print 'candidates: %s' % candidates
        return min_so_far

    @classmethod
    def read_tunable_parameters(cls, configfile=''):
        if not configfile:
            configfile = path.join(wsdir, 'config', 'tunables.yaml')
        try:
            tunables = yaml.load(open(configfile, 'r'))
        except (OSError, IOError), e:
            print 'Unable to open %s' % (configfile)
        else:
            cls.max_social_distance = tunables.get('max_social_distance', '600')
            cls.hop_decay = tunables.get('hop_decay', 0.05)
