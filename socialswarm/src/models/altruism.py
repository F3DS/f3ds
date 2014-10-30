"""
Compute altruism for social swarm.

Authored by Henry Longmore.
"""

# Standard python library imports
import sys

from copy import deepcopy
from os import path

# 3rd party imports

# modify the path to see the source we are testing,
# this makes it easy to run the unit test from its own directory
# and to make the relative paths work correctly.
# __file__ is <workspace root>/test/test_configuration.py
pdn = path.dirname
wsdir = pdn(pdn(path.abspath(__file__)))
for d in [path.join(wsdir, 'src'), path.join(wsdir, 'test')]:
    if d not in sys.path:
        sys.path.append(d)

# Our code
from models import NoInteractionsSetException, NotConnectedDueToNoReciprocalInteractionsException
from models.interaction import Interaction


class Altruism(object):

    def __init__(self, a_interactions=None, b_interactions=None):
        super(Altruism, self).__init__()
        self.reciprocal_interactions = None
        self.altruism_value = None
        self.a = None
        self.b = None
        if a_interactions and b_interactions:
            self.set_interactions(a_interactions, b_interactions)

    def set_interactions(self, a, b):
        tmp_a = deepcopy(a)
        tmp_b = deepcopy(b)
        self.a = [tmp_a] if not hasattr(tmp_a, 'sort') else tmp_a
        self.b = [tmp_b] if not hasattr(tmp_b, 'sort') else tmp_b

    def reset(self, what=''):
        if what:
            setattr(self, what, None)

    def reset_all(self):
        self.reset('reciprocal_interactions')
        self.reset('a')
        self.reset('b')
        self.reset('altruism_value')

    def find_reciprocal(self):
        """After this method, only "reciprocal" interactions of between a and b will remain in self.b.
        Currently, "reciprocal" means mutual posts on a's and b's timelines by the other (for FB).
        """
        if not self.a and not self.b:
            raise NoInteractionsSetException
        self.a.sort()
        self.b.sort()
        a_reciprocal = []
        b_reciprocal = []
        max_to_examine = len(self.b)
        examined = 0
        for a in self.a[:]:
            if examined >= max_to_examine:
                # We've looked at all of self.b and can find no more reciprocal interactions.
                break
            for b in self.b[:]:
                examined += 1
                if a.reciprocal(b):
                    a_reciprocal.append(a)
                    b_reciprocal.append(b)
                    self.b.remove(b)
                    # We found a reciprocal interaction; move to the next interaction in a.
                    break
        self.b = b_reciprocal
        self.reciprocal_interactions = len(self.b)

    def altruism(self):
        # Usually I'd rather do 'if not self.reciprocal_interactions' but
        # the number of reciprocal interactions could be 0
        if self.reciprocal_interactions == None:
            self.find_reciprocal()
        self.altruism_value = self.reciprocal_interactions / float(len(self.a))
        return self.altruism_value

    def social_distance(self):
        if self.altruism_value == None:
            self.altruism()
        if self.altruism_value == 0:
            raise NotConnectedDueToNoReciprocalInteractionsException
        return 1 / self.altruism_value

