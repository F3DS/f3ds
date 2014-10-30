"""
Unit test module for models module
Run tests by executing on the command line: python test_models.py
    -v flag for verbose output

Authored by Henry Longmore.
"""

# Standard python library imports
import os
import sys
import unittest
import uuid

from datetime import datetime
from os import path

# 3rd party imports
try:
    import yaml
except:
    import json as yaml

# modify the path to see the source we are testing,
# this makes it easy to run the unit test from its own directory
# and to make the relative paths work correctly.
# __file__ is <workspace root>/test/test_models.py
pdn = path.dirname
wsdir = pdn(pdn(path.abspath(__file__)))
for d in [path.join(wsdir, 'src'), path.join(wsdir, 'test')]:
    if d not in sys.path:
        sys.path.append(d)

# Our imports
import models
from models import interaction, altruism, node
from models import TimeFormatNotRecognized

class NodeTest(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        # We have to clean up the node ids created for this test.
        n = node.Node()
        n.IDS.clear()
        n.IDS.update({'': ''})

    def testInit(self):
        n = node.Node()
        # No exceptions raised.

    def testSetInteractions(self):
        n = node.Node()
        other_ids = [uuid.uuid4() for i in xrange(0, 5)]
        self.assertEqual(n.interactions, [])
        n.set_interactions([
            interaction.Interaction(formatted_dtstamp='2014-10-27T03:29:16+0000',
                                    actor=n.id, direct_object=other_ids[0]),
            interaction.Interaction(formatted_dtstamp='2014-10-27T03:49:52+0000',
                                    actor=n.id, direct_object=other_ids[1]),
            interaction.Interaction(formatted_dtstamp='2014-10-27T04:19:10+0000',
                                    actor=n.id, direct_object=other_ids[2]),
            interaction.Interaction(formatted_dtstamp='2014-10-27T04:25:35+0000',
                                    actor=n.id, direct_object=other_ids[3]),
            interaction.Interaction(formatted_dtstamp='2014-10-27T05:34:18+0000',
                                    actor=n.id, direct_object=other_ids[4]),
            ])
        self.assertEqual(len(n.interactions), 5)
        self.assertEqual(n.interactions[0].actor, n.id)
        self.assertEqual(n.interactions[1].actor, n.id)
        self.assertEqual(n.interactions[2].actor, n.id)
        self.assertEqual(n.interactions[3].actor, n.id)
        self.assertEqual(n.interactions[4].actor, n.id)
        self.assertEqual(n.interactions[0].direct_object, other_ids[0])
        self.assertEqual(n.interactions[1].direct_object, other_ids[1])
        self.assertEqual(n.interactions[2].direct_object, other_ids[2])
        self.assertEqual(n.interactions[3].direct_object, other_ids[3])
        self.assertEqual(n.interactions[4].direct_object, other_ids[4])

    def testSetId_IdIsEmpty(self):
        n = node.Node()
        self.assertTrue(n.id)
        self.assertTrue(n.id in n.IDS)

    def testSetId_IdNotEmptyNotInIDS(self):
        n = node.Node(node_id='012345678901234')
        self.assertTrue(n.id)
        self.assertTrue(n.id in n.IDS)
        self.assertTrue(n.id == '012345678901234')

    def testSetId_IdNotEmptyIdInIDS(self):
        n1 = node.Node(node_id='012345678901234')
        self.assertTrue(n1.id)
        self.assertTrue(n1.id in n1.IDS)
        self.assertTrue(n1.id == '012345678901234')
        n2 = node.Node(node_id='012345678901234')
        self.assertTrue(n2.id)
        self.assertTrue(n2.id in n2.IDS)
        self.assertFalse(n2.id == '012345678901234')

    def testSetId_AllIdsAccountedFor(self):
        # We have to clean up the nodes already created for this test.
        expected = ['012345678901234', '123456789012345', '234567890123456',
                    '345678901234567', '456789012345678', '567890123456789']
        nodes = []
        for node_id in expected:
            nodes.append(node.Node(node_id=node_id))
        actual = nodes[0].IDS.keys()
        if '' in actual: actual.remove('')
        self.assertEqual(set(expected), set(actual))

    def testReset_Interactions(self):
        expected = ['012345678901234', '123456789012345', '234567890123456',
                    '345678901234567', '456789012345678', '567890123456789']
        nodes = []
        for node_id in expected:
            nodes.append(node.Node(node_id=node_id))
        n = node.Node()
        n.set_interactions([
            interaction.Interaction(formatted_dtstamp='2014-10-27T03:29:16+0000',
                                    actor=n.id, direct_object=expected[0]),
            interaction.Interaction(formatted_dtstamp='2014-10-27T03:49:52+0000',
                                    actor=n.id, direct_object=expected[1]),
            interaction.Interaction(formatted_dtstamp='2014-10-27T04:19:10+0000',
                                    actor=n.id, direct_object=expected[2]),
            interaction.Interaction(formatted_dtstamp='2014-10-27T04:25:35+0000',
                                    actor=n.id, direct_object=expected[3]),
            interaction.Interaction(formatted_dtstamp='2014-10-27T05:34:18+0000',
                                    actor=n.id, direct_object=expected[4]),
            ])
        self.assertNotEqual(n.interactions, [])
        self.assertNotEqual(n.interactions, None)
        n.reset('interactions', None)
        self.assertEqual(n.interactions, None)

    def testDirectlyConnected(self):
        expected = []
        nodes = []
        for i in xrange(0, 6):
            n = node.Node()
            expected.append(n.id)
            nodes.append(n)
        n = nodes[0]
        n.set_interactions([
            interaction.Interaction(formatted_dtstamp='2014-10-27T03:29:16+0000',
                                    actor=n.id, direct_object=expected[1]),
            interaction.Interaction(formatted_dtstamp='2014-10-27T03:49:52+0000',
                                    actor=n.id, direct_object=expected[2]),
            ])
        n = nodes[1]
        n.set_interactions([
            interaction.Interaction(formatted_dtstamp='2014-10-28T01:31:19+0000',
                                    actor=n.id, direct_object=expected[0])
            ])
        n = nodes[2]
        n.set_interactions([
            interaction.Interaction(formatted_dtstamp='2014-10-28T01:31:19+0000',
                                    actor=n.id, direct_object=expected[0])
            ])
        self.assertTrue(nodes[0].is_directly_connected(nodes[1]))
        self.assertTrue(nodes[1].is_directly_connected(nodes[0]))
        self.assertFalse(nodes[2].is_directly_connected(nodes[1]))
        # Test that calling it again does not change the result
        before = nodes[1].altruism[nodes[0].id].altruism()
        self.assertTrue(nodes[1].is_directly_connected(nodes[0]))
        after = nodes[1].altruism[nodes[0].id].altruism()
        self.assertEqual(before, after)
        # Check initialized nodes are not the default empty containers.
        self.assertNotEqual(nodes[0].altruism, [])
        self.assertNotEqual(nodes[0].altruism, {})
        self.assertNotEqual(nodes[0].altruism, None)
        self.assertNotEqual(nodes[1].altruism, [])
        self.assertNotEqual(nodes[1].altruism, {})
        self.assertNotEqual(nodes[1].altruism, None)
        # We could test for the actual Altruism objects that we created,
        # but then we get into testing that class in this one, so test more simply.


    def testSocialDistanceInverseOfAltruism(self):
        expected = []
        nodes = []
        for i in xrange(0, 3):
            n = node.Node()
            expected.append(n.id)
            nodes.append(n)
        n = nodes[0]
        n.set_interactions([
            interaction.Interaction(formatted_dtstamp='2014-10-27T03:29:16+0000',
                                    actor=n.id, direct_object=expected[1]),
            interaction.Interaction(formatted_dtstamp='2014-10-27T03:49:52+0000',
                                    actor=n.id, direct_object=expected[2]),
            ])
        n = nodes[1]
        n.set_interactions([
            interaction.Interaction(formatted_dtstamp='2014-10-28T01:31:19+0000',
                                    actor=n.id, direct_object=expected[0])
            ])
        n = nodes[2]
        n.set_interactions([
            interaction.Interaction(formatted_dtstamp='2014-10-28T01:31:19+0000',
                                    actor=n.id, direct_object=expected[0])
            ])
        self.assertTrue(nodes[0].is_directly_connected(nodes[1]))
        self.assertTrue(nodes[1].is_directly_connected(nodes[0]))
        self.assertFalse(nodes[2].is_directly_connected(nodes[1]))
        # We could test for the actual Altruism objects that should be created,
        # but then we get into testing that class in this one, so test more simply.
        self.assertAlmostEqual(nodes[0].altruism[nodes[1].id].altruism(), 0.5)
        self.assertAlmostEqual(nodes[1].altruism[nodes[0].id].altruism(), 1.0)
        self.assertAlmostEqual(nodes[0].altruism[nodes[1].id].social_distance(), 2.0)
        self.assertAlmostEqual(nodes[1].altruism[nodes[0].id].social_distance(), 1.0)
        # An altruism value of 0 means they are not connected, and a key lookup
        # will fail. Neither .altruism() nore .social_distance() will be called;
        # any attempt will result in a KeyError.
        self.assertFalse(nodes[1].id in nodes[2].altruism)

    def testCandidateSocialDistance(self):
        expected = []
        nodes = []
        for i in xrange(0, 3):
            n = node.Node()
            expected.append(n.id)
            nodes.append(n)
        n = nodes[0]
        n.set_interactions([
            interaction.Interaction(formatted_dtstamp='2014-10-27T03:29:16+0000',
                                    actor=n.id, direct_object=expected[1]),
            ])
        n = nodes[1]
        n.set_interactions([
            interaction.Interaction(formatted_dtstamp='2014-10-28T01:31:19+0000',
                                    actor=n.id, direct_object=expected[0]),
            interaction.Interaction(formatted_dtstamp='2014-10-27T03:49:52+0000',
                                    actor=n.id, direct_object=expected[2]),
            ])
        n = nodes[2]
        n.set_interactions([
            interaction.Interaction(formatted_dtstamp='2014-10-28T01:31:19+0000',
                                    actor=n.id, direct_object=expected[1])
            ])
        a = nodes[0]
        b = nodes[1]
        c = nodes[2]
        self.assertTrue(a.is_directly_connected(b))
        self.assertTrue(b.is_directly_connected(c))
        self.assertFalse(a.is_directly_connected(c))
        csd = a.candidate_social_distance(a, b, c)
        #print 'SD(a,b):', a.social_distance(b) # 1.0
        #print 'SD(b,c):', b.social_distance(c) # 2.0
        #print 'SD(a,c):', csd
        expected_csd = (1 / (0.95 / (a.social_distance(b) * b.social_distance(c))))
        self.assertEqual(csd, expected_csd)
        self.assertEqual(csd, (1 / (0.95 / (1.0 * 2.0))))

    def testReadTunableParameters(self):
        node.Node.set_defaults()
        self.assertEqual(node.Node.max_social_distance, 600)
        self.assertEqual(node.Node.hop_decay, 0.95)
        node.Node.read_tunable_parameters()
        self.assertEqual(node.Node.max_social_distance, 500)
        self.assertEqual(node.Node.hop_decay, 0.55)
        node.Node.read_tunable_parameters(path.join(wsdir, 'test', 'tunables.yaml'))
        self.assertEqual(node.Node.max_social_distance, 432)
        self.assertEqual(node.Node.hop_decay, 0.39)

    def testFindMinCandidateSocialDistance(self):
        data = [('a', 'c', 0.75), ('a', 'c', 0.64), ('a', 'c', 0.95),
                ('a', 'c', 0.25), ('a', 'c', 0.34)]
        result = node.Node.find_min_candidate_social_distance(data)
        expected = 0.25
        self.assertEqual(result, expected)


class InteractionTest(unittest.TestCase):

    def setUp(self):
        pass
    def tearDown(self):
        pass

    def testInit(self):
        i = interaction.Interaction()
        # Should not raise exceptions

    def testSetdtstampFacebookVisualStyle(self):
        self.assertRaises(TimeFormatNotRecognized, interaction.Interaction,
                          formatted_dtstamp='Friday, September 5, 2014 at 6:57 pm')

    def testSetdtstampDashesUtc(self):
        i = interaction.Interaction(formatted_dtstamp='2014-10-27T03:29:16+0000')
        self.assertEqual(i.dtstamp, datetime(2014, 10, 27, 3, 29, 16))

    def testSetdtstampDashesNonUs(self):
        i = interaction.Interaction(formatted_dtstamp='27-10-2014 03:29:16')
        self.assertEqual(i.dtstamp, datetime(2014, 10, 27, 3, 29, 16))

    def testSetdtstampDashesUs(self):
        i = interaction.Interaction(formatted_dtstamp='10-27-2014 03:29:16')
        self.assertEqual(i.dtstamp, datetime(2014, 10, 27, 3, 29, 16))

    def testSetdtstampDashesUtcPositiveOffset(self):
        i = interaction.Interaction(formatted_dtstamp='2014-10-27T03:29:16+0700')
        self.assertEqual(i.dtstamp, datetime(2014, 10, 27, 10, 29, 16))

    def testSetdtstampDashesUtcNegativeOffset(self):
        i = interaction.Interaction(formatted_dtstamp='2014-10-27T10:29:16-0700')
        self.assertEqual(i.dtstamp, datetime(2014, 10, 27, 3, 29, 16))

    def testSetdtstampSlashesUtc(self):
        i = interaction.Interaction(formatted_dtstamp='2014/10/27T03:29:16+0000')
        self.assertEqual(i.dtstamp, datetime(2014, 10, 27, 3, 29, 16))

    def testSetdtstampSlashesNonUs(self):
        i = interaction.Interaction(formatted_dtstamp='27/10/2014 03:29:16')
        self.assertEqual(i.dtstamp, datetime(2014, 10, 27, 3, 29, 16))

    def testSetdtstampSlashesUs(self):
        i = interaction.Interaction(formatted_dtstamp='10/27/2014 03:29:16')
        self.assertEqual(i.dtstamp, datetime(2014, 10, 27, 3, 29, 16))

    def testSetdtstampSpacesUtc(self):
        i = interaction.Interaction(formatted_dtstamp='2014 10 27T03:29:16+0000')
        self.assertEqual(i.dtstamp, datetime(2014, 10, 27, 3, 29, 16))

    def testSetdtstampSpacesNonUs(self):
        i = interaction.Interaction(formatted_dtstamp='27 10 2014 03:29:16')
        self.assertEqual(i.dtstamp, datetime(2014, 10, 27, 3, 29, 16))

    def testSetdtstampSpacesUs(self):
        i = interaction.Interaction(formatted_dtstamp='10 27 2014 03:29:16')
        self.assertEqual(i.dtstamp, datetime(2014, 10, 27, 3, 29, 16))

    def testSetActor(self):
        n = node.Node()
        i = interaction.Interaction(actor=n.id)
        self.assertTrue(i.actor)
        self.assertEqual(i.actor, n.id)

    def testSetDirectObject(self):
        n = node.Node()
        i = interaction.Interaction(direct_object=n.id)
        self.assertTrue(i.direct_object)
        self.assertEqual(i.direct_object, n.id)

    def testInitNonEmpty(self):
        a = node.Node()
        b = node.Node()
        i = interaction.Interaction(formatted_dtstamp='2014-10-23T18:43:29+0000', actor=a.id, direct_object=b.id)
        self.assertTrue(i.actor)
        self.assertTrue(i.direct_object)
        self.assertEqual(i.actor, a.id)
        self.assertEqual(i.direct_object, b.id)
        self.assertEqual(i.dtstamp, datetime(2014, 10, 23, 18, 43, 29))


# Altruism's methods were all called while testing Node.
#class AltruismTest(unittest.TestCase):



def suite():
    interaction_suite = unittest.makeSuite(InteractionTest)
    node_suite = unittest.makeSuite(NodeTest)
    suite = unittest.TestSuite((interaction_suite, node_suite))
    return suite


if __name__ == '__main__':
    unittest.main()
