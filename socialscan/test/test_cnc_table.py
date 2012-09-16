"""
Unit test module for cnc's table module
Run tests by executing on the command line: python test_cnc_table.py
"""

import datetime
import sys
import unittest

from os import path

# Modify the path to include the source under test
# Then we can run the unit tests from the test directory
# __file__ is <root>/test/test_searchutil.py
pdn = path.dirname
projectdir = pdn(pdn(path.abspath(__file__)))
for d in [projectdir, path.join(projectdir, 'socialscan'), path.join(projectdir, 'util'), 
          path.join(projectdir, 'cnc'), path.join(projectdir, 'test')]:
    if d not in sys.path:
        sys.path.append(d)


from cnc import table
from cnc import tablev2
from socialscan.config import loadConfig


class TableTest(unittest.TestCase):
    config = None
    reverse_amis = {}

    def setUp(self):
        'Load configuration'
        self.config = loadConfig(path.join(projectdir, 'cnc', 'experiment.example.config'))
        amis = tablev2.amis
        for k, v in amis.items():
            self.reverse_amis[v] = k

    def testGenerateAmiList(self):
        'table.ami_list should be populated based on configuration.'
        table.generate_ami_list(self.config)
        scanhandlers = ['avgbe', 'avgbe', 'avgbe', 'avira', 'avira', 'kaspersky', 'kaspersky', 'mcafee']
        expected = [self.reverse_amis[k] for k in scanhandlers if k in self.reverse_amis]
        expected.sort()
        table.ami_list.sort()
        self.assertEqual(expected, table.ami_list)

    def testGenerateFunctionalAmisList(self):
        'table.functional_amis should be populated correctly.'
        scanhandlers = ['avast', 'avgbe', 'avira', 'kaspersky', 'mcafee', 'msseccli']
        expected = [self.reverse_amis[k] for k in self.reverse_amis if k in scanhandlers]
        table.generate_functional_amis_list()
        self.assertEqual(set(expected), set(table.functional_amis))

    def testGetAmiSmallNoConfig(self):
        'Should return a random ami from functional_amis, removing it from the same.'
        ami = table.get_ami(2)
        self.assertTrue(ami not in table.functional_amis)

    def testGetAmiLargeNoConfig(self):
        'Should return a random ami from functional_amis, leaving it there.'
        n = table.small_experiment_threshold + 1
        ami = table.get_ami(n)
        self.assertTrue(ami in table.functional_amis)

    # TODO: test get_ami with config
    # TODO: test get_ami with enough calls to empty the list with a small num_peers
    # TODO: test get_ami with a number larger than small_experiment_threshold
    # TODO: test get_ami with config and enough calls to empty the list with a small num_peers


def suite():
    cnc_table_suite = unittest.makeSuite(TableTest)
    suite = unittest.TestSuite((cnc_table_suite))
    return suite


if __name__ == "__main__":
    unittest.main()
