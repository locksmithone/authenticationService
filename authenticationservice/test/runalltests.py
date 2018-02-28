# -*- coding: utf-8 -*-
"""
Created on Mon Sep 12 11:39:34 2016

@author: locksmith
"""

import unittest

"""
Script to discover and run all tests within the current directory.

Extracted from http://stackoverflow.com/questions/3295386/python-unittest-and-discovery (Paul response)
"""

print("-------------------------")
print("Running all unit tests...")
print("-------------------------")
testLoader = unittest.defaultTestLoader.discover('.')
#print("Tests: ", testLoader)
testRunner = unittest.TextTestRunner()
testRunner.run(testLoader)