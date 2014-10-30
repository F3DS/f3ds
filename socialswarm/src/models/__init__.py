"""
Some basic definitions for use by all models.

Authored by Henry Longmore.
"""

# Exceptions
class NoInteractionsSetException(Exception): pass
class TimeFormatNotRecognized(Exception): pass
class NotConnectedDueToNoReciprocalInteractionsException(Exception): pass
