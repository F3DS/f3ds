"""
Some basic definitions for use by all social networks.
"""

class NoTimeWindowSetException(Exception): pass
class NoTimeWindowStartException(Exception): pass
class NoTimeWindowEndException(Exception): pass

class TimeWindowMixin(object):

    def __init__(self, begin, end):
        super(TimeWindowMixin, self).__init__()
        self.begin = begin
        self.end = end

    def get_time_window(self):
        "If the social network has an API to limit by a time window, use this method."
        if not self.begin and not self.end:
            raise NoTimeWindowSetException
        if not self.begin:
            raise NoTimeWindowStartException
        if not self.end:
            raise NoTimeWindowEndException
        if not hasattr(self.begin, 'today'):
            raise ValueError('Time Window beginning value must be of date or datetime type.')
        if not hasattr(self.end, 'today'):
            raise ValueError('Time Window ending value must be of date or datetime type.')
        return self.begin, self.end

    def filter(self, a_interactions, b_interactions):
        """If the social network does not provide an API to limit by time window, we must
        filter interactions ourselves.
        """
        a_filtered = [a for a in a_interactions if a.dtstamp <= self.end and a.dtstamp >= self.begin]
        b_filtered = [b for b in b_interactions if b.dtstamp <= self.end and a.dtstamp >= self.begin]
        return a_filtered), b_filtered
