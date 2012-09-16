

_cache = {}
def get(handler):
    try:
        module = _cache[handler]
        return module
    except KeyError:
        module = __import__(handler, globals(), {}, 0)
        _cache[handler] = module
        return module
