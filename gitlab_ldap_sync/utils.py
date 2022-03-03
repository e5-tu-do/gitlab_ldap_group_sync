import os


def getenvbool(key, default=False):
    '''Get True of False from an environment variable
    If the variable is not set, return `default`,
    if it is set, `yes`, `true` and `on` are matched case insensitive for True,
    everything else is false
    '''
    val = os.getenv(key)
    if val is None:
        return default
    return val.lower() in {'yes', 'true', 'on'}
