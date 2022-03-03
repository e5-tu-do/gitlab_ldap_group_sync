class Mock:
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs

    def __getattr__(self, name):
        if name in self.kwargs:
            return self.kwargs[name]
        return Mock()

    def __call__(self, *args, **kwargs):
        return Mock()

    def __repr__(self):
        return f'Mock({self.args}, {self.kwargs})'
