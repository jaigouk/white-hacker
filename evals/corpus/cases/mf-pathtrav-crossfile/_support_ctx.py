class Ctx:
    def __init__(self, target):
        self.target = target


def from_request(req):
    return Ctx(req["query"]["f"])
