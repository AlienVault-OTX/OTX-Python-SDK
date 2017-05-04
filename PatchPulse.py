class PatchPulse(object):
    body = {}

    def __init__(self, pulse_id):
        self.pulse_id = pulse_id

    def add(self, key, element):
        if key not in self.body:
            self.body[key] = {}
        self.body[key]["add"] = element

    def remove(self, key, element):
        if key not in self.body:
            self.body[key] = {}
        self.body[key]["remove"] = element

    def set(self, name, value):
        self.body[name] = value

    def getBody(self):
        return self.body

    def getPulseId(self):
        return self.pulse_id