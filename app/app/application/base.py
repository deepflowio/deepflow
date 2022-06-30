from data.status import Status

class Base(object):
    
    def __init__(self, args, headers):
        self.args = args
        self.start_time = int(self.args.get("time_start", 0))
        self.end_time = int(self.args.get("time_end", 0))
        self.headers = headers
        self.status = Status()