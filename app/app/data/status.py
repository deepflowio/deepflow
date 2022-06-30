import time


class Status(object):

    def __init__(self):
        self.start = time.time()
        self.end = None
        self.results = dict()
        self.description = ''
        self.status_code = 200
        self.status = {
            "_QUERY_IDS": [],
            "_TSDB_INFO": {
                "QUERY_TIME": 0,
                "QUERIES": []
            }
        }
        self.failed_regions = set()

    def append(self, name, result):
        index = 0
        while True:
            if f"{name}-{index}" in self.results:
                index += 1
                continue
            else:
                name = f"{name}-{index}"
                break
        self.results[name] = result
        if result.get("description"):
            self.description = result['description']
        if result.get('status') != 200:
            for region_name, value in result.get('regions', {}).items():
                if value == -1:
                    self.failed_regions.add(region_name)

    def get_status(self):
        self.end = time.time()
        status = 200
        for k, v in self.results.items():
            if v["status"] > status:
                status = v["status"]
        return status

    def to_debug(self):
        self.status["_TSDB_INFO"]["QUERY_TIME"] = self.end - self.start
        for k, v in self.results.items():
            self.status["_QUERY_IDS"].append({
                "query_name": k,
                "query_id": v["query_id"]
            })
            self.status["_TSDB_INFO"]["QUERIES"].append({
                "query_id": v["query_id"],
                "sql": v["sql"],
                "QUERY_TIMES": v["total_time"],
                "NODES": v["times"],
                "REGIONS": v["regions"]
            })
        return self.status

    def to_querier_debug(self):
        if not self.end:
            self.end = time.time()
        self.status["_TSDB_INFO"]["QUERY_TIME"] = self.end - self.start
        for k, v in self.results.items():
            if not v:
                continue
            self.status["_QUERY_IDS"].append({
                "query_name": k,
                "query_id": v.get("query_uuids")
            })
            self.status["_TSDB_INFO"]["QUERIES"].append({
                "query_id": v.get("query_uuids"),
                "sql": v.get("sql"),
                "query_time": v.get("total_time"),
                "query_region_times": v.get("regions"),
                "query_regions": v.get("debug"),
            })
        return self.status
