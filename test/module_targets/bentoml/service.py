import bentoml


@bentoml.service(resources={"cpu": "1"}, workers=1)
class Echo:
    @bentoml.api(batchable=True, max_batch_size=16, max_latency_ms=20)
    def summarize(self, texts: list[str]) -> list[str]:
        return texts
