import bentoml

runner = bentoml.picklable_model.get("module_target:latest").to_runner()
svc = bentoml.Service("module_runner_lab", runners=[runner])
