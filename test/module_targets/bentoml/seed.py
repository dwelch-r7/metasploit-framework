import bentoml
from model import AbsoluteModel

model = bentoml.picklable_model.save_model("module_target", AbsoluteModel())
print("Created native model:", model.tag)
