import numpy as np


class AbsoluteModel:
    def __call__(self, values):
        return np.abs(values)
