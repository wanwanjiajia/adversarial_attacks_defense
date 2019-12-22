from scipy.stats import energy_distance
import numpy as np

def ed(source, target):
    dis = energy_distance(np.array(source).ravel(), np.array(target).ravel())
    return dis

