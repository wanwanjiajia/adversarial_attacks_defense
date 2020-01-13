# _*_coding:utf-8 _*_

# @Time      :2019/12/22 20:03

# @Author    : Wanjia Zheng

# @File      :energi_distance.py

# @Software  :PyCharm
from scipy.stats import energy_distance
import numpy as np


def ed(source, target):
    dis = energy_distance(np.array(source).ravel(), np.array(target).ravel())
    print("Energy Distance:", dis)
    return dis

