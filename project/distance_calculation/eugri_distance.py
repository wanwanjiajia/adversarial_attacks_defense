# _*_coding:utf-8 _*_

# @Time      :2020/01/03 11:47

# @Author    : Wanjia Zheng

# @File      :eugri_distance.py

# @Software  :PyCharm

import numpy as np


def ed(source, target):
    ed = np.linalg.norm(np.array(source) - np.array(target))
    print("Eugrid Distance:", ed)
    return ed
