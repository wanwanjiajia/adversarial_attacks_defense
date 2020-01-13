# _*_coding:utf-8 _*_

# @Time      :2020/01/03 11:31

# @Author    : Wanjia Zheng

# @File      :distance_data.py

# @Software  :PyCharm

import random


def distance_data(X_train_reduced, Y_train):
    tmp_mal = []
    tmp_clean = []

    for i in range(X_train_reduced.shape[0]):
        if Y_train[i] == 1:
            tmp_mal.append(X_train_reduced[i][:])
        else:
            tmp_clean.append(X_train_reduced[i][:])

    if len(tmp_clean) > len(tmp_mal):
        distance_mal = tmp_mal
        distance_clean = tmp_clean[0:len(tmp_mal)]
    else:
        distance_mal = tmp_mal[0:len(tmp_clean)]
        distance_clean = tmp_clean

    return distance_mal, distance_clean
