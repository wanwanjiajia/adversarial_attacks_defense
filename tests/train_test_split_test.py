# _*_coding:utf-8 _*_

# @Time      :2020/01/04 12:02

# @Author    : Wanjia Zheng

# @File      :train_test_split_test.py

# @Software  :PyCharm

import os
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import HashingVectorizer

X = [[1,1],[2,2],[3,3],[4,4],[5,5],[6,6],[7,7],[8,8],[9,9]]
Y = [1,2,3,4,5,6,7,8,9]

X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.1, random_state=1)

print(X_train)
print(X_test)

X = [[11,11],[22,22],[33,33],[44,44],[55,55],[66,66],[77,77],[88,88],[99,99]]
Y = [1,2,3,4,5,6,7,8,9]

X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.1, random_state=0)

print("-----2------")
print(X_train)
print(X_test)