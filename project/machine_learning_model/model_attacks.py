# _*_coding:utf-8 _*_

# @Time      :2020/01/03 12:01

# @Author    : Wanjia Zheng

# @File      :model_attacks.py

# @Software  :PyCharm

from . import data_processing
from . import dimension_reduction
import numpy as np
import config as cf


def svm_attack(model, X_test_reduced, Y_test):
    w = model.coef_
    attack_x = []
    attack_y = []
    # take malware data from testing dataset
    test_mal = []
    for m in range(len(X_test_reduced)):
        if Y_test[m] == 1:
            test_mal.append(X_test_reduced[m][:])
    target_num = len(test_mal)

    # input adversarial examples(malware -> "clean") to the model
    # attack success rate = success_num/target_num
    eps = 0
    while eps <= 1:
        success_num = 0
        ww = w / np.linalg.norm(np.array(w), ord='fro')
        for ii in range(len(test_mal)):
            X_AE_test = test_mal[ii] - (eps * ww)
            Y_AE_test = model.predict(X_AE_test.reshape(1, len(X_AE_test[0])))
            X_prediction = test_mal[ii].reshape(1, len(test_mal[ii]))
            Y_prediction = model.predict(X_prediction)
            if Y_AE_test == 0 and Y_prediction == 1:
                success_num = success_num + 1
        attack_rate = round(100 * (success_num / target_num), 2)
        attack_x.append(eps)
        attack_y.append(attack_rate)

        eps = round(eps + 0.01, 2)

    return attack_x, attack_y


def delete_debug(model, X_test, Y_test, X_train_tmp, X_test_tmp, Y_train_reduced, Y_test_reduced):
    # take malware data from testing dataset
    X_test_mal = []
    X_test_mal_reduced = []

    X_train_reduced, X_test_reduced = dimension_reduction.dimension_reduction(X_train_tmp, X_test_tmp,
                                                                                      Y_train_reduced)
    for m in range(len(X_test)):
        if Y_test[m] == 1:
            X_test_mal.append(X_test[m][:])

    for m in range(len(X_test_reduced)):
        if Y_test_reduced[m] == 1:
            X_test_mal_reduced.append(X_test_reduced[m][:])

    target_num = cf.get_value("mal_debug")
    print("AE malware:", target_num)

    # input adversarial examples(malware -> "clean") to the model
    # attack success rate = success_num/target_num
    success_num = 0
    for ii in range(len(X_test_mal_reduced)):
        X_AE_test = np.array(X_test_mal_reduced[ii]).reshape(1,-1)
        Y_AE_test = model.predict(X_AE_test)
        X_prediction = np.array(X_test_mal[ii]).reshape(1,-1)
        Y_prediction = model.predict(X_prediction)
        if Y_AE_test == 0 and Y_prediction == 1:
            success_num = success_num + 1

    attack_rate = round(100 * (success_num / target_num), 2)
    print("Attack rate:", attack_rate)

    return attack_rate
