# _*_coding:utf-8 _*_

# @Time      :2020/01/03 11:52

# @Author    : Wanjia Zheng

# @File      :model_training.py

# @Software  :PyCharm

import sklearn.ensemble
from sklearn import svm
from sklearn.discriminant_analysis import LinearDiscriminantAnalysis


def rf():
    model = sklearn.ensemble.RandomForestClassifier(max_depth=None,
                                                    n_estimators=10,
                                                    bootstrap=False,
                                                    criterion='entropy', random_state=0)
    return model


def svm_rbf(X_train_reduced, Y_train):
    model = svm.SVC()
    model_attack = model
    model_attack.fit(X_train_reduced, Y_train.ravel())
    return model, model_attack


def svm_linear(X_train_reduced, Y_train):
    model = svm.LinearSVC(C=1, random_state=0)
    model_attack = model
    model_attack.fit(X_train_reduced, Y_train.ravel())
    return model, model_attack


def lda():
    model = LinearDiscriminantAnalysis(n_components=1)
    return model
