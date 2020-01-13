# _*_coding:utf-8 _*_

# @Time      :2020/01/03 11:21

# @Author    : Wanjia Zheng

# @File      :dimension_reduction.py

# @Software  :PyCharm

import numpy as np
import config as cf
from sklearn.decomposition import PCA
from sklearn.discriminant_analysis import LinearDiscriminantAnalysis


def dimension_reduction(X_train, X_test, Y_train):
    reduce_type = cf.get_value("dimen_reduc_type")
    if reduce_type == 0:
        X_pca_train = X_train
        X_pca_test = X_test
    if reduce_type == 1:
        pca = PCA(n_components=100)
        X_pca_train = np.array(pca.fit_transform(X_train))
        X_pca_test = pca.transform(X_test)
    if reduce_type == 2:
        pca = PCA(n_components=10)
        X_pca_train = np.array(pca.fit_transform(X_train))
        X_pca_test = pca.transform(X_test)
    if reduce_type == 3:
        pca = PCA(n_components=1)
        X_pca_train = np.array(pca.fit_transform(X_train))
        X_pca_test = pca.transform(X_test)
    if reduce_type == 4:
        lda = LinearDiscriminantAnalysis(n_components=1)
        X_pca_train = lda.fit_transform(X_train, Y_train.ravel())
        X_pca_test = lda.transform(X_test)

    return X_pca_train, X_pca_test
