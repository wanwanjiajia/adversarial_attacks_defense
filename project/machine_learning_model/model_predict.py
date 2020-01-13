# _*_coding:utf-8 _*_

# @Time      :2020/01/03 12:20

# @Author    : Wanjia Zheng

# @File      :model_predict.py

# @Software  :PyCharm

from sklearn.model_selection import cross_validate


def model_predict(model, X_train_reduced, Y_train):
    scores = cross_validate(model, X_train_reduced, Y_train.ravel(), cv=10,
                            scoring=['precision', 'f1', 'accuracy', 'recall'], return_train_score=False)
    auc = str(round(100 * scores['test_accuracy'].mean(), 2)) + "%"
    recall = str(round(100 * scores['test_recall'].mean(), 2)) + "%"
    f1 = str(round(100 * scores['test_f1'].mean(), 2)) + "%"
    precision = str(round(100 * scores['test_precision'].mean(), 2)) + "%"
    return auc, recall, f1, precision

