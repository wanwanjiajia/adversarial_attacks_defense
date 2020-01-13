# _*_coding:utf-8 _*_

# @Time      :2020/01/03 10:34

# @Author    : Wanjia Zheng

# @File      :config.py

# @Software  :PyCharm


def init():  # init
    global _global_dict
    _global_dict = {}


def set_value(key, value):
    _global_dict[key] = value


def get_value(key, defValue=None):
    try:
        return _global_dict[key]
    except KeyError:
        return 0
