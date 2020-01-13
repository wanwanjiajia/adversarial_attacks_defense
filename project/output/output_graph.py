# _*_coding:utf-8 _*_

# @Time      :2020/01/03 12:27

# @Author    : Wanjia Zheng

# @File      :output_graph.py

# @Software  :PyCharm

import matplotlib.pyplot as plt
import config as cf
import datetime


def output_graph(attack_x, attack_y, fig_name):
    plt.rcParams['font.family'] = 'Times New Roman'  # font familyの設定
    plt.rcParams['mathtext.fontset'] = 'stix'  # math fontの設定
    plt.rcParams["font.size"] = 15  # 全体のフォントサイズが変更されます。
    plt.rcParams['xtick.direction'] = 'in'  # x axis in
    plt.rcParams['ytick.direction'] = 'in'  # y axis in
    plt.rcParams['axes.linewidth'] = 1.0  # axis line width

    d_now = datetime.date.today()

    # drawing pictures of attack success rate
    format_str = ['b-.', 'g--', 'c:', 'y', 'r-']
    plt.xlabel('$\epsilon$', fontsize=15)
    plt.ylabel("Attack_Success_Rate(%)", fontsize=10)
    plt.axis([0, 1.0, 0, 100])

    for i in range(5):
        line, = plt.plot(attack_x[i], attack_y[i], format_str[i])
        print("attack_y:", max(attack_y[i]))
        if i == 3: line.set_dashes((10, 2))
    plt.legend(['No Dimension Reduction(3000D)', 'PCA(100D)', 'PCA(10D)', 'PCA(1D)', 'LDA(1D)'], fontsize=10)

    plt.tight_layout()
    plt.savefig("../experiments/"+fig_name+"_"+str(d_now)+".jpg")
    plt.show()
