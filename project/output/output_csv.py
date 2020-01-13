# _*_coding:utf-8 _*_

# @Time      :2020/01/03 12:27

# @Author    : Wanjia Zheng

# @File      :output_csv.py

# @Software  :PyCharm

import config as cf
import numpy as np
import datetime


def output_csv_data(model_type, dimen_reduc_type, feature_count, f1, precision, recall, auc,
                    eugrid_distance, mmd_distance, energy_distance, elapsed_time, attack_rate):

    output_data = cf.get_value("output_data")
    output_data.append([model_type, dimen_reduc_type, feature_count, f1, precision, recall, auc,
                        eugrid_distance, mmd_distance, energy_distance, elapsed_time, attack_rate])
    cf.set_value("output_data", output_data)


def output_csv(csv_name):
    output_data = cf.get_value("output_data")
    d_now = datetime.date.today()
    title = [["Model Type", "Dimension Reduction Method", "Feature Count",
              "F-Measure", "Precision", "Recall", "AUC",
              "Eugrid Distance", "MMD Distance", "Energy Distance", "Elapsed_Time", "Attack_Rate_Nodebug"]]

    np.savetxt("../experiments/" + csv_name + "_" + str(d_now) + ".csv", X=np.array(title+output_data),
               fmt='%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s', delimiter=",")
