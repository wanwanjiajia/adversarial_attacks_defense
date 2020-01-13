# _*_coding:utf-8 _*_

# @Time      :2020/01/02 16:49

# @Author    : Wanjia Zheng

# @File      :__main__.py

# @Software  :PyCharm

import time
import config as cf
from distance_calculation import *
from machine_learning_model import *
from output import *


def main():
    cf.init()  # config global var
    cf.set_value("output_data", [])
    cf.set_value("dimen_reduc_type", 0)
    cf.set_value("data_count", 3000)
    cf.set_value("feature_count", 3000)
    data_count = cf.get_value("data_count")
    feature_count = cf.get_value("feature_count")

    fe_type_num = 0
    output_file_name = "result_pe_"+str(data_count)

    attack_x = [[] for i in range(5)]
    attack_y = [[] for i in range(5)]
    attack_rate_nodebug = [[] for i in range(5)]

    dimen_reduc_type = ["No Dimension Reduction("+str(data_count)+")", "PCA(100D)", "PCA(10D)", "PCA(1D)", "LDA(1D)"]
    model_type = ['RF', 'SVM(Linear)', 'LDA']
    fe_type = ['pe_header', 'all_text', 'all_text_nodebug']

    # dataset_processing
    #   -> loading dataset(clean:5000, malware:5000)
    #   -> feature engineering
    #   -> hashing function
    #   -> divide dataset(test:1, train:9)

    if fe_type_num == 0:
        X_train_all, X_test_all, Y_train_all, Y_test_all = data_processing.data_processing(feature_count,
                                                                                           fe_type[0])
    else:
        X_train_all, X_test_all, Y_train_all, Y_test_all = data_processing.data_processing(feature_count,
                                                                                           fe_type[1])
        X_train_tmp, X_test_tmp, Y_train_reduced, Y_test_reduced = data_processing.data_processing(feature_count,
                                                                                           fe_type[2])

    j = cf.get_value("dimen_reduc_type")
    while j < len(dimen_reduc_type):
        print("dimen_reduc", dimen_reduc_type[j])
        # do dimension reduction to X axis
        X_train_reduced_all, X_test_reduced_all = dimension_reduction.dimension_reduction(X_train_all, X_test_all, Y_train_all)

        # select training data to calculate the distances
        distance_mal, distance_clean = distance_data.distance_data(X_train_reduced_all, Y_train_all)

        # mmd distance
        if j != 0 and j != 1:
            mmd_distance = md_distance.mmd_rbf(distance_clean, distance_mal)
        else:
            mmd_distance = 0
        # energy distance
        energy_distance = energi_distance.ed(distance_clean, distance_mal)
        # eugrid distance
        eugrid_distance = eugri_distance.ed(distance_clean, distance_mal)

        for n in range(3):
            t = time.process_time()
            if n == 0:
                model_all = model_training.rf()
            elif n == -1:
                model_all = model_training.svm_rbf(X_train_reduced_all, Y_train_all)
            elif n == 1:
                model_all, model_attack = model_training.svm_linear(X_train_reduced_all, Y_train_all)

                attack_x_tmp, attack_y_tmp = model_attacks.svm_attack(model_attack, X_test_reduced_all, Y_test_all)
                attack_x[j] = attack_x_tmp
                attack_y[j] = attack_y_tmp

                if fe_type_num != 0:
                    attack_rate_nodebug_tmp = model_attacks.delete_debug(model_attack, X_test_reduced_all, Y_test_all,
                                                                         X_train_tmp, X_test_tmp, Y_train_reduced, Y_test_reduced)
                    attack_rate_nodebug[j] = attack_rate_nodebug_tmp

            else:
                model_all = model_training.lda()

            # cross validate
            if n != 2:
                f1, precision, recall, auc = model_predict.model_predict(model_all, X_train_reduced_all, Y_train_all)
            else:
                f1, precision, recall, auc = model_predict.model_predict(model_all, X_test_reduced_all, Y_test_all)
            elapsed_time = time.process_time() - t

            output_csv.output_csv_data(model_type[n], dimen_reduc_type[j], feature_count,
                                       f1, precision, recall, auc,
                                       eugrid_distance, mmd_distance, energy_distance, elapsed_time,
                                       attack_rate_nodebug[j])

        j = j + 1
        cf.set_value("dimen_reduc_type", j)

    output_graph.output_graph(attack_x, attack_y, output_file_name)
    # output_graph.output_graph(attack_x_all, attack_y_all, "result_all")
    output_csv.output_csv(output_file_name)


if __name__ == "__main__":
    main()

