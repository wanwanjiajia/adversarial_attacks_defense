import numpy as np
import os
import time
import random
from sklearn import svm
from sklearn.model_selection import train_test_split
from sklearn.decomposition import PCA
import matplotlib.pyplot as plt
from sklearn.feature_extraction.text import HashingVectorizer
import sklearn.ensemble
from sklearn.model_selection import cross_validate
from sklearn.discriminant_analysis import LinearDiscriminantAnalysis

import MMD_Distance
import Energy_Distance

def pca_visulation(X_train, Y_train, X_test, dim):
    pca = PCA(n_components=dim)
    X_pca_train = np.array(pca.fit_transform(X_train))
    X_pca_test = pca.transform(X_test)
    print(pca.explained_variance_ratio_)

    # draw figure of train dataset and test dataset
    # X_pca_train_clean = np.array([[0., 0., 0.]])
    # X_pca_train_mal = np.array([[0., 0., 0.]])
    # ax = plt.subplot(111, projection='3d')
    # for i in range(0, Y_train.shape[0]):
    #     if Y_train[i] == [1]:
    #         X_pca_train_clean = np.insert(X_pca_train_clean, 0, X_pca_train[i], axis=0)
    #     else:
    #         X_pca_train_mal = np.insert(X_pca_train_mal, 0, X_pca_train[i], axis=0)
    #
    # ax.scatter(X_pca_train_clean[:, 0], X_pca_train_clean[:, 1], X_pca_train_clean[:, 2], c='y')
    # ax.scatter(X_pca_train_mal[:, 0], X_pca_train_mal[:, 1], X_pca_train_mal[:, 2], c='r')
    #
    # ax.set_zlabel('Z')
    # ax.set_ylabel('Y')
    # ax.set_xlabel('X')
    #
    # plt.show()

    return X_pca_train, X_pca_test

def feature_engineer_class(hash, type):

    if type == 1:
        tests = np.loadtxt("cleanware.csv", delimiter=",", skiprows=1, dtype=bytes).astype(str)[:, :]
    else:
        tests = np.loadtxt("malware.csv", delimiter=",", skiprows=1, dtype=bytes).astype(str)[:, :]

    hashes = tests[:, 3].tolist()
    print(hash)

    if hash in hashes:
        hash_index = hashes.index(hash)
    else:
        hash_index = -1
    print(hash_index)
    if hash_index != -1:
        # Platform,GUI Program,Console,Program,DLL,Packed,Anti-Debug,mutex,contains,base64
        dataset = tests[hash_index, 13:20]
        if dataset[0].find("32 bit") != -1: dataset[0] = -1
        else: dataset[0] = 1
        for i in range(1, 7):
            if dataset[i].find("no (yes)") != -1: dataset[i] = 0
            elif dataset[i].find("no") != -1: dataset[i] = -1
            else: dataset[i] = 1
    else:
        dataset = [2,2,2,2,2,2,2,2,2]
    return dataset

def feature_engineer_text(path, type, data_count):
    count = 0
    flag = 0
    text_features = []
    hash_features = []

    for root, dirs, files in os.walk(path):
        for file in files:
            file_path = "{0}{1}".format(root,file)
            if count > data_count-1:
                count = 0
                break
            count = count + 1
            with open(file_path,'r') as f:
                image_dos_header = ''
                image_NT_headers = ''
                image_file_header = ''
                image_optional_header = ''
                image_section_header = ''
                image_directory = ''
                image_import = ''
                image_resource = ''
                dll = ''
                debug = ''
                for line in f:
                    if line.find("[IMAGE_DOS_HEADER]") != -1:
                        flag = 1
                        continue
                    elif line.find("[IMAGE_NT_HEADERS]") != -1:
                        flag = 2
                        continue
                    elif line.find("[IMAGE_FILE_HEADER]") != -1:
                        flag = 3
                        continue
                    elif line.find("[IMAGE_OPTIONAL_HEADER]") != -1:
                        flag = 4
                        continue
                    elif line.find("[IMAGE_SECTION_HEADER]") != -1:
                        flag = 5
                        continue
                    elif line.find("[IMAGE_DIRECTORY_") != -1:
                        flag = 6
                        continue
                    elif line.find("[IMAGE_IMPORT_") != -1:
                        flag = 7
                        continue
                    elif line.find("[IMAGE_RESOURCE_") != -1:
                        flag = 8
                        continue
                    elif line.find(".dll") != -1:
                        flag = 9
                        dll = "{0}{1}".format(dll, ' '.join(line.split()[0]))
                        continue
                    elif line.find("[IMAGE_DEBUG_") != -1:
                        flag = 10
                        continue
                    elif line.find("-----") != -1 or line.find("0x") == -1:
                        flag = 0
                        continue
                    else :
                        if flag == 1:
                            image_dos_header = "{0}{1} ".format(image_dos_header, ' '.join(line.split()[2:]))
                        elif flag == 2:
                            image_NT_headers = "{0}{1} ".format(image_NT_headers, ' '.join(line.split()[2:]))
                        elif flag == 3:
                            image_file_header = "{0}{1} ".format(image_file_header, ' '.join(line.split()[2:]))
                        elif flag == 4:
                            image_optional_header = "{0}{1} ".format(image_optional_header, ' '.join(line.split()[2:]))
                        elif flag == 5:
                            image_section_header = "{0}{1} ".format(image_section_header, ' '.join(line.split()[2:]))
                        elif flag == 6:
                            image_directory = "{0}{1} ".format(image_directory, ' '.join(line.split()[2:]))
                        elif flag == 7:
                            image_import = "{0}{1} ".format(image_import, ' '.join(line.split()[2:]))
                        elif flag == 8:
                            image_resource = "{0}{1} ".format(image_resource, ' '.join(line.split()[2:]))
                        elif flag == 9:
                            dll = "{0}{1}".format(dll, ' '.join(line.split()[0]))
                        elif flag == 10:
                            debug = "{0}{1}".format(debug, ' '.join(line.split()[2:]))
                text_features.append(
                    [
                        "{0}{1}{2}{3}{4}{5}{6}{7}{8}{9}".format(image_dos_header, image_NT_headers,
                                                 image_file_header, image_optional_header, image_section_header,
                                                image_directory, image_import, image_resource, dll, debug).strip()
                     ]
                )

                #hash_feature = '"{0}"'.format(file.replace(".txt",""))
                #hash_features.append(feature_engineer_class(hash_feature, type))
                flag = 0

    return text_features,hash_features

def draw_2d_bar(x, y):
    plt.bar(x, y, label="test")

    plt.xlabel("num")
    plt.ylabel("distance")
    plt.legend(loc="upper right")
    plt.show()

def draw_2d_roc(x, y):
    plt.figure(figsize=(10, 10))
    plt.plot(fpr, tpr, color='darkorange',
             lw=2, label='ROC curve (area = %0.2f)' % roc_auc)


def main():
    # load dataset (clean:5000, malware:5000)
    data = []
    fig_count = 0

    plt.rcParams['font.family'] = 'Times New Roman'  # font familyの設定
    plt.rcParams['mathtext.fontset'] = 'stix'  # math fontの設定
    plt.rcParams["font.size"] = 15  # 全体のフォントサイズが変更されます。
    plt.rcParams['xtick.direction'] = 'in'  # x axis in
    plt.rcParams['ytick.direction'] = 'in'  # y axis in
    plt.rcParams['axes.linewidth'] = 1.0  # axis line width

    for r in range(1):
        data_count = 3000
        feature_count = [3000,2500,2000,1500,1000]
        mode_type = ['RF','SVM(Linear)','SVM(RBF)','LDA']

        mal_label = np.ones((data_count,1))*(1)
        clean_label = np.ones((data_count,1))*(0)

        print("*** Features Engineer Started ***")
        clean_path = "/Users/wanjiazheng/データセット/FFRIDataset2018/cleanware/"
        malware_path = "/Users/wanjiazheng/データセット/FFRIDataset2018/malware/"
        clean_texts,clean_hash = feature_engineer_text(clean_path, 1, data_count)
        malware_texts,malware_hash = feature_engineer_text(malware_path, -1, data_count)
        texts = clean_texts + malware_texts

        datasets_2 = np.array(texts).reshape(data_count*2,1)
        vectorizer = HashingVectorizer(n_features=3000)
        for h in range(data_count*2):
            if h==0:
                datasets_3 = vectorizer.fit_transform(datasets_2[0]).toarray()
            else:
                datasets_tmp = vectorizer.fit_transform(datasets_2[h]).toarray()
                datasets_3 = np.insert(datasets_3, 0, values=datasets_tmp, axis=0)

        print("*** Features Engineer End ***")

        # transfer data format to int32

        X = np.array(datasets_3)

        Y = np.append(clean_label, mal_label, axis=0)
        # divide the train data and test data(train 9,test 1)
        X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.1, random_state=0)
        np.set_printoptions(threshold=np.inf)

        attack_x = [[] for i in range(5)]
        attack_y = [[] for i in range(5)]

        for j in range(1):

            print("*** Dimension Reduction Started ***")
            if j == 0:
                fig_title = "No Dimension Reduction(3000)"
                X_pca_train = X_train
                X_pca_test = X_test
            if j == 1:
                fig_title = "PCA(100D)"
                pca = PCA(n_components=100)
                X_pca_train = np.array(pca.fit_transform(X_train))
                X_pca_test = pca.transform(X_test)
            if j == 2:
                fig_title = "PCA(10D)"
                pca = PCA(n_components=10)
                X_pca_train = np.array(pca.fit_transform(X_train))
                X_pca_test = pca.transform(X_test)
            if j == 3:
                fig_title = "PCA(1D)"
                pca = PCA(n_components=1)
                X_pca_train = np.array(pca.fit_transform(X_train))
                X_pca_test = pca.transform(X_test)
                fig_count = fig_count+1
            if j == 4:
                fig_title = "LDA(1D)"
                lda = LinearDiscriminantAnalysis(n_components=1)
                X_pca_train = lda.fit_transform(X_train,Y_train.ravel())
                X_pca_test = lda.transform(X_test)
                fig_count = fig_count+1

            print("*** Dimension Reduction Ended ***")

            tmp_mal = []
            tmp_clean = []
            for i in range(X_pca_train.shape[0]):
                if Y_train[i] == 1:
                    tmp_mal.append(X_pca_train[i][:])
                else:
                    tmp_clean.append(X_pca_train[i][:])

            if len(tmp_clean) > len(tmp_mal):
                mmd_mal = tmp_mal
                mmd_clean = random.sample(tmp_clean, len(tmp_mal))
            else :
                mmd_mal = random.sample(tmp_clean, len(tmp_clean))
                mmd_clean = tmp_clean

            if j != 0 and j!= 1:
                mmd_distance = MMD_Distance.mmd_rbf(mmd_clean, mmd_mal)
                print("MMD Distance: ",mmd_distance)
            else:
                mmd_distance = 0

            print(len(mmd_mal))
            print(len(mmd_clean))
            energy_distance = Energy_Distance.ed(mmd_clean, mmd_mal)
            print("Energy Distance:", energy_distance)

            # Distance self calculation #
            # for ii in range(len(tmp_clean)):
            #     for jj in range(len(tmp_mal)):
            #         distance_tmp = []
            #         distance_tmp.append(np.linalg.norm(tmp_clean[ii][:] - tmp_mal[jj][:]))
            #     distance_sum.append(np.mean(distance_tmp))
            # distance_self = round(np.mean(distance_sum),2)

            distance_self = np.linalg.norm(np.array(mmd_clean)-np.array(mmd_mal))
            print("Eugrid Distance:", distance_self)

            print("*** Model Training Started ***")
            for n in range(3):

                t = time.process_time()
                if n == 0:
                    model = sklearn.ensemble.RandomForestClassifier(max_depth=None,
                                  n_estimators=10,
                                  bootstrap=False,
                                  criterion='entropy', random_state=0)
                elif n == -1:
                    model = svm.SVC()
                    model.fit(X_pca_train, Y_train.ravel())
                elif n == 1:
                    model = svm.LinearSVC(C=1,random_state=0)
                    print("*** Model Attack Start ***")
                    model.fit(X_pca_train, Y_train.ravel())
                    w = model.coef_
                    test_mal = []
                    for m in range(len(X_pca_test)):
                        if Y_test[m] == 1:
                            test_mal.append(X_pca_test[m][:])
                    # for m in range(len(X_pca_train)):
                    #     if Y_train[m] == 0:
                    #         test_mal.append(X_pca_train[m][:])

                    # for m in range(len(X_test)):
                    #     if Y_test[m] == 0:
                    #         test_mal.append(X_test[m][:])
                    # for m in range(len(X_train)):
                    #     if Y_train[m] == 0:
                    #         test_mal.append(X_train[m][:])

                    target_num = len(test_mal)
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
                        attack_x[j].append(eps)
                        attack_y[j].append(attack_rate)
                        eps = round(eps + 0.01, 2)
                    print("attack_y:", attack_y[j])
                    print("*** Model Attack Ended ***")
                else:
                    model = LinearDiscriminantAnalysis(n_components=1)


                print("Model:", n)
                scores = cross_validate(model, X_pca_train, Y_train.ravel(), cv=10,
                                        scoring=['precision', 'f1', 'accuracy', 'recall'], return_train_score=False)
                elapsed_time = time.process_time() - t
                auc = str(round(100 * scores['test_accuracy'].mean(), 2)) + "%"
                recall = str(round(100 * scores['test_recall'].mean(), 2)) + "%"
                f1 = str(round(100 * scores['test_f1'].mean(), 2)) + "%"
                precision = str(round(100 * scores['test_precision'].mean(), 2)) + "%"
                # tp, fn, fp, tn = metrics.confusion_matrix(Y_test, Y_predict).ravel()

                # Y_predict = model.predict(X_pca_test)
                # precision = precision_score(Y_test, Y_predict)
                # recall = recall_score(Y_test, Y_predict)
                # f1 = f1_score(Y_test, Y_predict)
                # auc = roc_auc_score(Y_test, Y_predict)
                data.append([mode_type[n], fig_title, feature_count[r], f1, precision, recall, auc,
                             distance_self, mmd_distance, energy_distance, elapsed_time])
            print("*** Model Training Ended ***")

    # drawing pictures of attack success rate
    format_str = ['b-.', 'g--', 'c:', 'y', 'r-']

    #label = ['No Dimension Reduction', 'LDA(1D)','PCA(1D)', 'PCA(10D)', 'PCA(100D)']
    plt.xlabel('$\epsilon$', fontsize=15)
    plt.ylabel("Attack_Success_Rate(%)", fontsize=10)
    plt.axis([0, 1.0, 0, 100])
    for j in range(5):
        line, = plt.plot(attack_x[j], attack_y[j],format_str[j])
        if j == 3: line.set_dashes((10,2))
    plt.legend(['No Dimension Reduction(3000D)', 'PCA(100D)', 'PCA(10D)', 'PCA(1D)', 'LDA(1D)'],fontsize=10)

    plt.tight_layout()
    plt.savefig("result.jpg")
    plt.show()
    # title = [["FeatureHashingTrick(Feature_Count)", "Dimension Reduction Method", "F measure", "Recall", "AUC",
    #           "Distance_self", "Distance_MMD", "Distance_Energy", "Robustness", "Elapsed_Time"]]
    # np.savetxt("result.csv",X=np.array(title),fmt='%s', delimiter=",")
    np.savetxt("result.csv",X=np.array(data), fmt='%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s', delimiter=",")

if __name__ == "__main__":
    main()