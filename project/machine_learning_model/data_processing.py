# _*_coding:utf-8 _*_

# @Time      :2020/01/03 10:50

# @Author    : Wanjia Zheng

# @File      :data_processing.py

# @Software  :PyCharm

import os
import sys
import numpy as np
import config as cf
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import HashingVectorizer


def feature_engineer_text(path, data_count):
    count = 0
    flag = 0
    text_features = []

    for root, dirs, files in os.walk(path):
        for file in files:
            file_path = "{0}{1}".format(root, file)
            if count > data_count-1:
                count = 0
                break
            count = count + 1
            with open(file_path,'r') as f:
                image_dos_header = ''
                image_nt_headers = ''
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
                    # elif line.find(".dll") != -1:
                    #     flag = 9
                    #     continue
                    # elif line.find("[IMAGE_DEBUG_") != -1:
                    #     flag = 10
                    #     continue
                    elif line.find("-----") != -1 or line.find("0x") == -1:
                        flag = 0
                        continue
                    else :
                        if flag == 1:
                            image_dos_header = "{0}{1} ".format(image_dos_header, ' '.join(line.split()[2:]))
                        elif flag == 2:
                            image_nt_headers = "{0}{1} ".format(image_nt_headers, ' '.join(line.split()[2:]))
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
                        "{0}{1}{2}{3}{4}{5}{6}{7}".format(
                            image_dos_header, image_nt_headers,
                            image_file_header, image_optional_header, image_section_header,
                            image_directory, image_import, image_resource).strip()
                     ]
                )

                flag = 0

    return text_features


def feature_engineer_alltext(path, data_count):
    count = 0
    text_features = []

    for root, dirs, files in os.walk(path):
        for file in files:
            if file.find(".txt") != -1:
                file_path = "{0}{1}".format(root, file)
                if count > data_count-1:
                    count = 0
                    break
                count = count + 1
            else:
                continue

            with open(file_path, 'r') as f:
                lines = f.readlines()
                text_features.append(["{0}".format(lines).strip()])

    return text_features


def feature_engineer_alltext_nodebug(path, data_count):
    count = 0
    line_count = 0
    debug_file_count = 0
    flag = 0
    text_features = []

    for root, dirs, files in os.walk(path):
        for file in files:
            if file.find(".txt") != -1:
                file_path = "{0}{1}".format(root, file)
                if count > data_count-1:
                    count = 0
                    break
                count = count + 1
            else:
                continue

            with open(file_path, 'r') as f:
                lines = f.readlines()
                lines_tmp = lines
                for line in lines_tmp:
                    if line.find("Debug information") != -1:
                        flag = 1
                        debug_file_count = debug_file_count + 1
                    elif line.find("-----") != -1:
                        flag = 0
                    if flag == 1:
                        del(lines[line_count])
                    line_count = line_count + 1
                text_features.append(["{0}".format(lines).strip()])

            flag = 0
            line_count = 0

    if path.find("cleanware") != -1:
        print(path, debug_file_count)
        cf.set_value("clean_debug", debug_file_count)
    elif path.find("malware") != -1:
        print(path, debug_file_count)
        cf.set_value("mal_debug", debug_file_count)
    print(path, debug_file_count)
    return text_features


def load_dataset(fe_type='pe_header'):
    # set the path of dataset
    clean_path = "/Users/wanjiazheng/データセット/FFRIDataset2018/cleanware/"
    malware_path = "/Users/wanjiazheng/データセット/FFRIDataset2018/malware/"
    texts = ""
    data_count = cf.get_value("data_count")

    # load the dataset and do the feature engineering to the dataset
    if fe_type == 'pe_header':
        clean_texts = feature_engineer_text(clean_path, data_count)
        malware_texts = feature_engineer_text(malware_path, data_count)
        texts = clean_texts + malware_texts
    elif fe_type == 'all_text':
        clean_texts = feature_engineer_alltext(clean_path, data_count)
        malware_texts = feature_engineer_alltext(malware_path, data_count)
        texts = clean_texts + malware_texts
    elif fe_type == 'all_text_nodebug':
        clean_texts = feature_engineer_alltext_nodebug(clean_path, data_count)
        malware_texts = feature_engineer_alltext_nodebug(malware_path, data_count)
        texts = clean_texts + malware_texts

    # combine malware and clean files to a data
    datasets = np.array(texts, dtype=object)
    datasets = datasets.reshape(data_count * 2, 1)
    return datasets


def hashing_trick(feature_count, X_texts):
    # transfer texts to number
    vectorizer = HashingVectorizer(n_features=feature_count)
    data_count = cf.get_value("data_count")

    for h in range(data_count * 2):
        if h == 0:
            datasets_3 = vectorizer.fit_transform(X_texts[0]).toarray()
        else:
            datasets_tmp = vectorizer.fit_transform(X_texts[h]).toarray()
            datasets_3 = np.insert(datasets_3, 0, values=datasets_tmp, axis=0)

    X = np.array(datasets_3)

    return X


def data_processing(feature_count, fe_type='pe_header'):
    data_count = cf.get_value("data_count")
    X_texts = load_dataset(fe_type)
    X = hashing_trick(feature_count, X_texts)

    # set labels: malware as 1, clean files as 0
    mal_label = np.ones((data_count, 1))*1
    clean_label = np.ones((data_count, 1))*0
    Y = np.append(clean_label, mal_label, axis=0)

    # divide the train data and tests data(train 9,tests 1)
    X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.1, random_state=0)
    np.set_printoptions(threshold=np.inf)  # print more detail

    return X_train, X_test, Y_train, Y_test

