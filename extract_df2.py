## coding:utf-8

from cgi import test
from cmath import pi
from hashlib import new
import re
from joern.all import JoernSteps
from igraph import *
from access_db_operate import *
from slice_op2 import *
from access_db_operate import *
from py2neo.packages.httpstream import http
import json
from optparse import OptionParser

http.socket_timeout = 9999

def read_file(file_name):
    fr = open(file_name, 'r')
    lines = fr.readlines()
    fr.close()
    return lines

def write_to_file(file_name, str_output):
    fw = open(file_name, 'a+')
    fw.write(str_output)
    fw.close()

def ext_diff_funcname2dic(diff_name):
    new_dict = {}
    old_dict = {}

    lines = read_file(diff_name)
    for line in lines:
        if line.startswith("@@"):
            if "(" in line:
                func_name_raw = line.split("(")[0].strip().split(" ")[-1]
            else:
                if '{' in line:
                    func_name_raw = 'struct'
                else:
                    func_name_raw = 'none'

            if func_name_raw.startswith("*") or func_name_raw.startswith("&"):
                func_name= func_name_raw[1:]
            func_name = func_name_raw
            
            str_new_line = line.split("+")[-1].split(',')[0].strip()
            str_old_line = line[4:].split(",")[0].strip()

            new_line = int(str_new_line)
            old_line = int(str_old_line)

            new_dict[new_line] = func_name
            old_dict[old_line] = func_name
    
    return old_dict, new_dict

def funcname_for_changeline(line_num, dict):
    line_list = []
    for line_in_dict in dict.keys():
        line_list.append(line_in_dict)
    
    line_list.sort()

    line_res = line_list[0]
    for line in line_list:
        if line_num < line:
            break
        line_res = line
    
    func_name = dict[line_res]

    return func_name

def var_preprocess(variable_name):
    query_var = ''
    count = 0
    index = variable_name.find("->")

    for ch in variable_name:
        query_var += ch
        if ch == "&" or ch == ".":
            query_var = query_var[:-1]
            query_var += ' '
            query_var += ch
            query_var += ' '
        if ch == '*':
            query_var = query_var[:-1]
            query_var.strip()
        if index != -1:
            if count == index:
                query_var = query_var[:-1]
                query_var += ' '
                query_var += ch
            elif count == index + 1:
                query_var += ' '
        count += 1
    if "[" in query_var:
        query_var = query_var.split('[')[0] 
    return query_var
    
def query_funcnode_of_file(db, file_name):
    query = 'queryNodeIndex("type:File AND filepath:*%s*").out()' % file_name
    #query = 'queryNodeIndex("type:File AND name:*%s*").out()' % file_name
    func_nodes = db.runGremlinQuery(query)
    #print('func_nodes:')
    #print(func_nodes)
    
    if func_nodes == []:
        return []
    return func_nodes

def query_funcnode_fileinfo_by_name(db, func_name):
    query_with_var = 'getFunctionsByName("*%s*").in' % func_name
    try:
        file_info_list = db.runGremlinQuery(query_with_var)
    except:
        return []
    if file_info_list == []:
        return []
    return file_info_list

def query_funcnode_by_name(db, func_name):
    query_with_var = 'getFunctionsByName("*%s*")' % func_name
    func_node = db.runGremlinQuery(query_with_var)
    if func_node == []:
        return []
    return func_node

def query_node_by_funcid_loc(db, funcid, loc):
    query_with_var = 'queryNodeIndex("functionId:%d AND location:*%s*")' % (funcid, loc)
    node_list = db.runGremlinQuery(query_with_var)
    if node_list == []:
        return []
    for node in node_list[:]:
        node_loc = node['location']
        loc_str = node_loc.encode('unicode-escape').decode('string_escape')
        if node['code'] == '':
            node_list.remove(node)
            continue
        if not loc_str.startswith(str(loc)):
            node_list.remove(node)
    return node_list

def query_node_by_var_loc(db, query_var, location):
    query_with_var = 'queryNodeIndex("code:*%s* AND location:*%s*")' % (query_var, location)
    can_nodes = db.runGremlinQuery(query_with_var)
    if can_nodes == []:
        return []
    for node in can_nodes[:]:
        node_loc = node['location']
        loc_str = node_loc.encode('unicode-escape').decode('string_escape')
        if not loc_str.startswith(str(location)):
            can_nodes.remove(node)
    return can_nodes

def query_filename_of_funcid(db, funcid):
    query_with_var = 'g.v(%d).in()' % funcid
    can_nodes = db.runGremlinQuery(query_with_var)
    if can_nodes == []:
        return []
    return can_nodes


'''
查询方案：
    1. 先通过func_name查是否有该名称的函数节点，并输出该节点的父节点file节点信息
    2. 检查file节点信息，是否存在本文件的节点
    3. 再通过函数节点的funcid和loc共同查询
存在问题：
    1. func_name可能不准确
'''
def get_startnode_p1(db, func_name, file_name, loc):
    file_info_list = query_funcnode_fileinfo_by_name(db ,func_name)
    if file_info_list == []:
        return ['2'] #没有这个函数

    count = -1
    flag = 0
    for file_info in file_info_list:
        count += 1
        file_path = file_info['filepath']
        #print(file_path)
        if file_name in file_path:
            flag = 1
            break
    
    if flag == 0:
        return ['2'] #没有该函数
    
    node_list = query_funcnode_by_name(db, func_name)
    if node_list == []:
        return ['2'] #没有这个函数

    func_node = node_list[count]
    funcid = func_node._id
    
    node_list = query_node_by_funcid_loc(db, funcid, loc)
    
    if node_list == []:
        return ['3'] #没有合适的节点
    
    return node_list[0]


'''
查询方案：
    1. 先通过file_name查这个文件所有函数节点
    2. 匹配上述节点的funcid和已知的loc
    3. 由于一个文件中，代码行数是唯一标识符，所以能够选取startnode
存在问题：
    1. 速度比较慢
'''
def get_startnode_p2(db, file_name, loc):
    #file_name = "testCode/" + file_name
    func_nodes = query_funcnode_of_file(db, file_name)
    if func_nodes == []:
        return ['1'] #没有这个文件

    funcid = 0
    for node in func_nodes:
        funcid = node._id
        node_list = query_node_by_funcid_loc(db, funcid, loc)
        if node_list != []:
            return node_list[0]

    return ['2'] #没有这个点


'''
查询方案：
    1. 先通过var和loc查找
    2. 匹配上述节点的funcid的file_name
存在问题：
    1. var不一定准确
'''
def get_startnode_p3(db, var, loc, file_name):
    query_var = var_preprocess(var)
    node_list = query_node_by_var_loc(db, query_var, loc)
    if node_list == []:
        return ['2'] #查不到该点
    for node in node_list:
        funcid = node['functionId']
        file_info_list = query_filename_of_funcid(db, funcid)
        for file_info in file_info_list:
            file_path = file_info['filepath']
            if file_name in file_path:
                return node
    return ['2'] #没这个点

def get_startnode_sche(db, func_name, file_name, loc, var):
    
    startnode_1 = get_startnode_p1(db, func_name, file_name, loc)
    if startnode_1 != ['2'] and startnode_1 != ['3']:
        return startnode_1

    startnode_2 = get_startnode_p2(db, file_name, loc)
    if startnode_2 != ['1'] and startnode_2 != ['2']:
        return startnode_2

    startnode_3 = get_startnode_p3(db, var, loc, file_name)
    if startnode_3 != ['2']:
        return startnode_3

    if startnode_2 == ['1']:
        return ['3'] #没有这个文件
    
    if startnode_1 == ['2']:
        return ['1'] #没有函数
    elif startnode_1 == ['3']:
        return ['2'] #没有点 

def err_log(err_filepath,output_str):
    fout = open(err_filepath,'a')
    fout.write(output_str)
    fout.close()        

def get_slice_file_sequence(store_filepath, list_result, count, func_name, startline, filepath_all, var_list):
    list_for_line = []
    statement_line = 0
    vulnline_row = 0
    list_write2file = []
    point_var_list = []
    vulfunc_id = list_result[0]['functionId']#第一句肯定是漏洞函数的开头

    for node in list_result:
        if((node['filepath'][-5:] == 'OLD.c') or (node['filepath'][-5:] == 'NEW.c')):
            s_tmp = node['filepath'].split('_')
            index = 3
            file_name = s_tmp[3]
            while('.c' not in s_tmp[index]):
                index +=1
            for i in range(4, index + 1):
                file_name += ('_' + s_tmp[i])
        else:
            file_name = node['filepath']

        if node['type'] == 'Function':
            f2 = open(node['filepath'], 'r')
            content = f2.readlines()
            f2.close()
            raw = int(node['location'].split(':')[0])-1
            code = content[raw].strip()

            new_code = ""
            if code.find("#define") != -1:
                list_write2file.append(code + ' location: ' + str(raw+1) + ' file: ' + file_name + '\n')
                continue

            while (len(code) >= 1 and code[-1] != ')' and code[-1] != '{'):
                if code.find('{') != -1:
                    index = code.index('{')
                    new_code += code[:index].strip()
                    list_write2file.append(new_code + ' location: ' + str(raw+1) + ' file: ' + file_name + '\n')
                    break

                else:
                    new_code += code + '\n'
                    raw += 1
                    code = content[raw].strip()
                    #print "raw", raw, code

            else:
                new_code += code
                new_code = new_code.strip()
                if new_code[-1] == '{':
                    new_code = new_code[:-1].strip()
                    list_write2file.append(new_code + ' location: ' + str(raw+1) + ' file: ' + file_name + '\n')
                    #list_line.append(str(raw+1))
                else:
                    list_write2file.append(new_code + ' location: ' + str(raw+1) + ' file: ' + file_name + '\n')
                    #list_line.append(str(raw+1))

        elif node['type'] == 'Condition':
            raw = int(node['location'].split(':')[0])-1
            if raw in list_for_line:
                continue
            else:
                #print node['type'], node['code'], node['name']
                f2 = open(node['filepath'], 'r')
                content = f2.readlines()
                f2.close()
                code = content[raw].strip()
                pattern = re.compile("(?:if|while|for|switch)")
                #print code
                res = re.search(pattern, code)
                if res == None:
                    raw = raw - 1
                    code = content[raw].strip()
                    new_code = ""

                    while (code[-1] != ')' and code[-1] != '{'):
                        if code.find('{') != -1:
                            index = code.index('{')
                            new_code += code[:index].strip()
                            list_write2file.append(new_code + ' location: ' + str(raw+1) + ' file: ' + file_name + '\n')
                            #list_line.append(str(raw+1))
                            list_for_line.append(raw)
                            break

                        else:
                            new_code += code + '\n'
                            list_for_line.append(raw)
                            raw += 1
                            code = content[raw].strip()

                    else:
                        new_code += code
                        new_code = new_code.strip()
                        if new_code[-1] == '{':
                            new_code = new_code[:-1].strip()
                            list_write2file.append(new_code + ' location: ' + str(raw+1) + ' file: ' + file_name + '\n')
                            #list_line.append(str(raw+1))
                            list_for_line.append(raw)

                        else:
                            list_for_line.append(raw)
                            list_write2file.append(new_code + ' location: ' + str(raw+1) + ' file: ' + file_name + '\n')
                            #list_line.append(str(raw+1))

                else:
                    res = res.group()
                    if res == '':
                        print filepath_all + ' ' + func_name + " error!"
                        exit()

                    elif res != 'for':
                        new_code = res + ' ( ' + node['code'] + ' ) '
                        list_write2file.append(new_code + ' location: ' + str(raw+1) + ' file: ' + file_name + '\n')
                        #list_line.append(str(raw+1))

                    else:
                        new_code = ""
                        if code.find(' for ') != -1:
                            code = 'for ' + code.split(' for ')[1]

                        while code != '' and code[-1] != ')' and code[-1] != '{':
                            if code.find('{') != -1:
                                index = code.index('{')
                                new_code += code[:index].strip()
                                list_write2file.append(new_code + ' location: ' + str(raw+1) + ' file: ' + file_name + '\n')
                                #list_line.append(str(raw+1))
                                list_for_line.append(raw)
                                break

                            elif code[-1] == ';' and code[:-1].count(';') >= 2:
                                new_code += code
                                list_write2file.append(new_code + ' location: ' + str(raw+1) + ' file: ' + file_name + '\n')
                                #list_line.append(str(raw+1))
                                list_for_line.append(raw)
                                break

                            else:
                                new_code += code + '\n'
                                list_for_line.append(raw)
                                raw += 1
                                code = content[raw].strip()

                        else:
                            new_code += code
                            new_code = new_code.strip()
                            if new_code[-1] == '{':
                                new_code = new_code[:-1].strip()
                                list_write2file.append(new_code + ' location: ' + str(raw+1) + ' file: ' + file_name + '\n')
                                #list_line.append(str(raw+1))
                                list_for_line.append(raw)

                            else:
                                list_for_line.append(raw)
                                list_write2file.append(new_code + ' location: ' + str(raw+1) + ' file: ' + file_name + '\n')
                                #list_line.append(str(raw+1))
        
        elif node['type'] == 'Label':
            f2 = open(node['filepath'], 'r')
            content = f2.readlines()
            f2.close()
            raw = int(node['location'].split(':')[0])-1
            code = content[raw].strip()
            list_write2file.append(code + ' location: ' + str(raw+1) + ' file: ' + file_name + '\n')
            #list_line.append(str(raw+1))

        elif node['type'] == 'ForInit':
            continue

        elif node['type'] == 'Parameter':
            if((node['functionId'] == vulfunc_id) and ('* ' in node['code'])):#保存指针类型的变量
                pit_var = node['code'].split('* ')[-1] # int ff_hevc_decode_nal_sps(HEVCContext *s)
                if(pit_var[-1] == ','):
                    pit_var = pit_var[:-1]
                elif(pit_var[-1] == ')'):
                    pit_var = pit_var[:-1]
                point_var_list.append(pit_var)

            if list_result[0]['type'] != 'Function':
                row = node['location'].split(':')[0]
                list_write2file.append(node['code'] + ' location: ' + str(row) + ' file: ' + file_name + '\n')
                #list_line.append(row)
            else:
                continue

        elif node['type'] == 'IdentifierDeclStatement':
            if((node['functionId'] == vulfunc_id) and ('* ' in node['code'])):#保存指针类型的变量
                ass_var = node['code'].split(' = ') # BoxBlurContext * s = ctx->priv;    BoxBlurContext * s, linesize    BoxBlurContext * s, * linesize
                if(len(ass_var) > 1):
                    end = len(ass_var) - 1
                else:
                    end = len(ass_var)
                for i in range(end):#考虑连等的情况
                    pit_var = ass_var[i].split('* ')
                    for j in range(1, len(pit_var)):
                        tmp_var = pit_var[j]
                        if((tmp_var[-1] == ',') or (tmp_var[-1] == ';')):
                            point_var_list.append(tmp_var[:-1].strip())
                        else:
                            point_var_list.append(tmp_var.strip())
                        
            if node['code'].strip().split(' ')[0] == "undef":
                f2 = open(node['filepath'], 'r')
                content = f2.readlines()
                f2.close()
                raw = int(node['location'].split(':')[0])-1
                code1 = content[raw].strip()
                list_code2 = node['code'].strip().split(' ')
                i = 0
                while i < len(list_code2):
                    if code1.find(list_code2[i]) != -1:
                        del list_code2[i]
                    else:
                        break
                code2 = ' '.join(list_code2)

                list_write2file.append(code1 + ' location: ' + str(raw+1) + '\n' + code2 + ' location: ' + str(raw+2) + ' file: ' + file_name + '\n')

            else:
                list_write2file.append(node['code'] + ' location: ' + node['location'].split(':')[0] + ' file: ' + file_name + '\n')

        elif node['type'] == 'ExpressionStatement':
            row = int(node['location'].split(':')[0])-1
            if row in list_for_line:
                continue

            if node['code'] in ['\n', '\t', ' ', '']:
                list_write2file.append(node['code'] + ' location: ' + str(row+1) + ' file: ' + file_name + '\n')
                #list_line.append(row+1)
            elif node['code'].strip()[-1] != ';':
                list_write2file.append(node['code'] + '; location: ' + str(row+1) + ' file: ' + file_name + '\n')
                #list_line.append(row+1)
            else:
                list_write2file.append(node['code'] + ' location: ' + str(row+1) + ' file: ' + file_name + '\n')
                #list_line.append(row+1)

        elif node['type'] == "Statement":
            row = node['location'].split(':')[0]
            list_write2file.append(node['code'] + ' location: ' + str(row) + ' file: ' + file_name + '\n')
            #list_line.append(row+1)

        else:         
            #print node['name'], node['code'], node['type'], node['filepath']
            if node['location'] == None:
                continue
            f2 = open(node['filepath'], 'r')
            content = f2.readlines()
            f2.close()
            row = int(node['location'].split(':')[0])-1
            code = content[row].strip()
            if row in list_for_line:
                continue

            else:
                list_write2file.append(node['code'] + ' location: ' + str(row+1) + ' file: ' + file_name + '\n')
                #list_line.append(str(row+1))

    f = open(store_filepath, 'a')
    # f.write(str(count) + ' ' + filepath_all + ' ' + func_name + ' ' + startline + ' ' + str(var_list) + ' ' + '{')
    f.write(str(count) + ' @@ ' + filepath_all + ' @@ ' + func_name + ' @@ ' + startline + ' @@ ' + str(var_list) + ' @@ ' + '{')
    for i in point_var_list:
        if(i == point_var_list[-1]): # 最后一个不用写入‘, ’
            f.write(str(i))
        else:
            f.write(str(i) + ', ')
    f.write('}' + '\n')

    for wb in list_write2file:
        f.write(wb)
    f.write('------------------------------' + '\n')     
    f.close()

def read_step1_output(step1_out_filepath):
    startnode_info_all = {}
    f = open(step1_out_filepath ,'r')
    text_lines = f.readlines()
    print(text_lines)
    file_list = []
    this_file = []
    res_filname = []
    line_flag = 0
    
    if text_lines == '':
        return
    if text_lines[0] == '\n':
        test_lines = text_lines[1:]
    for line in text_lines:
        if line == '==============================================================\n': #一个diff文件结束
            print("over")
            line_flag = 1
            file_list.append(this_file) #this_file是一个diff文件的内容
            this_file = []
        else:
            if line_flag == 1 and line == '\n':
                line_flag = 0
            else:
                this_file.append(line)
        #print(this_file)

    #print(file_list)
    for _file in file_list:
        flag = 0
        startnode_info_diff = {}
        if len(_file) < 3: #说明没有内容
            file_name_tmp = _file[0].split("/")[-1].split('diff')[0][:-1]
            res_filname.append(file_name_tmp.split('_')[-2])#append进去的是漏洞文件名(例如ffserver.c)
            
            startnode_info_diff.setdefault(file_name_tmp,[]).append('')
        else:
            file_name_tmp = _file[0].split("/")[-1].split('diff')[0][:-1]
            res_filname.append(file_name_tmp.split('_')[-2]) #该diff文件所对应的文件名
            
            hunk_list = []
            this_hunk = []
            for conseq in _file[2:]: #从第三行开始是关键变量的内容
                if conseq == '\n': #说明这一行的关键变量信息结束了(包括删减类型、变量名、行号等信息)
                    hunk_list.append(this_hunk)
                    this_hunk = []
                else:
                    if(conseq.strip()[-6:] == 'Delete'):
                        flag = 1 #如果在遍历中发现了Delete的语句,就针对修补前文件进行解析,相应的把flag设置为1
                    if(conseq.strip()[-7:] == 'Replace'):
                        flag = 1
                    this_hunk.append(conseq)
            
            for hunk in hunk_list: #一个hunk是一个关键变量的全套信息
                if(len(hunk) == 4):
                    line_cv_dict = {}
                    '''
                    if hunk[2].split(' file')[0].split(" ")[-1] == 'new':
                        file_name = file_name_tmp + "_NEW.c"
                        if(flag == 1):
                            continue
                    else:
                        file_name = file_name_tmp + "_OLD.c"
                        if(flag == 0):
                            continue
                    '''
                    if hunk[2].split(' file')[0].split(" ")[-1] == 'old':
                        if(flag == 1):#含有删减行
                            file_name = file_name_tmp + "_OLD.c"
                            start_line = hunk[2].split("#")[-1].split('\n')[0]
                            print(file_name, start_line)
                            cv_result = re.findall(r"\'([^\']*)\'",hunk[3])
                        else:
                            cv_result = []
                    else:
                        if(flag == 0):
                            file_name = file_name_tmp + "_NEW.c"
                            #tf = open('./no_delete.txt', 'w+')
                            #print >> tf, file_name
                            start_line = hunk[2].split("#")[-1].split('\n')[0]
                            print(file_name, start_line)
                            cv_result = re.findall(r"\'([^\']*)\'",hunk[3])
                        else:
                            cv_result = []
                    if(cv_result != []):
                        for var in cv_result:
                            variable_name = var
                            line_cv_dict.setdefault(start_line,[]).append(variable_name)

                        startnode_info_diff.setdefault(file_name,[]).append(line_cv_dict)

                elif(len(hunk) == 5):#是Replace类型
                    line_cv_dict = {}
                    if(flag == 1):
                        file_name = file_name_tmp + '_OLD.c'
                        start_line = hunk[2].split("#")[-1].split('\n')[0]
                    elif(flag == 0):
                        file_name = file_name_tmp + '_NEW.c'
                        start_line = hunk[3].split("#")[-1].split('\n')[0]

                    cv_result = re.findall(r"\'([^\']*)\'",hunk[4])
                    if(cv_result != []):
                        for var in cv_result:
                            variable_name = var
                            line_cv_dict.setdefault(start_line,[]).append(variable_name)

                        startnode_info_diff.setdefault(file_name,[]).append(line_cv_dict)
                else:
                    
                    line_cv_dict_old = {}
                    file_name_old = file_name_tmp + "_OLD.c"

                    start_line_old = hunk[2].split("#")[-1].split('\n')[0]
                    print(file_name_old, start_line_old)
                    
                    cv_result = re.findall(r"\'([^\']*)\'",hunk[4])
                    if(cv_result != []):
                        for var in cv_result:
                            variable_name = var
                            line_cv_dict_old.setdefault(start_line_old,[]).append(variable_name)

                        startnode_info_diff.setdefault(file_name_old,[]).append(line_cv_dict_old)

        startnode_info_all.setdefault(file_name_tmp,[]).append(startnode_info_diff)

    f.close()
    return startnode_info_all, res_filname

def record_out_file(path_info, to_query):
    with open(path_info, 'r') as r:
        lines = r.readlines()
        for line in lines:
            if to_query in line:
                path = line.split(to_query)[-1].strip()
                return path

def check_step1_output(diff_count, startnode_info_step1, diff_name, slice_store_filepath, startnode_debug_path, sliceres_anatmp):
    str_out = ''
    flag = 0
    print(startnode_info_step1)

    diff_count = str(diff_count)
    write_to_file(slice_store_filepath, diff_name+':\n')
    write_to_file(startnode_debug_path, diff_name+':\n')
    write_to_file(sliceres_anatmp, diff_name+':\n')

    for op in startnode_info_step1[diff_name]:
        for k in op.keys():
            if op[k] == '' or op[k] == ['']:
                str_out = '\tErr_step1 : NO CV Got from Step1\n'
                flag  = 1
            else:
                str_out = str_out + '\t' + k + ' ' + str(op[k]) + '\n'
    write_to_file(slice_store_filepath, str_out)
    write_to_file(startnode_debug_path, str_out)
    write_to_file(sliceres_anatmp, str_out)
    
    if flag == 1:
        write_to_file(slice_store_filepath, '====================================================\n\n')
        write_to_file(startnode_debug_path, '====================================================\n\n')
        write_to_file(sliceres_anatmp, '====================================================\n\n')
        return -1
    else:
        return 0
        
def check_startnode(startnode, file_name, func_name, cv, startnode_res_path):
    output_str = ''
    if startnode == ['1']: #没有函数
        if func_name == 'none':
            output_str = '\t\tERR_4:\t' + file_name + '   diff function name is error: ' + func_name + '  ( ' + cv + ' )\n'
        elif func_name == 'struct':
            output_str = '\t\tERR_4:\t' + file_name + '   diff function name is STRUCT: ' + func_name + '  ( ' + cv + ' )\n'
        else:
            output_str = '\t\tERR_2:\t' + file_name + '  Joern has not parsed this FuncNode: ' + func_name + '  ( ' + cv + ' )\n'
    elif startnode == ['2']: #没有点
        output_str = '\t\tERR_3:\t' + file_name + '  Joern has not parsed this StatementNode: ' + cv  + '  ( ' + func_name + ' )\n'
    else: #没有文件
        output_str = '\t\tERR_1.1:\t' + file_name + ' Joern has not parsed this file.\n'
    write_to_file(startnode_res_path, output_str)

def check_startnode_debug_file(startnode_debug_path):
    if not os.path.exists(startnode_debug_path):
        return 0
    lines = read_file(startnode_debug_path)
    if lines == []:
        return 0
    else:
        return int(lines[-1])

def find_code_in_vuln(code, vuln_content, vul_func):
    print('code:')
    print(code)
    code = code.strip()
    location = 0
    flag = 0
    for vul_line in vuln_content:
        location += 1
        vul_line = vul_line.strip().replace(' ', '')
        vul_func = vul_func.strip().replace(' ', '')
        if(vul_line.find(vul_func) > -1):#匹配到了漏洞函数定义处
            flag = 1
        
        if(flag == 0):
            continue
        if(vul_line[-1] == '{'):
            vul_line = vul_line[:-1]
            
        if(code == vul_line):
            return location
        elif((code.find(vul_line) > -1) and (vul_line[-1] == ',')):#如果漏洞文件里分行写了，一行不完整
            return location
        #code = code.strip().replace(' ', '')
    return 0

def create_result_folder(cve, software):
    init_path = './results/' + software + '/' + cve
    if(not os.path.exists(init_path)):
        os.makedirs(init_path)
    return init_path + '/' + 'slices.txt'


if __name__ == "__main__":
    j = JoernSteps()
    j.connectToDatabase()
    
    f = open('./config.json')   
    path_data = json.load(f)
    #os.chdir(path_data["work_dir"])

    line_cv_dict = {}
    file_dict = {}

    step1_out_filepath = path_data['step1_output']['step1_output_tmp_txt']
    err_filepath = path_data['error_rec']['step2_err_filepath']
    diff_path = path_data['all_test_code']['all_diff_path'].replace("all_test_code","code")
    new_path = path_data['all_test_code']['all_new_path'].replace("all_test_code","code")
    old_path = path_data['all_test_code']['all_old_path'].replace("all_test_code","code")
    slice_store_filepath = path_data['step2_output']['record_tmp_slice'] #正常运行
    startnode_debug_path = path_data['step2_output']['startnode_debug_path'] #正常运行
    cv_path = path_data['all_test_code']['all_cv_path']

    sliceres_anatmp = path_data['step2_output']['sliceres_anatmp']
    sliceres_anall = path_data['step2_output']['sliceres_anall']
    
    startnode_info_step1, res_filname= read_step1_output(step1_out_filepath)
    print(startnode_info_step1)
    cnt = check_startnode_debug_file(sliceres_anall)

    diff_count = 0

    for diff_name in startnode_info_step1.keys(): #针对每一个diff文件
        # if diff_name != 'CVE-2015-3417_NVD-CWE-Other_e8714f6f93d1a32f4e4655209960afcf4c185214_h264.c_1.1':
        #     continue
        #print(diff_name)
        count = 1
        diff_cv_flag = 0
        cve_num = diff_name.split('_CWE')[0].split('_NVD')[0]
        #cve_num = diff_name.split('\\')[-2]
        #diff_name = diff_name.split('\\')[-1]
        #print(diff_name)
        print(cve_num)
        print(diff_path)
        print(diff_name)
        this_diff_path = diff_path + cve_num + '/' + diff_name + '.diff'
        store_filepath = create_result_folder(cve_num, diff_path.split('/')[-2]) #存储当前文件切片的结果

        diff_count += 1

        step1_checkres = check_step1_output(diff_count, startnode_info_step1, diff_name, slice_store_filepath, startnode_debug_path, sliceres_anatmp)#记录step1没有提取出变量的情况, 并写入文件头
        if step1_checkres == -1:
            continue

        file_line_cv_list = startnode_info_step1[diff_name]
        print("file_line_cv_list: ")
        print(file_line_cv_list)
        
        for file_cv_dic in file_line_cv_list:

            old_dict , new_dict = ext_diff_funcname2dic(this_diff_path) #把diff文件中的函数名存储到dict数据结构里
            
            for file_name in file_cv_dic.keys():#针对每一个old文件,new文件(这里只会有一个OLD文件,或者是一个NEW文件,不会同时存在)
                cnt += 1
                line_list = []
                code_store_file = file_name.split('_CWE')[0].split("_NVD")[0]
                line_cv_list = file_cv_dic[file_name]
                node_critical_variable = {}
                node_variable_pairs_all = []
                start_node_info = {} #记录本文件所有startnode信息
                starnode_checkres_list = []
                func_name_list = []
                print('file_name: ')
                print(file_name)

                if '_NEW' in file_name:
                    func_line_dic = new_dict
                    flag = 0
                    src_path = new_path + '/' + cve_num + '/' + file_name
                else:
                    func_line_dic = old_dict
                    flag = 1
                    src_path = old_path + '/' + cve_num + '/' + file_name
                    
                if(flag == 0):
                    store_filepath1 = store_filepath #slices.txt文件
                    store_filepath = store_filepath[:store_filepath.find('slices')] + 'slices_add.txt' #slices_add.txt作为中间过渡文件
                
                print('src_path:')
                print(src_path)
                if not os.path.exists(src_path):
                    output_str = '\t\t[!ERR_0:\t No such File:  ' + file_name + ']\n----------------------------------------\n'
                    write_to_file(sliceres_anatmp, output_str)
                    continue
                funcname_id = {}
                for line_cv in line_cv_list[:]: #处理每一行
                    if line_cv == '' or line_cv == {}:
                        line_cv_list.remove(line_cv)
                print('line_cv_list: ')
                print(line_cv_list)
                for line_cv in line_cv_list:
                    print(line_cv) #格式为line:cv
                    
                    line = int(line_cv.keys()[0])
                    print(line)
                    line_list.append(line)
                    cvlist_for_this_line = line_cv.values()[0]
                    print(cvlist_for_this_line)
                    
                    func_name = funcname_for_changeline(line, func_line_dic)
                    print(func_name)
                    
                    if func_name not in func_name_list:
                        func_name_list.append(func_name)

                    for cv in cvlist_for_this_line: #处理这一行的每个变量
                        print("cv: ")
                        print(cv)
                        print(func_name)
                        print(file_name)
                        print(line)
                        cv_name = cv_path + '/cv_' + file_name.split('_')[2] + '.txt'
                        cv_file = open(cv_name, 'w+')
                        print >> cv_file, cv
                        
                        startnode = get_startnode_sche(j, func_name, file_name, line, cv)
                        print("startnode: ")
                        print(startnode)
                        if startnode == ['1'] or startnode == ['2'] or startnode == ['3']:
                            #print(startnode)
                            #print("continue")
                            check_startnode(startnode, file_name, func_name, cv, startnode_debug_path) #将没有提取出startnode的情况记录
                            starnode_checkres_list.append(startnode)
                            continue

                        node_id = startnode._id
                        node_type = startnode['type']
                        #print("node type: ")
                        #print(node_type)
                        funcid = startnode['functionId']

                        funcname_id[funcid] = func_name
                        if node_type != [] and node_id != [] and funcid != []:
                            if node_id not in list(start_node_info.keys()):   
                                start_node_info.setdefault(node_id,[]).append(node_type)
                                start_node_info.setdefault(node_id,[]).append(funcid)
                            start_node_info.setdefault(node_id,[]).append(cv)
                print("start_node_info: ")
                print(start_node_info)
                
                if start_node_info == {}: #一个startnode都没选到
                    func_str = ''
                    for func in func_name_list:
                        func_str += func
                        func_str += ' '
                    if ['3'] in starnode_checkres_list: 
                        output_str = '\t[ !ERR_step2.1:\t Joern has not parse this File ]\t' + file_name + '\n'
                    elif ['1'] in starnode_checkres_list:
                        output_str = '\t[ !ERR_step2.2:\t Joern has not parse this Function Node ]\t' + file_name + '\t' + func_str + '\n'
                    elif ['2'] in starnode_checkres_list:
                        output_str = '\t[ !ERR_step2.3:\t Joern has not parse the Statament Node ]\t' + file_name + '\n'
                    write_to_file(sliceres_anatmp, output_str)
                    continue
                diff_cv_flag = 1
                
                 
                for node_id in start_node_info.keys():
                    var_list = []
                    node_type = start_node_info[node_id][0]
                    func_id = start_node_info[node_id][1]
                    varlist_for_node = start_node_info[node_id][2:]
                    print '=============== Start to Extract DataFlow ==============='
                    for var in varlist_for_node:
                        var_list.append(var)

                    #try to cross function
                    pdg = getFuncPDGById('testCode', func_id)#获取当前函数(漏洞函数)的PDG图
                    if(pdg == False):
                        print("Can't find vulnerable function's PDG!")
                        continue
                        #exit()
                    #print("PDG:")
                    #print(pdg)

                    #print("start_node_info.keys()")
                    #print(start_node_info.keys())                   
                    list_startnode = []
                    startline = ''
                    startline_path = ''

                    for node in pdg.vs:
                        print(type(node['name']), type(node_id))
                        print(node['name'], node_id)
                        if(node['name'] ==  str(node_id)): #在pdg图中找到关注点行的节点
                        #if(int(node['name']) in start_node_info.keys()):
                            list_startnode.append(node)
                    if(list_startnode == []):
                        print("Can't find startnode in PDG!")
                        continue

                    #获取关注点所在的文件和行数,作为标记
                    startline = list_startnode[0]['location'].split(':')[0]
                    startline_path = list_startnode[0]['filepath']

                    #如果是控制语句,需要执行不同的切片步骤:
                    #首先找到关键变量的定义处，然后从定义处往下切
                    list_startnode_tmp = []
                    if((node_type == 'Condition') or (node_type == 'ForStatement') or (node_type == 'ForInit')):
                        
                        for var in var_list: #var_list:这一行涉及到的关键变量
                            print('CV: ', var)
                            idenfitierDecl, successors, variable_name = backward_to_decl(j, list_startnode[0], var)
                            print("This cv's declaration line:   " + idenfitierDecl[0]['location'])
                            print("This cv's declaration code:   " + idenfitierDecl[0]['code'])
                            for idc in idenfitierDecl:
                                list_startnode_tmp.append(idc)
                    
                    if(list_startnode_tmp != []):#如果不为空,那么就从定义处开始切片
                        list_startnode = list_startnode_tmp
                        #startline = list_startnode_tmp[0]['location'].split(':')[0]
                        #startline_path = list_startnode_tmp[0]['filepath']

                    results_back = program_slice_backwards(pdg, list_startnode) #从关注点开始向上切片
                    print("results_back: ")
                    print(results_back)
                    for node_back in results_back:
                        if(node_back['name'] == str(node_id)):
                            results_back.remove(node_back)
                    
                    results_for = program_slice_forward(pdg, list_startnode) #从关注点开始向下切片
                    print("results_for:")
                    print(results_for)

                    #去掉重复的关注行
                    for node_back in results_back:
                        if(node_back in results_for):
                            results_back.remove(node_back)
                    
                    layer = 2
                    cnt = 1
                    testID = 'testCode'
                    not_scan_func_list = []
                    function_name = funcname_id[func_id]
                    all_result = []
                    #先从关注点获得向下的切片(item层)
                    #list_to_crossfunc_for = process_cross_func(results_for, testID, 1, results_for, not_scan_func_list)
                    list_to_crossfunc_for, not_scan_func_list = return_cross_func(results_for, testID, 1, results_for, not_scan_func_list, function_name, layer)

                    #新增功能，如果向下找未能找到sink点，则返回到调用该(漏洞)函数的那一行，再向下切片
                    list_return_for = process_return_func([], list_startnode[0], testID, layer, function_name, cnt)
                    #all_result.append(list_to_crossfunc_for + list_return_for) #TypeError: can only concatenate list (not "NoneType") to list
                    if(list_return_for != []):
                        for func_slice in list_return_for:
                            if((results_back + list_to_crossfunc_for + func_slice) in all_result):
                                continue
                            all_result.append(results_back + list_to_crossfunc_for + func_slice)
                            #list_to_crossfunc_for  = list_to_crossfunc_for + func_slice
                    #all_result.append(results_back + list_to_crossfunc_for)
                    else:
                        all_result.append(results_back + list_to_crossfunc_for)
                   
                    if(all_result == []):
                        fout = open('error.txt', 'a')
                        fout.write(function_name + ' ' + str(func_id) + ' found nothing!\n')
                        fout.close()
                    else:
                        for _list in all_result:
                            get_slice_file_sequence(store_filepath, _list, count,function_name, startline, startline_path, var_list)
                            #slice.op.py
                            #get_slice_file_sequence(j, store_filepath, _list, count, var_list, line_cv_list, file_name)
                            count +=1

        # 针对add型的文件 进行对比删除
        # 只是个对比作用 不需要joern中的解析
        '''
        2022.3.29修改:从slices.txt中识别出diff里的加号行，直接对这些行删除
        '''
        
        if(flag == 1):#说明不是只增类型的diff
            continue
        f_add = open(store_filepath1, 'a+')#即将被写入的文件
        f = open(store_filepath, 'r')
        slice_content = f.readlines()#读取切片文件slices_add.txt
        f2 = open(this_diff_path, 'r')
        diff_content = f2.readlines()#读取diff文件,识别加号行
        vuln_path = old_path + cve_num + '/' + diff_name + '_OLD.c'
        f3 = open(vuln_path, 'r')
        vuln_content = f3.readlines()#读取漏洞文件,匹配行号

        add_lines = []#存储加号行
        for line in diff_content:
            if((line[0] == '+') and (line[:3] != '+++')):
                add_lines.append(line[1:].replace(' ', '').strip()) #去掉开头的+并把语句中的空格都去掉
        
        func_define = slice_content[1].strip().split(' location: ')[0]#获取函数定义处的代码片段(但是可能不完整,所以后面的匹配不是==而是in)
        kvar = slice_content[0].split(' ')[3]#获取关注点的行号
        flag = 0

        for slice_line in slice_content:
            if(slice_line == slice_content[0]):
                slice_line = slice_line.replace('_NEW.c', '_OLD.c')
            
            if(slice_line[-2:] != '.c'):#可能是开始行、以逗号结尾的函数定义行、切片之间的分割行等
                f_add.write(slice_line + '\n')
                continue

            slice_line = slice_line.strip()
            #vuln_file = diff_name.split('_')[3]
            #获取漏洞文件名,可能存在以下划线分割的情况
            diff_tmp = diff_name.split('_')
            index = 3
            vuln_file = diff_tmp[3]
            while('.c' not in vuln_file):
                index += 1
                vuln_file  = vuln_file + '_' + diff_tmp[index]

            this_file = slice_line.split(' file: ')[-1].split('/')[-1] #获取当前行的文件名
            this_code = slice_line.split(' location: ')[0] #获取当前行的代码片段
            this_loc = slice_line.split(' location: ')[-1].split(' file: ')[0] #获取当前行的行号
            

            if(vuln_file == this_file):#如果是漏洞文件,需要更改一下行号
                if(this_loc == kvar):#关注点肯定是在漏洞文件中的
                    flag = 1
                new_loc = find_code_in_vuln(this_code, vuln_content, func_define)
                if(new_loc == 0):#没有找到行号
                    f_add.write('There is no correct code in vuln_file')
                    continue
                if(flag == 1):
                    new_line = this_code + ' location: ' + str(new_loc) + ' file: ' + this_file + '    (key_var lines)' + '\n'
                    flag = 0
                else:
                    new_line = this_code + ' location: ' + str(new_loc) + ' file: ' + this_file + '\n'
            else:#已经到了其他文件
                if(flag == 1):#竟然至今还没有找到关键变量行
                    new_line = this_code + ' location: ' + str(this_loc) + ' file: ' + this_file + '    (key_var lines)' + '\n'
                    flag = 0
                else:
                    new_line = slice_line + '\n'
            
            f_add.write(new_line)


            
        '''
        # add_filepath = './results/slices_add.txt'
        if(flag == 1):
            continue
        f_add = open(store_filepath1, 'a+')
        #vuln_path = '../code/C-Vulnerable_Files/ffmpeg/CVE-2011-3504/CVE-2011-3504_CWE-094_4f07a3aa2c6b7356c28646692261aa9080605fcc_matroskadec.c_3.1_OLD.c'
        vuln_path = old_path + cve_num + '/' + diff_name + '_OLD.c'

        vuln_file = '' #漏洞所在的源文件名
        for i in res_filname:
            if(i in vuln_path):
                vuln_file = i
                break

        f = open(store_filepath, 'r')
        slice_content = f.readlines()
        f2 = open(vuln_path, 'r')
        vuln_content = f2.readlines()

        start = 1#初始值标记为1 因为第一行就是起始标记行
        vul_func = slice_content[1].strip().split(' location: ')[0]#获取函数定义处的代码片段
        for line in slice_content:
            line = line.strip()
            if(start == 1):
                kvar = line.split(' ')[3] #获取起始点行数
                sign = 0
                f_add.write(line + '\n')
                start = 0
            elif(line == '------------------------------'):
                start = 1
                f_add.write('------------------------------\n')
            elif(line[-2:] == '.c'):
                slice_file = line.split(' file: ')[-1].split('/')[-1]
                code = line.split(' location: ')[0] #获取代码片段
                loc = line.split('location: ')[-1].split(' file: ')[0] #获取当前行的行号
                if(vuln_file == slice_file):
                    location = find_code_in_vuln(code, vuln_content, vul_func) #找到在漏洞函数中是第几行
                    if(location > 0):
                        if(sign == 1):
                            f_add.write(code + ' location: ' + str(location) + ' file: ' + slice_file + '    (key_var lines)' + '\n')
                            sign = 0 #已经找到了关键变量行
                        else:
                            f_add.write(code + ' location: ' + str(location) + ' file: ' + slice_file + '\n')
                else:
                    if(sign == 1):#如果已经到了别的文件，但仍然没有到关键变量行,那就把第一个别的文件行设置为关键变量行
                        f_add.write(code + ' location: ' + str(loc) + ' file: ' + slice_file + '    (key_var lines)' + '\n')
                        sign = 0
                    else:
                        f_add.write(line + '\n')
                    
                if(loc == kvar):
                    sign = 1
            elif(line[-1] == ','):
                f_add.write(line + '\n')
        '''

