# -*- coding: UTF-8 -*-
from operator import not_
import os
import re
import pickle as pkl
import json
#from typing import Counter

def get_filelist(now_dir):
    Filelist = []
    for root, dirs, files in os.walk(now_dir):
        for dir in dirs:
            project_path = os.path.join(root, dir)
            cve_list = os.listdir(project_path)
            
            for file in cve_list:
                if file.startswith('.'):
                    continue
                Filelist.append(os.path.join(project_path,file))
            '''
            for cve_num in cve_list:
                cve_path = os.path.join(project_path, cve_num)
                file_list = os.listdir(cve_path)
                for file in file_list:
                    if file.startswith('.'):
                        continue
                    Filelist.append(os.path.join(cve_path,file))
            '''
        return Filelist

def check_one_block(s):
    #检查一个diff文件中是否只有一个@@块
    block_pattern=re.compile('(\n\r|\n)@@',re.MULTILINE)
    count=len(block_pattern.findall(s))
    if count==1:
         return True
    return False

# 判断是不是数字
def is_number(s):
    if(s[:2] == '0x'):
        return True
    try:
        float(s)
        return True
    except ValueError:
        pass
 
    try:
        import unicodedata
        unicodedata.numeric(s)
        return True
    except (TypeError, ValueError):
        pass
 
    return False

def is_define(s): #isupper
    ss = s.replace('_', '')
    if(ss.isupper()):
        return True
    else:
        return False

def process(s):
    """
    获得+/-的语句，输出为一个列表

    input:string of one block
    output:一个列表，其中每一个元素对应一块连续的diff行,每行前有\n\r
    """
    output=[]
    lines=re.split('\n\r|\n',s) #按行获取整个代码文件
    flag=0 # 标记是否是连续行
    add_line_num = 0 # 记录每一个@@块里面的+/-号行的数量
    sub_line_num = 0
    temp=''
    sub_line = 0 #@@行提示的修补前文件的起始行
    add_line = 0 #修补后文件的起始行
    counter = 0 # 不算初始行的计数,记录空白行(非+/-行)的行数
    for i in lines:
        if(i[0:2] == '@@'):# 提取出来这一个@@块的行数提示
            counter = 0
            add_line_num = 0
            sub_line_num = 0 #归0操作
            
            tmp = i[(i.find('@@')):(i.rfind('@@'))]
            sub_line = tmp[(tmp.find('-') + 1):tmp.find(',')]
            add_line = tmp[(tmp.find('+') + 1):tmp.rfind(',')]
            # print(sub_line, add_line)
        elif((i[0:1] != '+') and (i[0:1] != '-')): # 空白行
            counter += 1
        
        # if flag==1 and (i[0:2]=='+ ' or i[0:2]=='- '):
        if(flag==1 and (i[0:1]=='+' or i[0:1]=='-')): # 连续的行
            if(i[0:1] == '+'):
                add_line_num += 1
            if(i[0:1] == '-'):
                sub_line_num += 1
                
            temp = temp + '\n\r' + i
        # 修改掉是因为存在和+之间不含空格的代码，例如CVE-2010-4705    (2020.11.27)    
        if((i[0:1]=='+' or i[0:1]=='-') and (i[0:3]!='+++') and (i[0:3]!= '---') and flag==0):
            flag=1    #连续的diff开始
            temp = str(sub_line_num) + ',' + str(add_line_num) + ',' + str(counter) + ',' + sub_line + ',' + add_line + '|'+ temp + '\n\r' + i # 把隔了几行放在一个block的最前面
            
            if(i[0:1] == '+'):
                add_line_num += 1
            if(i[0:1] == '-'):
                sub_line_num += 1
        if(flag==1 and i[0:1]!='+'and i[0:1]!='-'):
            flag=0    #连续的diff结束
            output.append(temp)
            temp=''

    return output

# 获取语句中的关键变量
def get_key(s, s_type):
    if(s_type == "Assignment"):
        return get_var_assign(s)

    elif(s_type == "Var-Declaration"):
        if(s[0] == '-'):
            flag = 1
        else:
            flag = 2  
        return get_var_decl(s, flag)

    elif(s_type == "Fun-Call"):
        return get_call_var(s, 1)

    elif(s_type == "if-Condition"):
        s_list = process_condition(s, 1)
        return get_cond_var(s_list, 1)
        # return get_cond_var(s, 1)
    
    elif(s_type == "while-Condition"):
        s_list = process_condition(s, 2)
        return get_cond_var(s_list, 2)
        # return get_cond_var(s, 2)

    elif(s_type == "for-Condition"):
        s_list = process_condition(s, 3)
        return get_cond_var(s_list, 3)
        # return get_cond_var(s, 3)

    elif(s_type == "Fun-Head"):
        return get_call_var(s, 2)

    else:
        return

def is_invalid_hunk(s):
    #define行
    if(s[1:8] == '#define'):
        return True
    #include行
    if(s[1:9] == '#include'):
       return True
    #空行
    if((s == "+") | (s == "-")):
        return True
    
    s = s.replace("+", "",1).replace("-", "",1)
    if(s[0:2] == "/*"):
        return True

#判断一句话是不是已经被注释掉的，如果是，则返回true
def is_invaild(s):
    #}行
    # tmp = s.replace("+", "").replace("-", "").replace(" ", "")
    #define行
    if(s[1:8] == '#define'):
        return True
    #include行
    if(s[1:9] == '#include'):
       return True
    if(s[1:2] == '#'):
        return True
    #空行
    if((s == "+") | (s == "-")):
        return True
    
    # s = s.replace("+", "").replace("-", "")
    s = s[1:]
    res = ''
    if(s[0:2] == "/*"):
        return True
    if(s[0:3] == " * "):
        return True
    if(s[0:2] == " *"):
        return True
    if(s[-2:] == "*/"):
        return True    
    s_tmp = s.replace(" ","")
    if(s_tmp.startswith('//')):
        return True
    # 注释行
    index = 0
    for i in range(len(s)):
        if(s[i] != ' '):
            index = i
            break
    if((index != 0) and (s[index] == '/') and ((index + 1) < len(s)) and (s[index + 1] == '*')):
        return True
    else:
        False

# 比较大小,返回最小值
def get_min(if_len, while_len, for_len):
    if(if_len > while_len):
        if(if_len > for_len):
            return "if"
        else:
            return "for"
    else:
        if(while_len < for_len):
            return "for"
        else:
            return "while"

#用比较符截断比较式的语句
def get_location(s):
    if(s.find(' < ') != -1):
        # print("1")
        return s.find(' < ')
    
    elif(s.find(' > ') != -1):
        # print("2")
        return s.find(' > ')
    
    elif(s.find(' <= ') != -1):
        # print("3")
        return s.find(' <= ')
    
    elif(s.find(' >= ') != -1):
        # print("4")
        return s.find(' >= ')
    
    elif(s.find(' == ') != -1):
        # print("5")
        return s.find(' == ')
    
    elif(s.find(' != ') != -1):
        # print("6")
        return s.find(' != ')
    else:
        return -2

def find_all(sub,s):
	index_list = []
	index = s.find(sub)
	while index != -1:
		index_list.append(index)
		index = s.find(sub,index+1)
	
	if len(index_list) > 0:
		return index_list
	else:
		return -1

def split_var(var):
    var_list_tmp = []
    greopr_loc = -1
    mem_flag = 0
    finish_flag = 0
    var = var.strip()
    if '<int32>' in var:
        var = var.split('<int32>')[-1]
    elif '<int>' in var:
        var = var.split('<int32>')[-1]

    operator_list = ['>=', '>', '<', '<=', '==', '!=']
    
    if '->' in var:
        mem_opr = '->'
        greopr_loc = var.find(mem_opr) + 1
        mem_flag = 1

    elif '- >' in var:
        mem_opr = '- >'
        greopr_loc = var.find(mem_opr) + 2
        mem_flag = 1

    if mem_flag == 1:
        var_splist = var.split(mem_opr)
        for var_sp in var_splist:
            for opr in operator_list:
                if opr in var_sp:
                    finish_flag = 1
                    if opr == '>':
                        arr_loc_tmp = []
                        arr_loc_list = find_all(mem_opr, var)
                        print(arr_loc_list)
                        opr_loc_list = find_all(opr, var)
                        print(opr_loc_list)
                        
                        if mem_opr == '->':
                            n = 1
                        elif mem_opr == '- >':
                            n = 2
                        
                        for arr_loc in arr_loc_list:
                            tmp = arr_loc + n
                            arr_loc_tmp.append(tmp)
            
                        for opr_loc in opr_loc_list:
                            if opr_loc not in arr_loc_tmp:
                                left_var = var[:opr_loc]
                                if((is_number(left_var) == False) and (is_define(left_var) == False)):
                                    var_list_tmp.append(left_var)
                                    break
                            
                    else:
                        left_var = var.split(opr)[0]
                        if((is_number(left_var) == False) and (is_define(left_var) == False)):
                            var_list_tmp.append(left_var)
                            break
            if finish_flag == 1:
                break

        if finish_flag == 0:
            if((is_number(var) == False) and (is_define(var) == False)):
                var_list_tmp.append(var)

    else:
        for opr in operator_list:
            if opr in var:
                finish_flag = 1
                left_var = var.split(opr)[0]
                if((is_number(left_var) == False) and (is_define(left_var) == False)):
                    var_list_tmp.append(left_var)
        
        if finish_flag == 0:
            if((is_number(var) == False) and (is_define(var) == False)):
                var_list_tmp.append(var)

    return list(set(var_list_tmp))

def rmv_str(s): #去除了字符串
    while "\'" in s:
        indL = s.find('\'')
        if '\'' in s[indL + 1:]:
            indR = s.find('\'',indL+1)
            s = s[:indL] + s[indR+1:]
        else:
            s = s[:indL] + s[indL + 1:]
   
    while "\"" in s:
        indL = s.find('\"')
        if '\"' in s[indL + 1:]:
            indR = s.find('\"',indL+1)
            s = s[:indL] + s[indR+1:]
        else:
            s = s[:indL] + s[indL + 1:]
    return s


def get_funcname(code):
    list_key_words = ['if', 'while', 'for', 'sizeof']  # 引起误报的关键字(容易出现在括号前面的)
    pattern = "((?:_|[A-Za-z])\w*(?:\s(?:\.|::|\->|)\s(?:_|[A-Za-z])\w*)*)\s?\("
    result = re.findall(pattern, code)

    i = 0
    while i < len(result):
        if result[i] in list_key_words:
            del result[i]
        else:
            i += 1

    return result


# 判断是什么类型的
def judge_type(s):
    pat1_1 = re.compile(r'(.*if[ ]?[(].*)|(.*else[ ]?[{].*)', re.MULTILINE)
    pat1_2 = re.compile(r'(.*while[ ]?[(].*)', re.MULTILINE)
    pat1_3 = re.compile(r'(.*for[ ]?[(].*)', re.MULTILINE)
    res1_1 = pat1_1.findall(s)
    res1_2 = pat1_2.findall(s)
    res1_3 = pat1_3.findall(s)
    # if_len = len(res1_1)
    if s.find('if ') != -1 or s.find('if') != -1:
        if_len = len(res1_1)
    elif s.find('switch ') != -1 or s.find('switch') != -1:
        if_len = s.find('switch ')
        if if_len == -1:
            if_len = s.find('switch')
    else:
        if_len = 0
    while_len = len(res1_2)
    for_len = len(res1_3)
    
    if((if_len > 0) and (while_len > 0) and (for_len > 0)):
        if s.find('if '):
            len_is = s.find('if ')
        elif s.find('switch '):
            len_is = s.find('switch ')
        res_type = get_min(len_is, s.find('while '), s.find('for '))
        if(res_type == "if" or res_type == 'switch'):
            return "if-Condition"
        elif(res_type == "while"):
            return "while-Condition"
        elif(res_type == "for"):
            return "for-Condition"
        
    elif((if_len > 0) and (while_len > 0)):
        if(s.find('if ') < s.find('while ')):
            return "if-Condition"
        else:
            return "while-Condition"
    elif((while_len > 0) and (for_len > 0)):
        if(s.find('for ') < s.find('while ')):
            return "for-Condition"
        else:
            return "while-Condition"
    elif((if_len > 0) and (for_len > 0)):
        if(s.find('for ') < s.find('if ')):
            return "for-Condition"
        else:
            return "if-Condition"
    elif(if_len > 0):
        return "if-Condition"
    elif(while_len > 0):
        return "while-Condition"
    elif(for_len > 0):
        return "for-Condition"
    
    pat1 = re.compile(r'.*=.*', re.MULTILINE) #匹配=
    res1 = pat1.findall(s)
    if((s[-3:] == "--;") or (s[-3:] == "++;")):
        return "Assignment"
    if(len(res1) > 0):  #如果有=/--/++，则说明是变量赋值语句
        countL_1 = s.split('=')[0].count("(")
        countR_1 = s.split('=')[0].count(")")
        countL_2 = s.split('=')[-1].count("(")
        countR_2 = s.split('=')[-1].count(")")

        if countL_1 != 0 and countR_2 != 0 and countL_1 != countR_1 and countR_2 != countL_2 and "{" not in s:
            return 'Fun-Call'
        else:
            if ('static const' in s and '{' in s) :#or ('(' in s and ')' in s and '{' in s and '}' not in s and s[1] != '{'):
                return "Fun-Declaration"
            else:
                return "Assignment"
    
    else:
        # pat2_1 = re.compile(r'(.*[(](.*?)[)].*)|(.*[(](.*?))|(.*[)].*)', re.MULTILINE)
        # res2_1 = pat2_1.findall(s)
        res2_1 = get_funcname(s)
        
        if(len(res2_1) > 0): #函数调用类型或者是函数声明
            if(len(res2_1) > 1): #解析出了多个函数名，这种情况只会在函数调用中出现
                return "Fun-Call"
            elif(s[-1] == ';'):
                return "Fun-Declaration"
            else:
                return "Fun-Head"
            # tmp = s[:s.find('(')].replace('+', '',1).replace('-', '',1).split(' ')
            # tmp = [i for i in tmp if i != ''] # 去除空
            # print(tmp)
            # print(s)
            # if((len(tmp) > 1) and (s[-1] == ';')): #有类型名，所以len(tmp)>1
            #     return "Fun-Declaration"
            # if((len(tmp) > 1) and (s[-1] != ';')):
            #     return "Fun-Head"
            # else:
            #     return "Fun-Call"
        else:
            s_tmp = s.replace('+', '',1).replace('-', '',1)
            if(s_tmp[:6] == 'return'):
                return "return"
            s_list = s_tmp.split(' ')
            s_list = [i for i in s_list if i != ''] # 去除空
            if(len(s_list) == 1):
                return "Undefine"
            elif s_list[0] == 'goto':
                return 'Undefine'
            elif s_list[-1] == '{':
                return 'Undefine'
            else:
                return "Var-Declaration"

# 判断修改处是否为替换类型，如果是则返回true
# 替换类型：类型名相同而且两句话涉及到修改的关键变量也相同
def judge_replace(flag, sub_conseq, add_conseq):
    if((flag == "if-Condition") or (flag == "while-Condition") or (flag == "for-Condition")):
        add_var, sub_var, mol = get_condition_key(add_conseq, sub_conseq, flag)
        if(add_var == sub_var): #如果两句话中的关键变量完全相同
            return True
        elif(mol == 'del' or mol == 'add'):
            return True
        else:
            False
    # if(flag == "if-Condition"):
    #     return True

    # if(flag == "for-Condition"):
    #     return True
    # if(flag == "while-Condition"):
    #     return True
    
    if(flag == "Undefine"):
        print("Undefine type doesn't be judged")
        return False
    
    if(flag == "Fun-Head"):
        print("Fun-Head type doesn't be judged")
        return False
    
    if(flag == "Assignment"):
        sub_res = get_var_assign(sub_conseq)
        add_res = get_var_assign(add_conseq)
        if(sub_res == add_res):
            return True
        else:
            return False
    
    if(flag == "Var-Declaration"):
        sub_var = get_var_decl(sub_conseq, 1) #flag,1表示删减类型，2表示增添类型
        add_var = get_var_decl(add_conseq, 2)
        
        if((sub_var == "none") or (add_var == "none")):
            return False
        
        if((sub_var == None) or (add_var == None)):
            return False
        
        sub_var.sort()
        add_var.sort()
        
        if(sub_var == add_var):
            return True
        else:
            return False
            
    if(flag == "Fun-Call"):
        sub_conseq = sub_conseq.strip()[1:]
        add_conseq = add_conseq.strip()[1:]
        
        sub_tmp = sub_conseq[:sub_conseq.find('(')]
        add_tmp = add_conseq[:add_conseq.find('(')]
        
        if(sub_tmp == add_tmp):
            return True
        else:
            return False
        
# 判断这句话是不是控制语句类型    
def not_control(s):
    pat1_1 = re.compile(r'(.*if[ ]?[(].*)|(.*else[ ]?[{].*)', re.MULTILINE)
    pat1_2 = re.compile(r'(.*while[ ]?[(].*)', re.MULTILINE)
    pat1_3 = re.compile(r'(.*for[ ]?[(].*)', re.MULTILINE)
    res1_1 = pat1_1.findall(s)
    res1_2 = pat1_2.findall(s)
    res1_3 = pat1_3.findall(s)
    
    if(res1_1 or res1_2 or res1_3):
        return False
    else:
        return True

def print_add_del(k, patch_model_s, Change_statement_type_s, file_type, Line_number_s, cri_var_s, result_file, txt_file):
    print("%s. Patch_model: %s"%(k, patch_model_s))
    print("Change_statement_type: %s"%Change_statement_type_s)
    print("Line_number: %s file:#%s"%(file_type, Line_number_s))
    print("Critical_variable: %s"%cri_var_s)
    print("")
    
    print("%s. Patch_model: %s"%(k, patch_model_s), file = txt_file)
    #print("%s. Patch_model: %s"%(k, patch_model_s),file = txt_file)
    print("Change_statement_type: %s"%Change_statement_type_s, file = txt_file)
    print("Line_number: %s file:#%s"%(file_type, Line_number_s), file = txt_file)
    print("Critical_variable: %s"%cri_var_s, file = txt_file)
    print("", file = txt_file)
    
    pkl.dump("%s. Patch_model: %s"%(k, patch_model_s), result_file)
    pkl.dump("Change_statement_type: %s"%Change_statement_type_s, result_file)
    pkl.dump("Line_number: %s file:#%s"%(file_type, Line_number_s), result_file)
    pkl.dump("Critical_variable: %s"%cri_var_s, result_file)
    pkl.dump("", result_file)
    
def my_print(k, sub_type, add_type, sub_line, add_line, sub_key, add_key, rep_key,result_file, txt_file, type_flag):
    if type_flag == 'add' or type_flag == 'del':
        if type_flag == 'add':
            patch_model_s = 'Add'
            Change_statement_type_s = add_type
            file_type = 'new'
            Line_number_s = add_line
            cri_var_s = add_key
        else:
            patch_model_s = 'Delete'
            Change_statement_type_s = sub_type
            file_type = 'old'
            Line_number_s = sub_line
            cri_var_s = sub_key

        print_add_del(k, patch_model_s, Change_statement_type_s, file_type, Line_number_s, cri_var_s, result_file, txt_file)
    
    elif type_flag == 'add_and_del':
        patch_model_s = 'Delete'
        Change_statement_type_s = sub_type
        file_type = 'old'
        Line_number_s = sub_line
        cri_var_s = sub_key
        if cri_var_s != [] and cri_var_s != None:
            print_add_del(k, patch_model_s, Change_statement_type_s, file_type, Line_number_s, cri_var_s, result_file, txt_file) 

        patch_model_s = 'Add'
        Change_statement_type_s = add_type
        file_type = 'new'
        Line_number_s = add_line
        cri_var_s = add_key
        k = k + 1
        if cri_var_s != [] and cri_var_s != None:
            print_add_del(k, patch_model_s, Change_statement_type_s, file_type, Line_number_s, cri_var_s, result_file, txt_file) 

    elif type_flag == 'rep':
        print("%s. Patch_model: Replace"%k)
        print("Change_statement_type: %s"%sub_type)
        print("Line_number: old file: #%s"%sub_line)
        print("Line_number: new file: #%s"%add_line)
        print("Critical_variable: %s"%rep_key)
        print("")
            
        print("%s. Patch_model: Replace"%k, file = txt_file)
        print("Change_statement_type: %s"%sub_type, file = txt_file)
        print("Line_number: old file: #%s"%sub_line, file = txt_file)
        print("Line_number: new file: #%s"%add_line, file = txt_file)
        print("Critical_variable: %s"%rep_key, file = txt_file)
        print("", file = txt_file)

        pkl.dump("%s. Patch_model: Replace"%k, result_file)
        pkl.dump("Change_statement_type: %s"%sub_type, result_file)
        pkl.dump("Line_number: new file:#%s"%sub_line, result_file)
        pkl.dump("Line_number: new file:#%s"%add_line, result_file)
        pkl.dump("Critical_variable: %s"%rep_key, result_file)
        pkl.dump("", result_file)

def check_var_again(res_vars):
    var_list = []
    var_tmp = []
    for res in res_vars:
        if '::' in res:
            loc = res.rfind("::")
            res = res[loc+1 :]
        res = res.strip()
        while res != '' and len(res) != 1 and (res[0] == '(' or res[0] == ')' or res[0] == '-' or res[0] == '+' or res[0] == '~' or res[0] == '|' or res[0] == '<' or res[0] == '>' or res[0] == '/' or res[0] == '|'  or res[0] == '!'  or res[0] == '{'  or res[0] == '}' or res[0] == '=' or res[0] == ':' or res[0] == ','):
            res = res[1:].strip()
            if res == '':
                continue
        while res != '' and len(res) != 1 and (res[-1] == '(' or res[-1] == ')' or res[-1] == '|' or res[-1] == '-' or res[-1] == '+' or res[-1] == '<' or res[-1] == '>' or res[-1] == '/'  or res[-1] == '%'  or res[-1] == '*' or res[-1] == '&'  or res[-1] == '{'  or res[-1] == '}' or res[-1] == ';' or res[-1] == '=' or res[-1] == ':' or res[-1] == ','):
            res = res[:-1].strip()
            if res == '':
                continue

        if res == '':
            continue

        if res == 'int' or res == 'char' or 'size_t' in res or 'signed' in res or 'float' in res or res == 'struct' or res.startswith('uint') or res == 'void' or res == 'const': 
            continue

        pat = re.compile(r'.*\[(.*?)\].*', re.MULTILINE) # 看是不是数组变量
        flag = pat.findall(res) #检查=前面，也就是变量所在的位置有没有[]
        locL = res.find("[")
        locR = res.find("]")
        
        if (flag): # 去除数组末尾的符号
            ind = res[:locL].find("-")
            if ind == -1:
                ind = res[locR+1:].find("-")
        else:
            ind = res.find('-')

        if ind != -1:
            if is_number(res[ind+1]): #变量提取出来是否有a-1这种表达式
                res = res[:ind]
                var_tmp.append(res)
            elif res[ind+1] != '>' and res[ind+1:ind+3] != ' >' and res[ind+1] != '-':#a - b的形式
                var_tmp.append(res[:ind])
                var_tmp.append(res[ind+1:])
            else:
                var_tmp.append(res)
        else:
            var_tmp.append(res)

    for res in var_tmp:
        flag_al = 0
        for r in res:
            if r.isalpha():
                flag_al = 1
                break
        if flag_al == 1:        
            if (is_number(res) != True) and (is_define(res) != True):
                if res.count("[") != res.count("]"):
                    if res.find("[") != -1:
                        res = res.split("[")[0]
                    else:
                        res = res.split(']')[-1]
                if res.count("(") == res.count(")"):
                    var_list.append(res)

    res_vars = [i for i in var_list if ((i != '') and (i != "\'") and (i != '\"') and (i != '-') and (i != '+') and (i != '/') and (i != '<') and (i != '>') and (i != '!') and (i != '=') and (i != '*') and (i != '&') and (i != '<=') and (i != '>=') and (i != '==') and (i != '<<') and (i != '>>'))] # 去除空和其它字符
    res_vars = list(set(res_vars))
    print(res_vars)
    return res_vars

#对控制语句中的条件语句进行提取，并按照&&||进行分割
def process_condition(s, flag):
    begin = 0
    diff = 0

    if 'switch ' in s:
        s = s.replace('switch ','if ')
    if ';' in s and 'if' in s: #if() break;写到一行的情况
        s = s.split(') ')[0]

    # s = rmv_str(s) #不应该去除字符串,因为这可能涉及到条件值
    if(flag == 1):
        begin = s.find('if(')
        diff = 2
        if(begin == -1):
            begin = s.find('if (')
            diff = 3
        if(begin == -1): #没有if条件框,所以不用进行提取
            return "nothing"
        if ',' in s and 'if(' in s and '(' in s.split('if(')[-1]: #函数调用
            if '&&' not in s and '||' not in s:
                ind = s.find('if(')
                begin = s.find("(", ind + 3) - diff
        if ',' in s and 'if (' in s and '(' in s.split('if (')[-1]: #if内包含函数调用
            if '&&' not in s and '||' not in s:
                ind = s.find('if (')
                begin = s.find("(", ind + 4) - diff

    elif(flag == 2):
        begin = s.find('while(')
        diff = 5
        if(begin == -1):
            begin = s.find('while (')
            diff = 6
        if(begin == -1): #没有if条件框,所以不用进行提取
            return "nothing"

    elif(flag == 3):
        begin = s.find('for(')
        diff = 3
        if(begin == -1):
            begin = s.find('for (')
            diff = 4
        if(begin == -1): #没有if条件框,所以不用进行提取
            return "noting"

    end = s.find('{')
    if(end != -1):
        s = s[(begin + diff):end] # 得到该行的句子,已经去掉了开头的if/while/for
    else:
        s = s[begin + diff:] # 得到该行的句子,已经去掉了开头的if/while/for

    # 提取出for循环两个分号之间的内容
    if(flag == 3):
        b = s.find(';') + 1
        e = s.rfind(';')
        s = s[b:e]
    
    s_list = re.split('&&|[||]', s) #用 &&和|| 隔开表达式 
    # s_list = [i for i in s_list if i != ''] # 去除空,(a > 10)
    s_list_tmp = []
    for i in s_list: #去除括号带来的不一致性
        i = i.strip()
        if(i == ''):
            continue
        while(i[-1] == ')'):
            i = i[:-1]
        while(i[0] == '('):
            i = i[1:]
        s_list_tmp.append(i)
    print('s_list: ', s_list)
    print('s_list_tmp: ', s_list_tmp)

    # return s_list
    return s_list_tmp

# 获取控制语句中的关键变量
# flag = 1是if类型，=2是while类型，=3是for类型
# okk
# def get_cond_var(s, flag):
def get_cond_var(s_list, flag):
    # begin = 0
    # diff = 0

    # if 'switch ' in s:
    #     s = s.replace('switch ','if ')
    # if ';' in s and 'if' in s: #if() break;写到一行的情况
    #     s = s.split(') ')[0]

    # s = rmv_str(s)
    # if(flag == 1):
    #     begin = s.find('if(')
    #     diff = 2
    #     if(begin == -1):
    #         begin = s.find('if (')
    #         diff = 3
    #     if(begin == -1): #没有if条件框,所以不用进行提取
    #         return "nothing"
    #     if ',' in s and 'if(' in s and '(' in s.split('if(')[-1]: #函数调用
    #         if '&&' not in s and '||' not in s:
    #             ind = s.find('if(')
    #             begin = s.find("(", ind + 3) - diff
    #     if ',' in s and 'if (' in s and '(' in s.split('if (')[-1]: #if内包含函数调用
    #         if '&&' not in s and '||' not in s:
    #             ind = s.find('if (')
    #             begin = s.find("(", ind + 4) - diff

    # elif(flag == 2):
    #     begin = s.find('while(')
    #     diff = 5
    #     if(begin == -1):
    #         begin = s.find('while (')
    #         diff = 6
    #     if(begin == -1): #没有if条件框,所以不用进行提取
    #         return "nothing"

    # elif(flag == 3):
    #     begin = s.find('for(')
    #     diff = 3
    #     if(begin == -1):
    #         begin = s.find('for (')
    #         diff = 4
    #     if(begin == -1): #没有if条件框,所以不用进行提取
    #         return "noting"

    # end = s.find('{')
    # if(end != -1):
    #     s = s[(begin + diff):end] # 得到该行的句子,已经去掉了开头的if/while/for
    # else:
    #     s = s[begin + diff:] # 得到该行的句子,已经去掉了开头的if/while/for

    # # 提取出for循环两个分号之间的内容
    # if(flag == 3):
    #     b = s.find(';') + 1
    #     e = s.rfind(';')
    #     s = s[b:e]
    
    # s_list = re.split('&&|[||]', s) #用 &&和|| 隔开表达式 
    # s_list = [i for i in s_list if i != ''] # 去除空,(a > 10)
    # print('s_list: ', s_list)
    # s_list = process_condition(s, flag)
    res_vars = [] #保存要返回去的关键变量
    for base_s in s_list:
        tmp = split_var(base_s)
        if len(tmp) >= 1:
            base_s = tmp[0]

        base_list = []
        base_s = base_s.strip()

        if(base_s.find('(unsigned)') != -1):
            index = base_s.find('(unsigned)')
            base_s = base_s[(index + 10):]

        pat = re.compile(r'.*\[(.*?)\].*', re.MULTILINE) # 看是不是数组变量
        res = pat.findall(base_s) #检查=前面，也就是变量所在的位置有没有[]
        if (res):
            base_list.append(base_s)
        else:
            base_list = re.split('[, ]|[ + ]|[ - ]|[ * ]|[ / ]|[; ][ & ]', base_s)

        if(flag == 1):           
            base_list = [i for i in base_list if ((i != '') and (i != '-') and (i != '+') and (i != '/') and (i != '*') and (i != '&'))] # 去除空和其它字符
        else:
            base_list = [i for i in base_list if ((i != '') and (i != '-') and (i != '+') and (i != '/') and (i != '<') and (i != '>') and (i != '!') and (i != '=') and (i != '*') and (i != '&'))] #去除空和其它字符

        var_list_res = []
        
        for var in base_list: #>\<等操作符切分表达式
            sym_L  = var.rfind('<')
            sym_R = var.find(">")
            if sym_R!= -1 and sym_L != -1 and '->' not in var[sym_L:sym_R] and ' ' not in var[sym_L:sym_R]:
                var = var.split(">")[-1]
            var_list_tmp = split_var(var)
            for var in var_list_tmp:
                if var == '':
                    continue
                var_list_res.append(var)

        count_for_con = 0
        for base_var in var_list_res: #去除括号
            start = base_var.rfind('(')
            end = base_var.find(')')

            if((start != -1) and (end != -1)):
                res = base_var[start+1:end] #去除if的括号 a < 0
                if count_for_con == 0:
                    if base_var.startswith("((") and end != len(base_var) - 1:
                        res = base_var[end + 1:]
                else:
                    if base_var.startswith("(") and end != len(base_var) - 1:
                        res = base_var[end + 1:]
            elif(start != -1):
                res = base_var[start+1:]
            elif(end != -1):
                res = base_var[:end]
            else:
                res = base_var
            count_for_con += 1
            
            res_vars.append(res)
            
    res_vars = check_var_again(res_vars)
    return res_vars

# 获取函数调用和函数头部里的关键变量
# flag=1表示函数调用，flag=2表示函数头部
# okk
def get_call_var(s, flag):
    # if '_log' in s or 'spprintf' in s or 'E_WARNING' in s or 'warning' in s or 'assert' in s or 'print' in s or 'ASSERT' in s or 'Exception' in s or 'Error' in s or 'FAIL' in s:
    if 'spprintf' in s or 'E_WARNING' in s or 'warning' in s or 'assert' in s or 'print' in s or 'ASSERT' in s or 'Exception' in s or 'Error' in s or 'FAIL' in s:
        return []
    print(s)
    s = rmv_str(s)
    if 'CreateMockRead(ping_frames.back()' in s:
        print(s)
    if s[1:].strip().startswith('(') and not s[1:].strip().startswith('(('): #去除 (void) func(a,b);情况中的(void)
        indR = s[1:].strip().find(")")
        s = s[1:].strip()[indR+1 :]

    start = s.find('(')
    end = s.rfind(')')
    
    if((start != -1) and (end != -1)):
        res = s[start + 1:end] # 已经去掉了括号
    elif(start != -1):
        res = s[start + 1:]
    elif(end != -1):
        res = s[:end]
    else:
        print("error")
        return
    
    res = re.split('[,]', res) #以逗号分割实参，将实参单独提出
    res = [i for i in res if i != ''] # 去除空
    res_vars = []

    for i in res:
        if i.strip() == '':
            continue
        if(i[0] == ' '):
            i = i[1:]
        if(i[0] == '\"' and i[-1] == '\"'):# 如果是字符换就不输出了
            continue
        if(i[0] == '\'' and i[-1] == '\''):# 如果是字符换就不输出了
            continue
        if flag == 2:
            res_vars.append(i.split(' ')[-1]) #去除变量类型
        else:# 分割函数参数中存在的表达式 提取出变量
            sym_L  = i.rfind('<')
            sym_R = i.find(">")
            if sym_R!= -1 and sym_L != -1 and '->' not in i[sym_L:sym_R] and ' ' not in i[sym_L:sym_R]:
                i = i.split(">")[-1]
            i_list = re.split('&&|[||]', i)
            i_list = [k for k in i_list if k != ''] # 去除空
            for j in i_list:
                if(j[0] == ' '): # 去除开头可能存在的空格
                    j = j[1:]
                
                if "(" in j and ')' not in j: #函数调用里面还有函数调用，套娃专用
                    ind = j.find('(')
                    j = j[ind+1:]

                if '(' in j and ')' in j: #(const int) a
                    locL = j.rfind('(')
                    locR = j.find(')')
                    if locL < locR:
                        if locR != len(j) - 1:#(const int) a
                            j = j.split(')')[-1]
                        else:
                            if locR != locL + 1:
                                j = j[locL+1 : locR]
                    else:
                        j = j[locL+1:]


                index = get_location(j)
                if(index != -2):
                    j = j[:index]
                
                j_list = re.split('[, ]|[ + ]|[ - ]|[ * ]|[ / ]|[; ][ & ]|[+]|[*]|[/]', j)
                j_list = [m for m in j_list if ((m != '') and (m != '-') and (m != '+') and (m != '/') and (m != '*') and (m != '&'))] # 去除空和其它字符
                for k in j_list: #处理每一个实参表达式, 去除表达式中的括号
                    if((is_number(k) == False) and (is_define(k) == False)):
                        if '(' in k and ')' not in k: ####
                            inde = k.find("(")
                            k = k[inde+1:]
                            res_vars.append(k)
                        else:
                            res_vars.append(k)

    res_vars2 = check_var_again(res_vars)
    return res_vars2

# 在判断变量赋值类型中，用来获取变量名, 没有去掉（int）a 的情况
# okk
def get_var_assign(s):
    s = s[1:].strip()
    s = rmv_str(s)
    ind = s.find('{')
    var_list = []
  
    if ind == len(s) - 1:
        print(s)
        return []

    if '{' in s and "}" not in s: #do{s[1] = 1这种类型
        s = s.split('{')[-1]

    s_tmp_left = []
    if((s.find('=')) == -1):# 判断是否是i++;i--形式
        if((s[-3:] == '++;') or (s[-3:] == '--;')):
            s_tmp = s[:-3]
            s_res = s_tmp.replace(" ", "")
            if(type(s_res) == list):
                return s_res
            else:
                var_list.append(s_res)
                return var_list
        else: 
            if s.find('(') != -1 and s.find(")") != -1:
                s_tmp_left.append(s[s.rfind('('):s.find(')')]) ######
            else:
                s_tmp_left.append(s)

    else: #有=的等式
        left_part = s.split("=")[0].strip()
        pat = re.compile(r'.*\[(.*?)\].*', re.MULTILINE) # 看是不是数组变量
        res = pat.findall(left_part) #检查=前面，也就是变量所在的位置有没有[]
        if (res):
            locL = left_part.find("[")
            locR = left_part.find("]")
            loc_space = left_part[:locL].rfind(" ")
            if loc_space == -1: #没有空格
                var_tmp = left_part
            else:
                # var_tmp = left_part[loc_space:].strip()
                var_tmp = left_part.strip()
            s_tmp_left.append(var_tmp)

        else:
            if '(' in s.split("=")[0] and ')' in s.split("=")[0]:#等号左边存在函数调用情况：func(a,b) = 1
                indL = s.split("=")[0].rfind('(')
                indR = s.split("=")[0].find(')')
                if '(' not in s[:2]: #避免（void）func1(a,b,c) = 1的情况
                    if indL < indR:
                        s_tmp_left = s[indL+1:indR].split(',')
                    else:
                        s_tmp_left.append(s[:s.find('=')])
                else:
                    s_tmp_left.append(s[indR+1:s.find('=')])
            else:
                s_tmp_left.append(s[:s.find('=')].strip())

    s_tmp = []
    for var in s_tmp_left: 
        if var == '' or var == ' ':
            continue
        pat = re.compile(r'.*\[(.*?)\].*', re.MULTILINE) # 看是不是数组变量
        res = pat.findall(var) #检查=前面，也就是变量所在的位置有没有[]
        
        if (res): # 去除数组末尾的符号
            s_tmp.append(var.replace(' ', '').strip())
        else:
            s_tmp_1 = []
            var = var.strip()
            sym_L  = var.rfind('<')
            sym_R = var.find(">")
            if sym_R!= -1 and sym_L != -1 and '->' not in var[sym_L:sym_R] and ' ' not in var[sym_L:sym_R]:
                var = var.split(">")[-1]
            var = var.split(' ') # 以空格为分界符获取=前的字符串
            var = [i for i in var if i != ''] # 去除空
            if var == []:
                return []
            if((var[-1] == '+') | (var[-1] == '-') | (var[-1] == '/') | (var[-1] == '*') | (var[-1] == '&') | (var[-1] == '|') | (var[-1] == '>>') | (var[-1] == '<<') | (var[-1] == '%')):
                s_tmp_1.append(var[-2])
            else:
                s_tmp_1.append(var[len(var) - 1]) # 提取出变量名

            for var in s_tmp_1:
                var = var.strip()
                locL = var.rfind("(")
                locR = var.find(")")
                true_var = var
                if locL != -1 and locR != -1 :
                    if locL < locR:
                        true_var = var[locL+1:locR]
                    else:
                        if locL == len(var) - 1:
                            true_var = var[:locL]
                else:
                    if locL != -1 and locR == -1:
                        if locL == len(var) - 1:
                            true_var = var[:locL]
                    elif locR != -1 and locL == -1:
                        if locR == len(var) - 1:
                            true_var = var[:locR]
 
                s_tmp.append(true_var.strip())
  
    var_list = check_var_again(s_tmp)
    return var_list

# 在判断变量定义类型中，用来获取变量名
# 参数flag,1表示删减类型，2表示增添类型
# okk
def get_var_decl(sub_conseq, flag):
    sub_var = []
    sub_conseq = rmv_str(sub_conseq)
    sub_conseq  = sub_conseq[1:].strip()

    sub_tmp = sub_conseq.split(',')
    for i in sub_tmp:
        is_arr = i.find('[')#去掉数组的[]
        if(is_arr != -1):
            i = i[:is_arr]
        sub_var.append(i)
    # sub_var = check_var_again(sub_tmp)

    var_list = []

    for var in sub_var:
        if '<' in var or '>' in var:
            continue
        var_tmp = var.split(' ')[-1]
        var_list.append(var_tmp)

    var_list_res = check_var_again(var_list)
    return var_list_res

    # sub_tmp = sub_conseq[1:].strip().split(' ')
    # sub_tmp = [i for i in sub_tmp if i != ''] # 去除空
    # print('get_var_decl(): sub_tmp: ', sub_tmp)
    # if len(sub_tmp) == 1:
    #     return ['']   
    
    # counter = 0
    # if ',' in sub_conseq:
    #     counter = sub_conseq.count(",")
    
    # counter += 1
    # sub_var = sub_tmp[-counter:]
    # print('sub_var: ', sub_var)
    # for var in sub_var:
    #     if '<' in var or '>' in var:
    #         sub_var.remove(var)

    # var_list = check_var_again(sub_var)
    # return var_list

def get_condition_key(add_line, sub_line, line_type):
    print('add_line: ', add_line)
    print('sub_line: ', sub_line)
    if line_type == "if-Condition":
        flag = 1
    elif line_type == "while-Condition":
        flag = 2
    elif line_type == "for-Condition":
        flag = 3
    add_child_condition = process_condition(add_line, flag)
    sub_child_condition = process_condition(sub_line, flag)

    add_fin_condition = list(set(add_child_condition) - set(sub_child_condition))
    sub_fin_condition = list(set(sub_child_condition) - set(add_child_condition))
    print('add_fin_condition: ', add_fin_condition)
    print('sub_fin_condition: ', sub_fin_condition)

    # 此时获得的关键变量都是可以直接输出的
    add_var = get_cond_var(add_fin_condition, flag)
    sub_var = get_cond_var(sub_fin_condition, flag)
    
    flag = 'normal'
    if(add_fin_condition == [] and sub_fin_condition == []):
        flag = 'no'
    elif(add_child_condition != [] and add_fin_condition == []): #说明add语句完全被del语句包含
        flag = 'del'
    elif(sub_child_condition != [] and sub_fin_condition == []):
        flag = 'add'


    return add_var, sub_var, flag

# input:string of all @@ block
def check_complex_type(s, result_file, txt_file):
    '''
    1. 修改了len(conseq_diffs)处
    2. 第一处：替换/纯增删
    3. 哪种类型
    4. input：diff hunk（@@隔开）
    '''
    sub_line = 0
    add_line = 0
    conseq_diffs = process(s) #将diff hunk 按照一块块连续的加减行切割，list中每个元素（str）存储的是该diff hunk中的每块连续的加减行
    if len(conseq_diffs) == 1:
        print("the num of consequent diff block is just 1")
    #判断替换/增删
    cnt = 1  # 标记是第几处修改
    conseq_counter = 1 #用来计数输出的第几句话
    for block in conseq_diffs:
        if '0,0,3,959,960' in block:
            print(1)
        line_num = block[:(block.find('|'))].split(',')
        sub_line_num = line_num[0] #前面的block有几个减号行
        add_line_num = line_num[1] #前面的block有几个加号行
        counter = line_num[2] # diff文件中没有+-的未修改行
        sub_line = line_num[3] # 修补前文件的起始行号
        add_line = line_num[4] #修补后文件的起始行号
        block = block[(block.find('|') + 1):]
        
        conseqs_tmp = block.split('\n\r') #conseqs为list：存储+/-行代码
        conseq_line_dict_tmp = {}
        line_num_count = 0
        for conseq in conseqs_tmp:#所有的+-行及行号存入conseq_line_dict_tmp
            if conseq == '':
                continue            
            else:
                conseq_line_dict_tmp[line_num_count] = conseq
                line_num_count += 1

        flag = 0
        tmp = ''
        conseq_line_dict = {}
        sub_conseq = {} # 存放这一个block的删减语句
        add_conseq = {}
        sub_typeNum = [] # 存放这一个block含有的删减类型
        add_typeNum = []
        for k,v in conseq_line_dict_tmp.items():
            v = v.strip()
            if '\t' in v or '\n' in v or '\r' in v:
                v = v.replace('\r','').replace('\n','').replace('\t','')
            if((len(v) >= 2) and (v[-1] == '\\') and (v[-2] == ' ')):
                v = v[:-2]

            if ';' in v:
                index1 = v.rfind(';') #去除句内注释
            elif '{' in v:
                index1 = v.rfind('{')
            else:
                index1 = -1

            if v.find("/*"):
                index2 = v.rfind('/*')
            elif v.find("//"):
                index2 = v.rfind('//')
            if((index1 != -1) and (index1 < index2)): #判断行内是否有/*...*/和//的注释
                v = v[:(index1 + 1)]

            if v.replace(' ','')[1:3] == '/*' and '*/' not in v.replace(' ',''): #去除/**/注释
                flag = 1
                continue
            elif flag == 1: #前面有/*
                if '*/' in v.replace(' ',''):
                    flag = 0
                    continue
                else:
                    continue
            elif flag == 0:
                if(is_invaild(v)): #判断该语句是否为注释
                    continue

                if(tmp != '' and (tmp[0] == v[0])): #上一句和本句是一句，需要连接起来,并且确保是相同属性的语句（+/-）
                    v = v.replace(v[0], "",1).strip()# .replace(" ", "") # 处理conseq以便于和上一句衔接
                    index = 0
                    for i in range(len(v)):
                        if(v[i] != ' '):
                            index = i
                            break
                    v = v[index:]
                    v = tmp + ' ' + v
                    k = line_tmp

                if((v[-1] == ')') and (not_control(v) == False) and v.count("(") == v.count(')')): # if语句后面没有{的情况，给加上{
                    v = v + '{'
                
                if((v[-1] != ';') and (not_control(v)) and (v[-1] != '}') and v[-4:] != 'else' and v[-1] != '{'): # 一句话被分成两行的情况
                    if tmp == '': #第一次出现该行不全的情况，则记录行号
                        line_tmp = k
                    tmp = v
                elif((v[-1] != ';') and (v[-1] != '{') and (not_control(v) == False)): #if语句分了两行
                    if tmp == '': #第一次出现该行不全的情况，则记录行号
                        line_tmp = k
                    tmp = v
                else:
                    tmp =  ''
                
                if tmp == '': #将语句和type存入数组
                    conseq_line_dict[k] = v
                    if (v[0] == '-'):
                        del_num = 0
                        v_tmp = v.strip()[1:].strip()
                        if(v_tmp[0:6] == "return"):
                            typenum = "return"
                        elif((v_tmp[0:4] == 'case') or (v_tmp[0:5] == "break")) or (v_tmp[0:5] == "else{"):
                            #typenum = "Undefine"
                            if('=' in v_tmp):
                                typenum = judge_type(v)
                            else:
                                typenum = "Undefine"
                        elif (v_tmp[0] == "}"):
                            if 'if' in v_tmp or 'while' in v_tmp:
                                typenum = judge_type(v)
                            else:
                                typenum = "Undefine"
                        else:
                            typenum = judge_type(v)
                        
                        for k_tmp in conseq_line_dict_tmp.keys():
                            if k_tmp != k:
                                if conseq_line_dict_tmp[k_tmp].strip()[0] == '-' :
                                    del_num += 1
                            else:
                                break
                                
                        sub_typeNum.append(typenum)
                        sub_conseq[del_num] = v
                    
                    elif (v[0] == '+'):
                        add_num = 0
                        v_tmp = v.strip()[1:].strip()
                        if(v_tmp[0:6] == "return"):
                            typenum = "return"
                        elif((v_tmp[0:4] == 'case') or (v_tmp[0:5] == "else{") or (v_tmp[0:5] == "break")):
                            typenum = "Undefine"
                        elif (v_tmp[0] == "}"):
                            if 'if' in v_tmp or 'while' in v_tmp:
                                typenum = judge_type(v)
                            else:
                                typenum = "Undefine"
                        else:
                            typenum = judge_type(v)
                        
                        for k_tmp in conseq_line_dict_tmp.keys():
                            if k_tmp != k:
                                if conseq_line_dict_tmp[k_tmp].strip()[0] == '+' :
                                    add_num += 1
                            else:
                                break
                                
                        add_typeNum.append(typenum)
                        add_conseq[add_num] = v

        print('````````````````````````````')
        for item in conseq_line_dict_tmp.items():
            print(item)
        print('````````````````````````````')
        
        print('=== sub ===')    
        for item in sub_conseq.items():
            print(item)

        print('=== add ===')
        for item in add_conseq.items():
            print(item)
        print('')

        cnt += 1
        len_sub = len(sub_conseq)
        len_add = len(add_conseq)

        if len_sub > 50 or len_add > 50:
            continue

        if(len_sub >= len_add):
            min_len = len_add
            max_len = len_sub
            max_flag = 0 #减号行数量大于加号行
        else:
            min_len = len_sub
            max_len = len_add
            max_flag = 1

        for i in range(min_len):
            res = False
            line_num_add = list(add_conseq.keys())[i]
            conseq_add = add_conseq[line_num_add]
            line_num_sub = list(sub_conseq.keys())[i]
            conseq_sub = sub_conseq[line_num_sub]

            sub_keyline = int(sub_line) + int(sub_line_num) + int(counter) + line_num_sub #减号行行号
            add_keyline = int(add_line) + int(add_line_num) + int(counter) + line_num_add #加号行行号
            print(sub_keyline, add_keyline)
            print(sub_typeNum[i], add_typeNum[i])
            if(sub_typeNum[i] == add_typeNum[i]): #如果减号行和加号行的类型相同，就一步判断是否为替换的情况
                res = judge_replace(sub_typeNum[i], conseq_sub, conseq_add)
                #判断两句是否完全一致
                conseq_sub_tmp = conseq_sub[1:].replace(' ','')
                conseq_add_tmp = conseq_add[1:].replace(' ','')
                if conseq_sub_tmp == conseq_add_tmp:
                    continue
            print('judge_replace result: ', res)
            not_xor = False
            if(res): #输出rep/add/del + cv
                if sub_typeNum[i] == "if-Condition" or sub_typeNum[i] == "while-Condition" or sub_typeNum[i] == "for-Condition":
                    add_var, key_var, mol = get_condition_key(conseq_add, conseq_sub, sub_typeNum[i]) #控制语句的关键变量需要比对加减行子语句之后进行获取
                    not_xor = True

                    if(mol == 'no'):
                        continue
                    elif(mol == 'add'):
                        type_flag = 'add'
                        fin_key = add_var
                        my_print(conseq_counter, 'sub_typeNum[i]', add_typeNum[i], 'sub_keyline', add_keyline, 'sub_key_var', fin_key, 'rep_key_var', result_file, txt_file, type_flag)
                        conseq_counter += 1
                        continue
                    elif(mol == 'del'):
                        type_flag = 'del'
                        sub_key_var = key_var
                        my_print(conseq_counter, sub_typeNum[i], 'add_typeNum[i]', sub_keyline, 'add_keyline', sub_key_var, 'add_key_var', 'rep_key_var', result_file, txt_file, type_flag)
                        conseq_counter += 1
                        continue
                    else:
                        key_var = add_var
                else:
                    key_var = get_key(conseq_sub, sub_typeNum[i]) #减号行的关键变量
                    add_var = get_key(conseq_add, sub_typeNum[i]) #加号行的关键变量
                    print('key_var:   ', key_var)
                    print('add_var:   ', add_var)
                    if key_var == [] or key_var == None:
                        continue
                    
                    if set(key_var) < set(add_var):
                        type_flag = 'add'
                        # fin_key = list(set(key_var) ^ set(add_var))
                        if(not_xor == False):
                            fin_key = list(set(key_var) ^ set(add_var))
                        else:
                            # fin_key = list(set(set(key_var) | set(add_var))) #|为set类型做并集
                            fin_key = add_var
                        my_print(conseq_counter, 'sub_typeNum[i]', add_typeNum[i], 'sub_keyline', add_keyline, 'sub_key_var', fin_key, 'rep_key_var', result_file, txt_file, type_flag)
                        conseq_counter += 1
                        continue
                    elif set(key_var) == set(add_var):
                        key_var = add_var
                    elif set(key_var) > set(add_var):
                        if(not_xor == False):
                            sub_key_var = list(set(key_var) - set(add_var))
                        else:
                            sub_key_var = key_var
                        type_flag = 'del'
                        my_print(conseq_counter, sub_typeNum[i], 'add_typeNum[i]', sub_keyline, 'add_keyline', sub_key_var, 'add_key_var', 'rep_key_var', result_file, txt_file, type_flag)
                        conseq_counter += 1
                        continue
                    else:
                        key_var = list(set(key_var) - set(add_var))
                # key_var = get_key(conseq_sub, sub_typeNum[i]) #减号行的关键变量
                # add_var = get_key(conseq_add, sub_typeNum[i]) #加号行的关键变量
                
                # print('not_xor: ', not_xor)
                
                # if set(key_var) < set(add_var):
                #     type_flag = 'add'
                #     # fin_key = list(set(key_var) ^ set(add_var))
                #     if(not_xor == False):
                #         fin_key = list(set(key_var) ^ set(add_var))
                #     else:
                #         # fin_key = list(set(set(key_var) | set(add_var))) #|为set类型做并集
                #         fin_key = add_var
                #     my_print(conseq_counter, 'sub_typeNum[i]', add_typeNum[i], 'sub_keyline', add_keyline, 'sub_key_var', fin_key, 'rep_key_var', result_file, txt_file, type_flag)
                #     conseq_counter += 1
                #     continue
                # elif set(key_var) == set(add_var):
                #     key_var = add_var
                # elif set(key_var) > set(add_var):
                #     if(not_xor == False):
                #         sub_key_var = list(set(key_var) - set(add_var))
                #     else:
                #         sub_key_var = key_var
                #     type_flag = 'del'
                #     my_print(conseq_counter, sub_typeNum[i], 'add_typeNum[i]', sub_keyline, 'add_keyline', sub_key_var, 'add_key_var', 'rep_key_var', result_file, txt_file, type_flag)
                #     conseq_counter += 1
                #     continue
                # else:
                #     key_var = list(set(key_var) - set(add_var))

                type_flag = 'rep'
                my_print(conseq_counter, sub_typeNum[i], sub_typeNum[i], sub_keyline, add_keyline, '', '', key_var, result_file, txt_file, type_flag)
                conseq_counter += 1

            else: #不是替换（注：可能是两句话类型不同)
                sub_key_var = get_key(conseq_sub, sub_typeNum[i])
                add_key_var = get_key(conseq_add, add_typeNum[i])
                
                if(sub_typeNum[i] == add_typeNum[i]):
                    fin_key = []
                    if(sub_typeNum[i] == "Fun-Head"): # 处理在函数头增加参数的情况 FIX:需要进一步对变量类型进行判断
                        if(len(add_key_var) >= len(sub_key_var)):
                            for m in range(len(sub_key_var)):
                                if(add_key_var[m] != sub_key_var[m]):
                                    tmp = add_key_var[m].split(' ')
                                    fin_key.append(tmp[-1])
                            for m in range(len(sub_key_var), len(add_key_var)):
                                tmp = add_key_var[m].split(' ')
                                fin_key.append(tmp[-1])
                        
                        sub_key_var = fin_key
                        add_key_var = fin_key
                    
                    # elif(sub_typeNum[i] == "if-Condition"): #  获得不一样的变量
                    #     fin_key = list(set(sub_key_var) ^ set(add_key_var))
                    #     sub_key_var = fin_key
                    #     add_key_var = fin_key
                    elif sub_typeNum[i] == "if-Condition" or sub_typeNum[i] == "while-Condition" or sub_typeNum[i] == "for-Condition":
                        add_key_var, sub_key_var, mol = get_condition_key(conseq_add, conseq_sub, sub_typeNum[i]) #控制语句的关键变量需要比对加减行子语句之后进行获取
                    
                    elif(sub_typeNum[i] == "Var-Declaration"):
                        add_list = set(add_key_var)
                        sub_list = set(sub_key_var)
                        add_key_var = list(add_list - sub_list)
                        sub_key_var = list(sub_list - add_list)
                                        
                type_flag = 'add_and_del'
                my_print(conseq_counter, sub_typeNum[i], add_typeNum[i], sub_keyline, add_keyline, sub_key_var, add_key_var, '', result_file, txt_file, type_flag)
                conseq_counter += 2

        for i in range(min_len, max_len):
            if max_flag == 0:
                line_num_sub = list(sub_conseq.keys())[i]
                conseq_sub = sub_conseq[line_num_sub]

                sub_keyline = int(sub_line) + int(sub_line_num) + int(counter) + line_num_sub #减号行行号
                sub_key_var = get_key(conseq_sub, sub_typeNum[i])
                if sub_key_var == [] or sub_key_var == None:
                    continue

                type_flag = 'del'
                my_print(conseq_counter, sub_typeNum[i], 'add_typeNum[i]', sub_keyline, 'add_keyline', sub_key_var, 'add_key_var', 'rep_key_var', result_file, txt_file, type_flag)
                conseq_counter += 1
            else:
                line_num_add = list(add_conseq.keys())[i]
                conseq_add = add_conseq[line_num_add]
                
                add_keyline = int(add_line) + int(add_line_num) + int(counter) + line_num_add #加号行行号
                add_key_var = get_key(conseq_add, add_typeNum[i])
                if add_key_var == [] or add_key_var == None:
                    continue
                
                type_flag = 'add'
                my_print(conseq_counter, 'sub_typeNum[i]', add_typeNum[i], 'sub_keyline', add_keyline, 'sub_key_var', add_key_var, 'rep_key_var', result_file, txt_file, type_flag) 
                conseq_counter += 1

def record_out_file(path_info, to_query):
    with open(path_info, 'r') as r:
        lines = r.readlines()
        for line in lines:
            if to_query in line:
                path = line.split(to_query)[-1].strip()
                return path

def main():
    current_work_dir = os.path.abspath(__file__)
    os.chdir(os.path.dirname(current_work_dir))
    print(current_work_dir)
    f = open('./config.json')   
    path_data = json.load(f)
    
    pkl_file_path = path_data['step1_output']['step1_output_tmp_pkl']
    txt_file_path = path_data['step1_output']['step1_output_tmp_txt']
    # pkl_file_path = '/Users/wangning/Documents/研一/跨函数测试/code/result_test/step1_result.pkl'
    # txt_file_path = '/Users/wangning/Documents/研一/跨函数测试/code/result_test/step1_result.txt'

    result_file = open(pkl_file_path,'wb')
    txt_file = open(txt_file_path, mode = 'w+', encoding = 'utf-8')
    diff_file_path = path_data['all_test_code']['all_diff_path'] #正常运行
    # diff_file_path = '/Users/wangning/Documents/研一/跨函数测试/code/code_test/'
    

    print(diff_file_path)
    tmp = get_filelist(diff_file_path)
    print(tmp)

    err_list = []
    
    for i in tmp:
        with open(i,"r") as f:
            if i.split('C-Diffs/')[-1].startswith('.') and not i.split('C-Diffs/')[-1].startswith('..'):
                err_list.append(i)
                continue
            try:
                s = f.read() #s为整个diff文件
            except:
                err_list.append(i)
                continue
            print(i)
            print(i, file = txt_file)
            pkl.dump(i, result_file)
            #fs = open(i, "r")
            #content = fs.readlines()
            #print(content)
            #for code in content:
                #if(code[:4] == '--- '):
                    #filename = code.split('/')[-1]
            #print(filename)
            #print(filename, file=txt_file)
            #pkl.dump(filename, result_file)
            
            print("=======================complex type===========================")
            print("=======================complex type===========================", file = txt_file)
            pkl.dump("=======================complex type===========================", result_file)
            
            check_complex_type(s, result_file, txt_file)

            print("==============================================================")
            print('')

            print("==============================================================", file = txt_file)
            print("", file = txt_file)
            pkl.dump("==============================================================", result_file)
            pkl.dump("", result_file)
    return err_list   

if __name__ == "__main__":
    err_list = main()
    print(len(err_list))
