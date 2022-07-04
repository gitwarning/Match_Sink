import sys

# from markupsafe import re
import re
import ast

from sink_CWE119 import sink_119
from sink_CWE189 import sink_189
from sink_CWE22 import sink_22
from sink_CWE369 import sink_369
from sink_CWE415 import sink_415, sink_416, sink_415_goto
from sink_CWE617 import sink_617
from sink_CWE772 import sink_772
from sink_CWE835 import sink_835
from sink_CWE476 import sink_476
from slice_op2 import get_call_var

cwe = '119'  # 匹配的漏洞类型
old_file = '/Users/wangning/Documents/研一/跨函数测试/sink-source点匹配测试/CWE125/tcpdump/CVE-2017-12999/CVE-2017-12999_CWE-125_3b32029db354cbc875127869d9b12a9addc75b50_print-isoclns.c_print-isoclns.c_OLD.c'
slice_file = '/Users/wangning/Documents/研一/跨函数测试/sink-source点匹配测试/CWE125/tcpdump/CVE-2017-12999/slices.txt'
# old_file = 'E:/漏洞检测/可自动化实现/漏洞重新测试/ffmpeg/CVE-2013-0850/CVE-2013-0850_CWE-119_d6c184880ee2e09fd68c0ae217173832cee5afc1_h264.c_1.1_OLD.c'
# slice_file = 'E:/漏洞检测/可自动化实现/漏洞重新测试/ffmpeg/CVE-2013-0850/slices.txt'
# diff_file = '/Users/wangning/Documents/研一/跨函数测试/sink-source点匹配测试/CWE835/qemu/CVE-2017-6505/CVE-2017-6505_CWE-835_95ed56939eb2eaa4e2f349fe6dcd13ca4edfd8fb_hcd-ohci.c_1.1.diff'
diff_file = ''  # 匹配CWE-772、401、415类型时使用
list_key_words = ['if', 'while', 'for']  # 控制结构关键字
# 变量类型列表
val_type = ['short', 'int', 'long', 'char', 'float', 'double', 'struct', 'union', 'enum', 'const', 'unsigned', 'signed',
            'uint32_t', 'struct', 'guint', 'size_t', 'uint64_t', 'PSH_Point']
C_func = ['sizeof']
# 操作运算符列表
sp_operators = ['+', '-', '/', '*', '%', '&', '|', '=']


# 判断是否为函数定义
def is_funcdefine(line):
    result = get_funcname(line)
    if (len(result) == 1):
        funcname = result[0]
        res_list = line.split(funcname)
        # print(res_list)
        if (res_list[0] != ''):
            for sp in sp_operators:
                if(' ' + sp + ' ' in res_list[0]):
                    return False
            for con_key in list_key_words:
                if(con_key in res_list[0]):
                    return False
            return True
        else:
            return False
    else:
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

# 特殊的cv处理(数组、指针、点操作等)
# 如果是数组的话，就取数组名，如果是指针的话就加空格
def special_cv_process(cv):
    if cv == '':
        print("===============!!!cv是空的===============")
        sys.exit(1)
    if (cv[0] == '*'):
        # return cv[1:]
        cv = cv.split('*')[1].strip()

    if (cv[0] == '&'):
        cv = cv.split('&')[1].strip()
    # if('[' in cv):#关键变量是一个下标含有内容的数组
    # cv = cv[:(cv.find('['))]
    # return cv
    if (('[' in cv) and (']' in cv)):  # 关键变量是一个下标含有内容的数组,先取出下标作为关键变量
        start = cv.rfind('[')
        end = cv.rfind(']')
        new_cv_str = cv[(start + 1):end]
        if new_cv_str == '':
            cv = cv[:start]
        # 在切分'-'的时候有问题，把减号单独拿出来切分
        elif '->' not in new_cv_str and '-' in new_cv_str:
            cv = new_cv_str.split('-')
        else:
            cv = re.split('[+|*|/|%|>>|<<|>|<|=]', new_cv_str)  # data [ plane + 4 ] [ end + 3 ]

    if ('.' in cv):  # pd.size转换成pd . size
        new_cv = ''
        cv_tmp = cv.split('.')
        for i in cv_tmp:
            new_cv += i + ' . '
        cv = [new_cv.strip(' . ')]
        if '->' not in cv[0]:  # ar->gpe.en
            return cv
        cv = cv[0]
    if ('->' in cv):
        new_cv = ''
        cv_tmp = cv.split('->')
        for i in cv_tmp:
            new_cv += i + ' -> '
        cv = [new_cv.strip(' -> ')]
        return cv
    if (type(cv) == type([])):
        return cv
    else:
        return [cv]


def get_min(sp1, sp2, sp3):  # 感觉处理的好繁琐,之后找一个更加简便的方法
    if ((sp1 == -1) and (sp2 == -1) and (sp3 != -1)):
        return 'sp3'
    elif ((sp1 == -1) and (sp2 != -1) and (sp3 == -1)):
        return 'sp2'
    elif ((sp1 != -1) and (sp2 == -1) and (sp3 == -1)):
        return 'sp1'
    elif ((sp1 != -1) and (sp2 != -1) and (sp3 == -1)):
        if (sp1 < sp2):
            return 'sp1'
        else:
            return 'sp2'
    elif ((sp1 != -1) and (sp2 == -1) and (sp3 != -1)):
        if (sp1 < sp3):
            return 'sp1'
        else:
            return 'sp3'
    elif ((sp1 == -1) and (sp2 != -1) and (sp3 != -1)):
        if (sp2 < sp3):
            return 'sp2'
        else:
            return 'sp3'
    elif ((sp1 != -1) and (sp2 != -1) and (sp3 != -1)):
        if (sp1 <= sp2):
            if (sp1 <= sp3):
                return 'sp1'
            else:
                return 'sp3'
        else:
            if (sp2 <= sp3):
                return 'sp2'
            else:
                return 'sp3'


def left_process(cv, sign):  # 对左边的特殊变量进行空格处理
    flag = ''
    # if (' ' in cv):
    #     sp1 = cv.find('->')
    #     sp2 = cv.find('.')
    #     sp3 = cv.find('[')
    #     # print(sp1, sp2, sp3)
    #     flag = get_min(sp1, sp2, sp3)
    #     print(flag, cv, sign)

    #     if (flag == 'sp1'):
    #         tmp_cv = cv[:sp1].strip().split(' ')[-1]
    #         if (sign == 'up'):
    #             return tmp_cv
    #         else:
    #             return (tmp_cv + cv[sp1:]).replace(' ', '')
    #     if (flag == 'sp2'):
    #         tmp_cv = cv[:sp2].strip().split(' ')[-1]
    #         if (sign == 'up'):
    #             return tmp_cv
    #         else:
    #             return (tmp_cv + cv[sp2:]).replace(' ', '')
    #     if (flag == 'sp3'):
    #         tmp_cv = cv[:sp3].strip().split(' ')[-1]
    #         if (sign == 'up'):
    #             return tmp_cv
    #         else:
    #             return (tmp_cv + cv[sp3:]).replace(' ', '')

    #     return cv.split(' ')[-1]
    # else:
    #     return cv

    # 不确定这样改了之后会不会有其他问题（目前好像没发现）
    if sign == 'space' and len(cv.split(' ')) == 2:
        type = cv.split(' ')[0]
        if type in val_type:
            cv = cv.split(' ')[-1].strip()

    if sign == 'space' and 'struct' in cv:
        if '*' in cv:
            cv = cv.split('*')[-1]
        else:
            cv = cv.split(' ')[-1]
        return cv
    if sign == 'space' and cv[0] == '*':
        cv = cv.split('*')[1].strip()
    if sign == 'space' and '*' in cv:
        if len(cv.split('*')) == 2:
            cv = cv.split('*')[-1].strip()
    if sign == 'space' and 'guint' in cv:
        cv = cv.replace('guint ', '').strip()
    sp1 = cv.find('->')
    sp2 = cv.find('.')
    sp3 = cv.find('[')
    # print(sp1, sp2, sp3)
    flag = get_min(sp1, sp2, sp3)

    if (flag == 'sp1'):
        tmp_cv = cv[:sp1].strip().split(' ')[-1]
        if (sign == 'up'):
            return tmp_cv
        else:
            return (tmp_cv + cv[sp1:]).replace(' ', '')
    if (flag == 'sp2'):
        tmp_cv = cv[:sp2].strip().split(' ')[-1]
        if (sign == 'up'):
            return tmp_cv
        else:
            return (tmp_cv + cv[sp2:]).replace(' ', '')
    if (flag == 'sp3'):
        tmp_cv = cv[:sp3].strip().split(' ')[-1]
        if (sign == 'up'):
            return tmp_cv
        else:
            return (tmp_cv + cv[sp3:]).replace(' ', '')

        return cv.split(' ')[-1]
    else:
        return cv


def get_funcname(code):
    # pattern = "((?:_|[A-Za-z])\w*(?:\s(?:\.|::|\->|)\s(?:_|[A-Za-z])\w*)*)\s\("
    pattern = "((?:_|[A-Za-z])\w*(?:\s(?:\.|::|\->|)\s(?:_|[A-Za-z])\w*)*)\s?\("
    result = re.findall(pattern, code)

    i = 0
    while i < len(result):
        if result[i] in list_key_words:
            del result[i]
        else:
            i += 1

    return result


# cv在等号右边（赋值给别人）
def has_cv_fz_right(cv, line):
    if '>=' in line or '<=' in line or '==' in line or '!=' in line or '= ' not in line:
        return False
    if '"' in line:  # av_log ( s , AV_LOG_WARNING , "par->codec_type is type = [%d]\n" , par -> codec_type )
        tmp = line.split('"')
        if len(tmp) > 1 and '=' in tmp[1]:
            return False
    right = line.split('=')[-1]
    # print('right:', right)
    if (has_cv(cv, right)):
        return True

    return False


# 判断该行是不是return关键变量的行
def is_return_cv(line, cv):
    line = line.strip()
    if (line[:7] != 'return '):
        return False

    if (' ' + cv + ' ') in line:
        return True
    else:
        return False


def find_sink(after_diff, cv_list, sink_results, sink_cv, epoch, vul_name, point_var):
    # 对于每一个cv都去匹配sink点
    for cv in cv_list[epoch]:
        if cv.isdigit() or cv.isupper():  # 如果关键变量是常数，直接跳过
            continue
        # 如果是转换的cv，从cv的转换行开始匹配sink点
        start_line = 0
        if '$$' in cv:
            start_line = int(cv.split('$$')[-1].strip())
            cv = cv.split('$$')[0].strip()
        array_sink = True
        pointer_sink = True
        risk_func_sink = True
        calculation_sink = True
        assert_sink = True
        path_sink = True
        free_sink = 0
        division_sink = True
        division_func_sink = True
        use_null_sink = True
        scatterlist_sink = True
        # if cwe == '119':
        #     calculation_sink = False
        # elif cwe == '189':
        #     calculation_sink = True
        return_flag = False
        if ('[' in cv):
            array_name = cv[:(cv.find('['))]
            if array_name not in cv_list[epoch]:
                # cv_list[epoch].append(cv[:(cv.find('['))])  # 先把数组头放进去
                cv_list[epoch] = append_cv(cv_list[epoch], cv[:(cv.find('['))])
        sp_cv = special_cv_process(cv)  # 特殊变量的处理
        if (len(sp_cv) > 1):
            cv = sp_cv[0]
            for i in range(1, len(sp_cv)):  # 这种是因为提取数组下标提取出了多个变量
                if sp_cv[i] not in cv_list[epoch]:
                    # cv_list[epoch].append(sp_cv[i])
                    cv_list[epoch] = append_cv(cv_list[epoch], sp_cv[i])
        else:
            cv = sp_cv[0]
        if cv.isupper():  # 如果cv全是大写，一般是宏定义的常数，这种也跳过
            continue
        if cv.isdigit() or cv.isupper():  # 如果关键变量是常数，直接跳过
            continue
        print("=======now CV is " + cv + "=========")
        sink_lines = after_diff[start_line:]
        # 找到diff修改的行，从diff修改行向下寻找sink点
        for i, line in enumerate(sink_lines):
            chang_flag = 1  # 排除if条件语句即使出现等号也只是判断的情况
            if is_return_cv(line, cv):
                return_flag = True
            # 如果当前行是函数定义行，不参加sink点的匹配，但是可能涉及到sink点的转换（通过参数位置转换
            if 'void' == line.strip():
                line = line + " "+ after_diff[i+1]
            if is_funcdefine(line):
                # 函数定义的上一行不一定是该函数的函数调用行,先判断上一行是否是函数调用行（函数名）获取上一行的信息，
                # 判断cv是否在函数调用语句的参数中，如果在就记录下来cv的位置（第几个参数）
                # 函数定义可能出现跨行的现象
                func_define = line
                if 'location' not in line:
                    func_define = ''
                    num = 0
                    while 'location' not in sink_lines[i + num]:
                        func_define += sink_lines[i + num]
                        num += 1  # 函数定义跨的行数
                    func_define += sink_lines[i + num]
                func_name = get_funcname(func_define)[0]
                if func_name in sink_lines[i - 1]:
                    tmp = sink_lines[i - 1]
                    tmp = tmp[tmp.find(func_name):]
                    call_paras = tmp[tmp.find('(') + 1:tmp.find(')')].split(',')  # 从函数名开始向后面查找括号的方式得到函数参数
                    cvv = ' ' + cv + ' '
                    if cvv in call_paras:
                        i = call_paras.index(cvv)
                        func_paras = func_define[func_define.find('(') + 1:func_define.rfind(')')].split(',')
                        change_cv = func_paras[i]
                        # chang_cv 需要去掉前面的变量类型
                        change_cv = left_process(change_cv, 'space')
                        if change_cv != cv and change_cv not in cv_list[epoch]:
                            if change_cv != '...':
                                # cv_list[epoch].append(change_cv)
                                cv_list[epoch] = append_cv(cv_list[epoch], change_cv)
                                print("当前CV跨函数，经转化后新的CV是：", change_cv)
                # continue return 语句中可能含有sink点
            # 如果是函数调用行，需要判断是不是对漏洞函数的调用，如果是且将关键变量作为返回值，需要把返回后的值加入关键变量列表
            func_name = get_funcname(line)
            if (' = ' in line) and (func_name != []) and return_flag:
                this_line_func = func_name[0]
                if this_line_func == vul_name:
                    print('该行是对漏洞函数的调用行且有返回值: ', line)
                    return_cv = line.split(' = ')[0].split(' ')[
                        -1].strip()  # int line = advance_line ( dst , line , stride , & y , h , interleave );
                    if return_cv != cv and return_cv not in cv_list[epoch]:
                        # cv_list[epoch].append(return_cv)
                        cv_list[epoch] = append_cv(cv_list[epoch], return_cv)
                        return_flag = False
                        print('当前CV经过漏洞函数返回，经转化后新的CV是：', return_cv)
            if 'for ' in line:
                if '->' in line and ' -> ' not in line:
                    line = line.replace('->', ' -> ')
                if '*' in line and '* ' not in line:
                    line = line.replace('*', '* ')
            # 进行sink点匹配
            # 对于不同的漏洞类型进行了封装
            if cwe == '189' or cwe == '190' or cwe == '191':
                array_sink, pointer_sink, risk_func_sink, calculation_sink, division_sink = sink_189(line, cv, sink_results, array_sink,
                                                                                      sink_cv, pointer_sink, risk_func_sink,
                                                                                      calculation_sink, point_var, division_sink)
            elif cwe == '119' or cwe == '125' or cwe == '787' or cwe == '120':
                array_sink, pointer_sink, risk_func_sink, scatterlist_sink = sink_119(line, cv, sink_results, array_sink, sink_cv,
                                                                    pointer_sink, risk_func_sink, scatterlist_sink, point_var)
            elif cwe == '617':
                assert_sink = sink_617(line, cv, sink_results, assert_sink, sink_cv)
            elif cwe == '22':
                path_sink = sink_22(line, cv, sink_results, path_sink, sink_cv)
            elif cwe == '415':
                free_sink = sink_415(line, cv, sink_results, free_sink, sink_cv, 'slices')
            elif cwe == '416':
                free_sink = sink_416(line, cv, sink_results, free_sink, sink_cv)
            elif cwe == '369':
                division_sink, division_func_sink = sink_369(line, cv, sink_results, division_sink, division_func_sink, sink_cv)
            elif cwe == '476':
                use_null_sink = sink_476(line, cv, sink_results, sink_cv, use_null_sink)
            # if 含等号是判断不是转换
            # if 'if' in line and ('==' in line or '!=' in line or '+=' in line or '<=' in line or '>=' in line):
            if 'if ' in line:  #涉及if条件语句行不转换
                chang_flag = 0
            # 如果当前行涉及到CV的转换，将其转换后的变量记录下来以作备用

            if has_cv_fz_right(cv, line) and chang_flag == 1:
                tmp_cv = cv
                # for循环怎么处理？for (j = 0; j < nelements && i < sh.sh_properties  cv需要从nelements==》j
                if 'for (' in line:
                    tmp_lines = re.split('[(;]', line)
                    for tmp_line in tmp_lines:
                        if '<' in tmp_line or '>' in tmp_line:
                            if '&&' in tmp_line:
                                tmp_lines.append(tmp_line.split('&&')[-1])
                                tmp_line = tmp_line.split('&&')[0]
                            if '->' in tmp_line:
                                tmp_line = tmp_line.replace(' -> ', '$')
                            tmps = re.split('[<>]', tmp_line)
                            tmp_last = tmps[-1].strip()
                            if '$' in tmp_last:
                                tmp_last = tmp_last.replace('$', ' -> ')
                            if cv == tmp_last:
                                tmp_cv = tmps[0].strip()
                elif '+=' in line:
                    tmp_cv = line.split('+=')[0].strip()
                elif '|=' in line:
                    tmp_cv = line.split('|=')[0].strip()
                elif '-=' in line:
                    tmp_cv = line.split('-=')[0].strip()
                else:
                    tmp_cv = line.split('=')[0].strip()
                tmp_cv = left_process(tmp_cv, 'space')  # 对等号左边的变量进行处理(去掉可能存在的类型名等)
                if ', ' in tmp_cv:  # x++, guest_ptr += cmp_bytes, server_ptr += cmp_bytes)
                    tmp_cv = tmp_cv.split(', ')[-1]
                if tmp_cv not in cv_list[epoch + 1] and tmp_cv not in cv_list[epoch]:
                    tmp_cv = tmp_cv+'$$'+str(i)
                    # cv_list[epoch + 1].append(tmp_cv)
                    cv_list[epoch + 1] = append_cv(cv_list[epoch + 1], tmp_cv)
                    print('CV转化行：', line)
                    print('转换后的CV：', tmp_cv)
    # 当前所有CV都没有匹配到sink点，将其上一级加入到下一次要匹配的CV中cvList[epoch+1]
    if len(sink_results) == 0:
        for cv in cv_list[epoch]:
            sp_cv = special_cv_process(cv)  # 特殊变量的处理
            if (len(sp_cv) > 1):
                cv = sp_cv[0]
                for i in range(1, len(sp_cv)):  # 这种是因为提取数组下标提取出了多个变量
                    # cv_list[epoch].append(sp_cv[i])
                    cv_list[epoch] = append_cv(cv_list[epoch], sp_cv[i])
            else:
                cv = sp_cv[0]
            new_cv = left_process(cv, 'up')
            if new_cv not in cv_list[epoch + 1] and new_cv not in cv_list[epoch]:
                print('CV的上一级是：', new_cv)
                # cv_list[epoch + 1].append(new_cv)
                cv_list[epoch + 1] = append_cv(cv_list[epoch + 1], new_cv)
    print(epoch)
    print("如果当前cv列表没有找到sink点，下次查找的cv是：", cv_list[epoch + 1])


def find_first_use(after_diff, cv_list, sink_results, sink_cv, epoch):
    for cv in cv_list[epoch]:
        print("********** "+cv+" *********")
        for line in after_diff:
            if not has_cv_fz_left(cv, line) and has_cv(cv, line):
                print('第一次使用的位置是: ' + line)
                sink_results.append(line)
                sink_cv.append(cv)
                break


def match_sinks(slices):
    print('.......................sink is start.......................')
    epoch = 0  # 二维数组cv的选取下标
    sink_results = []
    cv_list = [[] for _ in range(20)]  # cv数组定义为二维数组
    sink_cv = []  # 找到sink点的cv
    flag = 0  # 标记diff修改的位置
    start = slices[0].find('[')
    end = slices[0].rfind(']')
    flag_point = False
    if '@@' in slices[0]:
        tmp = slices[0].split(' @@ ')[-2]
        cv_list[0] = ast.literal_eval(slices[0].split(' @@ ')[-2])
        cv_list[0] = list(set(cv_list[0]))  # 对cv_list去重
        loc = slices[0].split(' @@ ')[3]
        diff_tmp = slices[0].split(' @@ ')[1].split('_')
        index = 3
        vul_file = diff_tmp[3]
        while ('.c' not in vul_file):
            index += 1
            vul_file = vul_file + '_' + diff_tmp[index]  # 漏洞文件名中可能含有下划线
        vul_name = slices[0].split(' @@ ')[2].strip()
        if (vul_name[0] == '*'):
            vul_name = vul_name[1:]
        flag_point = True
        # point_vars = [] # 存放漏洞函数中有的指针变量
        # 切片里用空格作为每种信息的分割不妥，之后用一个不会在代码中出现的符号(比如 @@ )进行分割，就可以直接用split函数了，但这样切片文件要全部更新
        # FIX
        # s = slices[0].find('{')
        # e = slices[0].rfind('}')
        # point_vars = slices[0][(s + 1):e].split(', ')
        point_vars = slices[0].split(' @@ ')[-1].replace('{', '').replace('}', '').split(', ')  # 将指针变量信息转换成列表
    else:
        cv_list[0] = ast.literal_eval(slices[0][start:(end + 1)])
        loc = slices[0].split(' ')[3]
        diff_tmp = slices[0].split(' ')[1].split('_')
        index = 3
        vul_file = diff_tmp[3]
        while ('.c' not in vul_file):
            index += 1
            vul_file = vul_file + '_' + diff_tmp[index]  # 漏洞文件名中可能含有下划线
        vul_name = slices[0].split(' ')[2].strip()
        if (vul_name[0] == '*'):
            vul_name = vul_name[1:]
    after_diff = []
    is_add = False
    # 找到diff修改的位置，将diff修改位置向下的切片加入到after_diff[]
    for line in slices:
        if 'cross_layer' in line:
            this_loc = line[line.find('location: '):line.rfind(' cross_layer')].replace('location: ', '')  # 当前切片的行号
        else:
            this_loc = line[line.find('location: '):line.rfind(' file')].replace('location: ', '')  # 当前切片的行号
        this_file = line.split('file: ')[-1].split('/')[-1]
        if flag == 0:
            if '(key_var lines)' in line:  # 含有(key_var lines)标志的表明当前行是diff修改的下一行,因为在diff只增加的类型中在漏洞文件中找不到修改行
                flag = 1
                is_add = True
            if this_loc == loc and this_file == vul_file:
                flag = 1
        if flag == 1:
            after_diff.append(line)

    if cwe == '772' or cwe == '401':
        sink_772(old_file, sink_results, diff_file, loc, vul_name)
        for tmp_cv in cv_list[0]:
            sink_cv_tmp = special_cv_process(tmp_cv)
            if (len(sink_cv_tmp) > 1):
                for i in range(1, len(sink_cv_tmp)):
                    if sink_cv_tmp[i] not in sink_cv:
                        sink_cv.append(sink_cv_tmp[i])

            sink_cv.append(sink_cv_tmp[0])
        print(sink_cv)
        return sink_results, sink_cv, cv_list
    
    if cwe == '835':
        idx = 1
        vul_define = slices[idx]
        while(slices[idx].strip()[-2:] != '.c'):
            idx += 1
            vul_define += slices[idx].strip('\n')
        sink_835(old_file, vul_define, sink_results, diff_file, loc, is_add)
        for tmp_cv in cv_list[0]:
            sink_cv_tmp = special_cv_process(tmp_cv)
            if (len(sink_cv_tmp) > 1):
                for i in range(1, len(sink_cv_tmp)):
                    if sink_cv_tmp[i] not in sink_cv:
                        sink_cv.append(sink_cv_tmp[i])

            sink_cv.append(sink_cv_tmp[0])
        print(sink_cv)
        return sink_results, sink_cv, cv_list

    while len(sink_cv) == 0 and cv_list[epoch] and epoch < 5:
        if flag_point:
            find_sink(after_diff, cv_list, sink_results, sink_cv, epoch, vul_name, point_vars)
        else:
            find_sink(after_diff, cv_list, sink_results, sink_cv, epoch, vul_name, '')
        epoch += 1

    # 对于416类型的如果没有找到free_sink点，则将sink点放在第一次使用的位置
    if cwe == '416' and not sink_cv:
        print('416类型没有找到free的sink点，现在开始寻找第一次使用的位置=========')
        new_epoch = 0
        while len(sink_cv) == 0 and new_epoch < 5:
            find_first_use(after_diff, cv_list, sink_results, sink_cv, new_epoch)
            new_epoch += 1
    # 对于415类型的，如果没有找到free的位置结合diff文件和old文件来寻找goto语句块
    if cwe == '415' and not sink_cv:
        print('416类型没有找到free的sink点，现在开始寻找goto语句块=========')
        sink_cv, sink_results = sink_415_goto(diff_file, old_file, sink_cv, sink_results, cv_list, loc)
    sink_cv = list(set(sink_cv))  # 对sink_cv 去重
    return sink_results, sink_cv, cv_list


def has_cv(cv, line):
    # print(('*' + cv + ','))

    if ((' ' + cv + ',') in line):
        return True
    if ((' ' + cv + ';') in line):
        return True
    if ((' ' + cv + ')') in line):
        return True
    if ((' ' + cv + ' ,') in line):
        return True
    if ((' ' + cv + ' ;') in line):
        return True
    if ((' ' + cv + ' )') in line):
        return True
    if (('*' + cv + ';') in line):
        return True
    if ((' ' + cv + ' ') in line):
        return True
    if ((' ' + cv + '[') in line):
        return True
    if (('*' + cv + ',') in line):
        return True
    if (('*' + cv + ')') in line):
        return True
    if (cv + ' =') in line:
        return True

    return False


# cv在等号左边（被赋值）
#  在'HYuvContext * s = avctx -> priv_data ; location: 404 file: huffyuv.c'中无法判断cv在左边
def has_cv_fz_left(cv, line):
    if (' = ' not in line):  # 加空格是为了避免+=的出现，这种情况不用转换
        return False
    left = line.split(' = ')[0].strip()
    # if((' ' + cv + ' ') in left):#要不要改成完全相同?
    # return True
    if (cv == left):
        return True
    if (line[:len(cv)] == cv):  # 关键变量在一行的开始处
        if (line[:(len(cv) + 1)] == cv + ' '):
            return True
    # 如果当前行是变量声明行 int buf_size = alac -> max_samples_per_frame * sizeof ( int32_t )
    left_list = left.split(' ')  #存在用户自定义变量的情况ca_slot_info_t * info = ( ca_slot_info_t * ) parg
    if left_list[0] in val_type or (not left_list[0].islower()):

        if cv == left_list[-1]:  # int * buf
            return True
    # 用户自定义变量类型只能是结构体变量
    if len(left_list)>1 and left_list[1] == '*' and cv == left_list[-1].strip():
        return True
    '''
    if('(' + cv + ' =' in line):
        return True
    if(' ' + cv + ' =' in line):
        return True
    if(' ' + cv + ' +=' in line):
        return True
    '''
    return False


# 在漏洞文件中继续往下找第一次用cv的地方
def find_in_vulfile(tmp_line, cv):
    location = 0
    tmp_file = tmp_line.split(' file: ')[-1].split('/')[-1]
    tmp_loc = tmp_line.split('location: ')[-1].split(' cross_layer: ')[0]
    tmp_layer = tmp_line.split(' cross_layer: ')[-1].split(' file: ')[0]
    if not tmp_loc.isnumeric():
        print("当前行没有location，是：", tmp_loc)
        return ''
    with open(old_file, 'r') as f:
        vul_content = f.readlines()
    for line in vul_content:
        location += 1
        if (location <= int(tmp_loc)):
            continue
        if (has_cv_fz_left(cv, line)):
            result = line.strip() + ' location: ' + str(location) + ' cross_layer: ' + tmp_layer + ' file: ' + tmp_file
            return result

    return ''  # 如果没找到的话,就返回空


# 要找到每个关键变量的source点
def has_only_cv(line, cv):
    if (cv + ' ->') in line:  # cv = s, line : bs -> opaque
        lines = line.split(" ")
        index = lines.index('->')
        if cv == lines[index - 1]:
            return False
    if (cv + ' .') in line:
        return False
    return has_cv(cv, line)


# 判断是否是表达式
def is_expression(cv):
    if '->' in cv:
        cv = cv.replace(" -> ", "$")
    # ( PhotoshopProfile * ) user_data
    if '*' in cv:
        tmps = cv.split(" ")
        if tmps[tmps.index('*')-1].isalpha() and not tmps[tmps.index('*')-1].islower():
            return False
    if '[' in cv:
        pattern = "\[.*\]"
        index = re.findall(pattern, cv)
        for i in index:
            cv = cv.replace(i, '').strip()
    cvs = re.split('[*+/-]', cv)


    if len(cvs) > 1:
        return True
    else:
        return False


def cv_from_expression(tmp_cv):
    # 对于一个表达式，考虑用空格把变量拆分出来，拆出来之前需要把-> . 不应该拆分的先替换掉
    if '->' in tmp_cv:
        tmp_cv = tmp_cv.replace(" -> ", "$")
    if '.' in tmp_cv:
        tmp_cv = tmp_cv.replace(' . ', '@')
    if '[' in tmp_cv and ']' in tmp_cv:
        tmp_cv = tmp_cv.replace(' [ ', '#')
        tmp_cv = tmp_cv.replace(' ]', '^')
    tmp_cvs = tmp_cv.split(' ')
    cvs = []
    for cv in tmp_cvs:
        if len(cv.strip()) > 1:
            if '0x' in cv:
                continue
            if cv in val_type or cv in C_func:
                continue
            if '@' in cv:
                cv = cv.replace('@', ' . ')
            if '$' in cv:
                cv = cv.replace('$', ' -> ')
            if '#' in cv and '^':
                # cv = cv.replace('#', ' [ ')
                # cv = cv.replace('^', ' ]')
                cv = cv.split('#')[0].strip()  # 只要数组名
            cvs.append(cv)
    return cvs

def append_cv(sink_cv, new_cv):
    if(new_cv in sink_cv):
        return sink_cv
    if(is_number(new_cv) == True):
        return sink_cv
    
    sink_cv.append(new_cv.strip())
    return sink_cv

def match_sources(slices, sink_cv, sinks):
    print('.......................source is start.......................')
    source_results = []
    source_lines = []
    vulf_define = ''
    if '@@' in slices[0]:
        # tmp = slices[0].split(' @@ ')[-2]
        loc = slices[0].split(' @@ ')[3]
        diff_tmp = slices[0].split(' @@ ')[1].split('_')
        index = 3
        vul_file = diff_tmp[3]
        while ('.c' not in vul_file):
            index += 1
            vul_file = vul_file + '_' + diff_tmp[index]  # 漏洞文件名中可能含有下划线
        vul_function = slices[0].split(' @@ ')[2].strip()
        if (vul_function[0] == '*'):
            vul_name = vul_function[1:]
        flag_point = True
        # point_vars = [] # 存放漏洞函数中有的指针变量
        # 切片里用空格作为每种信息的分割不妥，之后用一个不会在代码中出现的符号(比如 @@ )进行分割，就可以直接用split函数了，但这样切片文件要全部更新
        # FIX
        # s = slices[0].find('{')
        # e = slices[0].rfind('}')
        # point_vars = slices[0][(s + 1):e].split(', ')
        point_vars = slices[0].split(' @@ ')[-1].replace('{', '').replace('}', '').split(', ')  # 将指针变量信息转换成列表
    else:
        loc = slices[0].split(' ')[3]
        diff_tmp = slices[0].split(' ')[1].split('_')
        index = 3
        vul_file = diff_tmp[3]
        while ('.c' not in vul_file):
            index += 1
            vul_file = vul_file + '_' + diff_tmp[index]  # 漏洞文件名中可能含有下划线
        vul_function = slices[0].split(' ')[2].strip()
        if (vul_function[0] == '*'):
            vul_name = vul_function[1:]
    # print(vul_function)
    # print(slices[1])

    if (vul_function in slices[1]):
        vulf_define = slices[1].strip()
        if ('location' not in slices[1]):
            # vulf_define = slices[1].strip() + slices[2].strip()
            for line in slices[2:10]:
                if 'location' not in line:
                    vulf_define += line.strip()
                else:
                    vulf_define += line.strip()
                    break
    elif vul_function in slices[2]:
        vulf_define = slices[1].strip() + slices[2].strip()
        if 'location' not in slices[2]:
            for line in slices[3:10]:
                if 'location' not in line:
                    vulf_define += line.strip()
                else:
                    vulf_define += line.strip()
                    break
    else:  # 存在没有找到函数名的情况这种情况下函数定义可能还在第一行
        vulf_define = slices[1].strip()
        if ('location' not in slices[1]):
            # vulf_define = slices[1].strip() + slices[2].strip()
            for line in slices[2:10]:
                if 'location' not in line:
                    vulf_define += line.strip()
                else:
                    vulf_define += line.strip()
                    break
    # # cvs = eval(slices[0].split(' ')[-1])
    # start = slices[0].find('[')
    # end = slices[0].rfind(']')
    # print(slices[0][start:(end + 1)])
    #
    # cvs = ast.literal_eval(slices[0][start:(end + 1)])
    # print(cvs)
    pre_line = ''
    for line in slices:
        if ('(key_var lines)' in line):
            break
        if(pre_line != ''):
            line = pre_line.strip() + line
        if(' location: ' not in line and line != slices[0]):
            pre_line = line
            continue
        else:
            pre_line = ''
        this_loc = line.split('location: ')[-1].split(' cross_layer: ')[0]
        source_lines.append(line)
        if (this_loc == loc):
            break
    source_lines.reverse()  # 将切片逆序
    # print(source_lines)

    #开始针对每一个sink_cv匹配source点
    for cv in sink_cv:
        num = len(source_results)
        change_cv_flag = 0   # 标志此cv是否由表达式转换来的cv
        change_line = 0
        if '$$' in cv:
            change_cv_flag = 1
            change_line_index = int(cv.split('$$')[-1])
            cv = cv.split('$$')[0]
        print('now, is ' + cv)
        # 从sink_cv得到的关键变量不需要再一次的特殊处理
        # 寻找外部函数定义处
        flag = 0
        tmp_source_lines = source_lines  # 如果是表达式转换后的cv需要从转换行开始寻找source点
        if change_cv_flag == 1:
            tmp_source_lines = source_lines[change_line_index:]
        # 当修改行是常数的赋值语句不应该再继续向上跟踪
        if '=' in tmp_source_lines[0]:
            numb = tmp_source_lines[0].split("location")[0]
            numb = numb.split("=")[-1]
            if ';' in numb:
                numb = numb.replace(';', '')
            numb = numb.strip()
            if numb.isdigit():  # 如果关键变量是常数，直接跳过
                source_results.append(tmp_source_lines[0])
                continue
        # for line in source_lines:
        for line in tmp_source_lines:
            res_tmp = line.split('=')
            if (len(res_tmp) == 1):
                continue
            else:
                line_cvs = res_tmp[0].strip().split(',')  # 可能存在多个变量被赋值,例如a, b = recv()
                # 如果等号左边是变量声明的情况 stellaris_enet_state * s = qemu_get_nic_opaque ( nc )
                if line_cvs[0] != cv and len(line_cvs[0].split(" ")) > 1:  # 防止 cv含有->但是却被处理
                    line_cvs[0] = left_process(line_cvs[0], 'space')
                    if '*' in line_cvs[0]:
                        tmps = line_cvs[0].split('*')
                        if 'struct' in tmps[0]:
                            line_cvs[0] = tmps[-1].strip()
                        if tmps[0] in val_type or (not tmps[0].islower()):
                            line_cvs[0] = tmps[-1].strip()  # int * buf

                if (cv in line_cvs):
                    funcname = get_funcname(line)
                    if funcname:  # 如果是外部函数
                        if 'sizeof' in funcname:
                            funcname.remove('sizeof')
                        if len(funcname) == 1 and funcname[0] not in C_func:
                            if cv == "error" or cv == "err" or cv == "errors":
                                new_cv_list = get_call_var(line, 1)
                                print('当前匹配行是返回值为error的函数调用，其函数参数为：', new_cv_list)
                                for new_cv in new_cv_list:
                                    sink_cv = append_cv(sink_cv, new_cv[0])
                            elif line not in sinks:
                                source_results.append(line)
                                flag = 1
                                break
                        # return source_results
        if (flag == 1):
            print('外部函数定义')
            continue

        # 函数内变量定义处和函数参数
        # source_tmp = source_lines
        # source_tmp.reverse()

        # 找到定义后第一次用/初始化的地方
        # 使用跨函数的sink点测试
        '''
        for line in source_tmp:
            if(has_cv(cv, line)):#这一行出现过关键变量
                source_results.append(line)
        '''
        tmp_cv = cv
        tmp_line = ''
        for i, line in enumerate(tmp_source_lines):
            # 在找source点时如果当前行是对cv的成员赋值，不可以将此视为cv的赋值
            # 不能把切片的第一行信息行作为source点（尽管它可能含有cv）
            if has_only_cv(line, tmp_cv) and not has_cv_fz_left(tmp_cv, line) and line != slices[0]:  # 如果含有关键变量但不含等号赋值
                tmp_line = line  # 先暂存当前语句，然后继续向上找
                print('含有关键变量但cv不在等号左边,暂存的语句是: ', tmp_line)
                if 'for (' in line:
                    tmp_items = re.split('[(;]', line)
                    for item in tmp_items:
                        if '<' in item or '>' in item:
                            if '&&' in item:
                                tmp_items.append(item.split('&&')[-1])
                                item = item.split('&&')[0]
                            if '->' in item:
                                item = item.replace('->', '$')
                            tmps = re.split('[<>]', item)
                            if cv == tmps[0].strip():
                                tmp_cv = tmps[-1].strip()
                                if '$' in tmp_cv:
                                    tmp_cv = tmp_cv.replace('$', '->')
                                if '=' in tmp_cv:
                                    tmp_cv = tmp_cv.replace('=', '').strip()
                                print('当前语句含有for循环，控制循环次数的变量是：', tmp_cv)

            if has_only_cv(line, tmp_cv) and has_cv_fz_left(tmp_cv, line) and line != slices[0]:  # 含有等号的赋值
                # ( avctx -> width * avctx -> bits_per_coded_sample + 7 ) / 8  的值赋值给了CV tmp_cv可能是一个表达式，如何区分出来
                tmp_cv = re.split('[,;]', line.split(' = ')[-1])[0].strip()  # 取出等号右边的变量，把谁的值赋给了CV，CV=b，继续向上跟踪b
                #处理强制类型转换profile = ( PhotoshopProfile * ) user_data;
                if tmp_cv[0] == '(':
                    iii = tmp_cv[1:tmp_cv.find(')')-1].strip().split(' ')
                    if len(iii) > 2:
                        tmp_cv = tmp_cv
                    else:
                        tmp_cv = tmp_cv[tmp_cv.find(')')+1:].strip()
                # 对于表达式赋值的情况，需要继续向上跟踪
                if is_expression(tmp_cv):
                    change_cvs = cv_from_expression(tmp_cv)
                    change_cvs = list(set(change_cvs))  # 对从表达式中得到的cv去重
                    for change in change_cvs:
                        change = change + '$$' + str(i)
                        # sink_cv.append(change)
                        sink_cv = append_cv(sink_cv, change)
                    flag = 2
                    break
                else:
                    tmp_line = line
                    print(tmp_cv, '的值赋值给了CV')
                    print('转换的行是: ', tmp_line)
        if flag == 2:
            print("CV是表达式赋值的，此行后将继续向上跟踪转换后的多个cv", line)
            print("拆分出的多个cv是：", change_cvs)
            continue

        print(tmp_cv, '是CV最开始赋值的变量。经过变量转换后，CV最终是由', tmp_line)

        # 如果是指针/数组类型，就去掉具体变量，把前面的变量作为cv找；例如s->size变成s
        if (len(source_results) == num):  # 针对该变量没有找到source点(即经过source寻找之后source_results里没有增加新的数据)
            new_cv = left_process(tmp_cv, 'up')
            sink_cv = append_cv(sink_cv, new_cv)
            print('当前CV没有匹配到source点，开始匹配CV的上一级。CV的上一级是：', new_cv)
        '''
        当最后找到的source行中没有=时，有两种情况:
        1. 该变量为函数内定义，此时需要在漏洞函数中往下找，找到第一次赋值的地方  ==》如果第一次赋值是int A=B，还需要继续向上找B的值
        2. 该变量来自函数参数，此时直接把函数参数行输出即可
        '''
        if (tmp_line == ''):  # 没有找到任何有关键变量出现的语句(显然是不合理的，这种是数组/指针类型，还需要进一步处理)
            continue
        # print(vulf_define)
        if ('=' not in tmp_line):  # 当前行可能是函数定义行
            # print(vulf_define)
            # print(tmp_line)
            if (tmp_line.strip() in vulf_define.strip()):  # 如果出现在函数定义行,则视为函数参数
                # print(vulf_define)
                source_results.append(vulf_define)
            else:
                source_next_line = find_in_vulfile(tmp_line, cv)
                if (source_next_line == '' and tmp_line not in sinks):
                    source_results.append(tmp_line)
                elif(source_next_line not in sinks):
                    source_results.append(source_next_line)
        else:
            if not source_results and tmp_line not in sinks:  # 当source点匹配结果为空，就把暂存的含有cv且不含等号（for循环，函数调用）的行加进去
                source_results.append(tmp_line)

        print(cv, '匹配完成============')

    return source_results


def main():
    '''
    parser = OptionParser()
    (options, args) = parser.parse_args()
    if(len(args) != 1):
        print('Missing parameters! Please add software name.')
    cwe = args[0]
    '''

    slices = []
    all_sinks = []
    all_sources = []
    sink_cv = []
    # 可改成args[0]
    with open(slice_file, 'r') as f:
        all_content = f.readlines()
        for line in all_content:
            # print(line.strip())
            if len(line) == 1:  # 去掉空行的情况
                continue
            slices.append(line.strip())
            if (line.strip() == '------------------------------'):
                sinks, sink_cv, cv_list = match_sinks(slices)
                print('.......................sink is over.......................')
                sources = match_sources(slices, sink_cv, sinks)  # 考虑根据sink点来匹配source点
                # 如果匹配到sink点但是没有匹配到source点，考虑使用最开始的CV来匹配source点。
                # 对于只有整数溢出的sink点sink_cv是空的，所以必须使用这种方法才能匹配source点
                if sinks and not sources:
                    sources = match_sources(slices, cv_list[0], sinks)
                print('.......................source is over.......................')
                # print(slices)
                slices = []
                for sk in sinks:
                    if (sk not in all_sinks):
                        all_sinks.append(sk)
                for sc in sources:
                    if (sc not in all_sources):
                        all_sources.append(sc)

    print('sink点:')
    for i in all_sinks:
        print(i)
    # print(all_sinks)
    print('')
    print('source点:')
    for i in all_sources:
        print(i)
    # print(all_sources)


main()
