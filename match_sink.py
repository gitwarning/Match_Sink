import os

from markupsafe import re
import ast

# old_file = '/Users/wangning/Documents/研一/跨函数测试/sink-source点匹配测试/CWE119/FFmpeg/CVE-2013-4263/CVE-2013-4263_CWE-119_e43a0a232dbf6d3c161823c2e07c52e76227a1bc_vf_boxblur.c_4.0_OLD.c'
# slice_file = '/Users/wangning/Documents/研一/跨函数测试/sink-source点匹配测试/CWE119/FFmpeg/CVE-2013-4263/slices.txt'
old_file = "E:/漏洞检测/已分析过漏洞/CWE-189_FFmpeg/CWE-189/CVE-2013-0876/CVE-2013-0876_CWE-189_5260edee7e5bd975837696c8c8c1a80eb2fbd7c1_sanm.c_1.1_OLD.c"
slice_file = "E:/漏洞检测/已分析过漏洞/CWE-189_FFmpeg/CWE-189/CVE-2013-0876/slices.txt"
list_key_words = []  # api函数列表
# 变量类型列表
val_type = ['short', 'int', 'long', 'char', 'float', 'double', 'struct', 'union', 'enum', 'const', 'unsigned', 'signed']

# is_mem
def is_risk_func(line, cv):
    # print('this is a test.')
    if (' ' + cv + ' ' not in line):
        return False

    if ('memcpy' in line):  # 之后换成正则表达式应该会更好
        return True
    elif ('alloc' in line):
        return True
    elif ('memset' in line):
        return True
    elif ('bytestream2_get_buffer' in line):
        return True
    elif ('get_bits' in line):
        return True
    elif ('put_bits' in line):
        return True
    elif ('copy' in line):
        return True
    elif ('recv' in line):
        return True
    else:
        return False


def is_pointer(line, cv):
    if (('* ' + cv + ' ') in line):
        return True
    elif (('*' + cv + ' ') in line):
        return True
    else:
        return False


# 关键变量为数组下标或者作为数组的使用
def is_array(line, cv):
    # 其实关键变量只要在[]里面就算是在数组下标里了,可能和其他值一起参与了计算,例如dst[y+len]这样
    lbracket = line.find('[')
    rbracket = line.rfind(']')
    cv_loc = line.find(' ' + cv + ' ')
    if ((cv_loc > lbracket) and (cv_loc < rbracket)):
        return True
    '''
    if(('[' + cv + ']') in line):#作为数组下标
        #print('1')
        return True
    elif(('[ ' + cv + ' ]') in line):#作为数组下标
        #print('2')
        return True
    '''
    if ((' ' + cv + ' [') in line):  # 作为数组
        # print('3')
        return True
    if ((' ' + cv + '[') in line):
        # print('4')
        return True
    if (line[:len(cv)] == cv):  # 关键变量在一行的开始处
        if (line[:(len(cv) + 2)] == cv + ' ['):
            return True
        if (line[:(len(cv) + 1)] == cv + '['):
            return True
    return False


#  sink点是整数运算导致的整数溢出类型匹配
def is_calculation(line, cv):
    if (cv + ' *') in line and '=' in line:  # 要有等号才算是整数溢出吗？
        return True
    if ('* ' + cv) in line and '=' in line:
        return True
    if (cv + ' +') in line:
        return True
    if (cv + ' -') in line and (cv + ' ->') not in line:
        return True


# 判断是否为函数定义
def is_funcdefine(line):
    result = get_funcname(line)
    if (len(result) == 1):
        funcname = result[0]
        res_list = line.split(funcname)
        # print(res_list)
        if (res_list[0] != ''):
            if ('=' not in res_list[0]):
                return True
        else:
            return False


# 特殊的cv处理(数组、指针、点操作等)
# 如果是数组的话，就取数组名，如果是指针的话就加空格
def special_cv_process(cv):
    if (cv[0] == '*'):
        # return cv[1:]
        cv = [cv[1:]]
    # if('[' in cv):#关键变量是一个下标含有内容的数组
    # cv = cv[:(cv.find('['))]
    # return cv
    if (('[' in cv) and (']' in cv)):  # 关键变量是一个下标含有内容的数组,先取出下标作为关键变量
        start = cv.rfind('[')
        end = cv.rfind(']')
        new_cv_str = cv[(start + 1):end]
        cv = re.split('[+|-|*|/|%|>>|<<|>|<|=]', new_cv_str)  # data [ plane + 4 ] [ end + 3 ]

    if ('.' in cv):  # pd.size转换成pd . size
        new_cv = ''
        cv_tmp = cv.split('.')
        for i in cv_tmp:
            new_cv += i + ' . '
        cv = [new_cv.strip(' . ')]
        return cv
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
    if (' ' in cv):
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
    if ('=' not in line):
        return False
    right = line.split('=')[-1]
    # print('right:', right)
    if (has_cv(cv, right)):
        return True

    return False


def find_sink(after_diff, cv_list, sink_results, sink_cv, epoch):
    array_sink = True
    pointer_sink = True
    risk_func_sink = True
    calculation_sink = True
    sink_appended = False
    # 对于每一个cv都去匹配sink点
    for cv in cv_list[epoch]:
        num = len(sink_results)
        if ('[' in cv):
            cv_list.append(cv[:(cv.find('['))])  # 先把数组头放进去

        sp_cv = special_cv_process(cv)  # 特殊变量的处理
        if (len(sp_cv) > 1):
            cv = sp_cv[0]
            for i in range(1, len(sp_cv)):  # 这种是因为提取数组下标提取出了多个变量
                cv_list.append(sp_cv[i])
        else:
            cv = sp_cv[0]

        print("=======now CV is " + cv + "=========")
        # 找到diff修改的行，从diff修改行向下寻找sink点
        for i, line in enumerate(after_diff):
            # 如果当前行是函数定义行，不参加sink点的匹配，但是可能涉及到sink点的转换（通过参数位置转换
            if is_funcdefine(line):
                # 函数定义的上一行不一定是该函数的函数调用行,先判断上一行是否是函数调用行（函数名）获取上一行的信息，
                # 判断cv是否在函数调用语句的参数中，如果在就记录下来cv的位置（第几个参数）
                func_name = get_funcname(line)[0]
                if func_name in after_diff[i - 1]:
                    tmp = after_diff[i - 1]
                    tmp = tmp[tmp.find(func_name):]
                    call_paras = tmp[tmp.find('(') + 1:tmp.find(')')].split(',')  # 从函数名开始向后面查找括号的方式得到函数参数
                    cvv = ' ' + cv + ' '
                    if cvv in call_paras:
                        i = call_paras.index(cvv)
                        func_paras = line[line.find('(') + 1:line.rfind(')')].split(',')
                        change_cv = func_paras[i]
                        # chang_cv 需要去掉前面的变量类型
                        change_cv = left_process(change_cv, 'space')
                        if change_cv != cv and change_cv not in cv_list[epoch + 1]:
                            cv_list[epoch + 1].append(change_cv)
                            print("当前CV跨函数，经转化后新的CV是：", change_cv)
                continue
            # 进行sink点匹配
            if is_array(line, cv) and array_sink:
                print('sink点是数组访问越界：', line)
                sink_results.append(line)
                if not sink_appended:
                    sink_cv.append(cv)
                    sink_appended = True
                array_sink = False
            if is_pointer(line, cv) and pointer_sink:
                print('sink点是指针访问越界：', line)
                sink_results.append(line)
                if not sink_appended:
                    sink_cv.append(cv)
                    sink_appended = True
                pointer_sink = False
            if is_risk_func(line, cv) and risk_func_sink:
                print('sink点是风险函数使用：', line)
                sink_results.append(line)
                if not sink_appended:
                    sink_cv.append(cv)
                    sink_appended = True
                risk_func_sink = False
            if is_calculation(line, cv) and calculation_sink:
                print('sink点是整数运算导致的整数溢出类型：', line)
                sink_results.append(line)
                if not sink_appended:
                    sink_cv.append(cv)
                    sink_appended = True
                calculation_sink = False
            # 如果当前行涉及到CV的转换，将其转换后的变量记录下来以作备用
            if has_cv_fz_right(cv, line):
                tmp_cv = line.split('=')[0].strip()
                tmp_cv = left_process(tmp_cv, 'space')  # 对等号左边的变量进行处理(去掉可能存在的类型名等)
                if tmp_cv not in cv_list[epoch + 1]:
                    cv_list[epoch + 1].append(tmp_cv)
                print('CV转化行：', line)
                print('转换后的CV：', tmp_cv)
    # 当前所有CV都没有匹配到sink点，将其上一级加入到下一次要匹配的CV中cvList[epoch+1]
    # TODO 还是说要针对每一个CV？
    # if len(sink_results) == num:
    if len(sink_results) == 0:
        for cv in cv_list[epoch]:
            sp_cv = special_cv_process(cv)  # 特殊变量的处理
            if (len(sp_cv) > 1):
                cv = sp_cv[0]
                for i in range(1, len(sp_cv)):  # 这种是因为提取数组下标提取出了多个变量
                    cv_list.append(sp_cv[i])
            else:
                cv = sp_cv[0]
            new_cv = left_process(cv, 'up')
            if new_cv not in cv_list[epoch + 1] and new_cv not in cv_list[epoch]:
                print('CV的上一级是：', new_cv)
                cv_list[epoch + 1].append(new_cv)

    print("如果当前cv列表没有找到sink点，下次查找的cv是：", cv_list[epoch + 1])


def match_sinks(slices):
    print('.......................sink is start.......................')
    epoch = 0  # 二维数组cv的选取下标
    sink_results = []
    cv_list = [[] for _ in range(20)]  # cv数组定义为二维数组
    sink_cv = []  # 找到sink点的cv
    flag = 0  # 标记diff修改的位置
    start = slices[0].find('[')
    end = slices[0].rfind(']')

    cv_list[0] = ast.literal_eval(slices[0][start:(end + 1)])
    loc = slices[0].split(' ')[3]
    vul_file = slices[0].split(' ')[1].split('_')[3]

    after_diff = []
    # 找到diff修改的位置，将diff修改位置向下的切片加入到after_diff[]
    for line in slices:
        this_loc = line[line.find('location: '):line.rfind(' file')].replace('location: ', '')  # 当前切片的行号
        this_file = line.split('file: ')[-1].split('/')[-1]
        if flag == 0:
            if '(key_var lines)' in line:  # 含有(key_var lines)标志的表明当前行是diff修改的下一行,因为在diff只增加的类型中在漏洞文件中找不到修改行
                flag = 1
            if this_loc == loc and this_file == vul_file:
                flag = 1
        if flag == 1:
            after_diff.append(line)

    while len(sink_results) == 0 and epoch < 5:
        find_sink(after_diff, cv_list, sink_results, sink_cv, epoch)
        epoch += 1

    return sink_results, sink_cv





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
    left_list = left.split(' ')
    if left_list[0] in val_type or (not left_list[0].islower()):
        if cv == left_list[-1]:  # int * buf
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
    tmp_loc = tmp_line.split('location: ')[-1].split(' file: ')[0]
    with open(old_file, 'r') as f:
        vul_content = f.readlines()
    for line in vul_content:
        location += 1
        if (location <= int(tmp_loc)):
            continue
        if (has_cv_fz_left(cv, line)):
            result = line.strip() + ' location: ' + str(location) + ' file: ' + tmp_file
            return result

    return ''  # 如果没找到的话,就返回空


# 要找到每个关键变量的source点
def has_only_cv(line, cv):
    if (cv + ' ->') in line:
        return False
    if (cv + ' .') in line:
        return False
    return has_cv(cv, line)


def match_sources(slices, sink_cv):
    print('.......................source is start.......................')
    source_results = []
    source_lines = []

    vul_function = slices[0].strip().split(' ')[2]
    # print(vul_function)
    loc = slices[0].split(' ')[3].strip()
    vulf_define = ''
    # print(vul_function)
    # print(slices[1])

    if (vul_function in slices[1]):
        vulf_define = slices[1].strip()

        if ('location' not in slices[1]):
            vulf_define = slices[1].strip() + slices[2].strip()

    # # cvs = eval(slices[0].split(' ')[-1])
    # start = slices[0].find('[')
    # end = slices[0].rfind(']')
    # print(slices[0][start:(end + 1)])
    #
    # cvs = ast.literal_eval(slices[0][start:(end + 1)])
    # print(cvs)
    for line in slices:
        this_loc = line.split('location: ')[-1].split(' file: ')[0]
        source_lines.append(line)
        if ('(key_var lines)' in line):
            break
        elif (this_loc == loc):
            break
    source_lines.reverse()  # 将切片逆序
    # print(source_lines)

    for cv in sink_cv:
        num = len(source_results)
        print('now, is ' + cv)

        # cv = special_cv_process(cv)
        sp_cv = special_cv_process(cv)  # 特殊变量的处理
        if (len(sp_cv) > 1):
            cv = sp_cv[0]
            for i in range(1, len(sp_cv)):  # 这种是因为提取数组下标提取出了多个变量
                sink_cv.append(sp_cv[i])
        else:
            cv = sp_cv[0]

        # 寻找外部函数定义处
        flag = 0
        for line in source_lines:
            res_tmp = line.split('=')
            if (len(res_tmp) == 1):
                continue
            else:
                line_cvs = res_tmp[0].strip().split(',')  # 可能存在多个变量被赋值,例如a, b = recv()
                if (cv in line_cvs):
                    fucnname = get_funcname(line)
                    if fucnname:  # 如果是外部函数
                        source_results.append(line)
                        flag = 1
                        break
                        # return source_results
        if (flag == 1):
            print('外部函数定义')
            break

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
        for line in source_lines:
            # 在找source点时如果当前行是对cv的成员赋值，不可以将此视为cv的赋值
            if has_only_cv(line, tmp_cv) and not has_cv_fz_left(tmp_cv, line):  # 如果含有关键变量但不含等号赋值
                tmp_line = line  # 先暂存当前语句，然后继续向上找
            if has_only_cv(line, tmp_cv) and has_cv_fz_left(tmp_cv, line):  # 含有等号的赋值
                # print(tmp_cv, line)
                tmp_cv = re.split('[,;]', line.split(' = ')[-1])[0]  # 取出等号右边的变量，把谁的值赋给了CV，CV=b，继续向上跟踪b
                tmp_line = line
                print(tmp_cv, '的值赋值给了CV')

        print(tmp_cv, '是CV最开始赋值的变量。经过变量转换后，CV最终是由', tmp_line)

        # 如果是指针/数组类型，就去掉具体变量，把前面的变量作为cv找；例如s->size变成s
        if (len(source_results) == num):  # 针对该变量没有找到source点(即经过source寻找之后source_results里没有增加新的数据)
            # if ('->' in cv):
            #     index = cv.rfind('->')
            #     new_cv = cv[:index].strip()
            #     print(new_cv, '===============')
            #     cvs.append(new_cv)
            # if ('.' in cv):
            #     cvs.append(cv[:(cv.rfind('.'))].strip())
            # if (('[' in cv) and (']' in cv)):  # a[index][s]
            #     index = cv.rfind('[')
            #     new_cv = cv[:index].strip()
            #     cvs.append(new_cv)
            #  TODO 可以直接用之前写的函数
            new_cv = left_process(tmp_cv, 'up')
            if new_cv not in sink_cv:
                sink_cv.append(new_cv)
                print('当前CV没有匹配到source点，开始匹配CV的上一级。CV的上一级是：', new_cv)
        '''
        当最后找到的source行中没有=时，有两种情况:
        1. 该变量为函数内定义，此时需要在漏洞函数中往下找，找到第一次赋值的地方  ==》如果第一次赋值是int A=B，还需要继续向上找B的值
        2. 该变量来自函数参数，此时直接把函数参数行输出即可
        '''
        if (tmp_line == ''):  # 没有找到任何有关键变量出现的语句(显然是不合理的，这种是数组/指针类型，还需要进一步处理)
            continue
        # print(vulf_define)
        if ('=' not in tmp_line): # 当前行可能是函数定义行
            # print(vulf_define)
            # print(tmp_line)
            if (tmp_line.strip() in vulf_define.strip()):  # 如果出现在函数定义行,则视为函数参数
                # print(vulf_define)
                source_results.append(vulf_define)
            else:
                source_next_line = find_in_vulfile(tmp_line, cv)
                if (source_next_line == ''):
                    source_results.append(tmp_line)
                else:
                    source_results.append(source_next_line)
        # else:
        #     source_results.append(tmp_line)

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
    with open(slice_file, 'r') as f:
        all_content = f.readlines()
        for line in all_content:
            # print(line.strip())
            slices.append(line.strip())
            if (line.strip() == '------------------------------'):
                sinks, sink_cv = match_sinks(slices)
                print('.......................sink is over.......................')
                sources = match_sources(slices, sink_cv)  # 考虑根据sink点来匹配source点
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

