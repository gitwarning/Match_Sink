import os
import re
from markupsafe import re
import ast
from optparse import OptionParser


old_file = '/Users/wangning/Documents/研一/跨函数测试/sink-source点匹配测试/CWE119/FFmpeg/CVE-2013-4263/CVE-2013-4263_CWE-119_e43a0a232dbf6d3c161823c2e07c52e76227a1bc_vf_boxblur.c_4.0_OLD.c'
slice_file = '/Users/wangning/Documents/研一/跨函数测试/sink-source点匹配测试/CWE119/FFmpeg/CVE-2013-4263/slices.txt'
list_key_words = [] #api函数列表

def is_mem(line, cv):
    #print('this is a test.')
    if(' ' + cv + ' ' not in line):
        return False

    if('memcpy' in line):#之后换成正则表达式应该会更好
        return True
    elif('alloc' in line):
        return True
    elif('memset' in line):
        return True
    elif('bytestream2_get_buffer' in line):
        return True
    elif('get_bits' in line):
        return True
    elif('put_bits' in line):
        return True
    elif('copy' in line):
        return True
    elif('recv' in line):
        return True
    else:
        return False

def is_pointer(line, cv):
    if(('* ' + cv + ' ') in line):
        return True
    elif(('*' + cv + ' ') in line):
        return True
    else:
        return False

#关键变量为数组下标或者作为数组的使用
def is_array(line, cv):
    #其实关键变量只要在[]里面就算是在数组下标里了,可能和其他值一起参与了计算,例如dst[y+len]这样
    lbracket = line.find('[')
    rbracket = line.rfind(']')
    cv_loc = line.find(' ' + cv + ' ')
    if((cv_loc > lbracket) and (cv_loc < rbracket)):
        return True
    '''
    if(('[' + cv + ']') in line):#作为数组下标
        #print('1')
        return True
    elif(('[ ' + cv + ' ]') in line):#作为数组下标
        #print('2')
        return True
    '''
    if((' ' + cv + ' [') in line):#作为数组
        #print('3')
        return True
    if((' ' + cv + '[') in line):
        #print('4')
        return True
    if(line[:len(cv)] == cv):#关键变量在一行的开始处
        if(line[:(len(cv) + 2)] == cv + ' ['):
            return True
        if(line[:(len(cv) + 1)] == cv + '['):
            return True
    return False

#判断是否为函数定义
def is_funcdefine(line):
    result = get_funcname(line)
    if(len(result) == 1):
        funcname = result[0]
        res_list = line.split(funcname)
        #print(res_list)
        if(res_list[0]!= ''):
            if('=' not in res_list[0]):
                return True
        else:
            return False

#特殊的cv处理(数组、指针、点操作等)
#如果是数组的话，就取数组名，如果是指针的话就加空格
def special_cv_process(cv):
    if(cv[0] == '*'):
        #return cv[1:]
        cv = [cv[1:]]
    #if('[' in cv):#关键变量是一个下标含有内容的数组
        #cv = cv[:(cv.find('['))]
        #return cv
    if(('[' in cv) and (']' in cv)):#关键变量是一个下标含有内容的数组,先取出下标作为关键变量
        start = cv.rfind('[')
        end = cv.rfind(']')
        new_cv_str = cv[(start + 1):end]
        cv = re.split('[+|-|*|/|%|>>|<<|>|<|=]', new_cv_str) #data [ plane + 4 ] [ end + 3 ]
        
    if('.' in cv):#pd.size转换成pd . size
        new_cv = ''
        cv_tmp = cv.split('.')
        for i in cv_tmp:
            new_cv += i + ' . '
        cv = [new_cv.strip(' . ')]
        #return cv
    if('->' in cv):
        new_cv = ''
        cv_tmp = cv.split('->')
        for i in cv_tmp:
            new_cv += i + ' -> '
        cv = [new_cv.strip(' -> ')]
        #return cv
    if(type(cv) == type([])):
        return cv
    else:
        return [cv]

def get_min(sp1, sp2, sp3):#感觉处理的好繁琐,之后找一个更加简便的方法
    if((sp1 == -1) and (sp2 == -1) and (sp3 != -1)):
        return 'sp3'
    elif((sp1 == -1) and (sp2 != -1) and (sp3 == -1)):
        return 'sp2'
    elif((sp1 != -1) and (sp2 == -1) and (sp3 == -1)):
        return 'sp1'
    elif((sp1 != -1) and (sp2 != -1) and (sp3 == -1)):
        if(sp1 < sp2):
            return 'sp1'
        else:
            return 'sp2'
    elif((sp1 != -1) and (sp2 == -1) and (sp3 != -1)):
        if(sp1 < sp3):
            return 'sp1'
        else:
            return 'sp3'
    elif((sp1 == -1) and (sp2 != -1) and (sp3 != -1)):
        if(sp2 < sp3):
            return 'sp2'
        else:
            return 'sp3'
    elif((sp1 != -1) and (sp2 != -1) and (sp3 != -1)):
        if(sp1 <= sp2):
            if(sp1 <= sp3):
                return 'sp1'
            else:
                return 'sp3'
        else:
            if(sp2 <= sp3):
                return 'sp2'
            else:
                return 'sp3'

def left_process(cv, sign):#对左边的特殊变量进行空格处理
    flag = ''
    if(' ' in cv):
        sp1 = cv.find('->')
        sp2 = cv.find('.')
        sp3 = cv.find('[')
        #print(sp1, sp2, sp3)
        flag = get_min(sp1, sp2, sp3)

        if(flag == 'sp1'):
            tmp_cv = cv[:sp1].strip().split(' ')[-1]
            if(sign == 'up'):
                return tmp_cv
            else:
                return (tmp_cv + cv[sp1:]).replace(' ', '')
        if(flag == 'sp2'):
            tmp_cv = cv[:sp2].strip().split(' ')[-1]
            if(sign == 'up'):
                return tmp_cv
            else:
                return (tmp_cv + cv[sp2:]).replace(' ', '')
        if(flag == 'sp3'):
            tmp_cv = cv[:sp3].strip().split(' ')[-1]
            if(sign == 'up'):
                return tmp_cv
            else:
                return (tmp_cv + cv[sp3:]).replace(' ', '')

        return cv.split(' ')[-1]
    else:
        return cv

def match_sinks(slices):
    print('.......................sink is start.......................')
    sink_results = []
    start = slices[0].find('[')
    end = slices[0].rfind(']')
    print(slices[0][start:(end + 1)])

    cvs = ast.literal_eval(slices[0][start:(end + 1)])
    loc = slices[0].split(' ')[3]
    vul_file = slices[0].split(' ')[1].split('_')[3]
    
    tmp = []#记录被转换的变量
    '''
    mem = True #将匹配到的第一个目标函数作为sink点
    starcv = True
    arrycv = True
    '''
    for i in slices:
        if('(key_var lines)' in i):#包含当前行
            sign = 1
    
    for cv in cvs:#对于每个关键变量
        #print('now, is ' + cv)
        if(cv in tmp):
            continue
        tmp.append(cv)
        num = len(sink_results)
        if('[' in cv):
            cvs.append(cv[:(cv.find('['))])#先把数组头放进去

        sp_cv = special_cv_process(cv)#特殊变量的处理
        if(len(sp_cv) > 1):
            cv = sp_cv[0]
            for i in range(1, len(sp_cv)):#这种是因为提取数组下标提取出了多个变量
                cvs.append(sp_cv[i])
        else:
            cv = sp_cv[0]
        
        
        print('now, is ' + cv)

        mem = True #将匹配到的第一个目标函数作为sink点
        starcv = True
        arrycv = True
        flag = 0#说明还没到修改行
        sign = 0#标记该切片文件是不是含有key_var line

        for line in slices:
            this_loc = line.split('location: ')[-1].split(' file: ')[0]
            this_file = line.split('file: ')[-1].split('/')[-1].strip()
            if('(key_var lines)' in line):#包含当前行
                flag = 1
            elif((sign == 0) and (this_loc == loc) and (this_file == vul_file)):
                flag = 1
                print(line)
            if(flag == 0):
                continue
            if(is_funcdefine(line)):#如果是函数定义行,不参与sink点竞选,但如果涉及cv,则要进行一个cv的转换
                continue

            if(has_cv_fz_right(cv, line)):#允许1次转换
                tmp_cv = line.split(' =')[0].strip()
                tmp_cv= left_process(tmp_cv, 'space') #对等号左边的变量进行处理(去掉可能存在的类型名等)
                print(line)
                print(tmp_cv, '?????')
                if(cv not in tmp):
                    cvs.append(tmp_cv)
                    tmp.append(tmp_cv)

            if(is_mem(line, cv) and mem):
                print('mem:  ', line)
                sink_results.append(line)
                mem = False
            if(is_pointer(line, cv) and starcv):
                print('pointer:  ', line)
                sink_results.append(line)
                starcv = False
            if(is_array(line, cv) and arrycv):
                print('array:  ', line)
                sink_results.append(line)
                arrycv = False
        

        if(len(sink_results) == num):#针对该变量没有找到sink点,取它的上一级变量
            new_cv = left_process(cv, 'up')
            print(new_cv, '!!!!!!!!!!!')
            cvs.append(new_cv)
            tmp.append(cv)
            print(cvs)

    return sink_results

def get_funcname(code):
    #pattern = "((?:_|[A-Za-z])\w*(?:\s(?:\.|::|\->|)\s(?:_|[A-Za-z])\w*)*)\s\("
    pattern = "((?:_|[A-Za-z])\w*(?:\s(?:\.|::|\->|)\s(?:_|[A-Za-z])\w*)*)\s?\("
    result = re.findall(pattern, code)

    i = 0
    while i < len(result):
        if result[i] in list_key_words:
            del result[i]
        else:
            i += 1
    
    return result

def has_cv(cv, line):
    #print(('*' + cv + ','))
    
    if((' ' + cv + ',') in line):
        return True
    if((' ' + cv + ';') in line):
        return True
    if((' ' + cv + ')') in line):
        return True
    if((' ' + cv + ' ,') in line):
        return True
    if((' ' + cv + ' ;') in line):
        return True
    if((' ' + cv + ' )') in line):
        return True
    if(('*' + cv + ';') in line):
        return True
    if((' ' + cv + ' ') in line):
        return True
    if((' ' + cv + '[') in line):
        return True
    if(('*' + cv + ',') in line):
        return True
    if(('*' + cv + ')') in line):
        return True

    return False

#cv在等号左边（被赋值）
def has_cv_fz_left(cv, line):
    if(' = ' not in line):#加空格是为了避免+=的出现，这种情况不用转换
        return False
    left = line.split(' = ')[0].strip()
    #if((' ' + cv + ' ') in left):#要不要改成完全相同?
        #return True
    if(cv == left):
        return True
    elif(line[:len(cv)] == cv):#关键变量在一行的开始处
        if(line[:(len(cv) + 1)] == cv + ' '):
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

#cv在等号右边（赋值给别人）
def has_cv_fz_right(cv, line):
    if('=' not in line):
        return False
    right = line.split('=')[-1]
    #print('right:', right)
    if(has_cv(cv, right)):
        return True
    
    return False

#在漏洞文件中继续往下找第一次用cv的地方
def find_in_vulfile(tmp_line, cv):
    location = 0
    tmp_file = tmp_line.split(' file: ')[-1].split('/')[-1]
    tmp_loc = tmp_line.split('location: ')[-1].split(' file: ')[0]
    with open(old_file, 'r') as f:
        vul_content = f.readlines()
    for line in vul_content:
        location += 1
        if(location <= int(tmp_loc)):
            continue
        if(has_cv_fz_left(cv, line)):
            result = line.strip() + ' location: ' + str(location) + ' file: ' + tmp_file
            return result

    return ''#如果没找到的话,就返回空

#要找到每个关键变量的source点
def match_sources(slices):
    print('.......................source is start.......................')
    source_results = []
    source_lines = []

    vul_function = slices[0].strip().split(' ')[2]
    #print(vul_function)
    loc = slices[0].split(' ')[3].strip()
    vulf_define = ''
    #print(vul_function)
    #print(slices[1])
    
    if(vul_function in slices[1]):
        vulf_define = slices[1].strip()
        
        if('location' not in slices[1]):
            vulf_define = slices[1].strip() + slices[2].strip()
    
    #cvs = eval(slices[0].split(' ')[-1])
    start = slices[0].find('[')
    end = slices[0].rfind(']')
    print(slices[0][start:(end + 1)])
    
    cvs = ast.literal_eval(slices[0][start:(end + 1)])
    #print(cvs)
    for line in slices:
        this_loc = line.split('location: ')[-1].split(' file: ')[0]
        source_lines.append(line)
        if('(key_var lines)' in line):
            break
        elif(this_loc == loc):
            break
    source_lines.reverse() #将切片逆序
    #print(source_lines)

    for cv in cvs:
        num = len(source_results)
        print('now, is ' + cv)
        
        #cv = special_cv_process(cv)
        sp_cv = special_cv_process(cv)#特殊变量的处理
        if(len(sp_cv) > 1):
            cv = sp_cv[0]
            for i in range(1, len(sp_cv)):#这种是因为提取数组下标提取出了多个变量
                cvs.append(sp_cv[i])
        else:
            cv = sp_cv[0]

        #寻找外部函数定义处
        flag = 0
        for line in source_lines:
            res_tmp = line.split('=')
            if(len(res_tmp) == 1):
                continue
            else:
                line_cvs = res_tmp[0].strip().split(',') #可能存在多个变量被赋值,例如a, b = recv()
                if(cv in line_cvs):
                    fucnname = get_funcname(line)
                    if(fucnname != []): #如果是外部函数
                        source_results.append(line)
                        flag = 1
                        break
                        #return source_results
        if(flag == 1):
            print('外部函数定义')
            break
                        

        #函数内变量定义处和函数参数
        #source_tmp = source_lines
        #source_tmp.reverse()

        #找到定义后第一次用/初始化的地方
        #使用跨函数的sink点测试
        '''
        for line in source_tmp:
            if(has_cv(cv, line)):#这一行出现过关键变量
                source_results.append(line)
        '''
        tmp_cv = cv
        tmp_line = ''
        for line in source_lines:
            #print(line, '---------')
            if(has_cv(tmp_cv, line) and not has_cv_fz_left(tmp_cv, line)):#如果含有关键变量但不含等号赋值
                #print('okokokokokokok')
                tmp_line = line #先暂存当前语句，然后继续向上找
            if(has_cv_fz_left(tmp_cv, line)):#含有等号的赋值
                #print(tmp_cv, line)
                tmp_cv = re.split('[,|;]', line.split(' = ')[-1])[0] #取出等号右边的变量
                tmp_line = line
                print(tmp_cv)

        print(tmp_cv, tmp_line)

        #如果是指针/数组类型，就去掉具体变量，把前面的变量作为cv找；例如s->size变成s
        if(len(source_results) == num):#针对该变量没有找到source点(即经过source寻找之后source_results里没有增加新的数据)
            if('->' in cv):
                index = cv.rfind('->')
                new_cv = cv[:index].strip()
                print(new_cv, '===============')
                cvs.append(new_cv)
            if('.' in cv):
                cvs.append(cv[:(cv.rfind('.'))].strip())
            if(('[' in cv) and (']' in cv)):#a[index][s]
                index = cv.rfind('[')
                new_cv = cv[:index].strip()
                cvs.append(new_cv)
        '''
        当最后找到的source行中没有=时，有两种情况:
        1. 该变量为函数内定义，此时需要在漏洞函数中往下找，找到第一次赋值的地方
        2. 该变量来自函数参数，此时直接把函数参数行输出即可
        '''
        if(tmp_line == ''):#没有找到任何有关键变量出现的语句(显然是不合理的，这种是数组/指针类型，还需要进一步处理)
            continue
        #print(vulf_define)
        if('=' not in tmp_line):
            #print(vulf_define)
            #print(tmp_line)
            if(tmp_line.strip() in vulf_define.strip()):#如果出现在函数定义行,则视为函数参数
                #print(vulf_define)
                source_results.append(vulf_define)
            else:
                source_next_line = find_in_vulfile(tmp_line, cv)
                if(source_next_line == ''):
                    source_results.append(tmp_line)
                else:
                    source_results.append(source_next_line)
        else:
            source_results.append(tmp_line)
        
        print('one cv is over.......')

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
    with open(slice_file, 'r') as f:
        all_content = f.readlines()
        for line in all_content:
            #print(line.strip())
            slices.append(line.strip())
            if(line.strip() == '------------------------------'):
                sinks = match_sinks(slices)
                print('.......................sink is over.......................')
                sources = match_sources(slices)#考虑根据sink点来匹配source点
                print('.......................source is over.......................')
                #print(slices)
                slices = []
                for sk in sinks:
                    if(sk not in all_sinks):
                        all_sinks.append(sk)
                for sc in sources:
                    if(sc not in all_sources):
                        all_sources.append(sc)
                
    
    print('sink点:')
    for i in all_sinks:
        print(i)
    #print(all_sinks)
    print('')
    print('source点:')
    for i in all_sources:
        print(i)
    #print(all_sources)

#main()
for i in range(1, 9):
    print(i)