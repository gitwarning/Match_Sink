from share_func import *
from sink_CWE772 import get_diff_message
import re

list_key_words = ['if', 'while', 'for']  # 控制结构关键字
val_type = ['short', 'int', 'long', 'char', 'float', 'double', 'struct', 'union', 'enum', 'const', 'unsigned', 'signed',
            'uint32_t', 'struct', 'void', 'static']

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

# 判断是否为函数定义
def is_funcdefine(line):
    result = get_funcname(line)
    if (len(result) == 1):
        funcname = result[0]
        res_list = line.split(funcname)
        # print(res_list)
        if (res_list[0] != ''):
            if ('=' not in res_list[0]):
                for i in val_type:
                    if(i in res_list[0]):
                        return True
        else:
            return False
    
    return False

def is_con(line):
    if('while ' in line):
        return True
    elif('for ' in line):
        return True
    elif('do ' in line):
        return True
    elif(line == 'do'):
        return True
    elif(line == 'for'):
        return True
    elif(line == 'while'):
        return True
    
    return False

def get_sink_line(vul_content, func_define, start_line):
    func_define = func_define.split('location:')[0].replace(' ', '').strip()
    print('func_define: ', func_define)
    location = 0
    flag = False #标记有没有到达漏洞函数
    cnt = 0 #统计花括号的数量
    will_be_cal = []

    for line in vul_content:
        location += 1
        tmp_line = line.replace(' ', '').strip()
        if(tmp_line == func_define):
            flag = True
        
        if(flag == False):
            continue
        # print(line, location)

        if(location > start_line):
            break
        if(location == start_line):
            if(is_con(line.strip())):
                return line.strip(), location

        will_be_cal.append([line.strip(), location])
    will_be_cal.reverse()
    # print('will_be_cal: ', will_be_cal)

    sign = False
    for line in will_be_cal:
        tmp_line = line[0].replace(' ', '').strip()
        loc = line[1]    
        if(tmp_line != '' and tmp_line[-1] == '}'):
            cnt += 1
            sign = True
        if(tmp_line != '' and tmp_line[-1] == '{'):
            cnt -= 1
            sign = True

        if((sign== True) and (cnt < 0) and (is_con(line[0]))):
            print(cnt)
            # print(line, loc)
            return line[0].strip(), loc
    return '', 0


def get_goto_sink_line(vul_content, func_define, start_line):
    func_define = func_define.split('location:')[0].replace(' ', '').strip()
    print('func_define: ', func_define)
    goto_flag = ''
    goto_code = ''
    goto_loc = 0
    location = 0
    sign = False
    forward_line = []
    for line in vul_content:
        location += 1
        forward_line.append(line)

        if(sign and is_funcdefine(line)):#已经到了别的函数
            break

        if(line.replace(' ', '').strip() == func_define):
            sign = True#已经经过了漏洞函数的定义行

        if(location < start_line):
            continue
                
        #寻找后面有没有goto语句
        line_tmp = line.strip()
        if(line_tmp[:5] == 'goto '):
            goto_flag = line_tmp.split('goto ')[-1]
            if(goto_flag[-1] == ';' or goto_flag[-1] == ',' or goto_flag == '}'):
                goto_flag = goto_flag[:-1].strip()
                goto_code = line_tmp
                goto_loc = location
                break
    
    if(goto_flag == ''): #该函数不含goto语句
        return '', 0
    
    for line in forward_line:
        line = line.strip()
        if(line == goto_flag + ':'):
            return goto_code, goto_loc

    return '', 0 #只是普通的goto语句，没有构成循环

def get_recursion_sink_link(vul_content, func_define, start_line):
    func_define = func_define.split('location:')[0].strip()
    vulname = get_funcname(func_define)[0] #获取漏洞函数名
    location = 0
    sign = False

    for line in vul_content:
        line_tmp = line.replace(' ', '').strip()
        func_define_tmp = func_define.replace(' ', '').strip()
        location += 1

        if(sign and is_funcdefine(line)):#已经到了别的函数
            print(line)
            break

        if(line_tmp == func_define_tmp):
            sign = True#已经经过了漏洞函数的定义行
        elif(line_tmp != '' and line_tmp in func_define_tmp and line_tmp[-1] == ','):#函数定义行被分行写的情况
            sign = True

        if(location < start_line):
            continue

        res_func = get_funcname(line)
        if(len(res_func) > 0):
            for i in res_func:
                if(i == vulname):
                    return line.strip(), location
    
    return '', 0

def sink_835(old_file, func_define, sink_results, diff_file, loc, is_add):
    diff_mes = {}
    with open(old_file, 'r') as f:
        vul_content = f.readlines()
    
    with open(diff_file, 'r') as f:
        diff_content = f.readlines()
    # 如果该类型diff文件中有删除死循环比如while(1),for(;;),那么该行也被纳入sink点候选集
    diff_loc = 0
    for i, line in enumerate(diff_content):
        if '-' == line[0]:
            if 'while (1) {' in line:
                diff_loc = i  # 获取到diff文件中死循环的位置，需要将其对应回old文件中
                break
            # 还需要添加for(;;) 需要在代码中找一个例子
    #  从死循环位置反向找回diff块头，获取行号信息
    if diff_loc != 0:
        index = diff_loc
        while index > 0:
            if diff_content[index][:2] == "@@":
                tmp_line = diff_content[index].split("@@")[1]
                num_line = int(tmp_line.split(',')[0].replace('-', '').strip())
                location = num_line + (diff_loc - index) - 1
                tmp_line = diff_content[diff_loc][1:].replace('\n', '').strip()
                sink_line = tmp_line + ' location: ' + str(location)
                sink_results.append(sink_line)
                break
            index = index - 1
    if(is_add == False):#如果不是仅有加号行的文件,标记行号就是修改行号
        start_line = int(loc)
    else:
        num_fin = 0
        diff_mes = get_diff_message(diff_content)

        for start_line in diff_mes.keys():
            num_list = diff_mes[start_line]
            medium_tmp = num_list[0]
            add_tmp = num_list[1]
                                        
            if(int(loc) > (int(start_line) + medium_tmp + add_tmp + 1)):
                num_fin = add_tmp
            elif(int(loc) >= (int(start_line) + medium_tmp)):#说明是在加号块中间的一句
                already_num = int(loc) - (int(start_line) + medium_tmp + 1)
                print(already_num, loc, start_line, medium_tmp)
                num_fin += already_num
                break
                    
        print(loc, num_fin)
        start_line = int(loc) - num_fin

    print('将会从 ' + str(start_line) + '向上找循环') # 寻找循环头所在的地方，这一行可能就是循环头

    res_line, loc = get_sink_line(vul_content, func_define, start_line)
    print(type(res_line))
    print(type(loc))

    if(res_line == '' and loc == 0):#没有找到循环语句，考虑goto点情况和递归的情况
        print('将会尝试从' + str(start_line) + '向下寻找goto类型循环点')
        res_line, loc = get_goto_sink_line(vul_content, func_define, start_line)
    
    if(res_line == '' and loc == 0):
        print('将会尝试从' + str(start_line) + '向下寻找递归类型循环点')
        res_line, loc = get_recursion_sink_link(vul_content, func_define, start_line)
    if(res_line == '' and loc == 0):
        print('没有找到符合的sink点')
        return

    new_line = res_line + ' location: ' + str(loc)
    print(new_line)
    sink_results.append(new_line)