from share_func import *
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

def not_notes(line):
    if(line[:2] == '/*'):
        return False
    elif(line[:2] == '//'):
        return False
    else:
        return True

def get_diff_message(diff_content):
    diff_message = {}
    valid_message = False
    every_num = 0
    add_num = 0
    for line in diff_content:
        line = line.strip()
        if(line[:2] == '@@'):
            valid_message = True
            after_add_del = False
            add_line_tmp = re.findall('@@(.*?)@@', line)[0].strip()
            start_num = re.findall('\+(.*?),', add_line_tmp)[0].strip()#start_num
            
            medium_num = -1

        if(valid_message == False):
            continue

        if(line != '' and line[0] == '-'):
            after_add_del = True
            add_num -= 1
            every_num -= 1

        if(line != '' and line[0] == '+'):
            after_add_del = True
            add_num += 1
            every_num += 1
        
        if(after_add_del and line != '' and line != '' and line[0] != '+' and line[0] != '-'):#视为一个加减块结束
            after_add_del = False
            medium_num -= (every_num + 1)
            diff_message[start_num] = [medium_num, add_num]

            start_num_tmp = int(start_num) + (medium_num + add_num) #新的加减块的开始位置
            start_num = str(start_num_tmp)
            # diff_message.setdefault(start_num, []).append([medium_num, add_num])
            every_num = 0
        
        medium_num += 1
    
    print(diff_message)
    return diff_message

def sink_772(old_file, sink_results, diff_file, loc, vul_name):
    print(vul_name)
    diff_mes = {}
    with open(old_file, 'r') as f:
        vul_content = f.readlines()
    
    with open(diff_file, 'r') as f:
        diff_content = f.readlines()

    num_fin = 0
    diff_mes = get_diff_message(diff_content)

    for start_line in diff_mes.keys():
        num_list = diff_mes[start_line]
        medium_tmp = num_list[0]
        add_tmp = num_list[1]
                                    
        if(int(loc) > (int(start_line) + medium_tmp + add_tmp + 1)):
            num_fin = add_tmp
        elif(int(loc) >= (int(start_line) + medium_tmp)):#说明是在加号块中间的一句
            already_num = int(loc) - (int(start_line) + medium_tmp) + 1
            print(already_num, loc, start_line, medium_tmp)
            num_fin += already_num
            break
                
    print(loc, num_fin)
    start_line = int(loc) - num_fin

    print('将会从 ' + str(start_line) + '开始找sink点')
    location = 0
    result_tmp = '' #在没有return语句的情况下暂存函数的最后一句话
    next_define = False
    not_over = False
    location_tmp = start_line
    for line in vul_content:
        line_tmp = line
        location += 1
        line = line.strip().replace(' ', '')
        if(line == ''):
            continue
        if(location < int(start_line)):
            continue
        # print(line_tmp)
        # if(location == 7910):
        #     print(line)
        
        if(is_funcdefine(line_tmp) or line_tmp == vul_content[-1]):#当前函数结束或者是当前函数是文件的最后一个函数
            if(' ' + vul_name + '(' not in line_tmp):
                print('已经到了下一个函数定义: ', line_tmp)
                next_define = True

        if(next_define == True):
            result_line = result_tmp.strip() + ' location: ' + str(location_tmp)
            print(result_line)
            sink_results.append(result_line)
            return
        
        if(line != '}' and not_notes(line)):
            if(not_over == True):
                result_tmp += line_tmp.strip() #如果一句话一行没写完
                not_over = False
            else:
                result_tmp = line_tmp.strip()
            location_tmp = location
            if(line[-1] == ','):
                not_over = True

        if(line[:6] == 'return'):
            result_line = line_tmp.strip() + ' location: ' + str(location)
            print(result_line)
            sink_results.append(result_line)
            return

    