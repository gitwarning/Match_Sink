from audioop import add
from share_func import *
import re

def get_diff_message(diff_content):
    diff_message = {}
    valid_message = False
    has_delete = False
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
    return diff_message, has_delete

def sink_772(old_file, sink_results, diff_file, loc):
    diff_mes = {}
    with open(old_file, 'r') as f:
        vul_content = f.readlines()
    
    with open(diff_file, 'r') as f:
        diff_content = f.readlines()

    num_fin = 0
    diff_mes, has_delete = get_diff_message(diff_content)

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
    for line in vul_content:
        line_tmp = line
        location += 1
        line = line.strip().replace(' ', '')
        if(line == ''):
            continue
        if(location < int(start_line)):
            continue
        # print(line_tmp)
        if(location == 7910):
            print(line)
        if(line[:6] == 'return'):
            result_line = line_tmp.strip() + ' location: ' + str(location)
            print(result_line)
            sink_results.append(result_line)
            return

    