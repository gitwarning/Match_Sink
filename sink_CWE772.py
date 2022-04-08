from share_func import *
import re

def get_diff_message(diff_content):
    diff_message = {}
    valid_message = False
    add_num = 0
    every_num = 0
    for line in diff_content:
        line = line.strip()
        if(line[:2] == '@@'):
            valid_message = True
            after_add_del = False
            add_line_tmp = re.findall('@@(.*?)@@', line)[0].strip()
            start_num = re.findall('\+(.*?),', add_line_tmp)[0].strip()#start_num
            del_start_num = re.findall('\-(.*?),', add_line_tmp)[0].strip()
            
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
        
        if(after_add_del and line[0] != '+' and line[0] != '-'):#视为一个加减块结束
            valid_message = False
            medium_num -= (every_num + 1)
            # diff_message.setdefault(start_num, []).append([medium_num, add_num])
            diff_message[str(int(start_num) + medium_num + 1)] = del_start_num
            every_num = 0
        
        medium_num += 1
    
    print(diff_message)
    return diff_message

def sink_772(old_file, sink_results, diff_file, loc):
    diff_mes = {}
    with open(old_file, 'r') as f:
        vul_content = f.readlines()
    
    with open(diff_file, 'r') as f:
        diff_content = f.readlines()
    
    diff_mes = get_diff_message(diff_content)
    start_line = diff_mes[loc]
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
        if(line[:6] == 'return'):
            result_line = line_tmp.strip() + ' location: ' + str(location)
            print(result_line)
            sink_results.append(result_line)
            return

    