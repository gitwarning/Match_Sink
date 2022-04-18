from share_func import *
from sink_CWE772 import get_diff_message


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


def sink_835(old_file, func_define, sink_results, diff_file, loc):
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
            already_num = int(loc) - (int(start_line) + medium_tmp + 1)
            print(already_num, loc, start_line, medium_tmp)
            num_fin += already_num
            break
                
    print(loc, num_fin)
    start_line = int(loc) - num_fin

    print('将会从 ' + str(start_line) + '向上找sink点') # 寻找循环头所在的地方，这一行可能就是循环头

    res_line, loc = get_sink_line(vul_content, func_define, start_line)
    print(type(res_line))
    print(type(loc))
    new_line = res_line + ' location: ' + str(loc)
    print(new_line)
    sink_results.append(new_line)