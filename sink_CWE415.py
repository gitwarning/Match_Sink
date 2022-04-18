"""
use-after-free类型
sink点的规律：
优先匹配free位置
匹配不到就认为修改的位置是不正确的使用，匹配CV第一次被使用的位置
"""


# 在函数名中匹配会更好一些？
from share_func import has_only_cv


def is_free(line, cv):

    if not has_only_cv(line, cv):  # ar -> gpe . en = g_malloc0 ( len / 2 ); 避免这种情况匹配不到
        return False
    # 如果当前行是函数定义的话不考虑
    if 'static' == line.split(' ')[0].strip():
        return False
    if ('free' in line):
        return True
    elif ('delete' in line):
        return True
    elif 'realloc' in line:
        return True
    elif 'unregister' in line:  # 对于linux
        return True
    elif 'Destroy' in line:  # 对于imagemagick软件的
        return True
    elif 'close' in line:
        return True
    else:
        return False

def is_free_old(line, cv):
    # parameters = line[line.find('('):line.find(')')]
    if cv not in line:
        return False
    if ('free' in line):
        return True
    elif ('delete' in line):
        return True
    elif 'realloc' in line:
        return True
    elif 'unregister' in line:
        return True
    elif 'Destroy' in line:  # 对于imagemagick软件的
        return True
    else:
        return False

# double free类型 对于同一个cv找到两次调用free的位置
def sink_415(line, cv, sink_results, free_sink, sink_cv, sign):
    if sign == 'slices':
        if is_free(line, cv) and free_sink < 3:
            print('sink点是调用free函数：', line)
            sink_results.append(line)
            sink_cv.append(cv)
            free_sink += 1
    else:
        if is_free_old(line, cv) and free_sink < 3:
            print('sink点是调用free函数：', line)
            line = line.strip('\t')
            line = line.strip('\n')
            line = line + ' location: ' + sign
            sink_results.append(line)
            sink_cv.append(cv)
            free_sink += 1
    return free_sink


#  UAF类型 对于一个cv找到一次调用free的位置
def sink_416(line, cv, sink_results, free_sink, sink_cv):
    if is_free(line, cv) and free_sink < 3:
        print('sink点是调用free函数：', line)
        sink_results.append(line)
        sink_cv.append(cv)
        free_sink += 1
    return free_sink


def sink_415_goto(diff_file, old_file, sink_cv, sink_results, cv_list, loc):
    with open(old_file, 'r') as f:
        vul_content = f.readlines()

    with open(diff_file, 'r') as f:
        diff_content = f.readlines()
    # 寻找删除的goto语句获取到goto跳转的地方
    goto_line = ''
    goto_state = ''
    for line in diff_content:
        if line[0] == '-' and 'goto' in line:
            goto_line = line
            goto_state = line.split('goto')[-1].strip()
            goto_state = goto_state.replace(';', '')
    goto_list = []
    #在old文件找到漏洞函数，并且找到goto语句跳转的目的地
    start = int(loc)
    flag = 0
    location = 0
    for i,  line in enumerate(vul_content[start:]):
        if (goto_state + ':') in line:
            print('找到goto语句块')
            flag = 1
            location = i + start + 1
        if flag == 1:
            if line[0] == '\t':
                goto_list.append(line)
            elif (goto_state + ':') not in line and line[0] != '\t':
                break
    if goto_list:
        for cv in cv_list[0]:
            free_sink = 0
            for line in goto_list:
                location += 1
                sink_415(line, cv, sink_results, free_sink, sink_cv, str(location))
    return sink_cv, sink_results
