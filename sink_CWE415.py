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
    if ('free' in line):
        return True
    elif ('delete' in line):
        return True
    else:
        return False


# double free类型 对于同一个cv找到两次调用free的位置
def sink_415(line, cv, sink_results, free_sink, sink_cv):
    if is_free(line, cv) and free_sink < 3:
        print('sink点是调用free函数：', line)
        sink_results.append(line)
        sink_cv.append(cv)
        free_sink += 1
    return free_sink


#  UAF类型 对于一个cv找到一次调用free的位置
def sink_416(line, cv, sink_results, free_sink, sink_cv):
    if is_free(line, cv) and free_sink < 2:
        print('sink点是调用free函数：', line)
        sink_results.append(line)
        sink_cv.append(cv)
        free_sink += 1
    return free_sink
