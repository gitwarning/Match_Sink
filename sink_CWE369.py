"""
对于CWE-369除以0类型进行sink点匹配
大致有两种类型：
1.关于除法的运算且cv是除数（在运算符/%右边）
2.关于除法的函数
"""
from share_func import has_only_cv


def is_divisin(line, cv):
    if ('/ ' + cv) in line:
        return True
    elif ('% ' + cv) in line:
        return True
    else:
        return False


def is_divisin_func(line, cv):
    if not has_only_cv(line, cv):
        return False
    # 如果当前行是函数定义的话不考虑
    if 'static' == line.split(' ')[0].strip():
        return False
    if ('alloc' in line):
        return True
    elif ('mod' in line):
        return True
    # elif 'realloc' in line:
    #     return True
    # elif 'unregister' in line:  # 对于linux
    #     return True
    # elif 'Destroy' in line:  # 对于imagemagick软件的
    #     return True
    else:
        return False


def sink_369(line, cv, sink_results, division_sink, division_func_sink, sink_cv):
    if is_divisin(line, cv) and division_sink:
        print('sink点是有关除法的运算：', line)
        sink_results.append(line)
        sink_cv.append(cv)
        division_sink = False

    if is_divisin_func(line, cv):
        print('sink点是有关除法的函数调用：', line)
        sink_results.append(line)
        sink_cv.append(cv)
        division_func_sink = False
    return division_sink, division_func_sink
