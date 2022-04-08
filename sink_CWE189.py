from share_func import *


def sink_189(line, cv, sink_results, array_sink, sink_cv, pointer_sink, risk_func_sink, calculation_sink,point_var):
    if is_array(line, cv) and array_sink:
        print('sink点是数组访问越界：', line)
        sink_results.append(line)
        sink_cv.append(cv)
        array_sink = False
    if is_pointer(line, cv, point_var) and pointer_sink:
        print('sink点是指针访问越界：', line)
        sink_results.append(line)
        sink_cv.append(cv)
        pointer_sink = False
    if is_risk_func(line, cv) and risk_func_sink:
        print('sink点是风险函数使用：', line)
        sink_results.append(line)
        sink_cv.append(cv)
        risk_func_sink = False
    if is_calculation(line, cv) and calculation_sink:
        print('sink点是整数运算导致的整数溢出类型：', line)
        sink_results.append(line)
        sink_cv.append(cv)
        calculation_sink = False