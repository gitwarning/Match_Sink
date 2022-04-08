
# 在函数名中匹配会更好一些？
def is_free(line, cv):
    if (' ' + cv + ' ' not in line):
        return False

    if ('free' in line):
        return True
    elif ('delete' in line):
        return True
    elif ('krealloc' in line):
        return True


# double free类型 对于同一个cv找到两次调用free的位置
def sink_415(line, cv, sink_results, free_sink, sink_cv):
    if is_free(line, cv) and free_sink < 3:
        print('sink点是调用free函数：', line)
        sink_results.append(line)
        sink_cv.append(cv)
        free_sink += 1
