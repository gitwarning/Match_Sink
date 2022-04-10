def is_assert(line, cv):
    if (' ' + cv + ' ' not in line):
        return False

    if ('assert' in line):
        return True
    elif ('BUG' in line):
        return True
    elif ('OVS_NOT_REACHED' in line):
        return True
    elif ('validate_as_request' in line):
        return True


def sink_617(line, cv, sink_results, assert_sink, sink_cv):
    if is_assert(line, cv) and assert_sink:
        print('sink点是调用断言函数：', line)
        sink_results.append(line)
        sink_cv.append(cv)
        assert_sink = False
    return assert_sink