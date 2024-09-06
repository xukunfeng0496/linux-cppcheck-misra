# -*- encoding: utf8 -*-
"""
demo 工具
功能: 检查 xxx 场景下的 xxx 问题
用法: python3 main.py

本地调试步骤:
1. 添加环境变量: export SOURCE_DIR="xxx/src_dir"
2. 添加环境变量: export TASK_REQUEST="xxx/task_request.json"
3. 按需修改task_request.json文件中各字段的内容
4. 命令行cd到项目根目录,执行命令:  python3 src/main.py
"""

import os
import re
import json
import fnmatch
import argparse
import subprocess


class DemoTool(object):
    def __parse_args(self):
        """
        解析命令
        :return:
        """
        argparser = argparse.ArgumentParser()
        subparsers = argparser.add_subparsers(dest='command', help="Commands", required=True)
        # 检查在当前机器环境是否可用
        subparsers.add_parser('check', help="检查在当前机器环境是否可用")
        # 执行代码扫描
        subparsers.add_parser('scan', help="执行代码扫描")
        return argparser.parse_args()

    """demo tool"""
    def __get_task_params(self):
        """
        获取需要任务参数
        :return:
        """
        task_request_file = os.environ.get("TASK_REQUEST")

        with open(task_request_file, 'r') as rf:
            task_request = json.load(rf)

        task_params = task_request["task_params"]

        return task_params

    def __get_dir_files(self, root_dir, want_suffix=""):
        """
        在指定的目录下,递归获取符合后缀名要求的所有文件
        :param root_dir:
        :param want_suffix:
                    str|tuple,文件后缀名.单个直接传,比如 ".py";多个以元组形式,比如 (".h", ".c", ".cpp")
                    默认为空字符串,会匹配所有文件
        :return: list, 文件路径列表
        """
        files = set()
        for dirpath, _, filenames in os.walk(root_dir):
            for f in filenames:
                if f.lower().endswith(want_suffix):
                    fullpath = os.path.join(dirpath, f)
                    files.add(fullpath)
        files = list(files)
        return files

    def __format_str(self, text):
        """
        格式化字符串
        :param text:
        :return:
        """
        text = text.strip()
        if isinstance(text, bytes):
            text = text.decode('utf-8')
        return text.strip('\'\"')

    def __run_cmd(self, cmd_args):
        """
        执行命令行
        """
        print("[run cmd] %s" % ' '.join(cmd_args))
        p = subprocess.Popen(cmd_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (stdoutput, erroutput) = p.communicate()
        stdoutput = self.__format_str(stdoutput)
        erroutput = self.__format_str(erroutput)
        if stdoutput:
            print(">> stdout: %s" % stdoutput)
        if erroutput:
            print(">> stderr: %s" % erroutput)
        return stdoutput, erroutput

    def __convert_to_regex(self, wildcard_paths):
        """
        通配符转换为正则表达式
        :param wildcard_paths:
        :return:
        """
        return [fnmatch.translate(pattern) for pattern in wildcard_paths]

    def __get_path_filters(self, task_params):
        """
        获取过滤路径（工具按需使用），支持用户配置通配符和正则表达式2种格式的过滤路径表达式，该方法会将通配符转换为正则表达式，合并使用
        :param task_params:
        :return: 合并后的正则表达式过滤路径格式
        """
        # 用户输入的原始参数
        wildcard_include_paths = task_params["path_filters"].get("inclusion", [])
        wildcard_exclude_paths = task_params["path_filters"].get("exclusion", [])
        regex_include_paths = task_params["path_filters"].get("re_inclusion", [])
        regex_exlucde_paths = task_params["path_filters"].get("re_exclusion", [])

        print(">> 过滤路径原始配置：")
        print(">> 说明：")
        print(">> include - 只扫描指定文件, exclude - 过滤掉指定文件, 优先级: exclude > include (即：如果A文件同时匹配，会优先exclude，被过滤)")
        print("include（通配符格式）: %s" % wildcard_include_paths)
        print("exclude（通配符格式）: %s" % wildcard_exclude_paths)
        print("include（正则表达式格式）: %s" % regex_include_paths)
        print("exclude（正则表达式格式）: %s" % regex_exlucde_paths)

        # 通配符转换为正则表达式
        if wildcard_include_paths:
            converted_include_paths = self.__convert_to_regex(wildcard_include_paths)
            regex_include_paths.extend(converted_include_paths)
        if wildcard_exclude_paths:
            converted_exclude_paths = self.__convert_to_regex(wildcard_exclude_paths)
            regex_exlucde_paths.extend(converted_exclude_paths)

        print(">> 合并后过滤路径；")
        print("include（正则表达式格式）: %s" % regex_include_paths)
        print("exclude（正则表达式格式）: %s" % regex_exlucde_paths)
        return {
            "re_inclusion": regex_include_paths,
            "re_exclusion": regex_exlucde_paths
        }

    def __detect_injection_symbols(self, cmd_str, symbols=True, raise_exception=True):
        """检测可注入的符号，防止命令行注入
        :param cmd_str: <str> 命令行字符串
        :param symbols: <bool|regexp> 检查命令注入符号，默认为True，检查全部；指定regexp（正则表达式）时，检查传入的指定符号。
                                      全部注入符号正则表达式为 "\n|;|&+|\|+|`|\$\("
        :param raise_exception: <bool> 发现注入符号时，是否抛异常，默认抛异常
        """
        if isinstance(symbols, bool) and symbols is True:
            symbols = "|".join([
                "\n",
                ";",
                "&+",
                "\|+",
                "`",
                "\$\(",
            ])
        if isinstance(symbols, str):
            match_chars = re.findall(symbols, cmd_str)
            if match_chars:
                if raise_exception:
                    raise Exception(f"Find Injection Symbols({match_chars}) in command: {cmd_str}")
                else:
                    print(f"Find Injection Symbols({match_chars}) in command: {cmd_str}")

    def __scan(self):
        """
        扫码代码
        """
        # 代码目录直接从环境变量获取
        source_dir = os.environ.get("SOURCE_DIR", None)
        print("[debug] source_dir: %s" % source_dir)

        # 其他参数从task_request.json文件获取
        task_params = self.__get_task_params()

        # 按需获取环境变量
        print("- * - * - * - * - * - * - * - * - * - * - * - * -* -* -* -* -* -* -")
        envs = task_params["envs"]
        print("[debug] envs: %s" % envs)
        # 前置命令
        pre_cmd = task_params["pre_cmd"]
        print("[debug] pre_cmd: %s" % pre_cmd)
        # 编译命令
        build_cmd = task_params["build_cmd"]
        print("[debug] build_cmd: %s" % build_cmd)
        # 查看path环境变量
        print("[debug] path: %s" % os.environ.get("PATH"))
        # 查看python版本
        print("[debug] 查看python version")
        sp = subprocess.Popen(["python", "--version"])
        sp.wait()
        print("- * - * - * - * - * - * - * - * - * - * - * - * -* -* -* -* -* -* -")
        # 获取过滤路径
        path_filters = self.__get_path_filters(task_params)
        print("- * - * - * - * - * - * - * - * - * - * - * - * -* -* -* -* -* -* -")

        # ------------------------------------------------------------------ #
        # 获取需要扫描的文件列表
        # 此处获取到的文件列表,已经根据项目配置的过滤路径过滤
        # 增量扫描时，从SCAN_FILES获取到的文件列表与从DIFF_FILES获取到的相同
        # ------------------------------------------------------------------ #
        scan_files_env = os.getenv("SCAN_FILES")
        if scan_files_env and os.path.exists(scan_files_env):
            with open(scan_files_env, "r") as rf:
                scan_files = json.load(rf)
                print("[debug] files to scan: %s" % len(scan_files))

        # ------------------------------------------------------------------ #
        # 增量扫描时,可以通过环境变量获取到diff文件列表,只扫描diff文件,减少耗时
        # 此处获取到的diff文件列表,已经根据项目配置的过滤路径过滤
        # ------------------------------------------------------------------ #
        # 从 DIFF_FILES 环境变量中获取增量文件列表存放的文件(全量扫描时没有这个环境变量)
        diff_file_env = os.environ.get("DIFF_FILES")
        if diff_file_env and os.path.exists(diff_file_env):  # 如果存在 DIFF_FILES, 说明是增量扫描, 直接获取增量文件列表
            with open(diff_file_env, "r") as rf:
                diff_files = json.load(rf)
                print("[debug] get diff files: %s" % diff_files)

        # todo: 此处需要自行实现工具逻辑,输出结果,存放到result列表中
        # todo: 如果需要执行命令行（比如subprocess调用），请调用 __detect_injection_symbols 方法检查命令行字符串是否存在注入符号，防止命令行注入漏洞

        # todo: 这里是demo结果，仅供展示，需要替换为实际结果
        demo_path = os.path.join(source_dir, "run.py")
        result = [
            {
                "path": demo_path,
                'line': 5,
                'column': 3,
                'msg': "This is a testcase.",
                'rule': "DemoRule",
                "refs": [
                    {
                        "line": 1,
                        "msg": "first ref msg",
                        "tag": "first_tag",
                        "path": demo_path
                    },
                    {
                        "line": 3,
                        "msg": "second ref msg",
                        "tag": "second_tag",
                        "path": demo_path
                    }
                ]
            }
        ]

        # 输出结果json文件到RESULT_DIR指定的目录下
        result_dir = os.getenv("RESULT_DIR", os.getcwd())
        result_path = os.path.join(result_dir, "result.json")
        with open(result_path, "w") as fp:
            json.dump(result, fp, indent=2)

    def __check_usable(self):
        """
        检查工具在当前机器环境下是否可用
        """
        # 这里只是一个demo，检查python3命令是否可用，请按需修改为实际检查逻辑
        check_cmd_args = ["python3", "--version"]
        try:
            stdout, stderr = self.__run_cmd(check_cmd_args)
        except Exception as err:
            print("tool is not usable: %s" % str(err))
            return False
        return True

    def run(self):
        args = self.__parse_args()
        if args.command == "check":

            print(">> check tool usable ...")
            is_usable = self.__check_usable()
            result_path = "check_result.json"
            if os.path.exists(result_path):
                os.remove(result_path)
            with open(result_path, 'w') as fp:
                data = {"usable": is_usable}
                json.dump(data, fp)
        elif args.command == "scan":
            print(">> start to scan code ...")
            self.__scan()
        else:
            print("[Error] need command(check, scan) ...")


if __name__ == '__main__':
    DemoTool().run()
