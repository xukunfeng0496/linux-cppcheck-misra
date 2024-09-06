# -*- encoding: utf-8 -*-
# Copyright (c) 2021-2024 THL A29 Limited
#
# This source code file is made available under MIT License
# See LICENSE for details
# ==============================================================================

"""
cppcheck 分析任务
"""

import json
import os
import re

import os
import re
import json
import fnmatch
import argparse
import subprocess


import psutil
from task.codelintmodel import CodeLintModel
from task.scmmgr import SCMMgr
from util.envset import EnvSet
from util.exceptions import AnalyzeTaskError, ConfigError
from util.logutil import LogPrinter
from util.pathfilter import FilterPathUtil
from util.pathlib import PathMgr
from util.subprocc import SubProcController

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET


class CppcheckMisra():
    def __init__(self ):
        pass

    def _run_misra_addon_analyze(self, source_dir, files_path):
        """cppcheck执行misra规则检查
        """
        # rules = params["rules"]
        work_dir = params.work_dir
        misra_rule_prefix = "misra-c2012-"
        CPPCHECK_HOME = os.environ["CPPCHECK_HOME"]
        find_all_rule_version_regex = r'Rule ([\.\d]+) [R|M|A]'
        misra_rule_file = os.path.join(
            CPPCHECK_HOME, "addons", "config", "misra_rules.txt")

        # # 获取需要检查的misra规则
        # misra_rules = [
        #     rule for rule in rules if rule.startswith(misra_rule_prefix)]
        # LogPrinter.info(f"[misra_rules]: {misra_rules}")
        # if not misra_rules:
        #     return []

        # 其余的规则留给cppcheck进行检查
        # other_cppcheck_rules = list(set(rules) - set(misra_rules))
        # params["rules"] = other_cppcheck_rules

        # all_rule_versions_set 所有的规则版本号
        all_rule_versions_set = set(re.findall(
            find_all_rule_version_regex, open(misra_rule_file, "r").read()))
        LogPrinter.info(
            f"[misra_rules_all_rule_versions_set]: {all_rule_versions_set}")

        # disable_rule_version_set 需要关闭的规则版本号
        disable_rule_version_set = all_rule_versions_set - \
            set([rule[len(misra_rule_prefix):] for rule in rules])
        LogPrinter.info(
            f"[misra_rules_disable_rule_version_set]: {disable_rule_version_set}")
            
        # 构造misra分析所需的配置文件
        misra_config = {
            "script": os.path.join(CPPCHECK_HOME, "addons", "misra.py"),
            "args": [
                f"--rule-text={misra_rule_file}"
            ]
        }
        disable_rule_version_str = ','.join(list(disable_rule_version_set))
        if disable_rule_version_str:
            # 兼容全部规则启用的情况 ，不再需要 suppress-rules 参数
            misra_config["args"].append(
                f"--suppress-rules {disable_rule_version_str}")
        LogPrinter.info(f"[misra_config] {misra_config}")

        # 将配置写入到 misra.json 文件中，然后使用cppcheck --addon=<json file path> 指定配置
        misra_file = os.path.join(work_dir, "misra.json")
        with open(misra_file, "w") as f:
            f.write(json.dumps(misra_config))

        # 执行cppcheck misra 分析检查命令
        cmd_args = [
            "cppcheck",
            f"--addon={misra_file}",
            "--addon-python=python3",
            '--template="{file}[CODEDOG]{line}[CODEDOG]{id}[CODEDOG]{severity}[CODEDOG]{message}"',
            '--inconclusive',
            '--file-list=%s' % files_path
        ]
        LogPrinter.info(f"[misra_cmd_args]: {cmd_args}")
        scan_misra_result_path = "cppcheck_addon_misra_result.xml"
        return_code = SubProcController(
            cmd_args,
            cwd=CPPCHECK_HOME,
            stderr_filepath=scan_misra_result_path,
            stderr_line_callback=self._error_callback,
            stdout_line_callback=self.print_log,
        ).wait()
        LogPrinter.info(f"[misra_cmd run return code: {return_code}")

        # 如果没有结果文件的写入，直接返回空列表
        if not os.path.exists(scan_misra_result_path):
            LogPrinter.info("scan_misra_result is empty ")
            return []

        # 将列表中的结果格式化标准输出
        result_list = self._format_result(
            source_dir, scan_misra_result_path, misra_rules,
            [misra_rule_prefix +
                rule_version for rule_version in list(all_rule_versions_set)]
        )
        return result_list

    def analyze(self):
        """执行cppcheck分析任务
        :return: return a :py:class:`IssueResponse`
        """
        source_dir = os.environ.get("SOURCE_DIR", None)
        scan_files_env = os.getenv("SCAN_FILES")
        toscans = []
        if scan_files_env and os.path.exists(scan_files_env):
            with open(scan_files_env, "r") as rf:
                toscans = json.load(rf)
                print("[debug] files to scan: %s" % len(toscans))


        work_dir = os.getenv("RESULT_DIR", os.getcwd())
        files_path = os.path.join(work_dir, "paths.txt")

        with open(files_path, "w", encoding="UTF-8") as f:
            f.write("\n".join(scan_files))

        # 执行cppcheck misra规则分析检查
        addon_misra_result_list = self._run_misra_addon_analyze(
            source_dir, params, files_path)

        # 获取剩余的rules给cppcheck使用
        rules = params["rules"]

        id_severity_map = self._get_id_severity_map()  # 获取当前版本cppcheck的 规则名:严重级别 对应关系
        supported_rules = id_severity_map.keys()  # 获取当前版本cppcheck支持的所有规则名
        # 过滤掉当前版本cppcheck不支持的规则
        filtered_rules = [r for r in rules if r not in supported_rules]
        rules = list(set(rules) - set(filtered_rules))

        # 执行 cppcheck 工具
        scan_result_path = self._run_cppcheck(files_path, rules, id_severity_map)

        if not os.path.exists(scan_result_path):
            LogPrinter.info("result is empty ")
            cppcheck_result_list = []
        else:
            # 格式化cppcheck结果
            cppcheck_result_list = self._format_result(source_dir, scan_result_path, rules, supported_rules)

        # cppcheck + misra结果一起返回
        result_list = cppcheck_result_list + addon_misra_result_list
        return result_list

    def _get_id_severity_map(self):
        """获取cppcheck所有规则和严重级别的对应关系

        :return:
        """
        cmd_args = ["cppcheck", "--errorlist", "--xml-version=2"]
        errorlist_path = "cppcheck_errorlist.xml"
        return_code = SubProcController(
            cmd_args,
            cwd=os.environ["CPPCHECK_HOME"],
            stdout_filepath=errorlist_path,
            stderr_line_callback=self.print_log,
            env=EnvSet().get_origin_env(),
        ).wait()
        if return_code != 0:
            raise ConfigError("当前机器环境可能不支持cppcheck执行，请查阅任务日志，根据实际情况适配。")
        with open(errorlist_path, "r") as rf:
            errorlist = rf.read()

        error_root = ET.fromstring(errorlist).find("errors")
        id_severity_map = {error.get("id"): error.get("severity") for error in error_root}
        return id_severity_map

    def _get_needed_visitors(self, id_severity_map, rule_list):
        """cppcheck不能指定规则分析，只能指定规则级别，这里通过rules获取所属的规则级别"""
        assert rule_list is not None
        # cppcheck默认就是开启error规则（且无法指定enable=error),所以这里取补集
        return {id_severity_map[rule_name] for rule_name in rule_list} - {"error"}

    def _run_cppcheck(self, files_path, rules, id_severity_map):
        """
        执行cppcheck分析工具
        :param files_path:
        :param rules:
        :param id_severity_map:
        :return:
        """
        CPPCHECK_HOME = os.environ["CPPCHECK_HOME"]
        LogPrinter.info("使用 cppcheck 为 %s" % CPPCHECK_HOME)
        path_mgr = PathMgr()
        cmd_args = [
            "cppcheck",
            "--quiet",
            '--template="{file}[CODEDOG]{line}[CODEDOG]{id}[CODEDOG]{severity}[CODEDOG]{message}"',
            "--inconclusive",
        ]
        # LogPrinter.info(f'rules after filtering: {rules}')
        if not rules:
            # cmd_args.append('--enable=all')
            cmd_args.append("--enable=warning,style,information")
            cmd_args.append("-j %s" % str(psutil.cpu_count()))
        else:
            visitors = self._get_needed_visitors(id_severity_map, rules)
            if visitors:
                cmd_args.append("--enable=%s" % ",".join(visitors))
            # rules里出现unusedFunction 才不会开启并行检查
            if "unusedFunction" not in rules:
                cmd_args.append("-j %s" % psutil.cpu_count())

        # 添加自定义正则表达式规则--rule-file
        custom_rules = path_mgr.get_dir_files(os.path.join(CPPCHECK_HOME, "custom_plugins"), ".xml")
        custom_rules = ["--rule-file=" + rule for rule in custom_rules]
        cmd_args.extend(custom_rules)
        # 添加代码补丁配置cfg --library
        custom_cfgs = path_mgr.get_dir_files(os.path.join(CPPCHECK_HOME, "custom_cfg"), ".cfg")
        custom_cfgs = ["--library=" + cfg for cfg in custom_cfgs]
        cmd_args.extend(custom_cfgs)

        # 指定分析文件
        cmd_args.append("--file-list=%s" % files_path)
        scan_result_path = "cppcheck_result.xml"
        self.print_log(f"cmd: {' '.join(cmd_args)}")
        cmd_args = path_mgr.format_cmd_arg_list(cmd_args)
        SubProcController(
            cmd_args,
            cwd=CPPCHECK_HOME,
            stderr_filepath=scan_result_path,
            stderr_line_callback=self._error_callback,
            stdout_line_callback=self.print_log,
        ).wait()

        return scan_result_path

    def _error_callback(self, line):
        """

        :param line:
        :return:
        """
        if line.find("The command line is too long") != -1:
            raise AnalyzeTaskError("执行命令行过长")
        # self.print_log(line)

    def _format_result(self, source_dir, scan_result_path, rules, supported_rules):
        """格式化工具执行结果"""
        issues = []
        relpos = len(source_dir) + 1
        with open(scan_result_path, "rb") as rf:
            lines = rf.readlines()
            for line in lines:
                try:
                    line = line.decode("utf-8")
                except:
                    line = line.decode("gbk")
                error = line.split("[CODEDOG]")
                if len(error) != 5:
                    LogPrinter.info("该error信息不全或格式有误: %s" % line)
                    continue
                if "" in error:
                    LogPrinter.info("忽略error: %s" % line)
                    continue
                rule = error[2]
                if rule not in supported_rules:  # 没有指定规则时，过滤不在当前版本cppcheck支持的规则中的结果
                    LogPrinter.debug("rule not in supported_rules: %s" % rule)
                    continue
                if rule in ["missingInclude", "MissingIncludeSystem"]:
                    LogPrinter.info("unsupported rule:%s" % rule)
                    continue
                if rule not in rules:
                    continue
                # 格式为{file}[CODEDOG]{line}[CODEDOG]{id}[CODEDOG]{severity}[CODEDOG]{message}
                issue = {}
                issue["path"] = error[0][relpos:]
                issue["line"] = int(error[1])
                issue["column"] = "1"
                issue["msg"] = error[4]
                issue["rule"] = rule
                issues.append(issue)
        return issues

    def check_tool_usable(self ):
        """
        这里判断机器是否支持运行cppcheck
        1. 支持的话，便在客户机器上分析
        2. 不支持的话，就发布任务到公线机器分析
        :return:
        """
        check_cmd_args = ["cppcheck", "--version"]
        try:
            stdout, stderr = self.__run_cmd(check_cmd_args)
        except Exception as err:
            print("tool is not usable: %s" % str(err))
            return False
        return True
    
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
        sp = subprocess.Popen(["python3", "--version"])
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

        self.analyze()
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
    def run(self):
        args = self.__parse_args()
        if args.command == "check":

            print(">> check tool usable ...")
            is_usable = self.check_tool_usable()
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





if __name__ == "__main__":
    CppcheckMisra().run()
