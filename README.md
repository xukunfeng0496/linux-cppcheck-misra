# Demo 工具示例

## 开发指引
1. 修改`src/main.py`，按需实现工具逻辑。
2. 如果工具逻辑中需要执行命令行，请检查命令行字符串是否存在注入符号，防止命令行注入漏洞（参考`src/main.py`中的`__detect_injection_symbols`方法）
3. `tool.json`文件里声明了2个字段，`check_cmd`和`run_cmd`，对应`src/main.py`中需要实现的2个执行命令。
   - `check_cmd`：
     - 功能：判断当前执行环境是否满足工具要求。
       >比如某些工具只能在linux下执行，需要判断当前是否为linux环境。
     - 输出：将判断结果输出到`check_result.json`文件中，文件内容为`{"usable": true}`或`{"usable": false}`。
   - `run_cmd`：
     - 功能：扫描代码，执行自定义检查器逻辑。
     - 输出：按照指定格式，输出结果到`RESULT_DIR`环境变量指定的目录下的`result.json`文件中，文件格式：
         ```
         [
             {
                 "path": "文件绝对路径",
                 "line": "行号，int类型",
                 "column": "列号, int类型，如果工具没有输出列号信息，可以用0代替",
                 "msg": "提示信息",
                 "rule": "规则名称,可以根据需要输出不同的规则名",
                 "refs": [
                     {
                         "line": "回溯行号", 
                         "msg": "提示信息", 
                         "tag": "用一个词简要标记该行信息，比如uninit_member,member_decl等，如果没有也可以都写成一样的", 
                         "path": "回溯行所在文件绝对路径"
                     },
                     ...
                 ]
             },
             ...
         ]
         ```
   
         > 说明：
         `refs`：可选，记录问题回溯路径信息。比如当前文件的回溯路径其他的3行代码，可以将这三行的路径及提示信息，按顺序添加到refs数组中。

## 本地调试步骤

1. 修改`test.sh`中的`SOURCE_DIR`环境变量为需要扫描的代码目录。
2. 修改`test.sh`中的`RESULT_DIR`环境变量，指定某个本地目录为结果保存目录。
3. 按需修改`task_request.json`文件中`task_params`字段的内容，将工具代码中用到的字段替换为实际值。
4. 命令行`cd`到项目根目录,执行`test.sh`脚本：`bash test.sh`。
