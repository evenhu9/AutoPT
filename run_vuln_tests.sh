#!/bin/bash

# 多线程漏洞测试启动脚本
# 用法: ./run_vuln_tests.sh <target> [threads] [timeout]

TARGET="$1"
THREADS="${2:-5}"  # 默认5个线程
TIMEOUT="${3:-30}" # 默认30秒超时
OUTPUT="vulnerability_results_$(date +%Y%m%d_%H%M%S).json"

if [ -z "$TARGET" ]; then
    echo "用法: $0 <目标地址> [线程数] [超时时间]"
    echo "示例:"
    echo "  $0 127.0.0.1:8080"
    echo "  $0 192.168.1.100:8848 10 60"
    exit 1
fi

echo "=== 开始漏洞测试 ==="
echo "目标: $TARGET"
echo "线程数: $THREADS"
echo "超时时间: ${TIMEOUT}秒"
echo "输出文件: $OUTPUT"
echo

# 检查Python是否可用
if ! command -v python3 &> /dev/null; then
    echo "错误: 未找到 python3，请先安装Python"
    exit 1
fi

# 检查测试用例文件是否存在
if [ ! -f "test_cases.txt" ]; then
    echo "警告: 未找到 test_cases.txt，使用默认测试用例"
    TEST_CASES=""
else
    echo "使用 test_cases.txt 中的测试用例"
    TEST_CASES="-f test_cases.txt"
fi

# 执行测试
python3 vulnerability_tester.py \
    -t "$TARGET" \
    $TEST_CASES \
    -w "$THREADS" \
    --timeout "$TIMEOUT" \
    -o "$OUTPUT"

# 检查执行结果
if [ $? -eq 0 ]; then
    echo
    echo "=== 测试完成 ==="
    echo "结果已保存到: $OUTPUT"
    echo "可以使用以下命令查看结果:"
    echo "  cat $OUTPUT | python -m json.tool"
    echo "  jq '.' $OUTPUT"
else
    echo
    echo "=== 测试执行出错 ==="
    exit 1
fi