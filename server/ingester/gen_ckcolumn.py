import os
import re

def extract_variables(directory, output_file):
    # 正则表达式匹配 ckdb.COLUMN_xxx 格式
    pattern = re.compile(r"ckdb\.(COLUMN_[A-Z0-9_]+)")
    
    # 用于存储变量名的集合，自动去重
    variables = set()

    # 遍历目录和子目录
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    matches = pattern.findall(content)
                    variables.update(matches)
            except (UnicodeDecodeError, OSError):
                # 跳过无法读取的文件
                print(f"Skipping file: {file_path}")

    # 按字母排序
    sorted_variables = sorted(variables)

    # 生成 const 块
    const_block = "const (\n"
    for var in sorted_variables:
        value = var[len("COLUMN_"):].lower()  # 转换为小写，去掉 "COLUMN_" 前缀
        const_block += f"    {var} = \"{value}\"\n"
    const_block += ")\n"

    # 写入到文件
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(const_block)
        print(f"Constants written to {output_file}")
    except OSError as e:
        print(f"Failed to write to {output_file}: {e}")

if __name__ == "__main__":
    # 输入目录和输出文件路径
    input_directory = input("Enter the directory path to scan: ").strip()
    output_file_path = input("Enter the output file path: ").strip()

    extract_variables(input_directory, output_file_path)

