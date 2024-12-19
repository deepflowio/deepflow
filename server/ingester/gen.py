import re
import sys

def camel_case(snake_str):
    """Convert snake_case to CamelCase"""
    components = snake_str.split('_')
    return ''.join(x.capitalize() for x in components)

def parse_columns(lines):
    """Parse columns from input file"""
    column_pattern = re.compile(r'ckdb\.NewColumn\("([^"]+)",\s*(ckdb\.\w+)')
    columns = []
    for line in lines:
        match = column_pattern.search(line)
        if match:
            name, col_type = match.groups()
            columns.append((name, col_type))
    return columns

def generate_code(name, columns):
    """Generate block code for the given structure"""
    struct_name = camel_case(name) + "Block"
    variable_prefix = camel_case(name)
    reset_lines = []
    append_lines = []
    input_lines = []
    struct_fields = []

    for col_name, col_type in columns:
        camel_col_name = camel_case(col_name)
        field_name = f"Col{camel_col_name}"
        proto_type = col_type.replace("ckdb.", "proto.Col")
        struct_fields.append(f"    {field_name}    {proto_type}")
        reset_lines.append(f"    b.{field_name}.Reset()")
        append_lines.append(f"    block.{field_name}.Append(n.{camel_col_name})")
        input_lines.append(f'        proto.InputColumn{{Name: ckdb.COLUMN_{col_name.upper()}, Data: &b.{field_name}}},')

    block_code = f"""
type {struct_name} struct {{
{chr(10).join(struct_fields)}
}}

func (b *{struct_name}) Reset() {{
{chr(10).join(reset_lines)}
}}

func (b *{struct_name}) ToInput(input proto.Input) proto.Input {{
    return append(input,
{chr(10).join(input_lines)}
    )
}}

func (n *{variable_prefix}) NewColumnBlock() ckdb.CKColumnBlock {{
    return &{struct_name}{{}}
}}

func (n *{variable_prefix}) AppendToColumnBlock(b ckdb.CKColumnBlock) {{
    block := b.(*{struct_name})
{chr(10).join(append_lines)}
}}
"""
    return block_code

def main(input_file, output_file):
    """Main function to parse input and generate output"""
    with open(input_file, 'r') as infile:
        lines = infile.readlines()

    output = []
    block_start_pattern = re.compile(r'func\s+(\w+)Columns\s*\(\)\s*\[\]\*ckdb\.Column')
    block_end_pattern = re.compile(r'\}')
    in_block = False
    block_name = None
    columns = []

    for line in lines:
        if not in_block:
            match = block_start_pattern.search(line)
            if match:
                in_block = True
                block_name = match.group(1)
                columns = []
        else:
            if block_end_pattern.search(line):
                in_block = False
                output.append(generate_code(block_name, columns))
            else:
                columns.extend(parse_columns([line]))

    with open(output_file, 'w') as outfile:
        outfile.write("\n".join(output))

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python generate_blocks.py <input_file> <output_file>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])

