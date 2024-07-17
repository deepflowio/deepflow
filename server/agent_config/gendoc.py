import yaml
import sys
import re
import traceback

i18n = {
    'Tags': {
        'en': 'Tags',
        'ch': '标签',
    },
    'FQCN': 'FQCN',
    'Default value': {
        'en': 'Default value',
        'ch': '默认值',
    },
    'Enum options': {
        'en': 'Enum options',
        'ch': '枚举可选值',
    },
    'Schema': {
        'en': 'Schema',
        'ch': '模式',
    },
    'Description': {
        'en': 'Description',
        'ch': '详细描述',
    },
}

comments = {}


def count_leading_space(s):
    count = 0
    for c in s:
        if c == ' ':
            count += 1
        else:
            break
    return count


def get_yaml_value(yaml_dict, key_segments, dict_kv_in_list=None):
    if len(key_segments) == 1:
        if dict_kv_in_list:
            return {key_segments[0]: [dict_kv_in_list]}
        else:
            return {key_segments[0]: yaml_dict.get(key_segments[0])}
    else:
        return {
            key_segments[0]:
            get_yaml_value(yaml_dict.get(key_segments[0]), key_segments[1:],
                           dict_kv_in_list)
        }


def get_string_by_lang(item, lang):
    if not isinstance(item, dict):
        return item

    return item.get(lang, item.get('en'))


def generate_doc_for_yaml_item(key, yaml_value, parsed_comment, lang, wf):
    heading_level = '#' * (key.count('.') + 1)
    item_type = parsed_comment.get('type')
    name = get_string_by_lang(parsed_comment.get('name', '[FIXME]'), lang)
    desc = get_string_by_lang(parsed_comment.get('description', ''), lang)
    print(f"{heading_level} {name} " + "{#" + key + "}\n",
          file=wf)  # use custom-heading-id
    if item_type == 'section':
        if desc:
            print(f"{desc}\n", file=wf)
    else:
        # Tags
        modification = parsed_comment.get('modification', '')
        tag_i18n = get_string_by_lang(i18n.get('Tags'), lang)
        print(f"**{tag_i18n}**:\n", file=wf)
        if modification != 'hot_update':
            print(f"<mark>{modification}</mark>", file=wf)
        else:
            print(f"`{modification}`", file=wf)
        ee_feature = parsed_comment.get('ee_feature', False)
        if ee_feature:
            print(f"<mark>ee_feature</mark>", file=wf)
        deprecated = parsed_comment.get('deprecated', False)
        if deprecated:
            print(f"<mark>deprecated</mark>", file=wf)
        print("", file=wf)
        # FQCN
        upgrade_from = parsed_comment.get('upgrade_from', [])
        fqcn_i18n = get_string_by_lang(i18n.get('FQCN'), lang)
        print(f"**{fqcn_i18n}**:\n", file=wf)
        print(f"`{key}`\n", file=wf)
        if upgrade_from:
            print(f"Upgrade from old version: `{upgrade_from}`\n", file=wf)
        # Default value
        config_example = yaml.dump(yaml_value, default_flow_style=False)
        default_value_i18n = get_string_by_lang(i18n.get('Default value'),
                                                lang)
        print(f"**{default_value_i18n}**:", file=wf)
        print("```yaml", file=wf)
        print(f"{config_example}```\n", file=wf)
        # Enum options
        enum_options = parsed_comment.get('enum_options')
        if enum_options:
            enum_options_i18n = get_string_by_lang(i18n.get('Enum options'),
                                                   lang)
            print(f"**{enum_options_i18n}**:", file=wf)
            print("| Value | Note                         |", file=wf)
            print("| ----- | ---------------------------- |", file=wf)
            for eo in enum_options:
                if isinstance(eo, dict):
                    eok = list(eo.keys())[0]
                    eov = get_string_by_lang(eo.get(eok), lang)
                    print(f"| {eok} | {eov} |", file=wf)
                else:
                    print(f"| {eo} | |", file=wf)
            print("", file=wf)
        # Schema
        unit = parsed_comment.get('unit', '')
        value_range = parsed_comment.get('range', [])
        schema_i18n = get_string_by_lang(i18n.get('Schema'), lang)
        print(f"**{schema_i18n}**:", file=wf)
        print("| Key  | Value                        |", file=wf)
        print("| ---- | ---------------------------- |", file=wf)
        print(f"| Type | {item_type} |", file=wf)
        if unit:
            print(f"| Unit | {unit} |", file=wf)
        if value_range:
            print(f"| Range | {value_range} |", file=wf)
        print("", file=wf)
        # Description
        if desc:
            description_i18n = get_string_by_lang(i18n.get('Description'),
                                                  lang)
            print(f"**{description_i18n}**:\n", file=wf)
            print(f"{desc}\n", file=wf)


def load_comment_as_yaml(key, comment):
    try:
        parsed_comment = list(yaml.load_all(comment))
    except yaml.YAMLError as e:
        print(f"ERROR: parsing YAML comment at {key}: {e}", file=sys.stderr)
        print("----------", file=sys.stderr)
        print(f"{comment}", file=sys.stderr)
        print("----------", file=sys.stderr)
        print(traceback.format_exc(), file=sys.stderr)
    return parsed_comment


# Generate doc
def generate_doc(yaml_data, lang):
    if lang == 'en':
        wf = open("README.md", 'w')
    else:
        lang_upper = lang.upper()
        wf = open(f"README-{lang_upper}.md", 'w')

    for key, comment in comments.items():
        segments = key.split('.')

        parsed_comment = load_comment_as_yaml(key, comment)

        if not parsed_comment:
            parent_key = '.'.join(segments[:-1])
            parent_comment = comments.get(parent_key, '')
            parent_parsed_comment = load_comment_as_yaml(
                parent_key, parent_comment)
            if parent_parsed_comment:
                parent_type = parent_parsed_comment[0].get('type', '')
                if parent_type in ['section']:
                    print(
                        f"ERROR: yaml item {key} has no comment, parent type {parent_type}",
                        file=sys.stderr)
            continue

        if not parsed_comment[0].get('type'):
            print(f"ERROR: yaml comment has no `type` attribute, {key}",
                  file=sys.stderr)
            continue

        yaml_value = get_yaml_value(yaml_data, segments)
        generate_doc_for_yaml_item(
            key, yaml_value, parsed_comment[0], lang, wf)

        for i in range(len(parsed_comment))[1::2]:  # list[dict]
            if not parsed_comment[i].get('type'):
                print(f"ERROR: yaml comment has no `type` attribute, {key}",
                      file=sys.stderr)
                continue
            yaml_value = get_yaml_value(yaml_data, segments,
                                        parsed_comment[i + 1])
            generate_doc_for_yaml_item(
                key + '.' + list(parsed_comment[i + 1].keys())[0], yaml_value,
                parsed_comment[i], lang, wf)


def read_from_file():
    # Read YAML from file
    yaml_file = 'template.yaml'
    with open(yaml_file, 'r', encoding='utf-8') as file:
        yaml_content = file.read()

    # Match comments and yaml items
    comment_pattern = re.compile(r'^\s*#( ?)(.*)$')
    key_value_pattern = re.compile(r'^\s*([^#:\s]+)\s*:\s*(.*)$', re.MULTILINE)

    # Extract comments
    lines = yaml_content.split('\n')
    current_keys = []
    current_comment = []

    for line in lines:
        comment_match = comment_pattern.match(line)
        key_value_match = key_value_pattern.match(line)

        if comment_match:
            current_comment.append(comment_match.group(2))
        elif key_value_match:
            current_keys = current_keys[:count_leading_space(line) // 2]
            current_keys.append(key_value_match.group(1))
            comments['.'.join(current_keys)] = '\n'.join(current_comment)
            current_comment = []
        else:
            current_comment = []
            continue

    # Load Yaml items
    return yaml.safe_load(yaml_content)


# main process
yaml_data = read_from_file()
for lang in ['en', 'ch']:
    generate_doc(yaml_data, lang)
