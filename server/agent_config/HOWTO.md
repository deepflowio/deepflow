# Howto Write template.yaml

## Naming Convention

We use underscore instead of hyphen.

[Reddit: Underscores or hyphens for file naming convention?](https://www.reddit.com/r/datacurator/comments/r6lew9/underscores_or_hyphens_for_file_naming_convention/)

## Item Type

Supported item types:
- section
- non-section
  - int
  - string
  - bool
  - duration
  - ip
  - dict

Hint: You can set the configuration item of type `ip` to an IP address or a domain name.

## Item Default Value

If the type of the item value is a list, you must be careful when setting its default value, for example:
```yaml
items: []
```

Otherwise, you also need to explicitly set its default value; it cannot be left blank. For example:
```yaml
int_item: 0

string_item: ""

bool_item: false

duration_item: 0

ip_item: ""

dict_item:
  int_key: 0
  string_key: ""
```

## Item Comment

Every yaml item **MUST** hava a **head comment**, and the comment **MUST** writen in yaml syntax.

### Section Type

Section item must hava a head comment with 3 yaml items. Example:
```yaml
# type: section
# name: Item
# description:
item:
```

### Dict Type

How to describe a list of dict field (`items`) containing two sub-keys (`key1`, `key2`):
```yaml
# type: dict
# name: Item
# unit:
# range: []
# enum_options: []
# modification: hot_update
# ee_feature: false
# description:
#   en: |>
#     Example:
#     ```yaml
#     items:
#       - key1: 0
#         key2: []
#     ```
# ---
# type: int
# name: Key1
# unit:
# range: []
# enum_options: []
# modification: hot_update
# ee_feature: false
# description:
# ---
# key1: 0
# ---
# type: string
# name: Key2
# unit:
# range: [value1, value2]
# enum_options: []
# modification: hot_update
# ee_feature: false
# description:
# ---
# key2: []
items: []
```
As you can see, using the YAML multi-document mechanism, we can describe the schema of each dict in the list and the default values of the sub-keys in each dict within a single comment. When the number of sub-keys is `n`, we need to construct `1 dict_schema + (1 sub_key_schema + 1 sub_key_default) * n` YAML documents in the comment.


How to describe a nested dict field `item` where its sub-keys (`sub-key1`, `sub-key2`, ...) have identical structures, and each sub-key's structure includes two sub-sub-keys (`sub-sub-key1`, `sub-sub-key2`).
```yaml
# type: dict
# name: Item
# unit:
# range: []
# enum_options: []
# modification: hot_update
# ee_feature: false
# description:
item:
  # type: dict
  # name: $SubKey XXX
  # unit:
  # range: []
  # enum_options: []
  # modification: hot_update
  # ee_feature: false
  # description:
  #   en: |>
  #     Example:
  #     ```yaml
  #     item:
  #       sub_key_1:
  #         - sub_sub_key_1: v1
  #           sub_sub_key_2: v2
  #         - sub_sub_key_1: v3
  #           sub_sub_key_2: v4
  #       sub_key_2:
  #         - sub_sub_key_1: v5
  #           sub_sub_key_2: v6
  #         - sub_sub_key_1: v7
  #           sub_sub_key_2: v8
  #       # other sub_keys ...
  #     ```
  # ---
  # type: string
  # name: Sub Sub Key1
  # unit:
  # range: []
  # enum_options: []
  # modification: hot_update
  # ee_feature: false
  # description:
  # ---
  # sub_sub_key_1: ""
  # ---
  # type: bool
  # name: Sub Sub Key2
  # unit:
  # range: []
  # enum_options: []
  # modification: hot_update
  # ee_feature: false
  # description:
  # ---
  # sub_sub_key_2: true
  sub_key1: []
  sub_key2: []
  sub_key3: []
```

### Other Types

Non-section item must hava a head comment with the following yaml tiems. Example:
```yaml
# type: int
# name: Item
# unit:
# range: []
# enum_options: []
# modification: hot_update
# ee_feature: false
# description:
# upgrade_from: full.name.of.old.item
item:
```

Options of `modification`:
- hot_update
- thread_restart
- agent_restart

If the `enum_options` of a configuration item need to be dynamically fetched, please set it to `_DYNAMIC_OPTIONS_`.

## I18n

### Name

All languages share the same name:
```yaml
# name: my_name
item:
```

All languages hava their own name:
```yaml
# name:
#   en: english_name
#   ch: 中文名称
item:
```

Some languages hava their own name, others share the english name (you must set the english name):
```yaml
# name:
#   en: english_name
item:
```

### Enum Option

All languages share the same note:
```yaml
# enum_options:
#   - enum_value1: my_note
item:
```

All languages hava their own note (**the indentation for `en` and `ch` should be greater than that of `enum_key1`**):
```yaml
# enum_options:
#   - enum_value1:
#       en: english_note_1
#       ch: 中文注解_1
#   - enum_value2:
#       en: english_note_2
#       ch: 中文注解_2
item:
```

Some languages hava their own note, others share the english note (you must set the english note):
```yaml
# enum_options:
#   - enum_value1:
#       en: english_note_1
#   - enum_value2:
#       en: english_note_2
item:
```

Of course, the above forms can be mixed in the comments of a configuration item. For example:
```yaml
# enum_options:
#   - enum_value1:
#       en: english_note_1
#       ch: 中文注解_1
#   - enum_value2:
#       en: english_note_2
#   - enum_value3: note_3
item:
```

You can also choose not to set annotations for each option:
```yaml
# enum_options: [a, b, c]
item:
```

### Description

Similar to `name`.

Howto write multiline string in yaml: [link](https://yaml-multiline.info/).

# Howto Generate README.md

```bash
git clone https://github.com/deepflowio/deepflow/
cd deepflow/server/agent_config/

python3 gendoc.py
```

We use [custom-heading-id](https://github.com/markedjs/marked-custom-heading-id), please use the correct yaml compiler.

What is FQCN: Full Qulified Configuration Name.
