package policy

import (
	inputtype "gitlab.x.lan/yunshan/droplet-libs/datatype"
)

func GetTagTemplateByActionFlags(policy *inputtype.PolicyData, actionFlags inputtype.ActionFlag) inputtype.TagTemplate {
	if policy.ActionFlags&actionFlags == 0 {
		return 0
	}
	var tagTemplates inputtype.TagTemplate = 0
	for _, aclAction := range policy.AclActions {
		if aclAction.GetActionFlags()&actionFlags != 0 {
			tagTemplates |= aclAction.GetTagTemplates()
		}
	}
	return tagTemplates
}

// 1. 使用actionFlags过滤policy.AclActions
// 2. 根据ACLGID将AclActions数组按TagTemplates的交叠情况进行ActionFlags的合并
// 3. 保证TagTemplates无交叠，避免产生的重复doc数量
func FillPolicyTagTemplate(policy *inputtype.PolicyData, actionFlags inputtype.ActionFlag, templates []inputtype.AclAction) []inputtype.AclAction {
	templates = templates[:0]
	if policy.ActionFlags&actionFlags == 0 {
		return templates
	}

	for _, aclAction := range policy.AclActions {
		if aclAction.GetActionFlags()&actionFlags == 0 {
			continue
		}
		if aclAction.GetACLGID() == 0 {
			continue
		}
		aclAction = aclAction.SetActionFlags(actionFlags & aclAction.GetActionFlags()) // 仅保留指定的actionFlags

		newTagTemplates := aclAction.GetTagTemplates()
		for loc, existAclAction := range templates {
			if existAclAction.GetACLGID() != aclAction.GetACLGID() { // 仅考虑相同的ACLGID
				continue
			}

			sharedTagTemplates := existAclAction.GetTagTemplates() & aclAction.GetTagTemplates()
			if sharedTagTemplates == 0 { // 若TagTemplates无交集则跳过
				continue
			}
			existTagTemplates := existAclAction.GetTagTemplates() & (^aclAction.GetTagTemplates())
			newTagTemplates = (^existAclAction.GetTagTemplates()) & aclAction.GetTagTemplates()

			// Directions已经在Labeler中进行了合并，此处只需合并ActionFlags和TagTemplates
			if existTagTemplates == 0 { // TagTemplates完全覆盖已有的记录
				templates[loc] = templates[loc].AddActionFlags(aclAction.GetActionFlags())
				templates[loc] = templates[loc].SetTagTemplates(sharedTagTemplates)
			} else { // TagTemplates与已有记录不完全重叠
				templates[loc] = templates[loc].SetTagTemplates(existTagTemplates) // 已有记录仅保留差集
				if sharedTagTemplates != 0 {                                       // 新增记录保存交集
					shardAclAction := aclAction.AddActionFlags(existAclAction.GetActionFlags())
					shardAclAction = shardAclAction.SetTagTemplates(sharedTagTemplates)
					templates = append(templates, shardAclAction)
				}
			}

			aclAction = aclAction.SetTagTemplates(newTagTemplates)
			if newTagTemplates == 0 { // 新记录已完全合并
				break
			}
		}
		if newTagTemplates > 0 {
			templates = append(templates, aclAction)
		}
	}
	return templates
}
