package clickhouse

import (
	"errors"
	"fmt"
	"net"
	"strconv"

	"metaflow/querier/engine/clickhouse/tag"
	"metaflow/querier/engine/clickhouse/view"
)

func GetTagTranslator(name string, alias string) (Statement, error) {
	var stmt Statement
	withs := []view.Node{}
	selectTag := name
	if alias != "" {
		selectTag = alias
	}
	tag, ok := tag.GetTag(name)
	if !ok {
		if alias != "" {
			withs = []view.Node{&view.With{Value: name, Alias: alias}}
		}
	} else {
		if tag.TagTranslator != "" {
			withs = []view.Node{&view.With{Value: tag.TagTranslator, Alias: selectTag}}
		}
	}
	stmt = &SelectTag{Value: selectTag, Withs: withs}
	return stmt, nil
}

func GetTagFunctionTranslator(name string, args []string, alias string) (Statement, error) {
	var stmt Statement
	tag, ok := tag.GetTag(name + "_" + args[0])
	if !ok {
		errMessage := fmt.Sprintf("get tag %s failed", name)
		err := errors.New(errMessage)
		return stmt, err
	}
	withs := []view.Node{}
	selectTag := name
	if alias != "" {
		selectTag = alias
	}
	if tag.TagTranslator != "" {
		mask := args[1]
		maskInt, err := strconv.Atoi(mask)
		var ip4MaskInt uint64
		if maskInt >= 32 {
			ip4MaskInt = 4294967295
		} else {
			ip4Mask := net.CIDRMask(maskInt, 32)
			ip4MaskInt, err = strconv.ParseUint(ip4Mask.String(), 16, 64)
			if err != nil {
				log.Error(err)
				return stmt, err
			}
		}
		ip6Mask := net.CIDRMask(maskInt, 128)
		value := fmt.Sprintf(tag.TagTranslator, ip4MaskInt, ip6Mask.String())
		withs = []view.Node{&view.With{Value: value, Alias: selectTag}}
		stmt = &SelectTag{Value: selectTag, Withs: withs}
	}
	return stmt, nil
}

type SelectTag struct {
	Value string
	Alias string
	Flag  int
	Withs []view.Node
}

func (t *SelectTag) Format(m *view.Model) {
	m.AddTag(&view.Tag{Value: t.Value, Alias: t.Alias, Flag: t.Flag, Withs: t.Withs})
}
