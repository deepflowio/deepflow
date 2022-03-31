package clickhouse

import (
	//"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"metaflow/querier/common"
	"metaflow/querier/engine/clickhouse/metrics"
	"metaflow/querier/engine/clickhouse/tag"
	"metaflow/querier/engine/clickhouse/view"
)

const (
	TAG_FUNCTION_MASK                       = "mask"
	TAG_FUNCTION_TIME                       = "time"
	TAG_FUNCTION_TO_UNIX_TIMESTAMP_64_MICRO = "toUnixTimestamp64Micro"
	TAG_FUNCTION_TO_STRING                  = "toString"
	TAG_FUNCTION_IF                         = "if"
	TAG_FUNCTION_UNIQ                       = "uniq"
	TAG_FUNCTION_ANY                        = "any"
	TAG_FUNCTION_TOPK                       = "topK"
)

var TAG_FUNCTIONS = []string{
	TAG_FUNCTION_MASK, TAG_FUNCTION_TIME, TAG_FUNCTION_TO_UNIX_TIMESTAMP_64_MICRO,
	TAG_FUNCTION_TO_STRING, TAG_FUNCTION_IF, TAG_FUNCTION_UNIQ, TAG_FUNCTION_ANY,
	TAG_FUNCTION_TOPK,
}

func GetTagTranslator(name, alias, db, table string) (Statement, error) {
	var stmt Statement
	withs := []view.Node{}
	selectTag := name
	if alias != "" {
		selectTag = alias
	}
	tag, ok := tag.GetTag(name, db, table)
	if !ok {
		return nil, nil
	} else {
		if tag.TagTranslator != "" {
			withs = []view.Node{&view.With{Value: tag.TagTranslator, Alias: selectTag}}
		}
	}
	stmt = &SelectTag{Value: selectTag, Withs: withs}
	return stmt, nil
}

func GetMetricsTag(name string, alias string, db string, table string) (Statement, error) {
	metricStruct, ok := metrics.GetMetrics(name, db, table)
	if !ok {
		return nil, nil
	}
	if alias == "" && metricStruct.DBField != name {
		alias = name
	}
	return &SelectTag{Value: metricStruct.DBField, Alias: alias}, nil
}

func GetDefaultTag(name string, alias string) Statement {
	return &SelectTag{Value: name, Alias: alias}
}

func GetTagFunction(name string, args []string, alias, db, table string) (Statement, error) {
	if !common.IsValueInSliceString(name, TAG_FUNCTIONS) {
		return nil, nil
	}
	switch name {
	case "time":
		time := Time{Args: args, Alias: alias}
		err := time.Trans()
		return &time, err
	default:
		// TODO
		/* tag, ok := tag.GetTag("mask"+"_"+args[0], db, table)
		if !ok {
			return nil, errors.New(fmt.Sprintf("mask not support %s", args[0]))
		}
		mask := Mask{Args: args, Alias: alias}
		err := mask.Trans(tag)
		if err != nil {
			return nil, err
		}
		return &mask, nil */
		tagFunction := DefaultTagFunction{Name: name, Args: args}
		err := tagFunction.Trans()
		return &tagFunction, err
	}
	return nil, nil
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

type Mask struct {
	Alias string
	Args  []string
	Withs []view.Node
}

func (m *Mask) Trans(tag *tag.Tag) error {
	if m.Alias == "" {
		m.Alias = "mask"
	}
	maskInt, err := strconv.Atoi(m.Args[1])
	if err != nil {
		return err
	}
	var ip4MaskInt uint64
	if maskInt >= 32 {
		ip4MaskInt = 4294967295
	} else {
		ip4Mask := net.CIDRMask(maskInt, 32)
		ip4MaskInt, err = strconv.ParseUint(ip4Mask.String(), 16, 64)
		if err != nil {
			log.Error(err)
			return err
		}
	}
	ip6Mask := net.CIDRMask(maskInt, 128)
	value := fmt.Sprintf(tag.TagTranslator, ip4MaskInt, ip6Mask.String())
	m.Withs = []view.Node{&view.With{Value: value, Alias: m.Alias}}
	return nil
}

func (ma *Mask) Format(m *view.Model) {
	m.AddTag(&view.Tag{Value: ma.Alias, Withs: ma.Withs})
}

type Time struct {
	Args       []string
	Alias      string
	Withs      []view.Node
	TimeField  string
	Interval   int
	WindowSize int
}

func (t *Time) Trans() error {
	t.TimeField = strings.ReplaceAll(t.Args[0], "`", "")
	interval, err := strconv.Atoi(t.Args[1])
	t.Interval = interval
	if err != nil {
		return err
	}
	if len(t.Args) > 2 {
		t.WindowSize, err = strconv.Atoi(t.Args[2])
		if err != nil {
			return err
		}
	} else {
		t.WindowSize = 1
	}
	return nil
}

func (t *Time) Format(m *view.Model) {
	m.Time.Interval = t.Interval
	m.Time.WindowSize = t.WindowSize
	toIntervalFunction := "toIntervalSecond"
	var windows string
	w := make([]string, t.WindowSize)
	for i := range w {
		w[i] = strconv.Itoa(i)
	}
	windows = strings.Join(w, ",")
	var innerTimeField string
	if m.MetricsLevelFlag == view.MODEL_METRICS_LEVEL_FLAG_LAYERED {
		innerTimeField = "_" + t.TimeField
		withValue := fmt.Sprintf(
			"toStartOfInterval(%s, toIntervalSecond(%d))",
			t.TimeField, m.Time.DatasourceInterval,
		)
		withAlias := "_" + t.TimeField
		withs := []view.Node{&view.With{Value: withValue, Alias: withAlias}}
		m.AddTag(&view.Tag{Value: withAlias, Withs: withs, Flag: view.NODE_FLAG_METRICS_INNER})
		m.AddGroup(&view.Group{Value: withAlias, Flag: view.GROUP_FLAG_METRICS_INNTER})
	} else if m.MetricsLevelFlag == view.MODEL_METRICS_LEVEL_FLAG_UNLAY {
		innerTimeField = t.TimeField
	}
	withValue := fmt.Sprintf(
		"toStartOfInterval(%s, %s(%d)) + %s(arrayJoin([%s]) * %d)",
		innerTimeField, toIntervalFunction, t.Interval, toIntervalFunction, windows, t.Interval,
	)
	withAlias := "_" + t.Alias
	withs := []view.Node{&view.With{Value: withValue, Alias: withAlias}}
	tagField := fmt.Sprintf("toUnixTimestamp(%s)", withAlias)
	m.AddTag(&view.Tag{Value: tagField, Alias: t.Alias, Flag: view.NODE_FLAG_METRICS_OUTER, Withs: withs})
	m.AddGroup(&view.Group{Value: t.Alias, Flag: view.GROUP_FLAG_METRICS_OUTER})
}

type DefaultTagFunction struct {
	Name  string
	Args  []string
	Alias string
	Withs []view.Node
}

func (f *DefaultTagFunction) Trans() error {
	switch f.Name {
	case TAG_FUNCTION_TOPK:
		f.Name = fmt.Sprintf("topK(%s)", f.Args[1])
	}
	// TODO
	// tag translator
	return nil
}

func (f *DefaultTagFunction) Format(m *view.Model) {
	m.AddTag(&view.Tag{Value: f.Alias, Withs: f.Withs})
}
