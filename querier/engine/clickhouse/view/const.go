package view

const (
	NODE_FLAG_METRIC int = iota // 仅在计算层
	NODE_FLAG_TRANS             // 仅在翻译层

	METRIC_FLAG_INNER // METRIC专用FLAG，仅在计算层内层
	METRIC_FLAG_OUTER // METRIC专用FLAG，仅在计算层外层
)

const (
	MODEL_METRIC_LEVEL_FLAG_UNLAY   int = iota // 计算层不需要根据算子拆层
	MODEL_METRIC_LEVEL_FLAG_LAYERED            // 计算层需要根据算子拆层
)

const (
	METRIC_IS_0_MEANINGFUL_FALSE = false // 0值无意义，需要将0值作为null处理
	METRIC_IS_0_MEANINGFUL_TRUE  = true  // 0值有意义，需要将null作为0处理
)
