package view

const (
	NODE_FLAG_METRIC       int = iota // 仅在计算层
	NODE_FLAG_TRANS                   // 仅在翻译层
	NODE_FLAG_METRIC_INNER            // 仅在计算层内层
	NODE_FLAG_METRIC_OUTER            // 仅在计算层外层
)

const (
	METRIC_FLAG_INNER int = iota // METRIC专用FLAG，仅在计算层内层
	METRIC_FLAG_OUTER            // METRIC专用FLAG，仅在计算层外层
)

const (
	GROUP_FLAG_DEFAULT       int = iota // GROUP专用FLAG，计算层内外都携带group，with仅放计算层内层
	GROUP_FLAG_METRIC_OUTER             // GROUP专用FLAG，仅计算层外层携带该group
	GROUP_FLAG_METRIC_INNTER            // GROUP专用FLAG，仅计算层内层携带该group
)

const (
	MODEL_METRIC_LEVEL_FLAG_UNLAY   int = iota // 计算层不需要根据算子拆层
	MODEL_METRIC_LEVEL_FLAG_LAYERED            // 计算层需要根据算子拆层
)

// Div算子类型
const (
	FUNCTION_DIV_TYPE_DEFAULT          int = iota // 默认，不做任何处理
	FUNCTION_DIV_TYPE_FILL_MINIMUM                // 除数和被除数都+1e-15
	FUNCTION_DIV_TYPE_0DIVIDER_AS_NULL            // 除数为0时，结果为NULL
	FUNCTION_DIV_TYPE_0DIVIDER_AS_0               //除数为0时，结果为0
)
