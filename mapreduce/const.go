package mapreduce

const (
	DOCS_IN_BUFFER = 1 << 16 // FIXME: 放到配置文件中
	WINDOW_SIZE    = 30      // 30秒

	QUEUE_BATCH_SIZE = 4096
)
