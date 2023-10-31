# 初始化一个变量n为1
n=1

# 循环10次
for i in {1..10000}
do
  # 往文件中追加一行内容，格式为test+n
  echo "test$n                     , test${n}                   ," >> /home/luyao/gowork/deepflow/server/querier/db_descriptions/clickhouse/tag/flow_log/l7_flow_log.en
  
  # n自增1
  n=$((n+1))
done

