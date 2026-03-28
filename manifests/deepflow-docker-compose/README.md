# DeepFlow STANDALONE mode docker-compose deployment package

## System Requirements

Before deploying DeepFlow using Docker Compose, ensure your system meets the following minimum requirements:

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU      | 4 cores | 8+ cores    |
| Memory   | 8 GB    | 16+ GB      |
| Disk     | 100 GB  | 200+ GB     |

### Disk Space Details

DeepFlow stores data in the following directories under `/opt/deepflow/`:

- `/opt/deepflow/mysql/` - MySQL database files
- `/opt/deepflow/clickhouse/` - ClickHouse metadata and indexes
- `/opt/deepflow/clickhouse_storage/` - ClickHouse data storage (primary data location)
- `/opt/deepflow/grafana/` - Grafana dashboards, plugins, and provisioning

The actual disk usage depends on:
- Data retention period
- Traffic volume being monitored
- Number of agents reporting data

For production environments with high traffic volumes, consider allocating 500+ GB of disk space.

## Usage

```console
unset DOCKER_HOST_IP
DOCKER_HOST_IP="10.1.2.3"  # FIXME: Deploy the environment machine IP
wget  https://deepflow-ce.oss-cn-beijing.aliyuncs.com/pkg/docker-compose/stable/linux/deepflow-docker-compose.tar
tar -zxf deepflow-docker-compose.tar 
sed -i "s|FIX_ME_ALLINONE_HOST_IP|$DOCKER_HOST_IP|g" deepflow-docker-compose/docker-compose.yaml
docker-compose -f deepflow-docker-compose/docker-compose.yaml up -d
```

## License

[Apache 2.0 License](../../LICENSE).