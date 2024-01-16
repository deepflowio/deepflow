# DeepFlow STANDALONE mode docker-compose deployment package

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