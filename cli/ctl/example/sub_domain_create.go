package example

var YamlSubDomain = []byte(`
# 名称
name: sub-domain-test
domain_name: mars
config:
  # 所属 vpc [必填]
  vpc_uuid: 23e80045-43bb-55e7-9dc3-18f2414ce7a7
  # POD 子网 IPv4 地址最大掩码 [选填]
  pod_net_ipv4_cidr_max_mask: 16
  # POD 子网 IPv6 地址最大掩码 [选填]
  pod_net_ipv6_cidr_max_mask: 64
  # 输入正则表达式，指定需要额外对接路由接口 [选填]
  # port_name_regex: ^(cni|flannel|cali|vxlan.calico|tunl|en[ospx])
`)
