/*
 * Copyright (c) 2024 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package common

const (
	TYPE_UPDATE                  = 1
	TYPE_RENEW                   = 2
	TYPE_EXIT                    = 3
	DEVICE_TYPE_KVM_HOST         = "kvm-host"
	DEVICE_TYPE_KVM_VM           = "kvm-vm"
	DEVICE_TYPE_DOCKER_HOST      = "docker-host"
	DEVICE_TYPE_DOCKER_CONTAINER = "docker-container"
	DEVICE_TYPE_PUBLIC_CLOUD     = "public-cloud"
	DEVICE_TYPE_PHYSICAL_MACHINE = "physical-machine"
	K8S_DATA_TYPE_IP_POOL        = "*v1.IPPool"
)
