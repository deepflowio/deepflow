package metadata

type DomainPlatformData map[string]*PlatformData

type DomainToPlatformData struct {
	// domain包含所有平台数据 包含sub_domain数据
	domainToAllPlatformData DomainPlatformData
	// domainn内所有数据除去pod数据(包含subdomain数据)
	domainToPlatformDataExceptPod DomainPlatformData
	// domainn内所有数据只有pod数据
	domainToPlatformDataOnlyPod DomainPlatformData
	// 所有简化vinterface数据vtap使用
	allSimplePlatformData *PlatformData
	// 所有简化vinterface数据vtap使用，不包含POD/容器服务接口
	allSimplePlatformDataExceptPod *PlatformData

	serverToSkipAllSimplePlatformData  DomainPlatformData
	domainToSkipAllPlatformData        DomainPlatformData
	domainToSkipPlatformDataExceptPod  DomainPlatformData
	domainToSkipPlatformDataOnlyPod    DomainPlatformData
	skipAllSimplePlatformDataExceptPod *PlatformData
}

func newDomainToPlatformData() *DomainToPlatformData {
	return &DomainToPlatformData{
		domainToAllPlatformData:           make(DomainPlatformData),
		domainToPlatformDataExceptPod:     make(DomainPlatformData),
		domainToPlatformDataOnlyPod:       make(DomainPlatformData),
		serverToSkipAllSimplePlatformData: make(DomainPlatformData),
		domainToSkipAllPlatformData:       make(DomainPlatformData),
		domainToSkipPlatformDataExceptPod: make(DomainPlatformData),
		domainToSkipPlatformDataOnlyPod:   make(DomainPlatformData),
	}
}

func (s DomainPlatformData) checkVersion(t DomainPlatformData) bool {
	flag := true
	for lcuuid, newDomainData := range t {
		oldDomainData, ok := s[lcuuid]
		if ok == false {
			flag = false
			newDomainData.initVersion()
			log.Debug("add domain data. ", newDomainData)
			continue
		}

		if !oldDomainData.equal(newDomainData) {
			flag = false
			newDomainData.setVersion(oldDomainData.GetVersion() + 1)
			log.Infof("domain data changed, (%s) to (%s)", oldDomainData, newDomainData)
		} else {
			newDomainData.setVersion(oldDomainData.GetVersion())
		}
	}
	return flag
}

func (d *DomainToPlatformData) updateDomainToAllPlatformData(data DomainPlatformData) {
	d.domainToAllPlatformData = data
}

func (d *DomainToPlatformData) updateDomainToPlatformDataExceptPod(data DomainPlatformData) {
	d.domainToPlatformDataExceptPod = data
}

func (d *DomainToPlatformData) updateDomainToPlatformDataOnlyPod(data DomainPlatformData) {
	d.domainToPlatformDataOnlyPod = data
}

func (d *DomainToPlatformData) updateDomainToSkipAllPlatformData(data DomainPlatformData) {
	d.domainToSkipAllPlatformData = data
}

func (d *DomainToPlatformData) updateDomainToSkipPlatformDataExceptPod(data DomainPlatformData) {
	d.domainToSkipPlatformDataExceptPod = data
}

func (d *DomainToPlatformData) updateDomainToSkipPlatformDataOnlyPod(data DomainPlatformData) {
	d.domainToSkipPlatformDataOnlyPod = data
}

func (d *DomainToPlatformData) updateAllsimpleplatformdata(data *PlatformData) {
	d.allSimplePlatformData = data
}

func (d *DomainToPlatformData) updateAllSimplePlatformDataExceptPod(data *PlatformData) {
	d.allSimplePlatformDataExceptPod = data
}

func (d *DomainToPlatformData) updateSkipAllSimplePlatformDataExceptPod(data *PlatformData) {
	d.skipAllSimplePlatformDataExceptPod = data
}

func (d *DomainToPlatformData) updateServerToSkipAllSimplePlatformData(data DomainPlatformData) {
	d.serverToSkipAllSimplePlatformData = data
}

func (d *DomainToPlatformData) GetAllSimplePlatformData() *PlatformData {
	return d.allSimplePlatformData
}

func (d *DomainToPlatformData) GetServerToSkipAllSimplePlatformData() DomainPlatformData {
	return d.serverToSkipAllSimplePlatformData
}

func (d *DomainToPlatformData) GetAllSimplePlatformDataExceptPod() *PlatformData {
	return d.allSimplePlatformDataExceptPod
}

func (d *DomainToPlatformData) GetSkipAllSimplePlatformDataExceptPod() *PlatformData {
	return d.skipAllSimplePlatformDataExceptPod
}

func (d *DomainToPlatformData) GetDomainToAllPlatformData() DomainPlatformData {
	return d.domainToAllPlatformData
}

func (d *DomainToPlatformData) GetDomainToPlatformDataExceptPod() DomainPlatformData {
	return d.domainToPlatformDataExceptPod
}

func (d *DomainToPlatformData) GetDomainToPlatformDataOnlyPod() DomainPlatformData {
	return d.domainToPlatformDataOnlyPod
}

func (d *DomainToPlatformData) GetDomainToSkipAllPlatformData() DomainPlatformData {
	return d.domainToSkipAllPlatformData
}

func (d *DomainToPlatformData) GetDomainToSkipPlatformDataExceptPod() DomainPlatformData {
	return d.domainToSkipPlatformDataExceptPod
}

func (d *DomainToPlatformData) GetDomainToSkipPlatformDataOnlyPod() DomainPlatformData {
	return d.domainToSkipPlatformDataOnlyPod
}
