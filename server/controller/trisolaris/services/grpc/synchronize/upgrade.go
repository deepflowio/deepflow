package synchronize

import (
	"crypto/md5"
	"fmt"
	"io/ioutil"
	"math"

	"github.com/golang/protobuf/proto"
	api "github.com/metaflowys/metaflow/message/trident"

	"github.com/metaflowys/metaflow/server/controller/trisolaris"
	. "github.com/metaflowys/metaflow/server/controller/trisolaris/common"
)

type UpgradeEvent struct{}

type UpgradeData struct {
	content  []byte
	totalLen uint64
	pktCount uint32
	md5Sum   string
	step     uint64
}

func NewUpgradeEvent() *UpgradeEvent {
	return &UpgradeEvent{}
}

func sendFailed(in api.Synchronizer_UpgradeServer) error {
	response := &api.UpgradeResponse{
		Status: &STATUS_FAILED,
	}
	err := in.Send(response)
	if err != nil {
		log.Error(err)
	}
	return err
}

func (e *UpgradeEvent) GetUpgradeFile(os uint32) (*UpgradeData, error) {
	config := trisolaris.GetConfig()
	var tridentPath string
	if os == TRIDENT_LINUX {
		tridentPath = config.TridentLinuxPath
	} else if os == TRIDENT_WINDOWS {
		tridentPath = config.TridentWindowsPath
	}
	if tridentPath == "" {
		return nil, fmt.Errorf("trident(%s) file does not exist", tridentPath)
	}
	content, err := ioutil.ReadFile(tridentPath)
	if err != nil {
		return nil, fmt.Errorf("trident(%s) file does not exist, err: %s", tridentPath, err)
	}
	totalLen := uint64(len(content))
	step := uint64(1024 * 1024)
	pktCount := uint32(math.Ceil(float64(totalLen) / float64(step)))
	cipherStr := md5.Sum(content)
	md5Sum := fmt.Sprintf("%x", cipherStr)
	return &UpgradeData{
		content:  content,
		totalLen: totalLen,
		pktCount: pktCount,
		md5Sum:   md5Sum,
		step:     step,
	}, err
}

func (e *UpgradeEvent) Upgrade(r *api.UpgradeRequest, in api.Synchronizer_UpgradeServer) error {
	upgradeData, err := e.GetUpgradeFile(r.GetTridentOs())
	if err != nil {
		log.Error(err)
		return sendFailed(in)
	}
	for start := uint64(0); start < upgradeData.totalLen; start += upgradeData.step {
		end := start + upgradeData.step
		if end > upgradeData.totalLen {
			end = upgradeData.totalLen
		}
		response := &api.UpgradeResponse{
			Status:   &STATUS_SUCCESS,
			Content:  upgradeData.content[start:end],
			Md5:      proto.String(upgradeData.md5Sum),
			PktCount: proto.Uint32(upgradeData.pktCount),
			TotalLen: proto.Uint64(upgradeData.totalLen),
		}
		err = in.Send(response)
		if err != nil {
			log.Error(err)
			break
		}
	}

	log.Infof("vtap(%s) end upgrade trident", r.GetCtrlIp())
	return err
}
