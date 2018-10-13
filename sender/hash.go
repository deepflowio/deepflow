package sender

import (
	"gitlab.x.lan/yunshan/droplet-libs/utils"
	"gitlab.x.lan/yunshan/droplet-libs/zerodoc"
)

const MHASH_BASIS uint32 = 42

func codeHash(code zerodoc.Code) uint32 {
	return utils.MurmurHashFinish(utils.MurmurHashAddUint64(MHASH_BASIS, uint64(code)))
}
