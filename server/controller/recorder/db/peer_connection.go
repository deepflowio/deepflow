package db

import (
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
	"github.com/metaflowys/metaflow/server/controller/recorder/common"
)

type PeerConnection struct {
	OperatorBase[mysql.PeerConnection]
}

func NewPeerConnection() *PeerConnection {
	operater := &PeerConnection{
		OperatorBase[mysql.PeerConnection]{
			resourceTypeName: common.RESOURCE_TYPE_PEER_CONNECTION_EN,
			softDelete:       true,
		},
	}
	operater.setter = operater
	return operater
}

func (a *PeerConnection) setDBItemID(dbItem *mysql.PeerConnection, id int) {
	dbItem.ID = id
}
