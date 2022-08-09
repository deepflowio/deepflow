package synchronize

import (
	api "github.com/deepflowys/deepflow/message/controller"
	context "golang.org/x/net/context"

	"github.com/deepflowys/deepflow/server/controller/common"
)

type EncryptKeyEvent struct{}

func NewEncryptKeyEvent() *EncryptKeyEvent {
	return &EncryptKeyEvent{}
}

func (a *EncryptKeyEvent) Get(ctx context.Context, in *api.EncryptKeyRequest) (*api.EncryptKeyResponse, error) {
	encryptKey, err := common.EncryptSecretKey(in.GetKey())
	if err != nil {
		errorMsg := err.Error()
		return &api.EncryptKeyResponse{ErrorMsg: &errorMsg}, err
	}
	return &api.EncryptKeyResponse{EncryptKey: &encryptKey}, nil
}
