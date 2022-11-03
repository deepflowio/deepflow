package microsoft_acs

import (
	"bytes"
	"github.com/axgle/mahonia"
	"github.com/saintfish/chardet"
)

func GetCharset(str string) (string, error) {
	rawBytes := []byte(str)
	detector := chardet.NewTextDetector()
	charset, err := detector.DetectBest(rawBytes)
	if err != nil {
		return "", err
	}
	return charset.Charset, nil
}

func ConvertToByte(src string, srcCode string, tagCode string) []byte {
	srcCoder := mahonia.NewDecoder(srcCode)
	srcResult := srcCoder.ConvertString(src)
	tagCoder := mahonia.NewDecoder(tagCode)
	_, cdata, _ := tagCoder.Translate([]byte(srcResult), true)
	result := bytes.TrimPrefix(cdata, []byte("\xef\xbb\xbf"))
	return result
}
