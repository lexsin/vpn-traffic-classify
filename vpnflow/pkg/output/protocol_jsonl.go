package output

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"

	"vpnflow/pkg/model"
)

// WriteProtocolJSONL 写出标准协议会话结果，一行一个稳定 JSON 对象。
func WriteProtocolJSONL(rows []model.ProtocolResult, outputPath string) error {
	if dir := filepath.Dir(outputPath); dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	for _, row := range rows {
		if err := enc.Encode(row); err != nil {
			return err
		}
	}
	return w.Flush()
}
