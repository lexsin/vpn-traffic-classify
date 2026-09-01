package output

import (
	"encoding/csv"
	"os"
	"path/filepath"

	"vpnflow/pkg/model"
)

// WriteCSV 将 FeatureRow 列表写入 CSV 文件（含表头）。
// 若文件已存在则覆盖；输出目录不存在时自动创建。
func WriteCSV(rows []model.FeatureRow, outputPath string) error {
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

	w := csv.NewWriter(f)
	defer w.Flush()

	if err := w.Write(model.CSVHeader()); err != nil {
		return err
	}
	for _, row := range rows {
		if err := w.Write(row.ToCSVRecord()); err != nil {
			return err
		}
	}
	return w.Error()
}
