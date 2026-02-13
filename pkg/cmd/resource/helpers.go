package resource

import (
	"fmt"
	"io"
	"os"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/printers"
)

// LabelsToString formats a label map as a comma-separated key=value string.
func LabelsToString(labels map[string]string) string {
	var l []string
	for k, v := range labels {
		l = append(l, fmt.Sprintf("%s=%s", k, v))
	}
	return strings.Join(l, ",")
}

// AddLabelsColumnToTable appends a Labels column to a table and populates it
// from the embedded objects.
func AddLabelsColumnToTable(table *metav1.Table) {
	table.ColumnDefinitions = append(table.ColumnDefinitions, metav1.TableColumnDefinition{
		Name: "Labels", Type: "string", Description: "Labels for the resource",
	})
	for i := range table.Rows {
		if table.Rows[i].Object.Object != nil {
			if meta, ok := table.Rows[i].Object.Object.(metav1.Object); ok {
				table.Rows[i].Cells = append(table.Rows[i].Cells, LabelsToString(meta.GetLabels()))
			} else {
				table.Rows[i].Cells = append(table.Rows[i].Cells, "")
			}
		} else {
			table.Rows[i].Cells = append(table.Rows[i].Cells, "")
		}
	}
}

// ReadInputData reads configuration data from stdin or the given file path.
// If filename is empty, it reads from stdin if piped data is available.
func ReadInputData(filename string) ([]byte, error) {
	stat, _ := os.Stdin.Stat()
	if stat.Mode()&os.ModeCharDevice == 0 {
		if filename != "" {
			return nil, fmt.Errorf("cannot use --filename with stdin")
		}
		return io.ReadAll(os.Stdin)
	}
	if filename != "" {
		return os.ReadFile(filename)
	}
	return nil, fmt.Errorf("please provide a configuration via --filename or stdin")
}

// PrintTable prints a metav1.Table to stdout, optionally appending a labels column.
func PrintTable(table *metav1.Table, showLabels bool) error {
	if showLabels {
		AddLabelsColumnToTable(table)
	}
	printer := printers.NewTablePrinter(printers.PrintOptions{})
	return printer.PrintObj(table, os.Stdout)
}
