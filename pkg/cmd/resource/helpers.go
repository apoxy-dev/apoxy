package resource

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/mattn/go-runewidth"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

// PrintTable prints a metav1.Table to stdout using display-width-aware
// column alignment (handles emoji and other wide Unicode correctly).
func PrintTable(table *metav1.Table, showLabels bool) error {
	if showLabels {
		AddLabelsColumnToTable(table)
	}

	numCols := len(table.ColumnDefinitions)
	if numCols == 0 {
		return nil
	}

	// Stringify all cells.
	headers := make([]string, numCols)
	for i, col := range table.ColumnDefinitions {
		headers[i] = strings.ToUpper(col.Name)
	}
	rows := make([][]string, len(table.Rows))
	for i, row := range table.Rows {
		cells := make([]string, numCols)
		for j := 0; j < numCols; j++ {
			if j < len(row.Cells) {
				cells[j] = fmt.Sprintf("%v", row.Cells[j])
			}
		}
		rows[i] = cells
	}

	// Compute max display width per column.
	widths := make([]int, numCols)
	for i, h := range headers {
		widths[i] = runewidth.StringWidth(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if w := runewidth.StringWidth(cell); w > widths[i] {
				widths[i] = w
			}
		}
	}

	// Print header.
	const colGap = "   "
	var b strings.Builder
	for i, h := range headers {
		if i > 0 {
			b.WriteString(colGap)
		}
		b.WriteString(runewidth.FillRight(h, widths[i]))
	}
	b.WriteString("\n")

	// Print rows.
	for _, row := range rows {
		for i, cell := range row {
			if i > 0 {
				b.WriteString(colGap)
			}
			b.WriteString(runewidth.FillRight(cell, widths[i]))
		}
		b.WriteString("\n")
	}

	_, err := fmt.Fprint(os.Stdout, b.String())
	return err
}
