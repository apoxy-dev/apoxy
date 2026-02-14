package resource

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	sigyaml "sigs.k8s.io/yaml"

	"github.com/apoxy-dev/apoxy/client/versioned/scheme"
	"github.com/apoxy-dev/apoxy/config"
	"github.com/apoxy-dev/apoxy/pretty"
	"github.com/apoxy-dev/apoxy/rest"
)

// Object combines runtime.Object with metav1.Object to allow accessing both
// Kubernetes object metadata (Name, Labels, etc.) and runtime type information.
type Object interface {
	runtime.Object
	metav1.Object
}

// ResourceClient is the subset of the generated Kubernetes client interface
// needed for CRUD operations.
type ResourceClient[T, TList any] interface {
	Get(ctx context.Context, name string, opts metav1.GetOptions) (T, error)
	List(ctx context.Context, opts metav1.ListOptions) (TList, error)
	Create(ctx context.Context, obj T, opts metav1.CreateOptions) (T, error)
	Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (T, error)
}

// TableConverter is implemented by types that can convert to a metav1.Table.
type TableConverter interface {
	ConvertToTable(ctx context.Context, tableOptions runtime.Object) (*metav1.Table, error)
}

// TablePrinterConfig configures printing for types that implement ConvertToTable.
type TablePrinterConfig[T, TList any] struct {
	ObjToTable  func(T) TableConverter
	ListToTable func(TList) TableConverter
}

// CustomPrinterConfig configures printing for types that use pretty.Table.
type CustomPrinterConfig[T, TList any] struct {
	Header   func(showLabels bool) pretty.Header
	BuildRow func(item T, showLabels bool) []interface{}
	GetItems func(list TList) []T
}

// ResourceCommand defines a generic CLI resource command that generates
// get, list, create, delete, and apply subcommands.
type ResourceCommand[T Object, TList runtime.Object] struct {
	Use      string
	Aliases  []string
	Short    string
	Long     string
	KindName string

	ClientFunc func(*rest.APIClient) ResourceClient[T, TList]

	// Exactly one of these must be set.
	TablePrinter  *TablePrinterConfig[T, TList]
	CustomPrinter *CustomPrinterConfig[T, TList]

	// PostGet is an optional hook called after Get to display additional information.
	PostGet func(ctx context.Context, c *rest.APIClient, name string, obj T) error

	// ListFlags registers custom flags on both the root and list commands.
	// Returns a function that produces a field selector string from those flags.
	ListFlags func(cmd *cobra.Command) func() string
}

// PrintStructured serializes a runtime.Object as JSON or YAML to stdout.
func PrintStructured(obj runtime.Object, format string) error {
	// Populate Kind/APIVersion from the scheme so they appear in output.
	// The Kubernetes client strips TypeMeta during deserialization.
	gvks, _, err := scheme.Scheme.ObjectKinds(obj)
	if err == nil && len(gvks) > 0 {
		obj.GetObjectKind().SetGroupVersionKind(gvks[0])
	}

	switch format {
	case "json":
		data, err := json.MarshalIndent(obj, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
		fmt.Println(string(data))
		return nil
	case "yaml":
		data, err := json.Marshal(obj)
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
		out, err := sigyaml.JSONToYAML(data)
		if err != nil {
			return fmt.Errorf("failed to convert to YAML: %w", err)
		}
		fmt.Print(string(out))
		return nil
	default:
		return fmt.Errorf("unsupported output format: %q", format)
	}
}

func (r *ResourceCommand[T, TList]) printObj(ctx context.Context, obj T, showLabels bool, outputFormat string) error {
	if outputFormat != "" {
		return PrintStructured(obj, outputFormat)
	}
	if r.TablePrinter != nil {
		table, err := r.TablePrinter.ObjToTable(obj).ConvertToTable(ctx, &metav1.TableOptions{})
		if err != nil {
			return err
		}
		return PrintTable(table, showLabels)
	}
	if r.CustomPrinter != nil {
		t := pretty.Table{
			Header: r.CustomPrinter.Header(showLabels),
			Rows:   pretty.Rows{r.CustomPrinter.BuildRow(obj, showLabels)},
		}
		t.Print()
		return nil
	}
	return fmt.Errorf("no printer configured")
}

func (r *ResourceCommand[T, TList]) printList(ctx context.Context, list TList, showLabels bool, outputFormat string) error {
	if outputFormat != "" {
		return PrintStructured(list, outputFormat)
	}
	if r.TablePrinter != nil {
		table, err := r.TablePrinter.ListToTable(list).ConvertToTable(ctx, &metav1.TableOptions{})
		if err != nil {
			return err
		}
		return PrintTable(table, showLabels)
	}
	if r.CustomPrinter != nil {
		t := pretty.Table{
			Header: r.CustomPrinter.Header(showLabels),
		}
		for _, item := range r.CustomPrinter.GetItems(list) {
			t.Rows = append(t.Rows, r.CustomPrinter.BuildRow(item, showLabels))
		}
		t.Print()
		return nil
	}
	return fmt.Errorf("no printer configured")
}

// Build returns a fully-wired *cobra.Command with get/list/create/delete/apply
// subcommands and all standard flags.
func (r *ResourceCommand[T, TList]) Build() *cobra.Command {
	var (
		showLabels     bool
		outputFormat   string
		fieldSelector  string
		createFile     string
		applyFile      string
		fieldManager   string
		forceConflicts bool
	)

	// Register ListFlags on root and list commands; hold the closures for runtime.
	var rootListFlagsFn, listListFlagsFn func() string

	rootCmd := &cobra.Command{
		Use:     r.Use,
		Short:   r.Short,
		Long:    r.Long,
		Aliases: r.Aliases,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			c, err := config.DefaultAPIClient()
			if err != nil {
				return err
			}
			fs := fieldSelector
			if rootListFlagsFn != nil {
				if extra := rootListFlagsFn(); extra != "" {
					if fs != "" {
						fs += "," + extra
					} else {
						fs = extra
					}
				}
			}
			list, err := r.ClientFunc(c).List(cmd.Context(), metav1.ListOptions{FieldSelector: fs})
			if err != nil {
				return err
			}
			return r.printList(cmd.Context(), list, showLabels, outputFormat)
		},
	}

	getCmd := &cobra.Command{
		Use:       "get <name>",
		Short:     fmt.Sprintf("Get %s objects", r.KindName),
		ValidArgs: []string{"name"},
		Args:      cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			c, err := config.DefaultAPIClient()
			if err != nil {
				return err
			}
			obj, err := r.ClientFunc(c).Get(cmd.Context(), args[0], metav1.GetOptions{})
			if err != nil {
				return err
			}
			if err := r.printObj(cmd.Context(), obj, false, outputFormat); err != nil {
				return err
			}
			if r.PostGet != nil {
				return r.PostGet(cmd.Context(), c, args[0], obj)
			}
			return nil
		},
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: fmt.Sprintf("List %s objects", r.KindName),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			c, err := config.DefaultAPIClient()
			if err != nil {
				return err
			}
			fs := fieldSelector
			if listListFlagsFn != nil {
				if extra := listListFlagsFn(); extra != "" {
					if fs != "" {
						fs += "," + extra
					} else {
						fs = extra
					}
				}
			}
			list, err := r.ClientFunc(c).List(cmd.Context(), metav1.ListOptions{FieldSelector: fs})
			if err != nil {
				return err
			}
			return r.printList(cmd.Context(), list, showLabels, outputFormat)
		},
	}

	createCmd := &cobra.Command{
		Use:   "create [-f filename]",
		Short: fmt.Sprintf("Create %s objects", r.KindName),
		Long:  fmt.Sprintf("Create %s objects by providing a configuration as a file or via stdin.", r.KindName),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := ReadInputData(createFile)
			if err != nil {
				return err
			}

			cmd.SilenceUsage = true

			c, err := config.DefaultAPIClient()
			if err != nil {
				return err
			}

			obj, _, err := scheme.Codecs.UniversalDeserializer().Decode(data, nil, nil)
			if err != nil {
				return fmt.Errorf("failed to decode input: %w", err)
			}

			typed, ok := obj.(T)
			if !ok {
				return fmt.Errorf("expected %s, got %T", r.KindName, obj)
			}

			result, err := r.ClientFunc(c).Create(cmd.Context(), typed, metav1.CreateOptions{})
			if err != nil {
				return err
			}
			fmt.Printf("%s %q created\n", r.KindName, result.GetName())
			return nil
		},
	}

	deleteCmd := &cobra.Command{
		Use:   "delete",
		Short: fmt.Sprintf("Delete %s objects", r.KindName),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true

			c, err := config.DefaultAPIClient()
			if err != nil {
				return err
			}

			for _, name := range args {
				if err = r.ClientFunc(c).Delete(cmd.Context(), name, metav1.DeleteOptions{}); err != nil {
					return err
				}
				fmt.Printf("%s %q deleted\n", r.KindName, name)
			}
			return nil
		},
	}

	applyCmd := &cobra.Command{
		Use:   "apply [-f filename]",
		Short: fmt.Sprintf("Apply %s configuration using server-side apply", r.KindName),
		Long: fmt.Sprintf(`Apply %s configuration using Kubernetes server-side apply.

This command uses server-side apply to create or update %s objects.
Server-side apply tracks field ownership and allows multiple actors to
manage different fields of the same object without conflicts.`, r.KindName, r.KindName),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := ReadInputData(applyFile)
			if err != nil {
				return err
			}

			cmd.SilenceUsage = true

			c, err := config.DefaultAPIClient()
			if err != nil {
				return err
			}

			obj, _, err := scheme.Codecs.UniversalDeserializer().Decode(data, nil, nil)
			if err != nil {
				return fmt.Errorf("failed to decode input: %w", err)
			}

			typed, ok := obj.(T)
			if !ok {
				return fmt.Errorf("expected %s, got %T", r.KindName, obj)
			}

			name := typed.GetName()
			if name == "" {
				return fmt.Errorf("%s name is required", r.KindName)
			}

			patchData, err := json.Marshal(typed)
			if err != nil {
				return fmt.Errorf("failed to marshal %s: %w", r.KindName, err)
			}

			result, err := r.ClientFunc(c).Patch(
				cmd.Context(),
				name,
				types.ApplyPatchType,
				patchData,
				metav1.PatchOptions{
					FieldManager: fieldManager,
					Force:        &forceConflicts,
				},
			)
			if err != nil {
				return err
			}

			fmt.Printf("%s %q applied\n", r.KindName, result.GetName())
			return nil
		},
	}

	// Register flags.
	rootCmd.Flags().StringVarP(&outputFormat, "output", "o", "", `Output format: "json" or "yaml". Default is table.`)
	getCmd.Flags().StringVarP(&outputFormat, "output", "o", "", `Output format: "json" or "yaml". Default is table.`)
	listCmd.Flags().StringVarP(&outputFormat, "output", "o", "", `Output format: "json" or "yaml". Default is table.`)
	rootCmd.Flags().StringVar(&fieldSelector, "field-selector", "", "Filter list results by field selectors (e.g. spec.zone=example.com).")
	listCmd.Flags().StringVar(&fieldSelector, "field-selector", "", "Filter list results by field selectors (e.g. spec.zone=example.com).")
	createCmd.Flags().StringVarP(&createFile, "filename", "f", "", "The file that contains the configuration to create.")
	listCmd.Flags().BoolVar(&showLabels, "show-labels", false, fmt.Sprintf("Print the %s's labels.", r.KindName))
	applyCmd.Flags().StringVarP(&applyFile, "filename", "f", "", "The file that contains the configuration to apply.")
	applyCmd.Flags().StringVar(&fieldManager, "field-manager", "apoxy-cli", "Name of the field manager for server-side apply.")
	applyCmd.Flags().BoolVar(&forceConflicts, "force-conflicts", false, "Force apply even if there are field ownership conflicts.")

	if r.ListFlags != nil {
		rootListFlagsFn = r.ListFlags(rootCmd)
		listListFlagsFn = r.ListFlags(listCmd)
	}

	rootCmd.AddCommand(getCmd, listCmd, createCmd, deleteCmd, applyCmd)
	return rootCmd
}
