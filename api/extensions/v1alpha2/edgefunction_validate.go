package v1alpha2

import (
	"context"
	"encoding/base64"
	"path/filepath"
	"strings"

	runtime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/ptr"
	"github.com/apoxy-dev/apoxy/pkg/apiserver/builder/rest"
)

var _ rest.Defaulter = &EdgeFunction{}

// Default sets the default values for an EdgeFunction.
func (r *EdgeFunction) Default() {
	if r.Spec.RevisionHistoryLimit == nil {
		r.Spec.RevisionHistoryLimit = ptr.To(int32(10))
	}

	if r.Spec.Template.Mode == "" {
		if r.Spec.Template.Code.GoPluginSource != nil {
			r.Spec.Template.Mode = FilterEdgeFunctionMode
		} else {
			r.Spec.Template.Mode = BackendEdgeFunctionMode
		}
	}

	if r.Spec.Template.Runtime == nil {
		r.Spec.Template.Runtime = &EdgeFunctionRuntime{}
	}

	if r.Spec.Template.Mode == FilterEdgeFunctionMode {
		if r.Spec.Template.Code.GoPluginSource != nil &&
			r.Spec.Template.Code.GoPluginSource.OCI != nil &&
			r.Spec.Template.Code.GoPluginSource.OCI.Credentials != nil &&
			r.Spec.Template.Code.GoPluginSource.OCI.Credentials.Password != "" {
			enc := base64.StdEncoding.EncodeToString([]byte(r.Spec.Template.Code.GoPluginSource.OCI.Credentials.Password))
			r.Spec.Template.Code.GoPluginSource.OCI.Credentials.PasswordData = []byte(enc)
			r.Spec.Template.Code.GoPluginSource.OCI.Credentials.Password = ""
		}
	}

	r.Spec.Template.Mode = EdgeFunctionMode(strings.ToLower(string(r.Spec.Template.Mode)))
	if r.Spec.Template.Mode == BackendEdgeFunctionMode {
		if r.Spec.Template.Runtime.Port == nil {
			r.Spec.Template.Runtime.Port = ptr.To(int32(8080))
		}
	}
}

var _ rest.Validater = &EdgeFunction{}
var _ rest.ValidateUpdater = &EdgeFunction{}

// validate validates the EdgeFunction and returns an error if it is invalid.
func (r *EdgeFunction) validate() field.ErrorList {
	errs := field.ErrorList{}
	spec := r.Spec

	if spec.Template.Mode != "" && spec.Template.Mode != FilterEdgeFunctionMode && spec.Template.Mode != BackendEdgeFunctionMode {
		errs = append(errs,
			field.Invalid(field.NewPath("spec").Child("template").Child("mode"),
				r.Spec.Template.Mode, "mode must be either 'filter' or 'backend'"))
	}

	if spec.Template.Code.GoPluginSource != nil && (spec.Template.Mode != FilterEdgeFunctionMode && spec.Template.Mode != "") {
		errs = append(errs,
			field.Forbidden(field.NewPath("spec").Child("template").Child("code").Child("goPluginSource"),
				"goPluginSource can only be specified when mode is 'filter'"))
	}

	if spec.Template.Mode == FilterEdgeFunctionMode && spec.Template.Runtime != nil && spec.Template.Runtime.Port != nil {
		errs = append(errs,
			field.Forbidden(field.NewPath("spec").Child("template").Child("runtime").Child("port"),
				"port cannot be specified when mode is 'filter'"))
	}

	if spec.Template.Code.GoPluginSource == nil && spec.Template.Code.JsSource == nil &&
		spec.Template.Code.WasmSource == nil {
		errs = append(errs,
			field.Required(field.NewPath("spec").Child("template").Child("code"),
				"goPluginSource, jsSource, or wasmSource must be specified"))
	}
	if spec.Template.Code.GoPluginSource != nil {
		if spec.Template.Code.JsSource != nil || spec.Template.Code.WasmSource != nil {
			errs = append(errs,
				field.Forbidden(field.NewPath("spec").Child("template").Child("code"),
					"jsSource and wasmSource cannot be specified when goPluginSource is specified"))
		}

		if spec.Template.Code.GoPluginSource.OCI == nil && spec.Template.Code.GoPluginSource.URL == nil {
			errs = append(errs,
				field.Required(field.NewPath("spec").Child("template").Child("code").Child("goPluginSource"),
					"specific source must be specified"))
		}
		if spec.Template.Code.GoPluginSource.OCI != nil && spec.Template.Code.GoPluginSource.URL != nil {
			errs = append(errs,
				field.Forbidden(field.NewPath("spec").Child("template").Child("code").Child("goPluginSource"),
					"OCI and URL sources cannot both be specified"))
		}
		if spec.Template.Code.GoPluginSource.OCI != nil {
			if spec.Template.Code.GoPluginSource.OCI.Repo == "" {
				errs = append(errs,
					field.Required(field.NewPath("spec").Child("template").Child("code").Child("goPluginSource").Child("oci").Child("repo"),
						"OCI repository must be specified"))
			}
			if spec.Template.Code.GoPluginSource.OCI.Credentials != nil && spec.Template.Code.GoPluginSource.OCI.CredentialsRef != nil {
				errs = append(errs,
					field.Forbidden(field.NewPath("spec").Child("template").Child("code").Child("goPluginSource").Child("oci"),
						"credentials and credentialsRef cannot both be specified"))
			}
		}
	} else if spec.Template.Code.JsSource != nil {
		if spec.Template.Code.GoPluginSource != nil || spec.Template.Code.WasmSource != nil {
			errs = append(errs,
				field.Forbidden(field.NewPath("spec").Child("template").Child("code"),
					"goPluginSource and wasmSource cannot be specified when jsSource is specified"))
		}

		if spec.Template.Code.JsSource.Assets == nil && spec.Template.Code.JsSource.Git == nil && spec.Template.Code.JsSource.Npm == nil {
			errs = append(errs,
				field.Required(field.NewPath("spec").Child("template").Child("code").Child("jsSource"),
					"assets, git, or npm source must be specified"))
		}

		if spec.Template.Code.JsSource.Assets != nil && spec.Template.Code.JsSource.Git != nil {
			errs = append(errs,
				field.Forbidden(field.NewPath("spec").Child("template").Child("code").Child("jsSource"),
					"assets and git sources cannot both be specified"))
		}
		if spec.Template.Code.JsSource.Assets != nil && spec.Template.Code.JsSource.Npm != nil {
			errs = append(errs,
				field.Forbidden(field.NewPath("spec").Child("template").Child("code").Child("jsSource"),
					"assets and npm sources cannot both be specified"))
		}
		if spec.Template.Code.JsSource.Git != nil && spec.Template.Code.JsSource.Npm != nil {
			errs = append(errs,
				field.Forbidden(field.NewPath("spec").Child("template").Child("code").Child("jsSource"),
					"git and npm sources cannot both be specified"))
		}

		if spec.Template.Code.JsSource.Assets != nil {
			for i, f := range spec.Template.Code.JsSource.Assets.Files {
				if f.Path == "" {
					errs = append(errs,
						field.Required(field.NewPath("spec").Child("template").Child("code").Child("jsSource").Child("assets").Child("files").Index(i).Child("path"),
							"path must be specified"))
				}
				if f.Content == "" {
					errs = append(errs,
						field.Required(field.NewPath("spec").Child("template").Child("code").Child("jsSource").Child("assets").Child("files").Index(i).Child("content"),
							"content must be specified"))
				}

				cleanPath := filepath.Clean(f.Path)
				if cleanPath != f.Path && strings.Contains(cleanPath, "..") {
					errs = append(errs,
						field.Invalid(field.NewPath("spec").Child("template").Child("code").Child("jsSource").Child("assets").Child("files").Index(i).Child("path"),
							f.Path,
							"path segment cannot contain '..'"))
				}
				if filepath.IsAbs(f.Path) {
					errs = append(errs,
						field.Invalid(field.NewPath("spec").Child("template").Child("code").Child("jsSource").Child("assets").Child("files").Index(i).Child("path"),
							f.Path,
							"path must be relative"))
				}
			}
		}
	}

	return errs
}

func (r *EdgeFunction) Validate(ctx context.Context) field.ErrorList {
	return r.validate()
}

func (r *EdgeFunction) ValidateUpdate(ctx context.Context, obj runtime.Object) field.ErrorList {
	fun := obj.(*EdgeFunction)
	return fun.validate()
}
