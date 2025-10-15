package v1alpha1

import (
	"github.com/apoxy-dev/apoxy/api/extensions/v1alpha2"
)

func convertSpecFromV1Alpha1ToV1Alpha2(spec *EdgeFunctionSpec) (*v1alpha2.EdgeFunctionRevisionSpec, error) {
	v1alpha2Spec := &v1alpha2.EdgeFunctionRevisionSpec{
		Mode: v1alpha2.EdgeFunctionMode(spec.Mode),
		Env:  make([]v1alpha2.EnvVar, len(spec.Env)),
	}
	for i, e := range spec.Env {
		v1alpha2Spec.Env[i] = v1alpha2.EnvVar{
			Name:  e.Name,
			Value: e.Value,
		}
	}
	if spec.Runtime != nil {
		v1alpha2Spec.Runtime = &v1alpha2.EdgeFunctionRuntime{
			Timeout: spec.Runtime.Timeout,
			Port:    spec.Runtime.Port,
		}
		if spec.Runtime.Capabilities != nil {
			v1alpha2Spec.Runtime.Capabilities = &v1alpha2.RuntimeCapabilities{
				FetchAPI: spec.Runtime.Capabilities.FetchAPI,
				KV:       spec.Runtime.Capabilities.KV,
			}
		}
	}
	if spec.Code.GoPluginSource != nil {
		v1alpha2Spec.Code.GoPluginSource = &v1alpha2.GoPluginSource{}
		if spec.Code.GoPluginSource.URL != nil {
			v1alpha2Spec.Code.GoPluginSource.URL = spec.Code.GoPluginSource.URL
		} else if spec.Code.GoPluginSource.OCI != nil {
			v1alpha2Spec.Code.GoPluginSource.OCI = &v1alpha2.OCIImageRef{
				Repo: spec.Code.GoPluginSource.OCI.Repo,
				Tag:  spec.Code.GoPluginSource.OCI.Tag,
			}
			if spec.Code.GoPluginSource.OCI.Credentials != nil {
				v1alpha2Spec.Code.GoPluginSource.OCI.Credentials = &v1alpha2.OCICredentials{
					Username: spec.Code.GoPluginSource.OCI.Credentials.Username,
					Password: spec.Code.GoPluginSource.OCI.Credentials.Password,
				}
			}
		}
	}
	if spec.Code.JsSource != nil {
		v1alpha2Spec.Code.JsSource = &v1alpha2.JavaScriptSource{
			Entrypoint: spec.Code.JsSource.Entrypoint,
		}
		if spec.Code.JsSource.Assets != nil {
			v1alpha2Spec.Code.JsSource.Assets = &v1alpha2.JavaScriptAssetsSource{
				Files: make([]v1alpha2.SourceFile, len(spec.Code.JsSource.Assets.Files)),
			}
			for i, f := range spec.Code.JsSource.Assets.Files {
				v1alpha2Spec.Code.JsSource.Assets.Files[i] = v1alpha2.SourceFile{
					Path:    f.Path,
					Content: f.Content,
				}
			}
		} else if spec.Code.JsSource.Git != nil {
			v1alpha2Spec.Code.JsSource.Git = &v1alpha2.JavaScriptGitSource{
				Repository: spec.Code.JsSource.Git.Repository,
				Branch:     spec.Code.JsSource.Git.Branch,
				Commit:     spec.Code.JsSource.Git.Commit,
			}
		} else if spec.Code.JsSource.Npm != nil {
			v1alpha2Spec.Code.JsSource.Npm = &v1alpha2.JavaScriptNpmSource{
				Package: spec.Code.JsSource.Npm.Package,
				Version: spec.Code.JsSource.Npm.Version,
			}
		}
	}

	return v1alpha2Spec, nil
}

func convertSpecFromV1Alpha2ToV1Alpha1(spec *v1alpha2.EdgeFunctionRevisionSpec) (*EdgeFunctionSpec, error) {
	v1alpha1Spec := &EdgeFunctionSpec{
		Mode: EdgeFunctionMode(spec.Mode),
		Env:  make([]EnvVar, len(spec.Env)),
	}
	for i, e := range spec.Env {
		v1alpha1Spec.Env[i] = EnvVar{
			Name:  e.Name,
			Value: e.Value,
		}
	}
	if spec.Runtime != nil {
		v1alpha1Spec.Runtime = &EdgeFunctionRuntime{
			Timeout: spec.Runtime.Timeout,
			Port:    spec.Runtime.Port,
		}
		if spec.Runtime.Capabilities != nil {
			v1alpha1Spec.Runtime.Capabilities = &RuntimeCapabilities{
				FetchAPI: spec.Runtime.Capabilities.FetchAPI,
				KV:       spec.Runtime.Capabilities.KV,
			}
		}
	}
	if spec.Code.GoPluginSource != nil {
		v1alpha1Spec.Code.GoPluginSource = &GoPluginSource{}
		if spec.Code.GoPluginSource.URL != nil {
			v1alpha1Spec.Code.GoPluginSource.URL = spec.Code.GoPluginSource.URL
		} else if spec.Code.GoPluginSource.OCI != nil {
			v1alpha1Spec.Code.GoPluginSource.OCI = &OCIImageRef{
				Repo: spec.Code.GoPluginSource.OCI.Repo,
				Tag:  spec.Code.GoPluginSource.OCI.Tag,
			}
			if spec.Code.GoPluginSource.OCI.Credentials != nil {
				v1alpha1Spec.Code.GoPluginSource.OCI.Credentials = &OCICredentials{
					Username: spec.Code.GoPluginSource.OCI.Credentials.Username,
					Password: spec.Code.GoPluginSource.OCI.Credentials.Password,
				}
			}
		}
	}
	if spec.Code.JsSource != nil {
		v1alpha1Spec.Code.JsSource = &JavaScriptSource{
			Entrypoint: spec.Code.JsSource.Entrypoint,
		}
		if spec.Code.JsSource.Assets != nil {
			v1alpha1Spec.Code.JsSource.Assets = &JavaScriptAssetsSource{
				Files: make([]SourceFile, len(spec.Code.JsSource.Assets.Files)),
			}
			for i, f := range spec.Code.JsSource.Assets.Files {
				v1alpha1Spec.Code.JsSource.Assets.Files[i] = SourceFile{
					Path:    f.Path,
					Content: f.Content,
				}
			}
		} else if spec.Code.JsSource.Git != nil {
			v1alpha1Spec.Code.JsSource.Git = &JavaScriptGitSource{
				Repository: spec.Code.JsSource.Git.Repository,
				Branch:     spec.Code.JsSource.Git.Branch,
				Commit:     spec.Code.JsSource.Git.Commit,
			}
		} else if spec.Code.JsSource.Npm != nil {
			v1alpha1Spec.Code.JsSource.Npm = &JavaScriptNpmSource{
				Package: spec.Code.JsSource.Npm.Package,
				Version: spec.Code.JsSource.Npm.Version,
			}
		}
	}

	return v1alpha1Spec, nil
}

func convertEdgeFunctionStatusFromV1Alpha2ToV1Alpha1(status *v1alpha2.EdgeFunctionStatus) *EdgeFunctionStatus {
	return &EdgeFunctionStatus{
		LiveRevision: status.LiveRevision,
		Conditions:   status.Conditions,
	}
}

func convertEdgeFunctionStatusFromV1Alpha1ToV1Alpha2(status *EdgeFunctionStatus) *v1alpha2.EdgeFunctionStatus {
	return &v1alpha2.EdgeFunctionStatus{
		LiveRevision: status.LiveRevision,
		Conditions:   status.Conditions,
	}
}

func convertEdgeFunctionRevisionStatusFromV1Alpha2ToV1Alpha1(status *v1alpha2.EdgeFunctionRevisionStatus) *EdgeFunctionRevisionStatus {
	return &EdgeFunctionRevisionStatus{
		Ref:        status.Ref,
		Conditions: status.Conditions,
	}
}

func convertEdgeFunctionRevisionStatusFromV1Alpha1ToV1Alpha2(status *EdgeFunctionRevisionStatus) *v1alpha2.EdgeFunctionRevisionStatus {
	return &v1alpha2.EdgeFunctionRevisionStatus{
		Ref:        status.Ref,
		Conditions: status.Conditions,
	}
}
