package apiserver

import (
	"context"
	"testing"

	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

func TestSimpleAuthAuthorizer(t *testing.T) {
	denyBob := authorizer.AuthorizerFunc(func(_ context.Context, a authorizer.Attributes) (authorizer.Decision, string, error) {
		if a.GetUser().GetName() == "bob" {
			return authorizer.DecisionDeny, "bob is denied", nil
		}
		return authorizer.DecisionNoOpinion, "", nil
	})

	cases := []struct {
		name  string
		authz authorizer.Authorizer
		user  string
		want  authorizer.Decision
	}{
		{name: "no authorizer allows", user: "bob", want: authorizer.DecisionAllow},
		{name: "deny is final", authz: denyBob, user: "bob", want: authorizer.DecisionDeny},
		{name: "no opinion allows", authz: denyBob, user: "alice", want: authorizer.DecisionAllow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			attrs := authorizer.AttributesRecord{User: &user.DefaultInfo{Name: tc.user}}
			got, _, err := simpleAuthAuthorizer(tc.authz).Authorize(context.Background(), attrs)
			if err != nil {
				t.Fatalf("Authorize() error = %v", err)
			}
			if got != tc.want {
				t.Fatalf("Authorize() = %v, want %v", got, tc.want)
			}
		})
	}
}
