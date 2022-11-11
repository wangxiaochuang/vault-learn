package userpass

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/tokenutil"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathUserPolicies(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "users/" + framework.GenericNameRegex("username") + "/policies$",
		Fields: map[string]*framework.FieldSchema{
			"username": {
				Type:        framework.TypeString,
				Description: "Username for this user.",
			},
			"policies": {
				Type:        framework.TypeCommaStringSlice,
				Description: tokenutil.DeprecationText("token_policies"),
				Deprecated:  true,
			},
			"token_policies": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Comma-separated list of policies",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathUserPoliciesUpdate,
		},

		HelpSynopsis:    pathUserPoliciesHelpSyn,
		HelpDescription: pathUserPoliciesHelpDesc,
	}
}

func (b *backend) pathUserPoliciesUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	panic("not implement")
}

const pathUserPoliciesHelpSyn = `
Update the policies associated with the username.
`

const pathUserPoliciesHelpDesc = `
This endpoint allows updating the policies associated with the username.
`
