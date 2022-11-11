package userpass

import (
	"context"
	"time"

	sockaddr "github.com/hashicorp/go-sockaddr"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/tokenutil"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathUsersList(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "users/?",

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.pathUserList,
		},

		HelpSynopsis:    pathUserHelpSyn,
		HelpDescription: pathUserHelpDesc,
		DisplayAttrs: &framework.DisplayAttributes{
			Navigation: true,
			ItemType:   "User",
		},
	}
}

func pathUsers(b *backend) *framework.Path {
	p := &framework.Path{
		Pattern: "users/" + framework.GenericNameRegex("username"),
		Fields: map[string]*framework.FieldSchema{
			"username": {
				Type:        framework.TypeString,
				Description: "Username for this user.",
			},

			"password": {
				Type:        framework.TypeString,
				Description: "Password for this user.",
				DisplayAttrs: &framework.DisplayAttributes{
					Sensitive: true,
				},
			},

			"policies": {
				Type:        framework.TypeCommaStringSlice,
				Description: tokenutil.DeprecationText("token_policies"),
				Deprecated:  true,
			},

			"ttl": {
				Type:        framework.TypeDurationSecond,
				Description: tokenutil.DeprecationText("token_ttl"),
				Deprecated:  true,
			},

			"max_ttl": {
				Type:        framework.TypeDurationSecond,
				Description: tokenutil.DeprecationText("token_max_ttl"),
				Deprecated:  true,
			},

			"bound_cidrs": {
				Type:        framework.TypeCommaStringSlice,
				Description: tokenutil.DeprecationText("token_bound_cidrs"),
				Deprecated:  true,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.DeleteOperation: b.pathUserDelete,
			logical.ReadOperation:   b.pathUserRead,
			logical.UpdateOperation: b.pathUserWrite,
			logical.CreateOperation: b.pathUserWrite,
		},

		ExistenceCheck: b.userExistenceCheck,

		HelpSynopsis:    pathUserHelpSyn,
		HelpDescription: pathUserHelpDesc,
		DisplayAttrs: &framework.DisplayAttributes{
			Action:   "Create",
			ItemType: "User",
		},
	}

	tokenutil.AddTokenFields(p.Fields)
	return p
}

func (b *backend) userExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	panic("not implement")
}

func (b *backend) user(ctx context.Context, s logical.Storage, username string) (*UserEntry, error) {
	panic("not implement")
}

func (b *backend) setUser(ctx context.Context, s logical.Storage, username string, userEntry *UserEntry) error {
	panic("not implement")
}

func (b *backend) pathUserList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	panic("not implement")
}

func (b *backend) pathUserDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	panic("not implement")
}

func (b *backend) pathUserRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	panic("not implement")
}

func (b *backend) userCreateUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	panic("not implement")
}

func (b *backend) pathUserWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	panic("not implement")
}

type UserEntry struct {
	tokenutil.TokenParams

	Password string

	PasswordHash []byte

	Policies []string

	TTL time.Duration

	MaxTTL time.Duration

	BoundCIDRs []*sockaddr.SockAddrMarshaler
}

const pathUserHelpSyn = `
Manage users allowed to authenticate.
`

const pathUserHelpDesc = `
This endpoint allows you to create, read, update, and delete users
that are allowed to authenticate.

Deleting a user will not revoke auth for prior authenticated users
with that name. To do this, do a revoke on "login/<username>" for
the username you want revoked. If you don't need to revoke login immediately,
then the next renew will cause the lease to expire.
`
