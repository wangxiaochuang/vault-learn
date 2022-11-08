package token

type TokenHelper interface {
	Path() string
	Erase() error
	Get() (string, error)
	Store(string) error
}
