package logical

type Request struct {
}

// p356
type Operation string

// p380
type InitializationRequest struct {
	Storage Storage
}
