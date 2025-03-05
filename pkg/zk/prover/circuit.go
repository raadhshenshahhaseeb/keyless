package circuit

type Circuit interface {
}

type circuit struct{}

func New() Circuit {
	return &circuit{}
}

func (c *circuit) Validate(circuit Circuit) bool {
	return true
}
