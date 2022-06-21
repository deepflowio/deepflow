package utils

type Closable bool

func (c *Closable) Close() error {
	*c = Closable(true)
	return nil
}

func (c *Closable) Closed() bool {
	return bool(*c)
}
