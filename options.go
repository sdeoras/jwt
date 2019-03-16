package jwt

import "time"

const (
	optLifeSpan int = iota
	optEnforceExpiry
)

type Option interface {
	GetValue() interface{}
}

type option struct {
	optionType int
	value      interface{}
}

func (o *option) GetValue() interface{} {
	return o.value
}

func SetLifeSpan(dur time.Duration) Option {
	return &option{
		optionType: optLifeSpan,
		value:      dur,
	}
}

func EnforceExpiration() Option {
	return &option{
		optionType: optEnforceExpiry,
	}
}
