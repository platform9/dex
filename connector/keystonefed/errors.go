package keystonefed

import "fmt"

type configError string

func (e configError) Error() string { return string(e) }

func errf(format string, a ...interface{}) error {
	return configError(fmt.Sprintf(format, a...))
}
