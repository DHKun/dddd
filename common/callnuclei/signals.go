package callnuclei

import (
	"os"
)

func interruptSignals() []os.Signal {
	return []os.Signal{os.Interrupt}
}
