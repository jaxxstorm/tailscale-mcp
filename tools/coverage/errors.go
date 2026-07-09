package mcpcoverage

import "errors"

var ErrMutatingResource = errors.New("mutating operations cannot be mapped as resources")
