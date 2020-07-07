package ssh

import "errors"

var ErrAuthNotAllowed = errors.New("auth not allowed")
var ErrHostKeyIsDirectory = errors.New("host key is directory")

var ErrUnknownFingerprint = errors.New("invalid fingerprints")
var ErrForwardAlreadyBinded = errors.New("forward already binded")
var ErrForwardNotFound = errors.New("forward not found")
