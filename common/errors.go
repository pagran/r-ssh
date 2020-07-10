package common

import "errors"

var ErrAuthNotAllowed = errors.New("auth not allowed")
var ErrHostKeyIsDirectory = errors.New("host key is directory")

var ErrUnknownRequestType = errors.New("unknown request type")
var ErrForwardAlreadyBinded = errors.New("forward already binded")
var ErrForwardNotFound = errors.New("forward not found")
var ErrDomainNotAllowed = errors.New("domain not allowed")
