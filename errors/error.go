package errors

import "errors"

type SignatureError struct {
	err  string
	code int
}

func NewSignatureError(err string, code int) *SignatureError {
	return &SignatureError{
		err:  err,
		code: code,
	}
}
func (e *SignatureError) Error() string {
	return e.err
}
func (e *SignatureError) Code() int {
	return e.code
}

func SignatureCryptError(message string) error {
	return errors.New(message)
}
