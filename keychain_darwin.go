package keychain

import (
	"errors"
	"unsafe"
)

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Security -framework Foundation

#include <stdlib.h>

extern char *keychain_add(char *service, char *account, char *pass);
extern char *keychain_find(char *service, char *account, unsigned int *length, char **password);
extern char *keychain_remove(char *service, char *account);
*/
import "C"

func Add(service, account, pass string) error {
	errMsg := C.keychain_add(C.CString(service), C.CString(account), C.CString(pass))
	if errMsg != nil {
		defer C.free(unsafe.Pointer(errMsg))
		return errors.New(C.GoString(errMsg))
	}
	return nil
}

func Find(service, account string) (string, error) {
	var length C.uint
	var password *C.char

	errMsg := C.keychain_find(C.CString(service), C.CString(account), &length, &password)
	defer C.free(unsafe.Pointer(password))
	if errMsg != nil {
		defer C.free(unsafe.Pointer(errMsg))
		return "", errors.New(C.GoString(errMsg))
	}
	pass := C.GoStringN(password, C.int(length))
	return pass, nil
}

func Remove(service, account string) error {
	errMsg := C.keychain_remove(C.CString(service), C.CString(account))
	if errMsg != nil {
		defer C.free(unsafe.Pointer(errMsg))
		return errors.New(C.GoString(errMsg))
	}
	return nil
}
