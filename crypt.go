package main

import (
	"sync"
	"unsafe"
)

/*
#cgo LDFLAGS: -lcrypt
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
*/
import "C"

var (
	mu sync.Mutex
)

// Will Use the LibCrypt and will crypt a password and a salt.
func crypt(password, salt string) (string, error) {
	cPassword := C.CString(password)
	defer C.free(unsafe.Pointer(cPassword))

	cSalt := C.CString(salt)
	defer C.free(unsafe.Pointer(cSalt))

	mu.Lock()
	cEncrypted, err := C.crypt(cPassword, cSalt)
	mu.Unlock()

	if cEncrypted == nil {
		return "", err
	}

	return C.GoString(cEncrypted), err

}
