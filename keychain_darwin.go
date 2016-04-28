package keychain

import (
	"errors"
	"strings"
	"unsafe"
)

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Security -framework Foundation

#include <stdlib.h>
#include <security/security.h>

extern char *keychain_add_generic(char *service, char *account, char *pass);

extern char *keychain_find_generic(char *service, char *account, unsigned int *length, char **password);

extern char *keychain_remove_generic(char *service, char *account);

extern char *keychain_add_internet(char *service, char *domain, char *account, char *path, int port, int protocol, int auth_mech, char *pass);

extern char *keychain_find_internet(char *service, char *domain, char *account, char *path, int port, int protocol, int auth_mech, unsigned int *length, char **password);

extern char *keychain_remove_internet(char *service, char *domain, char *account, char *path, int port, int protocol, int auth_mech);
*/
import "C"

var auth_mechs = map[string]int{
	"ntlm":     C.kSecAuthenticationTypeNTLM,
	"msn":      C.kSecAuthenticationTypeMSN,
	"msna":     C.kSecAuthenticationTypeMSN,
	"dpa":      C.kSecAuthenticationTypeDPA,
	"dpaa":     C.kSecAuthenticationTypeDPA,
	"rpa":      C.kSecAuthenticationTypeRPA,
	"rpaa":     C.kSecAuthenticationTypeRPA,
	"basic":    C.kSecAuthenticationTypeHTTPBasic,
	"http":     C.kSecAuthenticationTypeHTTPBasic,
	"digest":   C.kSecAuthenticationTypeHTTPDigest,
	"httd":     C.kSecAuthenticationTypeHTTPDigest,
	"htmlform": C.kSecAuthenticationTypeHTMLForm,
	"form":     C.kSecAuthenticationTypeHTMLForm,
	"default":  C.kSecAuthenticationTypeDefault,
	"any":      C.kSecAuthenticationTypeAny,
	"*":        C.kSecAuthenticationTypeAny,
	"":         C.kSecAuthenticationTypeAny,
}

var protocols = map[string]int{
	"ftp":        C.kSecProtocolTypeFTP,
	"http":       C.kSecProtocolTypeHTTP,
	"irc":        C.kSecProtocolTypeIRC,
	"nntp":       C.kSecProtocolTypeNNTP,
	"pop3":       C.kSecProtocolTypePOP3,
	"smtp":       C.kSecProtocolTypeSMTP,
	"socks":      C.kSecProtocolTypeSOCKS,
	"imap":       C.kSecProtocolTypeIMAP,
	"ldap":       C.kSecProtocolTypeLDAP,
	"appletalk":  C.kSecProtocolTypeAppleTalk,
	"afp":        C.kSecProtocolTypeAFP,
	"telnet":     C.kSecProtocolTypeTelnet,
	"ssh":        C.kSecProtocolTypeSSH,
	"ftps":       C.kSecProtocolTypeFTPS,
	"https":      C.kSecProtocolTypeHTTPS,
	"httpproxy":  C.kSecProtocolTypeHTTPProxy,
	"httpsproxy": C.kSecProtocolTypeHTTPSProxy,
	"ftpproxy":   C.kSecProtocolTypeFTPProxy,
	"cifs":       C.kSecProtocolTypeCIFS,
	"smb":        C.kSecProtocolTypeSMB,
	"rtsp":       C.kSecProtocolTypeRTSP,
	"rtspproxy":  C.kSecProtocolTypeRTSPProxy,
	"daap":       C.kSecProtocolTypeDAAP,
	"eppc":       C.kSecProtocolTypeEPPC,
	"ipp":        C.kSecProtocolTypeIPP,
	"nntps":      C.kSecProtocolTypeNNTPS,
	"ldaps":      C.kSecProtocolTypeLDAPS,
	"telnets":    C.kSecProtocolTypeTelnetS,
	"imaps":      C.kSecProtocolTypeIMAPS,
	"ircs":       C.kSecProtocolTypeIRCS,
	"pop3s":      C.kSecProtocolTypePOP3S,
	"cvspserver": C.kSecProtocolTypeCVSpserver,
	"svn":        C.kSecProtocolTypeSVN,
	"any":        C.kSecProtocolTypeAny,
	"*":          C.kSecProtocolTypeAny,
	"":           C.kSecProtocolTypeAny,
}

func Add(service, account, pass string) error {
	errMsg := C.keychain_add_generic(C.CString(service), C.CString(account), C.CString(pass))
	if errMsg != nil {
		defer C.free(unsafe.Pointer(errMsg))
		return errors.New(C.GoString(errMsg))
	}
	return nil
}

func AddInternetPassword(service string, account string, domain string,
	path string, port int, protocol string,
	auth_mech string, pass string) error {
	errMsg := C.keychain_add_internet(C.CString(service), C.CString(domain),
		C.CString(account), C.CString(path), C.int(port), 0,
		C.kSecAuthenticationTypeDefault, C.CString(pass))
	if errMsg != nil {
		defer C.free(unsafe.Pointer(errMsg))
		return errors.New(C.GoString(errMsg))
	}
	return nil
}

func Find(service, account string) (string, error) {
	var length C.uint
	var password *C.char

	errMsg := C.keychain_find_generic(C.CString(service), C.CString(account), &length, &password)
	defer C.free(unsafe.Pointer(password))
	if errMsg != nil {
		defer C.free(unsafe.Pointer(errMsg))
		return "", errors.New(C.GoString(errMsg))
	}
	pass := C.GoStringN(password, C.int(length))
	return pass, nil
}

func FindInternetPassword(service string, account string, domain string,
	path string, port int, protocol string,
	auth_mech string) (string, error) {

	var length C.uint
	var password *C.char

	errMsg := C.keychain_find_internet(C.CString(service),
		C.CString(domain),
		C.CString(account),
		C.CString(path),
		C.int(port),
		C.int(protocols[strings.ToLower(protocol)]),
		C.int(auth_mechs[strings.ToLower(auth_mech)]),
		&length, &password)
	defer C.free(unsafe.Pointer(password))
	if errMsg != nil {
		defer C.free(unsafe.Pointer(errMsg))
		return "", errors.New(C.GoString(errMsg))
	}
	pass := C.GoStringN(password, C.int(length))
	return pass, nil
}

func Remove(service, account string) error {
	errMsg := C.keychain_remove_generic(C.CString(service), C.CString(account))
	if errMsg != nil {
		defer C.free(unsafe.Pointer(errMsg))
		return errors.New(C.GoString(errMsg))
	}
	return nil
}

func RemoveInternetPassword(service string, account string, domain string,
	path string, port int, protocol string,
	auth_mech string, pass string) error {
	errMsg := C.keychain_remove_internet(C.CString(service),
		C.CString(domain),
		C.CString(account),
		C.CString(path),
		C.int(port),
		C.int(protocols[strings.ToLower(protocol)]),
		C.int(auth_mechs[strings.ToLower(auth_mech)]))
	if errMsg != nil {
		defer C.free(unsafe.Pointer(errMsg))
		return errors.New(C.GoString(errMsg))
	}
	return nil
}
