#import <Foundation/Foundation.h>
#import <Security/Security.h>

char *get_error(OSStatus status) {
    char *buf = malloc(128);
    CFStringRef str = SecCopyErrorMessageString(status, NULL);
    int success = CFStringGetCString(str, buf, 128, kCFStringEncodingUTF8);
    if (success) {
        strncpy(buf, "Unknown error", 128);
    }
    return buf;
}

char *keychain_add_internet(char *service, char *domain, char *account,
      char *path, int port, int protocol, int auth_mech, char *pass) {
    int domain_length = strlen(domain);
    int path_length = strlen(path);
    if(domain_length == 0) domain = NULL;
    if(path_length == 0) path = NULL;

    OSStatus status = SecKeychainAddInternetPassword(
        NULL,
        strlen(service), service,
        domain_length, domain,
        strlen(account), account,
        path_length, path,
        port, protocol, auth_mech,
        strlen(pass), pass,
        NULL
    );
    if (status) return get_error(status);
    return NULL;
}

char *keychain_add_generic(char *service, char *account, char *pass) {
    OSStatus status = SecKeychainAddGenericPassword(
        NULL,
        strlen(service), service,
        strlen(account), account,
        strlen(pass), pass,
        NULL
    );
    if (status) return get_error(status);
    return NULL;
}


char *keychain_find_internet(char *service, char *domain, char *account, char *path, int port, int protocol, int auth_mech, unsigned int *length, char **password) {
    if (length == NULL || password == NULL) {
        return strdup("length == NULL || password == NULL");
    }
    SecKeychainItemRef item;
    char *tmp;
    int domain_length = strlen(domain);
    int path_length = strlen(path);
    if(domain_length == 0) domain = NULL;
    if(path_length == 0) path = NULL;

    OSStatus status = SecKeychainFindInternetPassword(
        NULL, // keychain, NULL is user's
        strlen(service), service, // service (aka hostname)
        domain_length, domain, // length and securityDomain, NULL to ignore
        strlen(account), account, // account (aka username)
        path_length, path, // length and path, NULL to ignore
        port, // TCP port number, 0 to ignore
        protocol, // protocol (eg https, ssh), "TypeAny" is wildcard
        auth_mech, // auth mechanism, eg HTTP Basic or NTLM
        length, (void **)&tmp,
        NULL
    );
    if (status) {
        *length = 0;
        return get_error(status);
    }
    *password = strdup(tmp);
    SecKeychainItemFreeContent(NULL, tmp);
    return NULL;
}

char *keychain_find_generic(char *service, char *account, unsigned int *length, char **password) {
    if (length == NULL || password == NULL) {
        return strdup("length == NULL || password == NULL");
    }
    SecKeychainItemRef item;
    char *tmp;
    OSStatus status = SecKeychainFindGenericPassword(
        NULL,
        strlen(service), service,
        strlen(account), account,
        length, (void **)&tmp,
        NULL
    );
    if (status) {
        *length = 0;
        return get_error(status);
    }
    *password = strdup(tmp);
    SecKeychainItemFreeContent(NULL, tmp);
    return NULL;
}

char *keychain_remove_generic(char *service, char *account) {
    SecKeychainItemRef item;
    OSStatus status = SecKeychainFindGenericPassword(
        NULL,
        strlen(service), service,
        strlen(account), account,
        NULL, NULL,
        &item
    );
    if (status) return get_error(status);

    status = SecKeychainItemDelete(item);
    if (status) return get_error(status);
    return NULL;
}

char *keychain_remove_internet(char *service, char *domain, char *account, char *path, int port, int protocol, int auth_mech) {
    SecKeychainItemRef item;

    int domain_length = strlen(domain);
    int path_length = strlen(path);
    if(domain_length == 0) domain = NULL;
    if(path_length == 0) path = NULL;

    OSStatus status = SecKeychainFindInternetPassword(
        NULL, // keychain, NULL is user's
        strlen(service), service, // service (aka hostname)
        domain_length, domain, // length and securityDomain, NULL to ignore
        strlen(account), account, // account (aka username)
        path_length, path, // length and path, NULL to ignore
        port, // TCP port number, 0 to ignore
        protocol, // protocol (eg https, ssh), "TypeAny" is wildcard
        auth_mech, // auth mechanism, eg HTTP Basic or NTLM
        NULL, NULL,
        &item
    );
    if (status) return get_error(status);

    status = SecKeychainItemDelete(item);
    if (status) return get_error(status);
    return NULL;
}
