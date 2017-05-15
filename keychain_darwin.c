#import <Foundation/Foundation.h>
#import <Security/Security.h>

char *get_error(OSStatus status) {
    char *buf = malloc(128);
    CFStringRef str = SecCopyErrorMessageString(status, NULL);
    int success = CFStringGetCString(str, buf, 128, kCFStringEncodingUTF8);
    if (!success) {
        strncpy(buf, "Unknown error", 128);
    }
    return buf;
}

char *keychain_add(char *service, char *account, char *pass) {
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

char *keychain_find(char *service, char *account, unsigned int *length, char **password) {
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

char *keychain_remove(char *service, char *account) {
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
