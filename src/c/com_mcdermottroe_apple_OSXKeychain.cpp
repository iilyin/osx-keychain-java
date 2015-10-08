/*
 * Copyright (c) 2011, Conor McDermottroe
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <Security/Security.h>

#include "com_mcdermottroe_apple_OSXKeychain.h"
#include <string.h>
#include <strings.h>
#include <stdio.h>

#define OSXKeychainException "com/mcdermottroe/apple/OSXKeychainException"

/* A simplified structure for dealing with jstring objects. Use jstring_unpack
 * and jstring_unpacked_free to manage these.
 */
typedef struct {
	int len;
	const char* str;
} jstring_unpacked;

/* Throw an exception.
 *
 * Parameters:
 *	env				The JNI environment.
 *	exceptionClass	The name of the exception class.
 *	message			The message to pass to the Exception.
 */
void throw_exception(JNIEnv* env, const char* exceptionClass, const char* message) {
	jclass cls = env->FindClass(exceptionClass);
	/* if cls is NULL, an exception has already been thrown */
	if (cls != NULL) {
		env->ThrowNew(cls, message);
	}
	/* free the local ref, utility funcs must delete local refs. */
	env->DeleteLocalRef(cls);
}

/* Shorthand for throwing an OSXKeychainException from an OSStatus.
 *
 * Parameters:
 *	env		The JNI environment.
 *	status	The non-error status returned from a keychain call.
 */
void throw_osxkeychainexception(JNIEnv* env, OSStatus status) {
	CFStringRef errorMessage = SecCopyErrorMessageString(status, NULL);
	throw_exception(
		env,
		OSXKeychainException,
		CFStringGetCStringPtr(errorMessage, kCFStringEncodingMacRoman)
	);
	CFRelease(errorMessage);
}

/* Unpack the data from a jstring and put it in a jstring_unpacked.
 *
 * Parameters:
 *	env	The JNI environment.
 *	js	The jstring to unpack.
 *	ret	The jstring_unpacked in which to store the result.
 */
void jstring_unpack(JNIEnv* env, jstring js, jstring_unpacked* ret) {
	if (ret == NULL) {
		return;
	}
	if (env == NULL || js == NULL) {
		ret->len = 0;
		ret->str = NULL;
		return;
	}

	/* Get the length of the string. */
	ret->len = (int)(env->GetStringUTFLength(js));
	if (ret->len <= 0) {
		ret->len = 0;
		ret->str = NULL;
		return;
	}
	ret->str = env->GetStringUTFChars(js, NULL);
}

/* Clean up a jstring_unpacked after it's no longer needed.
 *
 * Parameters:
 *	jsu	A jstring_unpacked structure to clean up.
 */
void jstring_unpacked_free(JNIEnv *env, jstring js, jstring_unpacked* jsu) {
	if (jsu != NULL && jsu->str != NULL) {
		env->ReleaseStringUTFChars(js, jsu->str);
		jsu->len = 0;
		jsu->str = NULL;
	}
}

/* Implementation of OSXKeychain.addGenericPassword(). See the Java docs for
 * explanations of the parameters.
 */
JNIEXPORT void JNICALL Java_com_mcdermottroe_apple_OSXKeychain__1addGenericPassword(JNIEnv* env, jobject obj, jstring serviceName, jstring accountName, jstring password) {
	OSStatus status;
	jstring_unpacked service_name;
	jstring_unpacked account_name;
	jstring_unpacked service_password;

	/* Unpack the params */
	jstring_unpack(env, serviceName, &service_name);
	jstring_unpack(env, accountName, &account_name);
	jstring_unpack(env, password, &service_password);
	/* check for allocation failures */
	if (service_name.str == NULL || 
	    account_name.str == NULL || 
		service_password.str == NULL) {
		jstring_unpacked_free(env, serviceName, &service_name);
		jstring_unpacked_free(env, accountName, &account_name);
		jstring_unpacked_free(env, password, &service_password);
		return;
	}

	/* Add the details to the keychain. */
	status = SecKeychainAddGenericPassword(
		NULL,
		service_name.len,
		service_name.str,
		account_name.len,
		account_name.str,
		service_password.len,
		service_password.str,
		NULL
	);
	if (status != errSecSuccess) {
		throw_osxkeychainexception(env, status);
	}

	/* Clean up. */
	jstring_unpacked_free(env, serviceName, &service_name);
	jstring_unpacked_free(env, accountName, &account_name);
	jstring_unpacked_free(env, password, &service_password);
}

JNIEXPORT void JNICALL Java_com_mcdermottroe_apple_OSXKeychain__1modifyGenericPassword(JNIEnv *env, jobject obj, jstring serviceName, jstring accountName, jstring password) {
	OSStatus status;
	jstring_unpacked service_name;
	jstring_unpacked account_name;
	jstring_unpacked service_password;
	SecKeychainItemRef existingItem;

	/* Unpack the params */
	jstring_unpack(env, serviceName, &service_name);
	jstring_unpack(env, accountName, &account_name);
	jstring_unpack(env, password, &service_password);
	/* check for allocation failures */
	if (service_name.str == NULL || 
	    account_name.str == NULL || 
		service_password.str == NULL) {
		jstring_unpacked_free(env, serviceName, &service_name);
		jstring_unpacked_free(env, accountName, &account_name);
		jstring_unpacked_free(env, password, &service_password);
		return;
	}

	status = SecKeychainFindGenericPassword(
		NULL,
		service_name.len,
		service_name.str,
		account_name.len,
		account_name.str,
		NULL,
		NULL,
		&existingItem
	);
	if (status != errSecSuccess) {
		throw_osxkeychainexception(env, status);
	}
	else {
		/* Update the details in the keychain. */
		status = SecKeychainItemModifyContent(
			existingItem,
			NULL,
			service_password.len,
			service_password.str
		);
		if (status != errSecSuccess) {
			throw_osxkeychainexception(env, status);
		}
	}

	/* Clean up. */
	jstring_unpacked_free(env, serviceName, &service_name);
	jstring_unpacked_free(env, accountName, &account_name);
	jstring_unpacked_free(env, password, &service_password);
}


/* Implementation of OSXKeychain.addInternetPassword(). See the Java docs for
 * explanation of the parameters.
 */
JNIEXPORT void JNICALL Java_com_mcdermottroe_apple_OSXKeychain__1addInternetPassword(JNIEnv* env, jobject obj, jstring serverName, jstring securityDomain, jstring accountName, jstring path, jint port, jint protocol, jint authenticationType, jstring password) {
	OSStatus status;
	jstring_unpacked server_name;
	jstring_unpacked security_domain;
	jstring_unpacked account_name;
	jstring_unpacked server_path;
	jstring_unpacked server_password;

	/* Unpack the string params. */
	jstring_unpack(env, serverName, &server_name);
	jstring_unpack(env, securityDomain, &security_domain);
	jstring_unpack(env, accountName, &account_name);
	jstring_unpack(env, path, &server_path);
	jstring_unpack(env, password, &server_password);
	/* check for allocation failures */
	if (server_name.str == NULL || 
	    security_domain.str == NULL ||
		account_name.str == NULL || 
		server_path.str == NULL ||
		server_password.str == NULL) {
		jstring_unpacked_free(env, serverName, &server_name);
		jstring_unpacked_free(env, securityDomain, &security_domain);
		jstring_unpacked_free(env, accountName, &account_name);
		jstring_unpacked_free(env, path, &server_path);
		jstring_unpacked_free(env, password, &server_password);
		return;
	}

	/* Add the details to the keychain. */
	status = SecKeychainAddInternetPassword(
		NULL,
		server_name.len,
		server_name.str,
		security_domain.len,
		security_domain.str,
		account_name.len,
		account_name.str,
		server_path.len,
		server_path.str,
		port,
		protocol,
		authenticationType,
		server_password.len,
		server_password.str,
		NULL
	);
	if (status != errSecSuccess) {
		throw_osxkeychainexception(env, status);
	}

	/* Clean up. */
	jstring_unpacked_free(env, serverName, &server_name);
	jstring_unpacked_free(env, securityDomain, &security_domain);
	jstring_unpacked_free(env, accountName, &account_name);
	jstring_unpacked_free(env, path, &server_path);
	jstring_unpacked_free(env, password, &server_password);
}

/* Implementation of OSXKeychain.findGenericPassword(). See the Java docs for
 * explanations of the parameters.
 */
JNIEXPORT jstring JNICALL Java_com_mcdermottroe_apple_OSXKeychain__1findGenericPassword(JNIEnv* env, jobject obj, jstring serviceName, jstring accountName) {
	OSStatus status;
	jstring_unpacked service_name;
	jstring_unpacked account_name;
	jstring result = NULL;

	/* Buffer for the return from SecKeychainFindGenericPassword. */
	void* password;
	UInt32 password_length;

	/* Query the keychain. */
	status = SecKeychainSetPreferenceDomain(kSecPreferencesDomainUser);
	if (status != errSecSuccess) {
		throw_osxkeychainexception(env, status);
		return NULL;
	}

	/* Unpack the params. */
	jstring_unpack(env, serviceName, &service_name);
	jstring_unpack(env, accountName, &account_name);
	if (service_name.str == NULL || 
	    account_name.str == NULL) {
		jstring_unpacked_free(env, serviceName, &service_name);
		jstring_unpacked_free(env, accountName, &account_name);
		return NULL;
	}
	
	status = SecKeychainFindGenericPassword(
		NULL,
		service_name.len,
		service_name.str,
		account_name.len,
		account_name.str,
		&password_length,
		&password,
		NULL
	);
	if (status != errSecSuccess) {
		throw_osxkeychainexception(env, status);
	}
	else {
		// the returned value from keychain is not 
		// null terminated, so a copy is created. 
		char *password_buffer = (char *)malloc(password_length+1);
		memcpy(password_buffer, password, password_length);
		password_buffer[password_length] = 0;

		/* Create the return value. */
		result = env->NewStringUTF(password_buffer);

		/* Clean up. */
		bzero(password_buffer, password_length);
		free(password_buffer);
		SecKeychainItemFreeContent(NULL, password);
	}
	jstring_unpacked_free(env, serviceName, &service_name);
	jstring_unpacked_free(env, accountName, &account_name);

	return result;
}

/* Implementation of OSXKeychain.findInternetPassword(). See the Java docs for
 * explanations of the parameters.
 */
JNIEXPORT jstring JNICALL Java_com_mcdermottroe_apple_OSXKeychain__1findInternetPassword(JNIEnv* env, jobject obj, jstring serverName, jstring securityDomain, jstring accountName, jstring path, jint port) {
	OSStatus status;
	jstring_unpacked server_name;
	jstring_unpacked security_domain;
	jstring_unpacked account_name;
	jstring_unpacked server_path;
	jstring result = NULL;

	/* This is the password buffer which will be used by
	 * SecKeychainFindInternetPassword
	 */
	void* password;
	UInt32 password_length;

	/* Query the keychain */
	status = SecKeychainSetPreferenceDomain(kSecPreferencesDomainUser);
	if (status != errSecSuccess) {
		throw_osxkeychainexception(env, status);
		return NULL;
	}

	/* Unpack all the jstrings into useful structures. */
	jstring_unpack(env, serverName, &server_name);
	jstring_unpack(env, securityDomain, &security_domain);
	jstring_unpack(env, accountName, &account_name);
	jstring_unpack(env, path, &server_path);
	if (server_name.str == NULL ||
		security_domain.str == NULL ||
		account_name.str == NULL || 
		server_path.str == NULL) {
		jstring_unpacked_free(env, serverName, &server_name);
		jstring_unpacked_free(env, securityDomain, &security_domain);
		jstring_unpacked_free(env, accountName, &account_name);
		jstring_unpacked_free(env, path, &server_path);		
		return NULL;
	}

	status = SecKeychainFindInternetPassword(
		NULL,
		server_name.len,
		server_name.str,
		security_domain.len,
		security_domain.str,
		account_name.len,
		account_name.str,
		server_path.len,
		server_path.str,
		port,
		kSecProtocolTypeAny,
		kSecAuthenticationTypeAny,
		&password_length,
		&password,
		NULL
	);
	if (status != errSecSuccess) {
		throw_osxkeychainexception(env, status);
	}
	else {
		// the returned value from keychain is not 
		// null terminated, so a copy is created. 
		char* password_buffer = (char *) malloc(password_length+1);
		memcpy(password_buffer, password, password_length);
		password_buffer[password_length] = 0;
		
		/* Create the return value. */
		result = env->NewStringUTF(password_buffer);

		/* Clean up. */
		bzero(password_buffer, password_length);
		free(password_buffer);
		SecKeychainItemFreeContent(NULL, password);
	}

	jstring_unpacked_free(env, serverName, &server_name);
	jstring_unpacked_free(env, securityDomain, &security_domain);
	jstring_unpacked_free(env, accountName, &account_name);
	jstring_unpacked_free(env, path, &server_path);

	return result;
}

/* Implementation of OSXKeychain.deleteGenericPassword(). See the Java docs for
 * explanations of the parameters.
 */
JNIEXPORT void JNICALL Java_com_mcdermottroe_apple_OSXKeychain__1deleteGenericPassword(JNIEnv* env, jobject obj, jstring serviceName, jstring accountName) {
	OSStatus status;
	jstring_unpacked service_name;
	jstring_unpacked account_name;
	SecKeychainItemRef itemToDelete;

	/* Query the keychain. */
	status = SecKeychainSetPreferenceDomain(kSecPreferencesDomainUser);
	if (status != errSecSuccess) {
		throw_osxkeychainexception(env, status);
		return;
	}

	/* Unpack the params. */
	jstring_unpack(env, serviceName, &service_name);
	jstring_unpack(env, accountName, &account_name);
	if (service_name.str == NULL || 
	    account_name.str == NULL) {
		jstring_unpacked_free(env, serviceName, &service_name);
		jstring_unpacked_free(env, accountName, &account_name);
		return;
	}
	status = SecKeychainFindGenericPassword(
		NULL,
		service_name.len,
		service_name.str,
		account_name.len,
		account_name.str,
		NULL,
		NULL,
		&itemToDelete
	);
	if (status != errSecSuccess) {
		throw_osxkeychainexception(env, status);
	}
	else {
		status = SecKeychainItemDelete(itemToDelete);
		if (status != errSecSuccess) {
			throw_osxkeychainexception(env, status);
		}
	}

	/* Clean up. */
	jstring_unpacked_free(env, serviceName, &service_name);
	jstring_unpacked_free(env, accountName, &account_name);
}

jboolean createKeychain(const char * keychainPath, const char *keychainPassword);
jboolean deleteKeychain(const char * keychainPath);
CFStringRef fileNameFromPath(const char *path);
jboolean importItemToKeychain(const char *keychainPath, const char *itemPath, const char *keychainPassword, const char *itemPassword);

JNIEXPORT jboolean JNICALL Java_com_mcdermottroe_apple_OSXKeychain__1createKeychain(JNIEnv* env, jobject obj, jstring keychainPath, jstring keychainPassword) {
    jstring_unpacked keychain_path;
    jstring_unpacked keychain_password;
    
    jstring_unpack(env, keychainPath, &keychain_path);
    jstring_unpack(env, keychainPassword, &keychain_password);

    jboolean result = createKeychain(keychain_path.str, keychain_password.str);
    
    /* Clean up. */
    jstring_unpacked_free(env, keychainPath, &keychain_path);
    jstring_unpacked_free(env, keychainPassword, &keychain_password);
    
    return result;
}

JNIEXPORT jboolean JNICALL Java_com_mcdermottroe_apple_OSXKeychain__1deleteKeychain
(JNIEnv *env, jobject obj, jstring keychainPath) {
    jstring_unpacked keychain_path;
    
    jstring_unpack(env, keychainPath, &keychain_path);
    
    jboolean result = deleteKeychain(keychain_path.str);
    
    /* Clean up. */
    jstring_unpacked_free(env, keychainPath, &keychain_path);
    
    return result;
}

JNIEXPORT jboolean JNICALL Java_com_mcdermottroe_apple_OSXKeychain__1importItemToKeychain
(JNIEnv *env, jobject obj, jstring keychainPath, jstring itemPath, jstring keychainPassword, jstring itemPassword)
{
    jstring_unpacked keychain_path;
    jstring_unpacked item_path;
    jstring_unpacked keychain_password;
    jstring_unpacked item_password;
    
    jstring_unpack(env, keychainPath, &keychain_path);
    jstring_unpack(env, itemPath, &item_path);
    jstring_unpack(env, keychainPassword, &keychain_password);
    jstring_unpack(env, itemPassword, &item_password);
    
    jboolean result = importItemToKeychain(keychain_path.str, item_path.str, keychain_password.str, item_password.str);
    
    /* Clean up. */
    jstring_unpacked_free(env, keychainPath, &keychain_path);
    jstring_unpacked_free(env, itemPath, &item_path);
    jstring_unpacked_free(env, keychainPassword, &keychain_password);
    jstring_unpacked_free(env, itemPassword, &item_password);
    
    return result;
}


// debug function
void console_printf(const char *fmt,...)
{
    int fd = open("/Users/iilyin/tmp/logs.log", O_WRONLY|O_APPEND);
    char buffer[1000];
    if (fd < 0)
        return;
    
    va_list ap;
    va_start(ap, fmt);
    vsprintf(buffer, fmt, ap);
    va_end(ap);
    
    write(fd, buffer, strlen(buffer));
    close(fd);
}


template<typename _T>
class CFTypePtr
{
    _T reference;
public:
    CFTypePtr() {
        reference = NULL;
    }
    
    CFTypePtr(_T ref) {
        reference = ref;
    }
    
    ~CFTypePtr()
    {
        if (reference != NULL)
            CFRelease(reference);
    }
    
    
    operator _T* (){
        return &reference;
    };
    
    operator _T& () {
        return reference;
    }
    
    CFTypePtr & operator =(_T ref) {
        reference = ref;
        return *this;
    }
    
    operator const void * ()
    {
        return reference;
    }
    
    _T val(){
        return reference;
    }
};

jboolean createKeychain(const char * keychainPath, const char *keychainPassword)
{
    //create access list to make access open to every application
    if (keychainPassword == NULL)
        keychainPassword = "";
    
    console_printf("Password %s", keychainPassword);
    
    CFTypePtr<CFStringRef> secDescr = fileNameFromPath(keychainPath);
    CFTypePtr<CFArrayRef> trustedList = CFArrayCreate(NULL, NULL, 0, NULL);
    CFTypePtr<SecAccessRef> access = NULL;
    OSStatus res = SecAccessCreate(secDescr, trustedList, access);
    if (res  != errSecSuccess)
        return JNI_FALSE;
    
    //create keychain
    CFTypePtr<SecKeychainRef> keychain = NULL;
    int passwordLen = keychainPassword ? (int)strlen(keychainPassword) : 0;
    SecKeychainCreate(keychainPath, passwordLen, keychainPassword, false, access, keychain);
    
    if (keychain.val()) {
        //add keychain to search list
        CFTypePtr<CFArrayRef> searchList;
        SecKeychainCopySearchList(searchList);
        
        CFTypePtr<CFMutableArrayRef> mutableSearchList = CFArrayCreateMutableCopy(NULL, 0, searchList);
        CFArrayAppendValue(mutableSearchList, keychain);
        
        SecKeychainSetSearchList(mutableSearchList);
        
        OSStatus res;
        res = SecKeychainUnlock(keychain, passwordLen, keychainPassword, true);
        
        //remove lock on sleep and timeout
        SecKeychainSettings settings;
        memset(&settings, 0, sizeof(settings));
        settings.version = 1;
        settings.lockOnSleep = false;
        settings.useLockInterval = false;
        settings.lockInterval = INT32_MAX;
        res = SecKeychainSetSettings(keychain, &settings);
        if (res == errSecSuccess)
            return JNI_TRUE;
    }
    return JNI_FALSE;
}

CFStringRef fileNameFromPath(const char *path)
{
    char *slashPos = strrchr(path, '/');
    if (slashPos == NULL)
        slashPos = const_cast<char*>(path);
    else
        slashPos += 1;
    return CFStringCreateWithBytes(NULL, (const UInt8*)slashPos, strlen(slashPos), kCFStringEncodingMacRoman, false);
}

jboolean deleteKeychain(const char * keychainPath)
{
    CFTypePtr<SecKeychainRef> keychain = NULL;
    if (SecKeychainOpen(keychainPath, keychain) != errSecSuccess)
        return JNI_FALSE;
    if (SecKeychainDelete(keychain) == errSecSuccess)
        return JNI_TRUE;
    else
        return JNI_FALSE;
}

CFDataRef readDataFromFile(const char *filePath)
{
    CFTypePtr<CFURLRef> fileUrl = CFURLCreateFromFileSystemRepresentation(NULL, (UInt8*)filePath, strlen(filePath), false);
    if (fileUrl.val() == NULL)
        return NULL;
    
    CFTypePtr<CFReadStreamRef> stream = CFReadStreamCreateWithFile(NULL, fileUrl);
    if (stream.val() == NULL)
        return NULL;
    
    CFReadStreamOpen(stream);
    
    UInt8 * buffer = (UInt8*)calloc(1, 1024);
    
    CFTypePtr<CFMutableDataRef> mutableData = CFDataCreateMutable(NULL, 0);
    
    CFIndex bytesRead = 0;
    do{
        bytesRead = CFReadStreamRead(stream, buffer, 1024);
        if (bytesRead > 0)
            CFDataAppendBytes(mutableData, buffer, bytesRead);
    }while (bytesRead > 0);
    
    free(buffer);
    
    CFReadStreamClose(stream);
    
    CFDataRef result = CFDataCreateCopy(NULL, mutableData);
    
    return result;
}

jboolean importItemToKeychain(const char *keychainPath, const char *itemPath, const char *keychainPassword, const char *itemPassword)
{
    if (keychainPassword == NULL)
        keychainPassword = "";
    if (itemPassword == NULL)
        itemPassword = "";
    
    CFTypePtr<SecKeychainRef> keychain = NULL;
    if (SecKeychainOpen(keychainPath, keychain) != errSecSuccess)
        return JNI_FALSE;
    
    CFTypePtr<CFDataRef> data = readDataFromFile(itemPath);
    if (data.val() && CFDataGetLength(data) != 0) {
        //parameters
        SecItemImportExportKeyParameters params;
        params.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
        params.flags = kSecKeyNoAccessControl;
        
        CFTypePtr<CFStringRef> password = CFStringCreateWithBytes(NULL, (UInt8*)itemPassword, strlen(itemPassword), kCFStringEncodingMacRoman, false);
        params.passphrase = password;
        params.alertPrompt = NULL;
        params.alertTitle = NULL;
        CFTypeRef usage[] = {kSecAttrCanSign};
        params.keyUsage = CFArrayCreate(NULL, (const void**)usage, 1, NULL);
        CFTypePtr<CFArrayRef> keyUsage = params.keyUsage;
        params.keyUsage = keyUsage;
        params.keyAttributes = NULL;
        
        //access information for private key
        CFTypePtr<CFStringRef> secDescr = fileNameFromPath(itemPath);
        CFTypePtr<CFArrayRef> trustedList = CFArrayCreate(NULL, NULL, 0, NULL);
        CFTypePtr<SecAccessRef> access = NULL;
        
        SecExternalFormat format = kSecFormatPKCS12;
        
        if (SecAccessCreate(secDescr, trustedList, access) != errSecSuccess)
            return JNI_FALSE;
        params.accessRef = access;
        
        //unlock
        if (SecKeychainUnlock(keychain, keychainPassword ? (UInt32)strlen(keychainPassword) : 0, keychainPassword, true) != errSecSuccess)
            return JNI_FALSE;
        
        if (SecItemImport(data, NULL, &format, NULL, 0, &params, keychain, NULL) == errSecSuccess)
            return JNI_TRUE;
    }
    return JNI_FALSE;
}
