#pragma once

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <jni.h>

// Helper macro to convert to string
#define STRINGIZE_DETAIL(x) #x
#define STRINGIZE(x) STRINGIZE_DETAIL(x)

// Abort macro
#define ABORT_IF(env, expr, message) do {         \
    if ((expr)) {                                 \
        char buffer[512];                         \
        snprintf(buffer, sizeof(buffer),          \
                 "ABORT_IF(%s): %s\n"             \
                 "\tat %s (%s:%s)",                \
                 #expr, message,                  \
                 __PRETTY_FUNCTION__,             \
                 __FILE__, STRINGIZE(__LINE__));  \
        (*env)->FatalError(env, buffer);          \
        abort();                                  \
    }                                             \
} while(0)

#define FORMAT_IOEXCEPTION(message) ({ \
	char buffer[512]; \
	snprintf(buffer, sizeof(buffer), \
		message ": " "%s\n" \
		"\tat %s (%s:%s)", \
		strerror(errno), \
		__PRETTY_FUNCTION__, \
		__FILE__, STRINGIZE(__LINE__) \
	); \
	buffer; \
})

// Macro to find a Java class
// TODO:  make this work with msvc because it doesn't support statement expressions
#define FIND_CLASS(env, className) ({ \
    static jclass cls = NULL; \
    if (cls == NULL) { \
        cls = (*env)->FindClass(env, className); \
        ABORT_IF(env, cls == NULL, "Could not find class " className); \
        cls = (*env)->NewGlobalRef(env, cls); \
    } \
    cls; \
})

// Macro to get a Java method ID
#define GET_METHOD_ID(env, jclassVar, methodName, methodSig) ({ \
    static jmethodID mid = NULL; \
    if (mid == NULL) { \
        mid = (*env)->GetMethodID(env, jclassVar, methodName, methodSig); \
        ABORT_IF(env, mid == NULL, "Could not find method " methodName " with signature " methodSig); \
    } \
    mid; \
})

// Macro to get a Java static method ID
#define GET_STATIC_METHOD_ID(env, jclassVar, methodName, methodSig) ({ \
    static jmethodID mid = NULL; \
    if (mid == NULL) { \
        mid = (*env)->GetStaticMethodID(env, jclassVar, methodName, methodSig); \
        ABORT_IF(env, mid == NULL, "Could not find static method " methodName " with signature " methodSig); \
    } \
    mid; \
})

// Macro to get a Java field ID
#define GET_FIELD_ID(env, jclassVar, fieldName, fieldSig) ({ \
    static jfieldID fid = NULL; \
    if (fid == NULL) { \
        fid = (*env)->GetFieldID(env, jclassVar, fieldName, fieldSig); \
        ABORT_IF(env, fid == NULL, "Could not find field " fieldName " with signature " fieldSig); \
    } \
    fid; \
})

// Function to concatenate strings and convert to jstring
static jobject concat_to_jstring(JNIEnv* env, char const* str1, char const* str2) {
    char* str = malloc(strlen(str1) + strlen(str2) + 1);
    strcpy(str, str1);
    strcat(str, str2);
    jobject jstr = (*env)->NewStringUTF(env, str);
    free(str);
    return jstr;
}

// Macro to throw a Java exception
#define THROW(env, exceptionCls, message) do { \
    jclass cls = FIND_CLASS(env, (exceptionCls)); \
    jmethodID constructor = GET_METHOD_ID(env, cls, "<init>", "(Ljava/lang/String;)V"); \
    jobject str = (*env)->NewStringUTF(env, (message)); \
    (*env)->Throw(env, (*env)->NewObject(env, cls, constructor, str)); \
} while(0)

// Macro to try an I/O operation and throw an IOException if it fails
#define IO_TRY(env, expr) ({ \
    int result = (expr); \
    if (result < 0) { \
        (*env)->ThrowNew(env, FIND_CLASS(env, "java/io/IOException"), FORMAT_IOEXCEPTION(#expr)); \
    } \
    result; \
})
