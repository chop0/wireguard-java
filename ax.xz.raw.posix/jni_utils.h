#pragma once

#include <stdlib.h>
#include <string.h>

#include <jni.h>

#define FIND_CLASS(envVar, className) ({ \
    static jclass cls = NULL; \
    if (cls == NULL) { \
        cls = (*envVar)->FindClass(envVar, className); \
        if (cls != NULL) { \
            cls = (*envVar)->NewGlobalRef(envVar, cls); /* convert to global reference */ \
        }                                   \
    } \
    cls; \
})

#define GET_METHOD_ID(envVar, jclassVar, methodName, methodSig) ({ \
    static jmethodID mid = NULL; \
    if (mid == NULL) { \
        mid = (*envVar)->GetMethodID(envVar, jclassVar, methodName, methodSig); \
    } \
    mid; \
})

#define GET_STATIC_METHOD_ID(envVar, jclassVar, methodName, methodSig) ({ \
    static jmethodID mid = NULL; \
    if (mid == NULL) { \
        mid = (*envVar)->GetStaticMethodID(envVar, jclassVar, methodName, methodSig); \
    } \
    mid; \
})

#define GET_FIELD_ID(envVar, jclassVar, fieldName, fieldSig) ({ \
    static jfieldID fid = NULL; \
    if (fid == NULL) { \
        fid = (*envVar)->GetFieldID(envVar, jclassVar, fieldName, fieldSig); \
    } \
    fid; \
})

jobject concat_to_jstring(JNIEnv* env, char const* str1, char const* str2) {
    char* str = malloc(strlen(str1) + strlen(str2) + 1);
    strcpy(str, str1);
    strcat(str, str2);

    jobject jstr = (*env)->NewStringUTF(env, str);
    free(str);

    return jstr;
}

#define THROW(env_, exceptionCls, message) ({ \
	JNIEnv *env = (env_); \
	jclass cls = FIND_CLASS(env, (exceptionCls)); \
	jmethodID constructor = GET_METHOD_ID(env, cls, "<init>", "(Ljava/lang/String;)V"); \
	jobject str = (*env)->NewStringUTF(env, (message)); \
	(*env)->Throw(env, (*env)->NewObject(env, cls, constructor, str)); \
})

#define STRINGIZE_DETAIL(x) #x
#define STRINGIZE(x) STRINGIZE_DETAIL(x)

// evaluates the given expression.  if its result is less than 0, throws an IOException with the string of expr concatenated with the string of strerror(errno)
#define IO_TRY(env, expr) ({ \
    JNIEnv *envEvaluated = (env); \
    int result = (expr); \
    if (result < 0) { \
        jclass ioExceptionCls = FIND_CLASS(envEvaluated, "java/io/IOException"); \
        jmethodID ioExceptionConstructor = GET_METHOD_ID(envEvaluated, ioExceptionCls, "<init>", "(Ljava/lang/String;)V"); \
        jobject str = concat_to_jstring(envEvaluated, __FILE__ ":" STRINGIZE(__LINE__) " " #expr ": ", strerror(errno)); \
        (*envEvaluated)->Throw(envEvaluated, (*envEvaluated)->NewObject(envEvaluated, ioExceptionCls, ioExceptionConstructor, str)); \
    } \
    result; \
})