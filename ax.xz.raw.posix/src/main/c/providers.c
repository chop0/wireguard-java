#include "providers.h"
#include "jni_utils.h"
#include "posix_raw.h"

#include <jni.h>
#include <net/if.h>
#include <stdio.h>

#ifdef __linux__
#include <sys/sysinfo.h>
//#define MULTIQUEUES get_nprocs()
#define MULTIQUEUES 0
#else
#define MULTIQUEUES 0
#endif

static jobject createFdObject(JNIEnv *env, int fd) {
    jclass sharedSecretsCls = FIND_CLASS(env, "jdk/internal/access/SharedSecrets");
    jclass javaIOFileDescriptorAccessCls = FIND_CLASS(env, "jdk/internal/access/JavaIOFileDescriptorAccess");
    jclass fileDescriptorCls = FIND_CLASS(env, "java/io/FileDescriptor");

    jmethodID getJavaIOFileDescriptorAccess = GET_STATIC_METHOD_ID(env, sharedSecretsCls, "getJavaIOFileDescriptorAccess", "()Ljdk/internal/access/JavaIOFileDescriptorAccess;");
    jmethodID fileDescriptorAccessSet = GET_METHOD_ID(env, javaIOFileDescriptorAccessCls, "set", "(Ljava/io/FileDescriptor;I)V");
    jmethodID fileDescriptorRegisterCleanup = GET_METHOD_ID(env, javaIOFileDescriptorAccessCls, "registerCleanup", "(Ljava/io/FileDescriptor;)V");
    jmethodID fdConstructor = GET_METHOD_ID(env, fileDescriptorCls, "<init>", "()V");

    jobject fileDescriptorAccess = (*env)->CallStaticObjectMethod(env, sharedSecretsCls, getJavaIOFileDescriptorAccess);
    jobject fdObj = (*env)->NewObject(env, fileDescriptorCls, fdConstructor);
    (*env)->CallVoidMethod(env, fileDescriptorAccess, fileDescriptorAccessSet, fdObj, fd);
    (*env)->CallVoidMethod(env, fileDescriptorAccess, fileDescriptorRegisterCleanup, fdObj);

    return fdObj;
}

JNIEXPORT jobject JNICALL Java_ax_xz_raw_posix_POSIXTunProvider_open(JNIEnv *env, jclass clazz) {
	// open tun device
	jclass posixTunCls = FIND_CLASS(env, "ax/xz/raw/posix/POSIXTun");
    jmethodID posixTunConstructor = GET_METHOD_ID(env, posixTunCls, "<init>", "([Ljava/io/FileDescriptor;Ljava/lang/String;)V");

    char name[IFNAMSIZ];
    int queueCount = MULTIQUEUES; // it's broken atm
    int queues[queueCount + 1]; // +1 for primary fd

    int primaryFd = IO_TRY(env, open_tun(name, sizeof(name), &queueCount, queues + 1));
    if (primaryFd < 0) {
		return NULL;
	}

	queues[0] = primaryFd;
	queueCount++;

    jobjectArray fds = (*env)->NewObjectArray(env, queueCount, FIND_CLASS(env, "java/io/FileDescriptor"), NULL);
    for (int i = 0; i < queueCount; i++) {
		jobject fdObj = createFdObject(env, queues[i]);
		(*env)->SetObjectArrayElement(env, fds, i, fdObj);
	}

    jstring nameObj = (*env)->NewStringUTF(env, name);
    return (*env)->NewObject(env, posixTunCls, posixTunConstructor, fds, nameObj);
}

static void getName(JNIEnv *env, jobject tunObj, char *name, int nameLength) {
	jclass tunCls = FIND_CLASS(env, "ax/xz/raw/posix/POSIXTun");
	jmethodID nameMethod = GET_METHOD_ID(env, tunCls, "name", "()Ljava/lang/String;");
	jstring nameStr = (*env)->CallObjectMethod(env, tunObj, nameMethod);

	const char *nameCStr = (*env)->GetStringUTFChars(env, nameStr, NULL);
	strncpy(name, nameCStr, nameLength);
	(*env)->ReleaseStringUTFChars(env, nameStr, nameCStr);
}

JNIEXPORT void JNICALL Java_ax_xz_raw_posix_POSIXTun_setMTU(JNIEnv *env, jobject tunObj, jint mtu) {
	char name[IFNAMSIZ];
	getName(env, tunObj, name, sizeof(name));

	set_mtu(name, sizeof(name), mtu);
}

JNIEXPORT int JNICALL Java_ax_xz_raw_posix_POSIXTun_mtu(JNIEnv *env, jobject tunObj) {
	char name[IFNAMSIZ];
	getName(env, tunObj, name, sizeof(name));

	return mtu(name, sizeof(name));
}

JNIEXPORT jint JNICALL Java_ax_xz_raw_posix_POSIXTunUtils_AFINET(JNIEnv *env, jclass clazz) {
	return AF_INET;
}

JNIEXPORT jint JNICALL Java_ax_xz_raw_posix_POSIXTunUtils_AFINET6(JNIEnv *env, jclass clazz) {
	return AF_INET6;
}