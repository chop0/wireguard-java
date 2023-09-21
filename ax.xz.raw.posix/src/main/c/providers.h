#pragma once
#include <jni.h>

JNIEXPORT jobject JNICALL Java_ax_xz_raw_posix_POSIXTunProvider_open(JNIEnv *env, jclass clazz);
JNIEXPORT void JNICALL Java_ax_xz_raw_posix_POSIXTun_setMTU(JNIEnv *env, jobject tunObj, jint mtu);
JNIEXPORT jint JNICALL Java_ax_xz_raw_posix_POSIXTun_mtu(JNIEnv *env, jobject tunObj);

JNIEXPORT jint JNICALL Java_ax_xz_raw_posix_POSIXTunUtils_AFINET(JNIEnv *env, jclass clazz);
JNIEXPORT jint JNICALL Java_ax_xz_raw_posix_POSIXTunUtils_AF_INET6(JNIEnv *env, jclass clazz);