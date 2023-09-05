load("@bazel_tools//tools/jdk:remote_java_repository.bzl", "remote_java_repository")

remote_java_repository(
    name = "openjdk_21_linux",
    prefix = "openjdk_21",
    target_compatible_with = [
        "@platforms//os:linux",
        "@platforms//cpu:x86_64",
    ],
    sha256 = "a30c454a9bef8f46d5f1bf3122830014a8fbe7ac03b5f8729bc3add4b92a1d0a",
    strip_prefix = "jdk-21",
    urls = ["https://download.java.net/java/GA/jdk21/fd2272bbf8e04c3dbaee13770090416c/35/GPL/openjdk-21_linux-x64_bin.tar.gz"],
    version = "21",
)

remote_java_repository(
    name = "openjdk_21_linux_aarch64",
        prefix = "openjdk_21",

    target_compatible_with = [
        "@platforms//os:linux",
        "@platforms//cpu:aarch64",
    ],
    sha256 = "e8f4ed1a69815ddf56d7da365116eefc1e5a1159396dffee3dd21616a86d5d28",
    strip_prefix = "jdk-21",
    urls = ["https://download.java.net/java/GA/jdk21/fd2272bbf8e04c3dbaee13770090416c/35/GPL/openjdk-21_linux-aarch64_bin.tar.gz"],
    version = "21",
)

remote_java_repository(
    name = "openjdk_21_macos",
        prefix = "openjdk_21",

    target_compatible_with = [
        "@platforms//os:macos",
        "@platforms//cpu:x86_64",
    ],
    sha256 = "af32e84c11009f72f783fdcdc9917efc277893988f097e198e2576875d1e88c1",
    strip_prefix = "jdk-21.jdk/Contents/Home",
    urls = ["https://download.java.net/java/GA/jdk21/fd2272bbf8e04c3dbaee13770090416c/35/GPL/openjdk-21_macos-x64_bin.tar.gz"],
    version = "21",
)

remote_java_repository(
    name = "openjdk_21_macos_aarch64",
        prefix = "openjdk_21",

    target_compatible_with = [
        "@platforms//os:macos",
        "@platforms//cpu:aarch64",
    ],
    sha256 = "f12e1e0a2dffc847951598f597c8ee60fb0913932f24b2b09c62cfd2f0f4dfb9",
    strip_prefix = "jdk-21.jdk/Contents/Home",
    urls = ["https://download.java.net/java/GA/jdk21/fd2272bbf8e04c3dbaee13770090416c/35/GPL/openjdk-21_macos-aarch64_bin.tar.gz"],
    version = "21",
)
register_toolchains("@openjdk_21_macos_aarch64//:all")

remote_java_repository(
    name = "openjdk_21_windows",
        prefix = "openjdk_21",

    target_compatible_with = [
        "@platforms//os:windows",
        "@platforms//cpu:x86_64",
    ],
    sha256 = "5434faaf029e66e7ce6e75770ca384de476750984a7d2881ef7686894c4b4944",
    strip_prefix = "jdk-21",
    urls = ["https://download.java.net/java/GA/jdk21/fd2272bbf8e04c3dbaee13770090416c/35/GPL/openjdk-21_windows-x64_bin.zip"],
    version = "21",
)