load(
    "@bazel_tools//tools/jdk:default_java_toolchain.bzl",
    "BASE_JDK9_JVM_OPTS",
    "DEFAULT_JAVACOPTS",
    "DEFAULT_TOOLCHAIN_CONFIGURATION",
    "default_java_toolchain",
)

default_java_toolchain(
    name = "openjdk_21_linux",
    configuration = DEFAULT_TOOLCHAIN_CONFIGURATION,
    java_runtime = "@openjdk_21_linux//:jdk",
    javacopts = DEFAULT_JAVACOPTS + ["--enable-preview"],
    jvm_opts = BASE_JDK9_JVM_OPTS + ["--enable-preview"],
    source_version = "21",
    target_version = "21",
    target_compatible_with = [
        "@platforms//os:linux",
        "@platforms//cpu:x86_64",
    ],
)

default_java_toolchain(
    name = "openjdk_21_linux_aarch64",
    configuration = DEFAULT_TOOLCHAIN_CONFIGURATION,
    java_runtime = "@openjdk_21_linux_aarch64//:jdk",
    javacopts = DEFAULT_JAVACOPTS + ["--enable-preview"],
    jvm_opts = BASE_JDK9_JVM_OPTS + ["--enable-preview"],
    source_version = "21",
    target_version = "21",

    target_compatible_with = [
            "@platforms//os:linux",
            "@platforms//cpu:aarch64",
        ],
)

default_java_toolchain(
    name = "openjdk_21_macos",
    configuration = DEFAULT_TOOLCHAIN_CONFIGURATION,
    java_runtime = "@openjdk_21_macos//:jdk",
    javacopts = DEFAULT_JAVACOPTS + ["--enable-preview"],
    jvm_opts = BASE_JDK9_JVM_OPTS + ["--enable-preview"],
    source_version = "21",
    target_version = "21",

    target_compatible_with = [
            "@platforms//os:macos",
            "@platforms//cpu:x86_64",
        ],
)

default_java_toolchain(
	name = "openjdk_21_macos_aarch64",
	configuration = DEFAULT_TOOLCHAIN_CONFIGURATION,
	java_runtime = "@openjdk_21_macos_aarch64//:jdk",
	javacopts = DEFAULT_JAVACOPTS + ["--enable-preview"],
	jvm_opts = BASE_JDK9_JVM_OPTS + ["--enable-preview"],
	source_version = "21",
	target_version = "21",

	target_compatible_with = [
            "@platforms//os:macos",
            "@platforms//cpu:aarch64",
        ],
)

default_java_toolchain(
	name = "openjdk_21_windows",
	configuration = DEFAULT_TOOLCHAIN_CONFIGURATION,
	java_runtime = "@openjdk_21_windows//:jdk",
	javacopts = DEFAULT_JAVACOPTS + ["--enable-preview"],
	jvm_opts = BASE_JDK9_JVM_OPTS + ["--enable-preview"],
	source_version = "21",
	target_version = "21",

	target_compatible_with = [
            "@platforms//os:windows",
            "@platforms//cpu:x86_64",
        ],
)