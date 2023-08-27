# Variables
CC = gcc

JAVAC = ${JAVA_HOME}/bin/javac
NATIVE_IMAGE = ${GRAALVM_HOME}/bin/native-image
JAR = ${JAVA_HOME}/bin/jar

OUT_DIR = out/production
MODULES = ax.xz.raw ax.xz.raw.posix ax.xz.wireguard ax.xz.wireguard.noise
JARFILE = $(OUT_DIR)/wireguard-java.jar

$(OUT_DIR)/wireguard-java: $(OUT_DIR)/libposix_raw.dylib $(addprefix $(OUT_DIR)/,$(MODULES))
	$(NATIVE_IMAGE) -o $@ -march=native --no-fallback -O2 --enable-preview -cp .:$(subst $(subst ,, ),:,$^):jsr305-3.0.2.jar ax.xz.wireguard.cli.WireguardTunnelCLI

$(OUT_DIR)/%: % FORCE
	$(JAVAC) --enable-preview --source 21 -d $(OUT_DIR) --module-path jsr305-3.0.2.jar --module-source-path './*/src/main/java' -m $<

$(OUT_DIR)/libposix_raw.dylib: ax.xz.raw.posix/posix_raw.c
	$(CC) -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/darwin -shared -o $@ $^

clean:
	rm -rf $(OUT_DIR)/*

FORCE: ;
.PHONY: all compile clean

