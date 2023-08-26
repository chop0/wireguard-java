# Variables
JAVAC = ${JAVA_HOME}/bin/javac
NATIVE_IMAGE = ${GRAALVM_HOME}/bin/native-image
JAR = ${JAVA_HOME}/bin/jar

OUT_DIR = out/production
MODULES = ax.xz.logging ax.xz.raw ax.xz.raw.posix ax.xz.raw.osx ax.xz.raw.linux ax.xz.wireguard ax.xz.wireguard.noise
JARFILE = $(OUT_DIR)/wireguard-java.jar

LIBS = $(subst $(subst ,, ),:,$(wildcard lib/*))

wireguard-java: modules
	$(NATIVE_IMAGE) --no-fallback --enable-preview -cp .:$(LIBS):$(subst $(subst ,, ),:,$(addprefix $(OUT_DIR)/,$(MODULES))) ax.xz.wireguard.cli.WireguardTunnelCLI


modules: $(addprefix $(OUT_DIR)/,$(MODULES))

$(OUT_DIR)/%: % FORCE
	$(JAVAC) --enable-preview --source 21 -d $(OUT_DIR) --module-path $(LIBS) --module-source-path './*/src/main/java' -m $<

clean:
	rm -rf $(OUT_DIR)/*

FORCE: ;
.PHONY: all compile clean

