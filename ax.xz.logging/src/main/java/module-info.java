module ax.xz.logging {
	requires transitive org.slf4j;
	requires ch.qos.logback.classic;

	exports ax.xz.logging;
	provides System.LoggerFinder with ax.xz.logging.Slf4jLoggerFinder;
}