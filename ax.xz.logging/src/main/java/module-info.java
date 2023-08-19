module ax.xz.logging {
	requires transitive org.slf4j;

	exports ax.xz.logging;
	provides System.LoggerFinder with ax.xz.logging.Slf4jLoggerFinder;
}
