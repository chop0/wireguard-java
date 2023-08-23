package ax.xz.logging;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.MessageFormat;
import java.util.ResourceBundle;

public class Slf4jLogger implements System.Logger {
	private final Logger delegate;

	public Slf4jLogger(String name) {
		this.delegate = LoggerFactory.getLogger(name);
	}

	@Override
	public String getName() {
		return delegate.getName();
	}

	@Override
	public boolean isLoggable(Level level) {
		return delegate.isEnabledForLevel(translateLevel(level));
	}

	@Override
	public void log(Level level, ResourceBundle bundle, String msg, Throwable thrown) {
		var builder = delegate.atLevel(translateLevel(level)).setCause(thrown)
				.setMessage(msg);

		builder.log();
	}

	@Override
	public void log(Level level, ResourceBundle bundle, String format, Object... params) {
		var builder = delegate.atLevel(translateLevel(level)).setMessage(MessageFormat.format(format, params));

		builder.log();
	}

	private static org.slf4j.event.Level translateLevel(Level level) {
		return switch (level) {
			case ALL -> org.slf4j.event.Level.TRACE;
			case TRACE -> org.slf4j.event.Level.TRACE;
			case DEBUG -> org.slf4j.event.Level.DEBUG;
			case INFO -> org.slf4j.event.Level.INFO;
			case WARNING -> org.slf4j.event.Level.WARN;
			case ERROR -> org.slf4j.event.Level.ERROR;
			default -> throw new IllegalArgumentException("Unknown level: " + level);
		};
	}

	private static Level translateLevel(org.slf4j.event.Level level) {
		return switch (level) {
			case TRACE -> Level.TRACE;
			case DEBUG -> Level.DEBUG;
			case INFO -> Level.INFO;
			case WARN -> Level.WARNING;
			case ERROR -> Level.ERROR;
		};
	}
}
