package ax.xz.logging;

import jdk.internal.vm.ThreadContainers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.ResourceBundle;

public class Slf4jLogger implements System.Logger {
	private static final ThreadLocal<List<String>> scopeBacktrace = ThreadLocal.withInitial(Slf4jLogger::getThreadScopeBacktrace);
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

		for (var marker : scopeBacktrace.get()) {
			builder = builder.addMarker(MarkerFactory.getMarker(marker));
		}

		builder.log();
	}

	@Override
	public void log(Level level, ResourceBundle bundle, String format, Object... params) {
		var builder = delegate.atLevel(translateLevel(level)).setMessage(MessageFormat.format(format, params));

		// build marker from scope backtrace
		Marker marker = null;
		for (var scope : scopeBacktrace.get()) {
			if (marker == null) {
				marker = MarkerFactory.getMarker(scope);
			} else {
				var inner = MarkerFactory.getMarker(scope);
				marker.add(inner);
				marker = inner;
			}
		}

		builder = builder.addMarker(marker);

		builder.log();
	}

	private static List<String> getThreadScopeBacktrace() {
		var result = new ArrayList<String>();

		var container = ThreadContainers.container(Thread.currentThread());
		do {
			if (container.owner() != null)
				result.add(container.owner().getName());
			container = container.parent();
		} while (container != null && container != ThreadContainers.root());

		return result.reversed();
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
