package ax.xz.wireguard;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.slf4j.Marker;
import org.slf4j.event.Level;
import org.slf4j.helpers.AbstractLogger;

import java.util.HashMap;
import java.util.Objects;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.function.Function;

public class ScopedLogger extends AbstractLogger {
	private static final ConcurrentLinkedQueue<ScopedMarker<?, ?>> markers = new ConcurrentLinkedQueue<>();
	private static final ThreadLocal<HashMap<String, String>> context = ThreadLocal.withInitial(ScopedLogger::calculateContextMap);


	private final Logger delegate;

	public ScopedLogger(Logger delegate) {
		this.delegate = delegate;
	}

	public static ScopedLogger getLogger(Class<?> clazz) {
		return new ScopedLogger(LoggerFactory.getLogger(clazz));
	}

	public static <T, R> void addScopedMarker(String name, ScopedValue<T> value, Function<T, R> mapper) {
		markers.add(new ScopedMarker<>(name, value, mapper));
	}

	public static <T> void addScopedMarker(String name, ScopedValue<T> value) {
		markers.add(new ScopedMarker<>(name, value, Objects::toString));
	}


	@Override
	protected String getFullyQualifiedCallerName() {
		return delegate.getName();
	}

	@Override
	protected void handleNormalizedLoggingCall(Level level, Marker marker, String messagePattern, Object[] arguments, Throwable throwable) {
		MDC.setContextMap(context.get());

		var builder = delegate.atLevel(level)
			.addMarker(marker)
			.setMessage(messagePattern)
			.setCause(throwable);

		if (arguments != null)
			for (Object argument : arguments) {
				builder = builder.addArgument(argument);
			}

		builder.log();
	}

	private static HashMap<String, String> calculateContextMap() {
		var map = new HashMap<String, String>();
		for (ScopedMarker<?, ?> marker : markers) {
			if (!marker.value.isBound()) {
				continue;
			}

			var value = marker.value().get();
			map.put(marker.name, ((Function<Object, Object>) marker.mapper).apply(value).toString());
		}

		return map;
	}

	@Override
	public boolean isTraceEnabled() {
		return delegate.isTraceEnabled();
	}

	@Override
	public boolean isTraceEnabled(Marker marker) {
		return delegate.isTraceEnabled(marker);
	}

	@Override
	public boolean isDebugEnabled() {
		return delegate.isDebugEnabled();
	}

	@Override
	public boolean isDebugEnabled(Marker marker) {
		return delegate.isDebugEnabled(marker);
	}

	@Override
	public boolean isInfoEnabled() {
		return delegate.isInfoEnabled();
	}

	@Override
	public boolean isInfoEnabled(Marker marker) {
		return delegate.isInfoEnabled(marker);
	}

	@Override
	public boolean isWarnEnabled() {
		return delegate.isWarnEnabled();
	}

	@Override
	public boolean isWarnEnabled(Marker marker) {
		return delegate.isWarnEnabled(marker);
	}

	@Override
	public boolean isErrorEnabled() {
		return delegate.isErrorEnabled();
	}

	@Override
	public boolean isErrorEnabled(Marker marker) {
		return delegate.isErrorEnabled(marker);
	}

	public record ScopedMarker<T, R>(String name, ScopedValue<T> value, Function<T, R> mapper) {
	}
}
