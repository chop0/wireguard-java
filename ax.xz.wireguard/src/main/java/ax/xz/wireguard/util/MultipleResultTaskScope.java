package ax.xz.wireguard.util;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.StructuredTaskScope;

public class MultipleResultTaskScope<T> extends StructuredTaskScope<T> {
	private final Set<T> results = ConcurrentHashMap.newKeySet();

	@Override
	protected void handleComplete(Subtask<? extends T> subtask) {
		results.add(subtask.get());
	}

	public Set<T> results() {
		ensureOwnerAndJoined();
		return results;
	}
}
