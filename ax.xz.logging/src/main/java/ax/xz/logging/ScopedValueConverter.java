package ax.xz.logging;

import ch.qos.logback.classic.pattern.ClassicConverter;
import ch.qos.logback.classic.spi.ILoggingEvent;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;

/**
 * Allows you to reference a {@link ScopedValue} from your logback configuration.
 */
public class ScopedValueConverter extends ClassicConverter {
	private VarHandle scopedValue;

	@Override
	public void start() {
		String option = getFirstOption();
		if (option == null) {
			addError("Missing option for ScopedValueConverter");
			return;
		}

		try {
			var pathClass = Class.forName(option.substring(0, option.lastIndexOf('.')));
			var pathField = option.substring(option.lastIndexOf('.') + 1);

			ScopedValueConverter.class.getModule().addReads(pathClass.getModule());
			scopedValue = MethodHandles.lookup().findStaticVarHandle(pathClass, pathField, ScopedValue.class);
		} catch (Exception e) {
			addError("Failed to get scopedValue for " + option, e);
			return;
		}
	}

	@Override
	public String convert(ILoggingEvent event) {
		try {
			var sv = (ScopedValue<?>) scopedValue.get();
			return String.valueOf(sv.get());
		} catch (Exception e) {
			return "ERROR";
		}
	}

}
