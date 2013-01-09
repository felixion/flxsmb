package flxsmb.tests.utils;

import java.util.logging.*;

/**
 * Utility class to configure logging.
 */
public class LoggingUtil
{
    /** Whether setupLogging set run */
    private static volatile boolean initialized = false;

    /**
     * Configures logging.
     */
    public static void setupLogging()
    {
        if (!isFirstCall())
            return;

        Handler handler = new LoggingHandler();
        handler.setLevel(Level.INFO);

        Logger logger = Logger.getLogger("");

        // remove all default handlers
        for (Handler h : logger.getHandlers())
        {
            logger.removeHandler(h);
        }

        logger.addHandler(handler);
        logger.setLevel(Level.INFO);
    }

    /**
     * @return true if this is the first call
     */
    private static boolean isFirstCall()
    {
        if (initialized)
            return initialized;

        synchronized (LoggingUtil.class)
        {
            if (!initialized)
            {
                initialized = true;
            }

            return initialized;
        }
    }

    /**
     * Formats log messages.
     */
    static class LoggingFormatter extends SimpleFormatter
    {
        @Override
        public synchronized String format(LogRecord logRecord)
        {
            return String.format("[%d %s] %s\n", logRecord.getSequenceNumber(), logRecord.getLevel(), logRecord.getMessage());
        }
    };

    /**
     * Handler that flushes the stdout on each message.
     */
    static class LoggingHandler extends StreamHandler
    {
        LoggingHandler()
        {
            super(System.out, new LoggingFormatter());
        }

        @Override
        public synchronized void publish(LogRecord logRecord)
        {
            super.publish(logRecord);
            flush();
        }
    }
}
