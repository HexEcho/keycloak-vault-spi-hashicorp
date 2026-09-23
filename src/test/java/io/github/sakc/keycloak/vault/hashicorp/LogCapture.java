/*
 * Copyright 2026 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.github.sakc.keycloak.vault.hashicorp;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

/**
 * Captures java.util.logging output for a given class (jboss-logging falls back to JUL in tests)
 * so tests can assert that sensitive values never appear in log messages or attached throwables.
 */
public final class LogCapture implements AutoCloseable {

    private final Logger julLogger;
    private final Handler handler;
    private final List<String> messages = new ArrayList<>();

    private LogCapture(Class<?> loggedClass) {
        julLogger = Logger.getLogger(loggedClass.getName());
        handler = new Handler() {
            @Override
            public void publish(LogRecord record) {
                StringBuilder sb = new StringBuilder();
                if (record.getMessage() != null) {
                    sb.append(record.getMessage());
                }
                if (record.getThrown() != null) {
                    sb.append(" | ").append(record.getThrown());
                    for (StackTraceElement element : record.getThrown().getStackTrace()) {
                        sb.append(' ').append(element);
                    }
                }
                messages.add(sb.toString());
            }

            @Override
            public void flush() {
            }

            @Override
            public void close() {
            }
        };
        julLogger.addHandler(handler);
    }

    public static LogCapture forClass(Class<?> loggedClass) {
        return new LogCapture(loggedClass);
    }

    public List<String> messages() {
        return messages;
    }

    public boolean anyMessageContains(String needle) {
        return messages.stream().anyMatch(m -> m.contains(needle));
    }

    @Override
    public void close() {
        julLogger.removeHandler(handler);
    }
}
