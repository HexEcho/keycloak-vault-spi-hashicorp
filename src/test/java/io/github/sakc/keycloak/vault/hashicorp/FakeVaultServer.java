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

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

/**
 * Minimal in-process HTTP server standing in for a HashiCorp Vault instance so retry, timeout,
 * and status-mapping behavior in {@link HashicorpVaultClient} can be exercised deterministically
 * without a real Vault (or Testcontainers) dependency.
 */
final class FakeVaultServer implements AutoCloseable {

    private final HttpServer server;
    private final AtomicInteger requestCount = new AtomicInteger();
    private final Queue<String> requestPaths = new ConcurrentLinkedQueue<>();
    private volatile Deque<Response> scriptedResponses;
    private volatile Function<HttpExchange, Response> handler;
    private volatile long responseDelayMs;

    private FakeVaultServer(HttpServer server) {
        this.server = server;
    }

    static FakeVaultServer start() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        FakeVaultServer fake = new FakeVaultServer(server);
        server.createContext("/", fake::handle);
        server.setExecutor(java.util.concurrent.Executors.newCachedThreadPool());
        server.start();
        return fake;
    }

    String baseUrl() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    int requestCount() {
        return requestCount.get();
    }

    List<String> requestPaths() {
        return List.copyOf(requestPaths);
    }

    /** Every subsequent request gets the next response in order; the last one repeats after that. */
    void enqueue(int status, String body) {
        if (scriptedResponses == null) {
            scriptedResponses = new ArrayDeque<>();
        }
        scriptedResponses.add(new Response(status, body));
    }

    void alwaysRespond(int status, String body) {
        handler = exchange -> new Response(status, body);
    }

    void delayEveryResponseBy(long delayMs) {
        this.responseDelayMs = delayMs;
    }

    private void handle(HttpExchange exchange) throws IOException {
        requestCount.incrementAndGet();
        requestPaths.add(exchange.getRequestURI().getPath());
        if (responseDelayMs > 0) {
            try {
                Thread.sleep(responseDelayMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        Response response = nextResponse(exchange);
        byte[] bytes = response.body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(response.status, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private Response nextResponse(HttpExchange exchange) {
        Deque<Response> scripted = this.scriptedResponses;
        if (scripted != null) {
            synchronized (scripted) {
                if (scripted.size() > 1) {
                    return scripted.poll();
                }
                if (!scripted.isEmpty()) {
                    return scripted.peek();
                }
            }
        }
        Function<HttpExchange, Response> h = this.handler;
        if (h != null) {
            return h.apply(exchange);
        }
        return new Response(200, "{}");
    }

    @Override
    public void close() {
        server.stop(0);
    }

    private record Response(int status, String body) {
    }
}
