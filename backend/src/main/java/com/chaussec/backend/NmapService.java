package com.chaussec.backend;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

@Service
public class NmapService {

    private static final long NMAP_TIMEOUT_SECONDS = 120;
    private static final String NMAP_IMAGE = "instrumentisto/nmap:latest";
    private static final Set<String> ALLOWED_SCAN_TYPES = Set.of("sS", "sT", "sU", "sV", "sN", "sF", "sX", "sA", "sW", "sM", "A");

    public ResponseEntity<Map<String, Object>> startScan(String sanitizedScanType, List<String> sanitizedTargets) {
        List<String> command = buildDockerCommand(sanitizedScanType, sanitizedTargets);

        ProcessBuilder processBuilder = new ProcessBuilder(command);
        processBuilder.redirectErrorStream(true);

        try {
            Process process = processBuilder.start();
            boolean finished = process.waitFor(NMAP_TIMEOUT_SECONDS, TimeUnit.SECONDS);

            if (!finished) {
                process.destroyForcibly();
                return ResponseEntity.status(HttpStatus.REQUEST_TIMEOUT)
                        .body(Map.of(
                                "status", "timeout",
                                "message", "nmap scan exceeded timeout of " + NMAP_TIMEOUT_SECONDS + " seconds",
                                "targets", sanitizedTargets,
                                "command", String.join(" ", command)));
            }

            int exitCode = process.exitValue();
            String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);

            Map<String, Object> response = new HashMap<>();
            response.put("status", exitCode == 0 ? "ok" : "error");
            response.put("exitCode", exitCode);
            response.put("startedAt", Instant.now().toString());
            response.put("scanType", sanitizedScanType);
            response.put("targets", sanitizedTargets);
            response.put("command", String.join(" ", command));
            response.put("output", output);

            return ResponseEntity.status(exitCode == 0 ? HttpStatus.OK : HttpStatus.BAD_REQUEST).body(response);
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of(
                            "status", "error",
                            "message", "Failed to start docker command. Is Docker installed and accessible?",
                            "details", e.getMessage()));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of(
                            "status", "error",
                            "message", "The scan process was interrupted.",
                            "details", e.getMessage()));
        }
    }

    public String sanitizeScanType(String scanType) {
        if (scanType == null || scanType.isBlank()) {
            return "sV";
        }

        String trimmed = scanType.trim();
        String normalized = trimmed.startsWith("-") ? trimmed.substring(1) : trimmed;

        if (!ALLOWED_SCAN_TYPES.contains(normalized)) {
            return null;
        }

        return normalized;
    }

    public List<String> sanitizeTargets(List<String> targets) {
        List<String> sanitized = new ArrayList<>();
        for (String rawTarget : targets) {
            if (rawTarget == null) {
                continue;
            }
            String trimmed = rawTarget.trim();
            // Keep a conservative whitelist to avoid malformed targets.
            if (!trimmed.isEmpty() && trimmed.matches("^[a-zA-Z0-9._:/-]+$")) {
                sanitized.add(trimmed);
            }
        }
        return sanitized;
    }

    private List<String> buildDockerCommand(String sanitizedScanType, List<String> sanitizedTargets) {
        List<String> command = new ArrayList<>();
        command.add("docker");
        command.add("run");
        command.add("--rm");
        command.add(NMAP_IMAGE);
        command.add("-" + sanitizedScanType);
        command.add("-Pn");
        command.addAll(sanitizedTargets);
        return command;
    }
}
