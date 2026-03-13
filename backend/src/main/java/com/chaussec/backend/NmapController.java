package com.chaussec.backend;

import java.util.List;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;


@RestController
@RequestMapping("/nmap")
public class NmapController {

    private final NmapService nmapService;

    public NmapController(NmapService nmapService) {
        this.nmapService = nmapService;
    }
    
    @GetMapping()
    public String getNmapStatus(@RequestParam String param) {
        return "Nmap controller is ready. Received param=" + param;
    }

    @PostMapping("/start")
    public ResponseEntity<Map<String, Object>> startNmapScan(@RequestBody NmapScanRequest request) {
        if (request == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "Request body is required."));
        }

        List<String> rawTargets = request.getTargets();
        if (rawTargets.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "At least one target is required."));
        }

        String sanitizedScanType = nmapService.sanitizeScanType(request.scanType());
        if (sanitizedScanType == null) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "Unsupported scanType. Allowed values: sS, sT, sU, sV, sN, sF, sX, sA, sW, sM"));
        }

        List<String> sanitizedTargets = nmapService.sanitizeTargets(rawTargets);
        if (sanitizedTargets.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "No valid targets provided."));
        }

        return nmapService.startScan(sanitizedScanType, sanitizedTargets);
    }

}
