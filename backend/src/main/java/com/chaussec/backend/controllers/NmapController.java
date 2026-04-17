package com.chaussec.backend.controllers;
import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.chaussec.backend.models.NmapModel;
import com.chaussec.backend.services.NmapService;

@RestController
@RequestMapping("/chaussec/nmap") 
public class NmapController {

    @Autowired 
    private NmapService nmapService;

    @PostMapping("/scan")
    public ResponseEntity<NmapModel> startScan(@RequestParam String target) {
        try {
            NmapModel result = nmapService.executeScan(target);
            return ResponseEntity.ok(result); 
        } catch (IOException e) {
            return ResponseEntity.status(500).build(); 
        }
    }
}
