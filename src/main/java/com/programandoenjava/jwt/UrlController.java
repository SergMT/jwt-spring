package com.programandoenjava.jwt;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.GetMapping;


@Controller
@RequestMapping("/")
public class UrlController {

    @GetMapping()
    public String getMethodName() {
        return "login";
    }
    @GetMapping("index")
    public String index() {
        return "index";
    }
    
}
