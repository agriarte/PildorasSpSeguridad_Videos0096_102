package com.tallerdeapps.seguridad.config.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 *
 */
@Controller
public class LoginController {
    
    @GetMapping("/miFormularioLogin")
    public String muestraLogin(){
        return "milogin";
    }
} 