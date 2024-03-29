package com.tallerdeapps.seguridad.config.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 *
 */
@Controller
public class SeguridadController {
    
    @GetMapping("/")
    public String mostrarInicio(){
        return "inicio";
    }
    
    //mapping para zona administradores
    @GetMapping("/administradores")
    public String mostrarAdministradores(){
        return "administradores";
    }
    
    //mapping para zona ayudantes
    @GetMapping("/ayudante")
    public String mostrarAyudante(){
        return "ayudante";
    }
    
    //mapping para pantalla acceso denegado
    @GetMapping("/acceso_denegado")
    public String mostrarAccesoDenegado(){
        return "acceso_denegado";
    }
    
    
    
}
