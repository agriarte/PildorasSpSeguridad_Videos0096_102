package com.tallerdeapps.seguridad.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.ViewResolver;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.view.InternalResourceViewResolver;

/**
 * Clase de configuración hecha a mano desde el curso
 * 1-Anotación para indicar que es una configuración 
 * 2-Anotación para habilitar MVC 
 * 3-Anotación para indicar donde buscará Spring todas las clases de componentes
 */
@Configuration
@EnableWebMvc
@ComponentScan("com.tallerdeapps.seguridad")
public class AppConfig {
    //método que se encarga de resolver las vistas de los recursos internos, directorio web y extensión de archivos

    @Bean
    public ViewResolver viewResolver() {
        InternalResourceViewResolver viewResolver = new InternalResourceViewResolver();
        viewResolver.setPrefix("/WEB-INF/view/"); //donde están las vistas
        viewResolver.setSuffix(".jsp"); // extensión

        return viewResolver;
    }
}
