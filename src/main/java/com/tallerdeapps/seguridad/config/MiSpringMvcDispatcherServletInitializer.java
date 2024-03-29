package com.tallerdeapps.seguridad.config;

import org.springframework.web.servlet.support.AbstractAnnotationConfigDispatcherServletInitializer;

/**
 *
 */
public class MiSpringMvcDispatcherServletInitializer extends AbstractAnnotationConfigDispatcherServletInitializer {

    // devuelve un array de clases de configuracion. Aquellas que tienen @Configuration.
    // Suelen contener definiciones de bean, configuraciones de bbdd, seguridad y otras configuraciones de contexto. De momento, no usamos
    @Override
    protected Class<?>[] getRootConfigClasses() {
        return null;
    }

    // devuelve un array de clases de configuracion
    // También pueden contener definiciones de bean. Suelen definir configuraciones relacionadas con la capa web: servletdispatcher, controladores, viewresolver
    @Override
    protected Class<?>[] getServletConfigClasses() {
        return new Class[]{AppConfig.class}; // devuelve la única clase de config que tenemos dentro de un nuevo array
    }

    // devuelve un array de strings que define los patrones de mapeo de URL para el servletdispatcher
    // en este caso, de momento solo la raiz
    @Override
    protected String[] getServletMappings() {
        return new String[]{"/"}; // directorio raiz mapeado por servletdispatcher
    }

}
