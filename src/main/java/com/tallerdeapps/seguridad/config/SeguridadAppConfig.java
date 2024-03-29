package com.tallerdeapps.seguridad.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.User.UserBuilder;

/**
 *
 */
@Configuration
@EnableWebSecurity
public class SeguridadAppConfig extends WebSecurityConfigurerAdapter {

    // OBSOLETO: se crea lista de usuarios para login. Lo normal sería obtener los usuarios de una bbdd.
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        UserBuilder usuarios = User.withDefaultPasswordEncoder();

        auth.inMemoryAuthentication()
                .withUser(usuarios.username("Pedro").password("123").roles("usuario", "administrador"))
                .withUser(usuarios.username("Juan").password("123").roles("usuario"))
                .withUser(usuarios.username("Ivan").password("000").roles("usuario", "ayudante"))
                .withUser(usuarios.username("Maria").password("123").roles("invitado"));
    }

    // (método para desviar el login predeterminado del ejemplo del video anterior a uno personalizado)
    // Método para configurar la seguridad de la aplicación
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // Autorizar todas las peticiones entrantes                                //
        // http.authorizeRequests().anyRequest().authenticated().and().formLogin() //
        
        
        http.authorizeRequests()
                .antMatchers("/").hasRole("usuario")// Establecer que a la pantalla de inicio pueda entrar quien tenga rol de "usuario"
                .antMatchers("/administradores/**").hasRole("administrador")// Establecer que a la pantalla de admins(y sus subdirectorios) solo entra quien tenga ese rol
                .antMatchers("/ayudante/**").hasRole("ayudante")// Establecer que a la pantalla de "ayudante" solo entra ese rol 
                .and().formLogin()
                // Establecer la página de inicio de sesión personalizada como "/miFormularioLogin"
                .loginPage("/miFormularioLogin")
                // Establecer la URL de procesamiento del inicio de sesión
                // el formulario envía el login por HTTP POST a "/autenticacionUsuario" y este método de Spring Security procesa los datos ahí
                .loginProcessingUrl("/autenticacionUsuario")
                .permitAll() // Permitir que todos los usuarios intenten iniciar sesión
                // Configurar la funcionalidad de cierre de sesión, permitiendo a todos los usuarios cerrar sesión
                .and().logout().permitAll()
                .and().exceptionHandling().accessDeniedPage("/acceso_denegado");
    }

}
