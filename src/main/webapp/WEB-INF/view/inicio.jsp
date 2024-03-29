<%@page contentType="text/html" pageEncoding="UTF-8"%>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>
<%@ taglib prefix = "c" uri = "http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="sec" uri="http://www.springframework.org/security/tags" %> <%-- para usar tags de roles de usuario,... --%>

<!DOCTYPE html>
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">

        <link href="//netdna.bootstrapcdn.com/bootstrap/3.2.0/css/bootstrap.min.css" rel="stylesheet" id="bootstrap-css">
        <script src="//netdna.bootstrapcdn.com/bootstrap/3.2.0/js/bootstrap.min.js"></script>
        <script src="//code.jquery.com/jquery-1.11.1.min.js"></script>
        <!--Pulling Awesome Font -->
        <link href="//maxcdn.bootstrapcdn.com/font-awesome/4.2.0/css/font-awesome.min.css" rel="stylesheet">

        <title>Proyecto Seguridad</title>
    </head>
    <body>
        <div class="container">
            <h1>Pantalla de inicio</h1>
            <!-- Mostrar el nombre de usuario -->
            <p>Mostrar usuario con expresiones de lenguaje:</p>
            <p> Bienvenido usuario: ${pageContext.request.userPrincipal.name} rol: ${pageContext.request.userPrincipal.authorities}</p>
            
            <p>Mostrar usuario con taglibs:</p>
            <p> Bienvenido usuario: <sec:authentication property="principal.username"/> rol: <sec:authentication property="principal.authorities"/>

            <form:form action="${pageContext.request.contextPath}/logout" method="POST">
                <input type="submit" value="Logout" class="btn btn-danger"/>
            </form:form>
                
            <!<!-- Link para administradores -->
            <sec:authorize access="hasRole('administrador')">
            <br><br>
            <a href="${pageContext.request.contextPath}/administradores">Ir a zona de Admins</a>
            </sec:authorize>
            <!<!-- Link para ayudantes -->
            <sec:authorize access="hasRole('ayudante')">
            <br><br>
            <a href="${pageContext.request.contextPath}/ayudante">Ir a zona de Ayudantes</a>
            </sec:authorize>
        </div>
    </body>
</html>
