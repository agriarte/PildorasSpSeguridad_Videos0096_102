<%-- 
    No usado en el programa. Lo dejo a modo de ejemplo
--%>

<%@page contentType="text/html" pageEncoding="UTF-8"%>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>
<%@ taglib prefix = "c" uri = "http://java.sun.com/jsp/jstl/core" %>
<!DOCTYPE html>
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
        <title>Login de Usuario</title>
        <style>
            .formatoError{
                color:red;
            }
        </style>
    </head>
    <body>
        <h2 style="text-align: center">Login de Usuario Personalizado</h2>
        <form:form action="${pageContext.request.contextPath}/autenticacionUsuario" method="POST">
            
            <c:if test="${param.error!=null}">
                <strong class="formatoError">Usuario o password incorrecto</strong>
            </c:if>
            
            <p>
                Usuario: <input type="text" name="username"/>
            </p>
            
             <p>
                Contraseña: <input type="password" name="password"/>
            </p>
            
            <input type="submit" value="Enviar">
            
        </form:form>
    </body>
</html>
