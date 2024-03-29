<%-- 

--%>

<%@page contentType="text/html" pageEncoding="UTF-8"%>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>
<%@ taglib prefix = "c" uri = "http://java.sun.com/jsp/jstl/core" %>


<!DOCTYPE html>
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">

        <link href="//netdna.bootstrapcdn.com/bootstrap/3.2.0/css/bootstrap.min.css" rel="stylesheet" id="bootstrap-css">
        <script src="//netdna.bootstrapcdn.com/bootstrap/3.2.0/js/bootstrap.min.js"></script>
        <script src="//code.jquery.com/jquery-1.11.1.min.js"></script>
        <!--Pulling Awesome Font -->
        <link href="//maxcdn.bootstrapcdn.com/font-awesome/4.2.0/css/font-awesome.min.css" rel="stylesheet">

        <link href="http://fonts.googleapis.com/css?family=Roboto:400" rel="stylesheet" type="text/css">
        <style>
            body {
                background-color:#fff;
                -webkit-font-smoothing: antialiased;
                font: normal 14px Roboto,arial,sans-serif;
            }

            .container {
                padding: 25px;
                position: fixed;
            }

            .form-login {
                background-color: #EDEDED;
                padding-top: 10px;
                padding-bottom: 20px;
                padding-left: 20px;
                padding-right: 20px;
                border-radius: 15px;
                border-color:#d2d2d2;
                border-width: 5px;
                box-shadow:0 1px 0 #cfcfcf;
            }

            h4 {
                border:0 solid #fff;
                border-bottom-width:1px;
                padding-bottom:10px;
                text-align: center;
            }

            .form-control {
                border-radius: 10px;
            }

            .wrapper {
                text-align: center;
            }
        </style>

        <title>Login de Usuario</title>
    </head>
    <body>
        <div class="container">
            <div class="row">
                <div class="col-md-offset-5 col-md-3">
                    <div class="form-login">
                        <h4>Inicio de sesión</h4>
                        <form:form action="${pageContext.request.contextPath}/autenticacionUsuario" method="POST"><!<!-- URL donde Spring Security envía por HTTP POST los datos de login. Se procesa en SeguridadApConfig  -->
                            <input type="text" id="userName" name="username" class="form-control input-sm chat-input" placeholder="usuario" />
                            </br>
                            <input type="text" id="userPassword" name="password" class="form-control input-sm chat-input" placeholder="contraseña" />
                            </br>
                            <div class="wrapper">
                                <span class="group-btn">     
                                    <button type="submit" class="btn btn-primary btn-md">
                                        Entrar <i class="fa fa-sign-in"></i>
                                    </button>
                                </span>
                            </div>
                        </form:form>
                        <c:if test="${param.error != null}">
                            <div class="alert alert-danger mt-3" role="alert">
                                <strong>Usuario o contraseña incorrecto</strong>
                            </div>
                        </c:if>
                        <c:if test="${param.logout != null}">
                            <div class="alert alert-primary mt-3" role="alert">
                                <strong>Has Hecho logout</strong>
                            </div>
                        </c:if>
                    </div>
                </div>
            </div>
        </div>
    </body>
</html>


