<%@page contentType="text/html" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <!-- Enlace a Bootstrap CSS -->
        <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
        <!-- Enlace a Font Awesome -->
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.1/css/all.min.css" rel="stylesheet">

        <title>Acceso denegado</title>
    </head>
    <body>
        <div class="container">
            <h1>Usuario con acceso restringido a esa zona</h1>
            <p> El usuario ${pageContext.request.userPrincipal.name} con rol: ${pageContext.request.userPrincipal.authorities} no tiene permiso de acceso.</p>
            <div class="d-flex justify-content-center">
                <!-- Botón para volver a la página anterior -->
                <button onclick="goBack()" class="btn btn-primary">Volver a la Página Anterior</button>
            </div>

            <!-- Script para volver a la página anterior -->
            <script>
                function goBack() {
                    window.history.back();
                }
            </script>
        </div>
    </body>
</html>
