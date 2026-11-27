# Evidencias del Lab 7 — R1 (control de acceso según rol)

Capturas de las pruebas funcionales de R1 ejecutadas en el slice el 27/11/2026 con `main` en el commit `4a63653`.

| Prueba | Qué valida |
| --- | --- |
| P0 | Túneles SSH usados para hablar como cada equipo |
| P1 | Un equipo sin sesión solo alcanza el portal |
| P2 | Login de la comunidad (RADIUS→LDAP), rol `academic` y regla 200 en SW3 |
| P3 | Rechazo uniforme y cuarentena tras 5 fallos |
| P4 | Contexto del puesto (403) y operador con dos factores |
| P5 | Trazabilidad de las decisiones y panel de administración |
| P6 | Cierre de sesión

| Figura | Archivo | Descripción |
| --- | --- | --- |
| 1 | [`R1-P0-01_tunel-h1.png`](R1-P0-01_tunel-h1.png) | Túnel SSH de la ventana A: el navegador accede al portal como h1 (PC1) |
| 2 | [`R1-P0-02_tunel-h3-consola.png`](R1-P0-02_tunel-h3-consola.png) | Túnel SSH de la ventana B: portal y consola vistos desde h3 (PC3) |
| 3 | [`R1-FIG-maquina-estados.png`](R1-FIG-maquina-estados.png) | Máquina de estados del cliente en R1 |
| 4 | [`R1-P1-01_h1-sin-sesion.png`](R1-P1-01_h1-sin-sesion.png) | h1 sin sesión: el ping a h4 falla y el portal responde 200 |
| 5 | [`R1-P2-01_usr0001-formulario.png`](R1-P2-01_usr0001-formulario.png) | Login de USR-0001 en el portal desde PC1 |
| 6 | [`R1-P2-02_usr0001-200-academic.png`](R1-P2-02_usr0001-200-academic.png) | Respuesta del IAM: sesión con rol academic y cuatro reglas aplicadas en SW3 (token tapado) |
| 7 | [`R1-P2-03_sw3-regla200-y-210.png`](R1-P2-03_sw3-regla200-y-210.png) | SW3: regla de sesión 200 hacia 10.0.0.0/24 y tres DROP 210 hacia los servidores |
| 8 | [`R1-P2-04_h1-pings-con-sesion.png`](R1-P2-04_h1-pings-con-sesion.png) | h1 con sesión: h4 responde y la red de gestión no |
| 9 | [`R1-P3-01_usr9999-formulario.png`](R1-P3-01_usr9999-formulario.png) | Intento de acceso con un usuario inexistente (USR-9999) |
| 10 | [`R1-P3-02_usr9999-401.png`](R1-P3-02_usr9999-401.png) | Respuesta al usuario inexistente: invalid credentials |
| 11 | [`R1-P3-03_usr0005-formulario.png`](R1-P3-03_usr0005-formulario.png) | Intento de acceso de USR-0005 con su clave correcta, ya en cuarentena |
| 12 | [`R1-P3-04_usr0005-401-cuarentena.png`](R1-P3-04_usr0005-401-cuarentena.png) | Respuesta a la cuenta en cuarentena: el mismo invalid credentials |
| 13 | [`R1-P3-05_sw3-sin-reglas.png`](R1-P3-05_sw3-sin-reglas.png) | SW3 sin reglas de sesión tras los intentos inválidos |
| 14 | [`R1-P4-01_usr0002-formulario-pc3.png`](R1-P4-01_usr0002-formulario-pc3.png) | Intento de acceso de un alumno desde PC3 (puesto de operaciones) |
| 15 | [`R1-P4-02_usr0002-403-puesto.png`](R1-P4-02_usr0002-403-puesto.png) | Rechazo por contexto: población no permitida en el puesto |
| 16 | [`R1-P4-03_adm-bench-paso1.png`](R1-P4-03_adm-bench-paso1.png) | Operador: primer factor (usuario y contraseña) |
| 17 | [`R1-P4-04_adm-bench-totp-requerido.png`](R1-P4-04_adm-bench-totp-requerido.png) | Respuesta del IAM: se requiere el segundo factor |
| 18 | [`R1-P4-05_adm-bench-paso2-totp.png`](R1-P4-05_adm-bench-paso2-totp.png) | Operador: segundo factor (código TOTP, tapado) |
| 19 | [`R1-P4-06_adm-bench-200.png`](R1-P4-06_adm-bench-200.png) | Sesión emitida con rol network_admin y reglas aplicadas en SW6 (token tapado) |
| 20 | [`R1-P4-07_sw6-reglas-admin.png`](R1-P4-07_sw6-reglas-admin.png) | Reglas de sesión del administrador en SW6: VIP y red de gestión |
| 21 | [`R1-P5-01_decisiones-operador.png`](R1-P5-01_decisiones-operador.png) | Trazabilidad del login del operador: segundo factor requerido, TOTP erróneo y acceso concedido |
| 22 | [`R1-P5-02_decisiones-comunidad.png`](R1-P5-02_decisiones-comunidad.png) | Trazabilidad de los logins de la comunidad: credenciales verificadas, rechazos, cuarentena y puesto |
| 23 | [`R1-P5-03_panel-operadores-puestos.png`](R1-P5-03_panel-operadores-puestos.png) | Panel de administración: operadores con su rol y mapa de puestos (token tapado) |
| 24 | [`R1-P5-04_panel-altas.png`](R1-P5-04_panel-altas.png) | Panel de administración: formularios de alta de operadores y de puestos |
| 25 | [`R1-P6-01_sw3-sin-sesion.png`](R1-P6-01_sw3-sin-sesion.png) | SW3 sin reglas de sesión tras el cierre |
| 26 | [`R1-P6-02_sw6-sin-sesion.png`](R1-P6-02_sw6-sin-sesion.png) | SW6 sin reglas de sesión tras el cierre de ADM-BENCH |
| 27 | [`R1-OBS-01_cuarentena-usr0001.png`](R1-OBS-01_cuarentena-usr0001.png) | Cuarentena de USR-0001 tras cinco fallos consecutivos |
