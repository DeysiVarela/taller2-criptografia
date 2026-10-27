# Guion de video de sustentación

Duración sugerida: entre 6 y 9 minutos. Puedes leer este guion con calma; no
es necesario memorizarlo.

## Antes de grabar

1. Abre VS Code en la carpeta del proyecto.
2. Abre una terminal integrada.
3. Ejecuta `go test ./...` y deja visible el resultado exitoso.
4. Ejecuta `go run .`.
5. Ten abiertas las diapositivas y el README.
6. Comparte únicamente la ventana del proyecto; no muestres contraseñas ni
   información personal.

## Guion paso a paso

### 1. Saludo y objetivo (30 segundos)

> Hola, mi nombre es Deysi. En este video presentaré el Taller Dos de
> Criptografía. El objetivo es proteger un archivo de logs académicos que
> contiene operaciones sensibles de registro y modificación de notas. La
> solución busca garantizar integridad, confidencialidad y verificabilidad.

Muestra las diapositivas 1 y 2.

### 2. Modelo del log (1 minuto)

> Cada evento está representado como un objeto JSON. Incluye un identificador
> único, fecha y hora UTC, tipo de operación, identificadores del actor,
> estudiante y curso, y los datos de la nota. Para una modificación se guardan
> tanto la nota anterior como la nueva.

Muestra la diapositiva del modelo y el diagrama de estructura.

### 3. Hash por evento (1 minuto)

> Para cada operación construyo un payload con todos los campos del evento
> excepto `payload_hash`. Después serializo ese payload como JSON y calculo
> SHA-256. El campo `payload_hash` se excluye porque incluirlo produciría una
> dependencia circular: el hash tendría que incluirse a sí mismo.

> SHA-256 permite detectar cambios: si alguien modifica un campo del evento,
> el hash resultante será diferente.

Muestra la diapositiva de integridad.

### 4. Cifrado del log (1 minuto)

> Después de generar los eventos, serializo el log completo y calculo su hash
> original. Luego uso AES-256-GCM, una construcción autenticada que proporciona
> confidencialidad y detecta modificaciones del ciphertext. La clave y el
> nonce se generan con `crypto/rand`. El nonce se almacena como prefijo del
> archivo cifrado porque no es secreto, pero no debe repetirse con la misma
> clave.

Muestra la diapositiva de cifrado.

### 5. Demostración en la terminal (2 minutos)

Ejecuta:

```powershell
go test ./...
go run .
```

En el menú selecciona **Ejecutar flujo completo** e introduce `5`.

Lee el resultado:

> La aplicación informa cuántos eventos generó, cuántos fueron registros y
> cuántos modificaciones. También muestra el hash del log claro, el hash del
> log cifrado y el hash del log descifrado.

> El hash del ciphertext es diferente al hash del log claro porque el
> contenido fue cifrado. Finalmente, el hash del log descifrado coincide con
> el hash original. Esto demuestra que el proceso de cifrado y descifrado
> preservó la información.

Abre la carpeta `artifacts` y muestra brevemente los archivos generados:
`log.json`, `log.enc`, los hashes y `log.decrypted.json`.

### 6. Explicación de seguridad (1 minuto)

> El archivo `log.json` es legible; `log.enc` no permite leer directamente las
> notas. Si se altera el ciphertext, AES-GCM rechaza el descifrado por fallo de
> autenticación. La clave se guarda separada para esta demostración académica.
> En producción debería almacenarse en un gestor de secretos, KMS o HSM, y no
> junto al archivo cifrado.

### 7. Cierre y uso responsable de IA (30 segundos)

> La solución fue probada con `go test ./...` y compilada con Go. La
> inteligencia artificial se utilizó como apoyo para organizar, revisar y
> documentar la solución; yo revisé y probé el código y soy responsable de
> comprender y presentar el resultado.

> Gracias por su atención.

## Consejos para una persona principiante

- Habla despacio y lee el guion; es completamente válido.
- Haz una prueba corta antes de grabar el video final.
- Si te equivocas, pausa unos segundos y repite la frase; puedes cortar esa
  parte en el editor.
- No necesitas explicar cada línea de código. Explica el flujo y las razones
  de diseño.
- Verifica que la terminal muestre `Verificación: ÉXITO`.
