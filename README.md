# Mini Code Injector

Esta herramienta es un pequeño programa diseñado para inyectar shellcode en un proceso de Windows. Su desarrollo surgió a raíz de mi curiosidad por comprender el funcionamiento del comando *migrate* en *Metasploit Framework*. Al ejecutarla, es importante tener en cuenta que el shellcode por defecto está configurado para abrir la aplicación *calc.exe*. Si se desea utilizar un código diferente, será necesario generarlo en función de la arquitectura del sistema operativo. Para facilitar esta tarea, se puede emplear *msfvenom*.

## Pasos de script

El proceso de inyección consta de los siguientes pasos:

1. Identificar el identificador de proceso (PID) a partir de su nombre.
2. Abrir el proceso objetivo.
3. Reservar un segmento de memoria dentro del proceso.
4. Escribir el shellcode en la memoria reservada.
5. Crear un nuevo hilo dentro del proceso que ejecute el shellcode inyectado.

## Tener en cuenta

* Puede que a veces se reserve memoria inválida lo que puede generar que se cierre el proceso padre o directamente que el shellcode no se ejecute.
* La shellcode para ejecutar *calc.exe* es para versiones de x64. Para cualquier otro hay que reemplazar el del source code.
