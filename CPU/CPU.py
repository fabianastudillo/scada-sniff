import psutil
import logging
from graypy import GELFUDPHandler
import time

def obtener_informacion_sistema():
    # Obtener el porcentaje de uso del CPU
    porcentaje_cpu = psutil.cpu_percent(interval=1)
    
    # Obtener la información de memoria
    memoria = psutil.virtual_memory()
    porcentaje_memoria = memoria.percent
    
    # Obtener la Información de disco
    disco = psutil.disk_usage('/')
    porcentaje_disco = disco.percent
    
    # Construir un diccionario con la información recopilada
    informacion_sistema = {
        'porcentaje_cpu': porcentaje_cpu,
        'porcentaje_memoria': porcentaje_memoria,
        'porcentaje_disco': porcentaje_disco
    }
    return informacion_sistema

if __name__ == "__main__":
    # Dirección IP y puerto de Graylog
    graylog_host = '127.0.0.1'
    graylog_port = 6514
    
    # Configurar el cliente Graylog una vez fuera del bucle
    handler = GELFUDPHandler(graylog_host, graylog_port)
    logger = logging.getLogger('graylog')
    logger.addHandler(handler)
    
    # Bucle infinito para enviar la información cada 10 segundos
    while True:
        # Obtener la información del sistema
        informacion_sistema = obtener_informacion_sistema()
        
        # Enviar la información a Graylog
        logger.warning(informacion_sistema)
        
        # Esperar 10 segundos antes de la próxima ejecución
        time.sleep(10)
