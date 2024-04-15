# from scapy.all import sniff, TCP
# from scapy.layers.inet import IP
# import scapy.contrib.modbus as mb
# import logging
# from graypy import GELFUDPHandler

# # Diccionario de mapeo de direcciones IP a nombres
# mapeo_ips = {
#     "192.168.222.9": "PLC apis1",
#     "192.168.222.11": "PLC1 apis2",
#     "192.168.222.12": "PLC2 apis2",
#     "192.168.222.13": "PLC3 apis2",
#     "192.168.222.14": "PLC4 apis2",
#     "192.168.222.15": "PLC apis3",
#     "192.168.222.55": "SCADA"
# }

# # Definir el filtro de captura para el puerto 502 de Modbus
# def filtro_modbus(packet):
#     return TCP in packet and (packet[TCP].sport == 502 or packet[TCP].dport == 502)

# # Función para manejar cada paquete capturado
# def manejar_paquete(packet):
#     tipo_mensaje = None
#     if mb.ModbusADUResponse in packet:
#         tipo_mensaje = "ADUResponse"
#     elif mb.ModbusADURequest in packet:
#         tipo_mensaje = "ADURequest"

#     ipsrc = packet[IP].src
#     ipdest = packet[IP].dst

#     # Obtener el nombre asociado a la dirección IP de origen y destino
#     nombre_ipsrc = mapeo_ips.get(ipsrc, "Desconocido")
#     nombre_ipdest = mapeo_ips.get(ipdest, "Desconocido")

#     if tipo_mensaje:
#         logger.debug("Mensaje Modbus: Tipo=%s, IP_SRC=%s(%s), IP_DST=%s(%s)", tipo_mensaje, ipsrc, nombre_ipsrc, ipdest, nombre_ipdest)

# # Set logs
# logger = logging.getLogger("gelf")
# logger.setLevel(logging.DEBUG)

# handler = GELFUDPHandler(host="127.0.0.1", port=5514)
# logger.addHandler(handler)

# # Iniciar la captura
# sniff(prn=manejar_paquete, lfilter=filtro_modbus, iface="ens36", store=False)


from scapy.all import sniff, TCP
from scapy.layers.inet import IP
import scapy.contrib.modbus as mb
import logging
from graypy import GELFUDPHandler

# Diccionario de mapeo de direcciones IP a nombres
mapeo_ips = {
    "192.168.222.9": "PLC apis1",
    "192.168.222.11": "PLC1 apis2",
    "192.168.222.12": "PLC2 apis2",
    "192.168.222.13": "PLC3 apis2",
    "192.168.222.14": "PLC4 apis2",
    "192.168.222.15": "PLC apis3",
    "192.168.222.55": "SCADA"
}

# Contadores para ADUResponses y ADURequests
num_adu_responses = 0
num_adu_queries = 0

# Definir el filtro de captura para el puerto 502 de Modbus
def filtro_modbus(packet):
    return TCP in packet and (packet[TCP].sport == 502 or packet[TCP].dport == 502)

# Función para manejar cada paquete capturado
def manejar_paquete(packet):
    global num_adu_responses, num_adu_request
    
    if mb.ModbusADUResponse in packet:
        num_adu_responses += 1
        tipo_mensaje = "ADUResponse"
    elif mb.ModbusADURequest in packet:  # Cambio aquí a ModbusADUQuery
        num_adu_request += 1
        tipo_mensaje = "ADURequest"      # Y aquí a ADUQuery
    else:
        return

    ipsrc = packet[IP].src
    ipdest = packet[IP].dst

    # Obtener el nombre asociado a la dirección IP de origen y destino
    nombre_ipsrc = mapeo_ips.get(ipsrc, "Desconocido")
    nombre_ipdest = mapeo_ips.get(ipdest, "Desconocido")

    logger.debug("Mensaje Modbus: Tipo=%s, IP_SRC=%s(%s), IP_DST=%s(%s)", tipo_mensaje, ipsrc, nombre_ipsrc, ipdest, nombre_ipdest)

    # Aquí puedes enviar los contadores a Graylog si lo deseas
    # Por ejemplo:
    logger.debug("ADUResponses: %d, ADURequest: %d", num_adu_responses, num_adu_request)

# Set logs
logger = logging.getLogger("gelf")
logger.setLevel(logging.DEBUG)

handler = GELFUDPHandler(host="127.0.0.1", port=5514)
logger.addHandler(handler)

# Iniciar la captura
sniff(prn=manejar_paquete, lfilter=filtro_modbus, iface="ens36", store=False)

# Al final de la ejecución, puedes imprimir los contadores si lo deseas
#print("ADUResponses:", num_adu_responses)
#print("ADUQueries:", num_adu_queries)
